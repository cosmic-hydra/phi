//! Parallel transaction executor (docs/ARCHITECTURE.md §3, §5).
//!
//! Transactions declare access sets; the scheduler partitions a block into
//! *waves* of mutually disjoint transactions. Waves run in order, the
//! transactions inside a wave run in parallel across threads, and the result
//! is guaranteed byte-identical to serial execution:
//!
//! - Conflicting transactions never reorder across waves (a transaction is
//!   scheduled after the last wave it conflicts with).
//! - Execution cannot escape the declared access set — `phi-state` rejects
//!   undeclared access (`TxError::AccessViolation`) before any mutation.
//!
//! This is the seed of the Block-STM optimistic engine (Phase 2): the wave
//! schedule replaces optimistic re-execution while keeping the same
//! serial-equivalence contract, which the property tests below pin down.

use std::collections::BTreeSet;
use std::thread;

use phi_state::{Receipt, State};
use phi_types::{AccountId, Hash, Transaction};

/// Result of executing a batch: the post-state root and one receipt per
/// transaction in batch order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub state_root: Hash,
    pub receipts: Vec<Receipt>,
    /// Total figs burned as inclusion fees across the batch (the sum of every
    /// receipt's `fee_paid`). The Cargo supply audit reconciles this against
    /// the change in total supply.
    pub fees_burned: u64,
}

/// Partition `txs` (by index) into waves of mutually disjoint transactions.
/// Waves execute in order; everything within a wave may run in parallel.
///
/// A transaction is placed in the wave *after the last wave containing a
/// conflict*. Placing it any earlier — e.g. greedy first-fit — is unsound:
/// with writes `{Y}`, `{Y,X}`, `{X}`, first-fit puts the third transaction
/// in wave 0 next to the first, executing it *before* the conflicting second
/// transaction and breaking serial order.
pub fn conflict_groups(txs: &[Transaction]) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (i, tx) in txs.iter().enumerate() {
        let mut target = 0;
        for (g, group) in groups.iter().enumerate() {
            if group
                .iter()
                .any(|&j| !txs[j].access.disjoint_from(&tx.access))
            {
                target = g + 1;
            }
        }
        if target == groups.len() {
            groups.push(Vec::new());
        }
        groups[target].push(i);
    }
    groups
}

/// Every account a transaction can possibly read or write: the declared set
/// plus the sender and credited account. For well-formed transactions the
/// extras are already declared; for malformed ones they let the sandboxed
/// validation fail with exactly the same error as serial execution.
fn touchable_accounts(tx: &Transaction) -> BTreeSet<AccountId> {
    let mut ids: BTreeSet<AccountId> = tx.access.reads.iter().copied().collect();
    ids.extend(tx.access.writes.iter().copied());
    ids.insert(tx.sender);
    if let Some(sponsor) = tx.sponsor {
        ids.insert(sponsor);
    }
    match &tx.kind {
        phi_types::TransactionKind::Transfer { to, .. }
        | phi_types::TransactionKind::Mint { to, .. } => {
            ids.insert(*to);
        }
    }
    ids
}

/// Execute `txs` against `state`, scheduling disjoint transactions in
/// parallel. Produces the same state and receipts as serially calling
/// `state.apply_tx` for each transaction in order.
pub fn execute(state: &mut State, txs: &[Transaction]) -> ExecutionOutput {
    let mut receipts: Vec<Option<Receipt>> = vec![None; txs.len()];

    for group in conflict_groups(txs) {
        // Build one sandbox per transaction: a mini-state holding only the
        // accounts the transaction may touch. Within a wave the declared
        // sets are disjoint, so sandboxes never share a mutable account.
        let jobs: Vec<(usize, State)> = group
            .iter()
            .map(|&i| {
                // Inherit the ledger's consensus config (chain_id, minter) so
                // sandboxed validation matches the real state exactly.
                let mut sandbox = state.empty_like();
                for id in touchable_accounts(&txs[i]) {
                    if let Some(account) = state.account(&id) {
                        sandbox.upsert_account(account.clone());
                    }
                }
                (i, sandbox)
            })
            .collect();

        let results = run_jobs(jobs, txs);

        // Merge sandbox effects back. Only declared writes are merged; a
        // transaction that failed validation mutated nothing, and one that
        // executed had its writes covered by the declaration.
        for (i, sandbox, receipt) in results {
            let writes: BTreeSet<AccountId> = txs[i].access.writes.iter().copied().collect();
            for id in writes {
                if let Some(account) = sandbox.account(&id) {
                    state.upsert_account(account.clone());
                }
            }
            receipts[i] = Some(receipt);
        }
    }

    let receipts: Vec<Receipt> = receipts
        .into_iter()
        .map(|r| r.expect("every tx scheduled exactly once"))
        .collect();
    let fees_burned = receipts.iter().map(|r| r.fee_paid).sum();
    ExecutionOutput {
        state_root: state.root(),
        receipts,
        fees_burned,
    }
}

/// Run the wave's jobs, spreading them over the available cores.
///
/// Scoped spawns keep the starter dependency-free; per-wave thread startup
/// costs more than executing a small wave, so the Phase-2 engine replaces
/// this with a persistent worker pool fed by the same wave schedule.
fn run_jobs(jobs: Vec<(usize, State)>, txs: &[Transaction]) -> Vec<(usize, State, Receipt)> {
    let run = |(i, mut sandbox): (usize, State)| {
        let receipt = sandbox.apply_tx(&txs[i]);
        (i, sandbox, receipt)
    };

    if jobs.len() <= 1 {
        return jobs.into_iter().map(run).collect();
    }

    let workers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(jobs.len());
    let chunk_size = jobs.len().div_ceil(workers);

    let mut chunks: Vec<Vec<(usize, State)>> = Vec::with_capacity(workers);
    let mut jobs = jobs.into_iter().peekable();
    while jobs.peek().is_some() {
        chunks.push(jobs.by_ref().take(chunk_size).collect());
    }

    thread::scope(|scope| {
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| scope.spawn(move || chunk.into_iter().map(run).collect::<Vec<_>>()))
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().expect("executor worker panicked"))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use phi_types::AccountId;

    fn id(label: &str) -> AccountId {
        AccountId::from_label(label)
    }

    fn funded_state(labels: &[&str], balance: u64) -> State {
        let mut state = State::new();
        for label in labels {
            state.genesis_account(id(label), balance);
        }
        state
    }

    /// Serial reference: receipts + root from `State::apply_tx` in order.
    fn serial(state: &mut State, txs: &[Transaction]) -> ExecutionOutput {
        let receipts: Vec<Receipt> = txs.iter().map(|tx| state.apply_tx(tx)).collect();
        let fees_burned = receipts.iter().map(|r| r.fee_paid).sum();
        ExecutionOutput {
            state_root: state.root(),
            receipts,
            fees_burned,
        }
    }

    #[test]
    fn sandboxes_inherit_chain_id_and_minter_from_the_ledger() {
        // Regression: sandboxes were built with State::new(), dropping the
        // ledger's consensus config, so authorized mints failed and a
        // non-zero chain_id rejected its own transactions inside the
        // executor — diverging from serial execution.
        let mut state = State::new();
        state.set_chain_id(42);
        state.set_minter(Some(id("treasury")));
        state.genesis_account(id("treasury"), 0);
        state.genesis_account(id("alice"), 0); // Open auth, can spend unsigned

        let txs = vec![
            Transaction::mint(id("treasury"), 0, id("alice"), 500).with_chain_id(42),
            Transaction::transfer(id("alice"), 0, id("bob"), 200).with_chain_id(42),
        ];
        let mut serial_state = state.clone();
        let expected = serial(&mut serial_state, &txs);
        let actual = execute(&mut state, &txs);
        assert_eq!(expected, actual);
        assert!(actual.receipts.iter().all(|r| r.result.is_ok()));
        assert_eq!(state.balance(&id("bob")), 200);

        // A transaction for the wrong network fails inside the sandbox too.
        let wrong_chain =
            vec![Transaction::mint(id("treasury"), 1, id("alice"), 1).with_chain_id(7)];
        let out = execute(&mut state, &wrong_chain);
        assert_eq!(
            out.receipts[0].result,
            Err(phi_state::TxError::WrongChain {
                expected: 42,
                got: 7
            })
        );
    }

    #[test]
    fn disjoint_txs_share_a_wave_conflicts_split() {
        let txs = vec![
            Transaction::transfer(id("alice"), 0, id("bob"), 1), // writes alice,bob
            Transaction::transfer(id("carol"), 0, id("dave"), 1), // disjoint -> same wave
            Transaction::transfer(id("alice"), 1, id("eve"), 1), // conflicts #1 -> next wave
        ];
        let groups = conflict_groups(&txs);
        assert_eq!(groups, vec![vec![0, 1], vec![2]]);
    }

    #[test]
    fn conflicting_txs_never_reorder_across_waves() {
        // Regression for the first-fit scheduling bug: tx2 conflicts with
        // tx1 (account x) but not with tx0, and must NOT land in wave 0
        // ahead of tx1.
        let txs = vec![
            Transaction::transfer(id("y1"), 0, id("y2"), 1), // {y1,y2}
            Transaction::transfer(id("y1"), 1, id("x"), 60), // {y1,x}
            Transaction::transfer(id("x"), 0, id("z"), 50),  // {x,z}
        ];
        let groups = conflict_groups(&txs);
        assert_eq!(groups, vec![vec![0], vec![1], vec![2]]);

        // And the semantic consequence: x can only afford the 50 after
        // receiving 60; reordering would make the third transfer fail.
        let mut serial_state = funded_state(&["y1", "y2"], 100);
        serial_state.genesis_account(id("x"), 0);
        let mut parallel_state = serial_state.clone();

        let expected = serial(&mut serial_state, &txs);
        let actual = execute(&mut parallel_state, &txs);
        assert!(actual.receipts.iter().all(|r| r.result.is_ok()));
        assert_eq!(expected, actual);
    }

    #[test]
    fn fees_burn_in_parallel_exactly_as_serially() {
        // base_fee burns figs from each payer; a sponsored transfer debits
        // the sponsor. Parallel execution must reproduce serial byte-for-byte
        // including the post-supply drop and the reported fees_burned.
        let mut state = State::new();
        state.set_base_fee(7);
        state.genesis_account(id("alice"), 1_000);
        state.genesis_account(id("bob"), 1_000);
        state.genesis_account(id("treasury"), 1_000);

        let txs = vec![
            // alice pays her own fee (disjoint from bob's transfer -> 1 wave).
            Transaction::transfer(id("alice"), 0, id("carol"), 100).with_max_fee(7),
            Transaction::transfer(id("bob"), 0, id("dave"), 50).with_max_fee(7),
            // treasury sponsors alice's second transfer's fee.
            Transaction::transfer(id("alice"), 1, id("carol"), 100)
                .with_max_fee(7)
                .with_sponsor(id("treasury")),
        ];

        let mut serial_state = state.clone();
        let expected = serial(&mut serial_state, &txs);
        let actual = execute(&mut state, &txs);

        assert_eq!(expected, actual);
        assert!(actual.receipts.iter().all(|r| r.result.is_ok()));
        // Three successful transactions at 7 figs each.
        assert_eq!(actual.fees_burned, 21);
        // Pre-supply 3000 less the 21 burned.
        assert_eq!(state.total_supply(), 2_979);
        // The treasury footed only the third fee; alice paid the other one.
        assert_eq!(state.balance(&id("treasury")), 993);
        // alice sent 200 across two transfers but only burned the fee on the
        // first (the sponsor covered the second).
        assert_eq!(state.balance(&id("alice")), 1_000 - 200 - 7);
    }

    #[test]
    fn parallel_matches_serial_with_failures_and_account_creation() {
        let txs = vec![
            Transaction::transfer(id("alice"), 0, id("new-1"), 10), // creates account
            Transaction::transfer(id("bob"), 0, id("new-2"), 10),   // parallel with #0
            Transaction::transfer(id("alice"), 1, id("bob"), 1_000_000), // runtime failure
            Transaction::transfer(id("ghost"), 0, id("alice"), 1),  // unknown sender
            Transaction::transfer(id("new-1"), 0, id("bob"), 5),    // unclaimed: RevealMismatch
        ];
        let mut serial_state = funded_state(&["alice", "bob"], 500);
        let mut parallel_state = serial_state.clone();

        let expected = serial(&mut serial_state, &txs);
        let actual = execute(&mut parallel_state, &txs);
        assert_eq!(expected, actual);
        assert!(actual.receipts[2].result.is_err());
        assert!(actual.receipts[3].result.is_err());
        assert!(actual.receipts[4].result.is_err());
    }

    /// Deterministic xorshift-style generator (no dependencies).
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 11
        }
    }

    #[test]
    fn fuzz_serial_equivalence() {
        let labels: Vec<String> = (0..12).map(|i| format!("acct-{i}")).collect();
        let label_refs: Vec<&str> = labels.iter().map(|s| s.as_str()).collect();

        for seed in 0..30 {
            let mut rng = Rng(0x5eed + seed);
            let mut serial_state = funded_state(&label_refs, 1_000);
            let mut parallel_state = serial_state.clone();
            // Track expected nonces so most generated txs are valid while
            // some still exercise failure paths.
            let mut nonces = vec![0u64; labels.len()];

            for _ in 0..6 {
                let batch: Vec<Transaction> = (0..16)
                    .map(|_| {
                        let from = (rng.next() % labels.len() as u64) as usize;
                        let to = (rng.next() % labels.len() as u64) as usize;
                        let amount = rng.next() % 400; // sometimes exceeds funds
                        let nonce = if rng.next().is_multiple_of(8) {
                            rng.next() % 4 // occasionally invalid
                        } else {
                            nonces[from]
                        };
                        let tx = Transaction::transfer(
                            id(&labels[from]),
                            nonce,
                            id(&labels[to]),
                            amount,
                        );
                        if nonce == nonces[from] {
                            nonces[from] += 1; // ok or runtime failure: consumed
                        }
                        tx
                    })
                    .collect();

                let expected = serial(&mut serial_state, &batch);
                let actual = execute(&mut parallel_state, &batch);
                assert_eq!(expected, actual, "divergence at seed {seed}");
            }
            assert_eq!(serial_state.total_supply(), parallel_state.total_supply());
        }
    }
}
