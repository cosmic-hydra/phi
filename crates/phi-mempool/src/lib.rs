//! Mempool: admission control and batch selection.
//!
//! Responsibilities in the full design (docs/ARCHITECTURE.md §3): auth
//! pre-validation, fee/quota checks (free lane), access-set conflict graph,
//! and lane routing. The starter implements admission against current state
//! with per-sender nonce *and balance* projection over queued transactions,
//! a free-lane quota, duplicate rejection, and re-queuing of batches whose
//! round failed to commit. Conflict grouping lives in `phi-executor`, which
//! consumes the batches this mempool produces.

use std::collections::{HashMap, HashSet, VecDeque};

use phi_state::State;
use phi_types::{AccountId, Hash, Transaction, TransactionKind};

/// Default global capacity: maximum transactions held pending across all
/// senders. Bounds mempool memory so a flood of distinct senders cannot
/// exhaust it.
pub const DEFAULT_MAX_PENDING: usize = 100_000;

/// Why a transaction was refused admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// Stateful validation failed (nonce, balance, auth, unknown sender,
    /// wrong chain, oversized, unauthorized issuance).
    Invalid(phi_state::TxError),
    /// Free-lane quota exhausted for this sender this block window.
    QuotaExceeded,
    /// Global mempool capacity reached.
    Full,
    /// Same transaction already pending.
    Duplicate,
}

/// Per-sender aggregate over the queued transactions, so admission checks
/// are O(1) instead of scanning the whole queue per submit.
#[derive(Clone, Copy, Default)]
struct SenderProjection {
    /// Number of queued transactions from this sender.
    queued: u64,
    /// Total amount this sender's queued transfers would spend.
    outflow: u64,
}

fn outflow_of(tx: &Transaction) -> u64 {
    match &tx.kind {
        TransactionKind::Transfer { amount, .. } => *amount,
        TransactionKind::Mint { .. } => 0,
    }
}

/// FIFO mempool with per-sender free-lane quotas.
pub struct Mempool {
    queue: VecDeque<Transaction>,
    /// Ids of queued transactions for O(1) duplicate rejection.
    pending_ids: HashSet<Hash>,
    /// Queued-count and outflow per sender, kept in sync with `queue`.
    per_sender: HashMap<AccountId, SenderProjection>,
    /// Free-lane txs admitted per sender in the current window ("mana").
    window_usage: HashMap<AccountId, u32>,
    /// Max free transactions per sender per window.
    pub quota_per_window: u32,
    /// Global capacity across all senders (memory-exhaustion bound).
    pub max_pending: usize,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(16)
    }
}

impl Mempool {
    pub fn new(quota_per_window: u32) -> Self {
        Self::with_capacity(quota_per_window, DEFAULT_MAX_PENDING)
    }

    /// Construct with an explicit global capacity.
    pub fn with_capacity(quota_per_window: u32, max_pending: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            pending_ids: HashSet::new(),
            per_sender: HashMap::new(),
            window_usage: HashMap::new(),
            quota_per_window,
            max_pending,
        }
    }

    fn track(&mut self, tx: &Transaction) {
        self.pending_ids.insert(tx.id());
        let projection = self.per_sender.entry(tx.sender).or_default();
        projection.queued += 1;
        projection.outflow += outflow_of(tx);
    }

    fn untrack(&mut self, tx: &Transaction) {
        self.pending_ids.remove(&tx.id());
        let projection = self
            .per_sender
            .get_mut(&tx.sender)
            .expect("untracked sender");
        projection.queued -= 1;
        projection.outflow -= outflow_of(tx);
        if projection.queued == 0 {
            self.per_sender.remove(&tx.sender);
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Admit a transaction if it is valid against `state` *projected over
    /// transactions already queued from the same sender* (nonce sequence and
    /// remaining spendable balance) and within the free-lane quota.
    ///
    /// The head-of-line transaction per sender gets full stateful validation
    /// including auth; deeper-queued ones are admitted on projection and
    /// re-checked at execution.
    pub fn submit(&mut self, tx: Transaction, state: &State) -> Result<(), AdmissionError> {
        // Structural bounds first — before hashing the id or any state work —
        // so an oversized transaction can't make us do expensive work just to
        // reject it.
        State::check_limits(&tx).map_err(AdmissionError::Invalid)?;

        if self.queue.len() >= self.max_pending {
            return Err(AdmissionError::Full);
        }

        if self.pending_ids.contains(&tx.id()) {
            return Err(AdmissionError::Duplicate);
        }

        let used = self.window_usage.get(&tx.sender).copied().unwrap_or(0);
        if used >= self.quota_per_window {
            return Err(AdmissionError::QuotaExceeded);
        }

        // Project the expected nonce forward over already-queued txs so a
        // sender can queue several sequential transactions. The per-sender
        // aggregate keeps this O(1) regardless of queue size.
        let projection = self.per_sender.get(&tx.sender).copied().unwrap_or_default();
        if let Some(account) = state.account(&tx.sender) {
            let expected_nonce = account.nonce + projection.queued;
            if tx.nonce != expected_nonce {
                return Err(AdmissionError::Invalid(phi_state::TxError::BadNonce {
                    expected: expected_nonce,
                    got: tx.nonce,
                }));
            }

            // Project the spendable balance over queued transfers, so a
            // sender cannot queue more outflow than it holds.
            if let TransactionKind::Transfer { amount, .. } = &tx.kind {
                let spendable = account.balance.saturating_sub(projection.outflow);
                if *amount > spendable {
                    return Err(AdmissionError::Invalid(
                        phi_state::TxError::InsufficientBalance {
                            have: spendable,
                            need: *amount,
                        },
                    ));
                }
            }
        }
        if projection.queued == 0 {
            // Head-of-line: full stateful validation (auth, access, funds).
            state.validate(&tx).map_err(AdmissionError::Invalid)?;
        }

        self.window_usage.insert(tx.sender, used + 1);
        self.track(&tx);
        self.queue.push_back(tx);
        Ok(())
    }

    /// Take up to `max` transactions for the next block proposal.
    pub fn take_batch(&mut self, max: usize) -> Vec<Transaction> {
        let n = max.min(self.queue.len());
        let batch: Vec<Transaction> = self.queue.drain(..n).collect();
        for tx in &batch {
            self.untrack(tx);
        }
        batch
    }

    /// Select up to `max` transactions for the next block **fee-first**: at
    /// each step the pending head of the highest-`max_fee` sender is taken,
    /// so a richer tip jumps the line — yet each sender's transactions still
    /// leave in strict nonce order (a sender's nonce *n+1* can never be
    /// selected before its nonce *n*, which would produce an unincludable
    /// gap). Ties break toward the earlier submission, so a uniform-fee
    /// mempool drains in exactly the FIFO order of [`Mempool::take_batch`].
    ///
    /// This is the standard-lane counterpart to the free lane: it turns the
    /// otherwise-dormant `max_fee` into inclusion priority under congestion.
    pub fn take_priority_batch(&mut self, max: usize) -> Vec<Transaction> {
        let n = max.min(self.queue.len());
        if n == 0 {
            return Vec::new();
        }

        // Snapshot positions, grouped per sender in nonce (submission) order.
        let snapshot: Vec<Transaction> = self.queue.iter().cloned().collect();
        let mut heads: HashMap<AccountId, VecDeque<usize>> = HashMap::new();
        for (i, tx) in snapshot.iter().enumerate() {
            heads.entry(tx.sender).or_default().push_back(i);
        }

        let mut selected = vec![false; snapshot.len()];
        let mut chosen: Vec<usize> = Vec::with_capacity(n);
        for _ in 0..n {
            // Highest-fee pending head wins; index comparison makes the
            // tie-break (and thus the whole selection) deterministic
            // regardless of hash-map iteration order.
            let mut best: Option<usize> = None;
            for positions in heads.values() {
                if let Some(&head) = positions.front() {
                    let wins = match best {
                        None => true,
                        Some(b) => {
                            let (head_fee, best_fee) = (snapshot[head].max_fee, snapshot[b].max_fee);
                            head_fee > best_fee || (head_fee == best_fee && head < b)
                        }
                    };
                    if wins {
                        best = Some(head);
                    }
                }
            }
            let head = best.expect("n <= queue length guarantees a pending head");
            heads
                .get_mut(&snapshot[head].sender)
                .expect("the chosen head's sender is grouped")
                .pop_front();
            selected[head] = true;
            chosen.push(head);
        }

        let batch: Vec<Transaction> = chosen.iter().map(|&i| snapshot[i].clone()).collect();
        // Keep the unselected transactions in their original relative order.
        self.queue = snapshot
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !selected[*i])
            .map(|(_, tx)| tx)
            .collect();
        for tx in &batch {
            self.untrack(tx);
        }
        batch
    }

    /// Return a batch to the front of the queue in its original order —
    /// called when a consensus round fails to commit, so transactions are
    /// never silently dropped with the rejected proposal.
    pub fn requeue_front(&mut self, batch: Vec<Transaction>) {
        for tx in batch.into_iter().rev() {
            self.track(&tx);
            self.queue.push_front(tx);
        }
    }

    /// Reset free-lane quotas (called per block window).
    pub fn reset_window(&mut self) {
        self.window_usage.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phi_types::AccountId;

    fn id(label: &str) -> AccountId {
        AccountId::from_label(label)
    }

    fn funded_state() -> State {
        let mut s = State::new();
        s.genesis_account(id("alice"), 1000);
        s.genesis_account(id("bob"), 1000);
        s.genesis_account(id("carol"), 1000);
        s
    }

    #[test]
    fn admits_sequential_nonces_from_same_sender() {
        let state = funded_state();
        let mut pool = Mempool::new(16);
        assert!(pool
            .submit(Transaction::transfer(id("alice"), 0, id("bob"), 1), &state)
            .is_ok());
        assert!(pool
            .submit(Transaction::transfer(id("alice"), 1, id("bob"), 1), &state)
            .is_ok());
        // Skipping a nonce is rejected.
        assert!(matches!(
            pool.submit(Transaction::transfer(id("alice"), 5, id("bob"), 1), &state),
            Err(AdmissionError::Invalid(_))
        ));
    }

    #[test]
    fn global_capacity_bounds_memory() {
        let state = funded_state();
        // Generous per-sender quota but a tiny global cap.
        let mut pool = Mempool::with_capacity(1000, 2);
        assert!(pool
            .submit(Transaction::transfer(id("alice"), 0, id("bob"), 1), &state)
            .is_ok());
        assert!(pool
            .submit(Transaction::transfer(id("alice"), 1, id("bob"), 1), &state)
            .is_ok());
        assert_eq!(
            pool.submit(Transaction::transfer(id("alice"), 2, id("bob"), 1), &state),
            Err(AdmissionError::Full)
        );
    }

    #[test]
    fn oversized_transaction_rejected_at_admission() {
        let state = funded_state();
        let mut pool = Mempool::new(16);
        let mut huge = Transaction::transfer(id("alice"), 0, id("bob"), 1);
        huge.access.writes = (0..200).map(|i| id(&format!("a-{i}"))).collect();
        assert_eq!(
            pool.submit(huge, &state),
            Err(AdmissionError::Invalid(
                phi_state::TxError::TransactionTooLarge
            ))
        );
    }

    #[test]
    fn quota_limits_free_lane() {
        let state = funded_state();
        let mut pool = Mempool::new(2);
        for nonce in 0..2 {
            pool.submit(
                Transaction::transfer(id("alice"), nonce, id("bob"), 1),
                &state,
            )
            .unwrap();
        }
        assert_eq!(
            pool.submit(Transaction::transfer(id("alice"), 2, id("bob"), 1), &state),
            Err(AdmissionError::QuotaExceeded)
        );
        pool.reset_window();
        assert!(pool
            .submit(Transaction::transfer(id("alice"), 2, id("bob"), 1), &state)
            .is_ok());
    }

    #[test]
    fn duplicate_rejected() {
        let state = funded_state();
        let mut pool = Mempool::new(16);
        let tx = Transaction::transfer(id("alice"), 0, id("bob"), 1);
        pool.submit(tx.clone(), &state).unwrap();
        assert_eq!(pool.submit(tx, &state), Err(AdmissionError::Duplicate));
    }

    #[test]
    fn queued_outflow_cannot_exceed_balance() {
        let state = funded_state(); // alice: 1000
        let mut pool = Mempool::new(16);
        pool.submit(
            Transaction::transfer(id("alice"), 0, id("bob"), 600),
            &state,
        )
        .unwrap();
        // Head-of-line alone would pass (600 < 1000); the projection over
        // the queue must reject the cumulative 1200.
        assert_eq!(
            pool.submit(
                Transaction::transfer(id("alice"), 1, id("bob"), 600),
                &state
            ),
            Err(AdmissionError::Invalid(
                phi_state::TxError::InsufficientBalance {
                    have: 400,
                    need: 600
                }
            ))
        );
        assert!(pool
            .submit(
                Transaction::transfer(id("alice"), 1, id("bob"), 400),
                &state
            )
            .is_ok());
    }

    #[test]
    fn unsigned_spend_from_keyed_account_rejected_at_admission() {
        use phi_crypto::Keypair;
        use phi_types::AuthPolicy;

        let kp = Keypair::from_label("alice-key");
        let policy = AuthPolicy::SingleKey(kp.public());
        let alice = AccountId::from_auth(&policy, 0);
        let mut state = State::new();
        state.genesis_account_with_auth(alice, 1000, policy);

        let mut pool = Mempool::new(16);
        assert_eq!(
            pool.submit(Transaction::transfer(alice, 0, id("bob"), 1), &state),
            Err(AdmissionError::Invalid(phi_state::TxError::AuthFailed))
        );
        assert!(pool
            .submit(
                Transaction::transfer(alice, 0, id("bob"), 1).signed(&kp),
                &state
            )
            .is_ok());
    }

    #[test]
    fn requeue_preserves_order_and_duplicate_protection() {
        let state = funded_state();
        let mut pool = Mempool::new(16);
        for nonce in 0..3 {
            pool.submit(
                Transaction::transfer(id("alice"), nonce, id("bob"), 1),
                &state,
            )
            .unwrap();
        }
        let batch = pool.take_batch(2);
        assert_eq!(pool.len(), 1);

        let resubmit = batch[0].clone();
        pool.requeue_front(batch);
        assert_eq!(pool.len(), 3);
        // Order restored: nonces 0,1,2 from the front.
        let drained = pool.take_batch(3);
        assert_eq!(
            drained.iter().map(|t| t.nonce).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        pool.requeue_front(drained);
        assert_eq!(
            pool.submit(resubmit, &state),
            Err(AdmissionError::Duplicate)
        );
    }

    #[test]
    fn projections_stay_consistent_across_take_and_requeue() {
        let state = funded_state(); // alice: 1000
        let mut pool = Mempool::new(16);
        pool.submit(
            Transaction::transfer(id("alice"), 0, id("bob"), 300),
            &state,
        )
        .unwrap();
        pool.submit(
            Transaction::transfer(id("alice"), 1, id("bob"), 300),
            &state,
        )
        .unwrap();

        let batch = pool.take_batch(2);
        // Taken txs no longer count toward projections: nonce 0 is expected
        // again (the caller owns the in-flight batch until commit/requeue).
        assert_eq!(
            pool.submit(Transaction::transfer(id("alice"), 1, id("bob"), 1), &state),
            Err(AdmissionError::Invalid(phi_state::TxError::BadNonce {
                expected: 0,
                got: 1
            }))
        );

        pool.requeue_front(batch);
        // Projections restored: expected nonce 2, outflow 600 of 1000.
        assert!(pool
            .submit(
                Transaction::transfer(id("alice"), 2, id("bob"), 400),
                &state
            )
            .is_ok());
        assert_eq!(
            pool.submit(Transaction::transfer(id("alice"), 3, id("bob"), 1), &state),
            Err(AdmissionError::Invalid(
                phi_state::TxError::InsufficientBalance { have: 0, need: 1 }
            ))
        );
    }

    #[test]
    fn priority_batch_serves_higher_fees_first_preserving_nonce_order() {
        let state = funded_state();
        let mut pool = Mempool::new(16);
        // Alice queues two low-fee transactions; Bob one high-fee transaction.
        pool.submit(
            Transaction::transfer(id("alice"), 0, id("carol"), 1).with_max_fee(1),
            &state,
        )
        .unwrap();
        pool.submit(
            Transaction::transfer(id("alice"), 1, id("carol"), 1).with_max_fee(1),
            &state,
        )
        .unwrap();
        pool.submit(
            Transaction::transfer(id("bob"), 0, id("carol"), 1).with_max_fee(9),
            &state,
        )
        .unwrap();

        let batch = pool.take_priority_batch(3);
        // Bob's richer tip jumps ahead; Alice's two follow in nonce order.
        assert_eq!(batch[0].sender, id("bob"));
        assert_eq!((batch[1].sender, batch[1].nonce), (id("alice"), 0));
        assert_eq!((batch[2].sender, batch[2].nonce), (id("alice"), 1));
        assert!(pool.is_empty());
    }

    #[test]
    fn priority_batch_with_uniform_fees_matches_fifo() {
        let state = funded_state();
        let mut pool = Mempool::new(16);
        pool.submit(Transaction::transfer(id("alice"), 0, id("bob"), 1), &state)
            .unwrap();
        pool.submit(Transaction::transfer(id("carol"), 0, id("bob"), 1), &state)
            .unwrap();
        pool.submit(Transaction::transfer(id("alice"), 1, id("bob"), 1), &state)
            .unwrap();

        let order: Vec<(AccountId, u64)> = pool
            .take_priority_batch(3)
            .iter()
            .map(|t| (t.sender, t.nonce))
            .collect();
        // No fee differences -> identical to FIFO submission order.
        assert_eq!(
            order,
            vec![(id("alice"), 0), (id("carol"), 0), (id("alice"), 1)]
        );
    }

    #[test]
    fn priority_batch_leaves_lowest_fee_behind_and_stays_consistent() {
        let state = funded_state();
        let mut pool = Mempool::new(16);
        pool.submit(
            Transaction::transfer(id("alice"), 0, id("bob"), 1).with_max_fee(1),
            &state,
        )
        .unwrap();
        pool.submit(
            Transaction::transfer(id("bob"), 0, id("carol"), 1).with_max_fee(5),
            &state,
        )
        .unwrap();
        pool.submit(
            Transaction::transfer(id("carol"), 0, id("alice"), 1).with_max_fee(3),
            &state,
        )
        .unwrap();

        // Take the two richest; the low-fee tx stays queued.
        let batch = pool.take_priority_batch(2);
        assert_eq!(
            batch.iter().map(|t| t.max_fee).collect::<Vec<_>>(),
            vec![5, 3]
        );
        assert_eq!(pool.len(), 1);
        // Tracking stayed consistent: the still-queued tx rejects its duplicate.
        let duplicate = Transaction::transfer(id("alice"), 0, id("bob"), 1).with_max_fee(1);
        assert_eq!(
            pool.submit(duplicate, &state),
            Err(AdmissionError::Duplicate)
        );
    }
}
