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

/// Why a transaction was refused admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// Stateful validation failed (nonce, balance, auth, unknown sender).
    Invalid(phi_state::TxError),
    /// Free-lane quota exhausted for this sender this block window.
    QuotaExceeded,
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
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(16)
    }
}

impl Mempool {
    pub fn new(quota_per_window: u32) -> Self {
        Self {
            queue: VecDeque::new(),
            pending_ids: HashSet::new(),
            per_sender: HashMap::new(),
            window_usage: HashMap::new(),
            quota_per_window,
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
}
