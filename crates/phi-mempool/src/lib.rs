//! Mempool: admission control and batch selection.
//!
//! Responsibilities in the full design (docs/ARCHITECTURE.md §3): auth
//! pre-validation, fee/quota checks (free lane), access-set conflict graph,
//! and lane routing. The starter implements admission against current state,
//! a free-lane quota, and conflict-aware batch grouping that the parallel
//! executor will consume.

use std::collections::{HashMap, VecDeque};

use phi_state::State;
use phi_types::{AccountId, Transaction};

/// Why a transaction was refused admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    /// Stateful validation failed (nonce, balance, unknown sender).
    Invalid(phi_state::TxError),
    /// Free-lane quota exhausted for this sender this block window.
    QuotaExceeded,
    /// Same transaction already pending.
    Duplicate,
}

/// FIFO mempool with per-sender free-lane quotas.
pub struct Mempool {
    queue: VecDeque<Transaction>,
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
            window_usage: HashMap::new(),
            quota_per_window,
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Admit a transaction if it is valid against `state` (accounting for
    /// txs already queued from the same sender) and within quota.
    pub fn submit(&mut self, tx: Transaction, state: &State) -> Result<(), AdmissionError> {
        if self.queue.iter().any(|q| q.id() == tx.id()) {
            return Err(AdmissionError::Duplicate);
        }

        let used = self.window_usage.get(&tx.sender).copied().unwrap_or(0);
        if used >= self.quota_per_window {
            return Err(AdmissionError::QuotaExceeded);
        }

        // Project the expected nonce forward over already-queued txs so a
        // sender can queue several sequential transactions.
        let queued_ahead = self
            .queue
            .iter()
            .filter(|q| q.sender == tx.sender)
            .count() as u64;
        let expected_nonce = state
            .account(&tx.sender)
            .map(|a| a.nonce + queued_ahead)
            .unwrap_or(0);
        if state.account(&tx.sender).is_some() && tx.nonce != expected_nonce {
            return Err(AdmissionError::Invalid(phi_state::TxError::BadNonce {
                expected: expected_nonce,
                got: tx.nonce,
            }));
        }
        if queued_ahead == 0 {
            // Only the head-of-line tx can be fully validated statefully.
            state.validate(&tx).map_err(AdmissionError::Invalid)?;
        }

        self.window_usage.insert(tx.sender, used + 1);
        self.queue.push_back(tx);
        Ok(())
    }

    /// Take up to `max` transactions for the next block proposal.
    pub fn take_batch(&mut self, max: usize) -> Vec<Transaction> {
        let n = max.min(self.queue.len());
        self.queue.drain(..n).collect()
    }

    /// Reset free-lane quotas (called per block window).
    pub fn reset_window(&mut self) {
        self.window_usage.clear();
    }

    /// Group a batch into sub-batches whose access sets are mutually
    /// disjoint — each group can run in parallel; groups run in order.
    /// This is the seed of the Block-STM scheduler (Phase 2).
    pub fn parallel_groups(batch: &[Transaction]) -> Vec<Vec<Transaction>> {
        let mut groups: Vec<Vec<Transaction>> = Vec::new();
        'next_tx: for tx in batch {
            for group in groups.iter_mut() {
                if group.iter().all(|g| g.access.disjoint_from(&tx.access)) {
                    group.push(tx.clone());
                    continue 'next_tx;
                }
            }
            groups.push(vec![tx.clone()]);
        }
        groups
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
            pool.submit(Transaction::transfer(id("alice"), nonce, id("bob"), 1), &state)
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
    fn parallel_groups_separate_conflicts() {
        let txs = vec![
            Transaction::transfer(id("alice"), 0, id("bob"), 1), // writes alice,bob
            Transaction::transfer(id("carol"), 0, id("dave"), 1), // disjoint -> same group
            Transaction::transfer(id("alice"), 1, id("eve"), 1), // conflicts with #1 -> new group
        ];
        let groups = Mempool::parallel_groups(&txs);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].len(), 2);
        assert_eq!(groups[1].len(), 1);
    }
}
