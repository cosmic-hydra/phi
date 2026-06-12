//! NexChain state machine: account store + deterministic state transition.
//!
//! The starter uses an in-memory BTreeMap with a simple sequential-hash
//! commitment. The production design replaces this with a versioned object
//! store under a Sparse Merkle Tree (docs/SPECIFICATION.md §5); the public
//! interface (`apply_block`, `root`) is designed to survive that swap.

use std::collections::BTreeMap;

use nex_types::{Account, AccountId, Block, Hash, Transaction, TransactionKind};

/// Why a transaction failed the state transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    UnknownSender,
    BadNonce { expected: u64, got: u64 },
    InsufficientBalance { have: u64, need: u64 },
    Overflow,
}

/// Per-transaction outcome included in execution receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub tx_id: Hash,
    pub result: Result<(), TxError>,
}

/// The ledger state.
#[derive(Clone, Debug, Default)]
pub struct State {
    accounts: BTreeMap<AccountId, Account>,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an account with an initial balance (genesis helper).
    pub fn genesis_account(&mut self, id: AccountId, balance: u64) {
        self.accounts.insert(id, Account::new(id, balance));
    }

    pub fn account(&self, id: &AccountId) -> Option<&Account> {
        self.accounts.get(id)
    }

    pub fn balance(&self, id: &AccountId) -> u64 {
        self.accounts.get(id).map(|a| a.balance).unwrap_or(0)
    }

    /// Total supply across all accounts (conservation invariant checks).
    pub fn total_supply(&self) -> u64 {
        self.accounts.values().map(|a| a.balance).sum()
    }

    /// Commitment to the full state. BTreeMap iteration is ordered, so this
    /// is deterministic across nodes. (Production: SMT root.)
    pub fn root(&self) -> Hash {
        let mut hasher_input: Vec<u8> = b"nex:state".to_vec();
        for account in self.accounts.values() {
            hasher_input.extend_from_slice(&account.encode());
        }
        Hash::of(&hasher_input)
    }

    /// Validate a transaction against current state without applying it.
    pub fn validate(&self, tx: &Transaction) -> Result<(), TxError> {
        let sender = self.accounts.get(&tx.sender).ok_or(TxError::UnknownSender)?;
        if sender.nonce != tx.nonce {
            return Err(TxError::BadNonce {
                expected: sender.nonce,
                got: tx.nonce,
            });
        }
        match &tx.kind {
            TransactionKind::Transfer { amount, .. } => {
                if sender.balance < *amount {
                    return Err(TxError::InsufficientBalance {
                        have: sender.balance,
                        need: *amount,
                    });
                }
            }
            TransactionKind::Mint { .. } => {}
        }
        Ok(())
    }

    /// Apply one transaction. Failed transactions consume the nonce (replay
    /// protection) but make no other state change.
    pub fn apply_tx(&mut self, tx: &Transaction) -> Receipt {
        let result = self.validate(tx).and_then(|()| self.execute(tx));
        // Bump nonce on any attempt by a known sender so replays are rejected.
        if let Some(sender) = self.accounts.get_mut(&tx.sender) {
            if sender.nonce == tx.nonce {
                sender.nonce += 1;
            }
        }
        Receipt {
            tx_id: tx.id(),
            result,
        }
    }

    fn execute(&mut self, tx: &Transaction) -> Result<(), TxError> {
        match &tx.kind {
            TransactionKind::Transfer { to, amount } => {
                let sender = self.accounts.get_mut(&tx.sender).expect("validated");
                sender.balance -= amount;
                let recipient = self
                    .accounts
                    .entry(*to)
                    .or_insert_with(|| Account::new(*to, 0));
                recipient.balance = recipient
                    .balance
                    .checked_add(*amount)
                    .ok_or(TxError::Overflow)?;
            }
            TransactionKind::Mint { to, amount } => {
                let recipient = self
                    .accounts
                    .entry(*to)
                    .or_insert_with(|| Account::new(*to, 0));
                recipient.balance = recipient
                    .balance
                    .checked_add(*amount)
                    .ok_or(TxError::Overflow)?;
            }
        }
        Ok(())
    }

    /// Deterministic serial state transition for a whole block.
    /// The parallel executor (Phase 2) must produce identical results — this
    /// function is the reference implementation for those property tests.
    pub fn apply_block(&mut self, block: &Block) -> Vec<Receipt> {
        block.transactions.iter().map(|tx| self.apply_tx(tx)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(label: &str) -> AccountId {
        AccountId::from_label(label)
    }

    #[test]
    fn transfer_moves_funds_and_bumps_nonce() {
        let mut state = State::new();
        state.genesis_account(id("alice"), 100);
        state.genesis_account(id("bob"), 0);

        let receipt = state.apply_tx(&Transaction::transfer(id("alice"), 0, id("bob"), 40));
        assert!(receipt.result.is_ok());
        assert_eq!(state.balance(&id("alice")), 60);
        assert_eq!(state.balance(&id("bob")), 40);
        assert_eq!(state.account(&id("alice")).unwrap().nonce, 1);
    }

    #[test]
    fn insufficient_balance_rejected_but_nonce_consumed() {
        let mut state = State::new();
        state.genesis_account(id("alice"), 10);

        let receipt = state.apply_tx(&Transaction::transfer(id("alice"), 0, id("bob"), 40));
        assert_eq!(
            receipt.result,
            Err(TxError::InsufficientBalance { have: 10, need: 40 })
        );
        assert_eq!(state.balance(&id("alice")), 10);
        assert_eq!(state.account(&id("alice")).unwrap().nonce, 1);
    }

    #[test]
    fn replay_rejected() {
        let mut state = State::new();
        state.genesis_account(id("alice"), 100);
        let tx = Transaction::transfer(id("alice"), 0, id("bob"), 5);
        assert!(state.apply_tx(&tx).result.is_ok());
        assert_eq!(
            state.apply_tx(&tx).result,
            Err(TxError::BadNonce { expected: 1, got: 0 })
        );
        assert_eq!(state.balance(&id("bob")), 5);
    }

    #[test]
    fn transfers_conserve_supply() {
        let mut state = State::new();
        state.genesis_account(id("alice"), 100);
        state.genesis_account(id("bob"), 50);
        let before = state.total_supply();
        state.apply_tx(&Transaction::transfer(id("alice"), 0, id("bob"), 30));
        state.apply_tx(&Transaction::transfer(id("bob"), 0, id("alice"), 80));
        assert_eq!(state.total_supply(), before);
    }

    #[test]
    fn state_root_is_deterministic_and_changes_on_writes() {
        let mut a = State::new();
        let mut b = State::new();
        a.genesis_account(id("alice"), 100);
        b.genesis_account(id("alice"), 100);
        assert_eq!(a.root(), b.root());

        a.apply_tx(&Transaction::transfer(id("alice"), 0, id("bob"), 1));
        assert_ne!(a.root(), b.root());
    }
}
