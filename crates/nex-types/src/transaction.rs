//! Transaction format with declared access sets.

use crate::account::AccountId;
use crate::hash::Hash;

/// The state a transaction declares it will touch. The scheduler uses this to
/// run non-conflicting transactions in parallel and to route owned-object
/// transactions onto the consensus-free fast path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessSet {
    pub reads: Vec<AccountId>,
    pub writes: Vec<AccountId>,
}

impl AccessSet {
    /// True if two access sets can safely execute in parallel
    /// (no write-write or read-write overlap).
    pub fn disjoint_from(&self, other: &AccessSet) -> bool {
        let conflicts = |a: &[AccountId], b: &[AccountId]| a.iter().any(|x| b.contains(x));
        !conflicts(&self.writes, &other.writes)
            && !conflicts(&self.writes, &other.reads)
            && !conflicts(&self.reads, &other.writes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionKind {
    /// Move `amount` from `sender` to `to`.
    Transfer { to: AccountId, amount: u64 },
    /// Create `to` with `amount` minted (genesis/faucet; simulation only).
    Mint { to: AccountId, amount: u64 },
}

/// A NexChain transaction.
///
/// Fees: the starter models the free lane only (fee = 0, quota enforcement in
/// the mempool). `max_fee` is carried so the standard-lane fee market can be
/// added without changing the format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub sender: AccountId,
    pub nonce: u64,
    pub kind: TransactionKind,
    pub access: AccessSet,
    pub max_fee: u64,
    /// Optional sponsor paying fees on the sender's behalf (native
    /// fee sponsorship; unused while fees are zero).
    pub sponsor: Option<AccountId>,
}

impl Transaction {
    pub fn transfer(sender: AccountId, nonce: u64, to: AccountId, amount: u64) -> Self {
        Self {
            sender,
            nonce,
            kind: TransactionKind::Transfer { to, amount },
            access: AccessSet {
                reads: vec![],
                writes: vec![sender, to],
            },
            max_fee: 0,
            sponsor: None,
        }
    }

    pub fn mint(sender: AccountId, nonce: u64, to: AccountId, amount: u64) -> Self {
        Self {
            sender,
            nonce,
            kind: TransactionKind::Mint { to, amount },
            access: AccessSet {
                reads: vec![],
                writes: vec![sender, to],
            },
            max_fee: 0,
            sponsor: None,
        }
    }

    /// Canonical transaction id.
    pub fn id(&self) -> Hash {
        let mut parts: Vec<Vec<u8>> = vec![b"nex:tx".to_vec()];
        parts.push(self.sender.0.as_bytes().to_vec());
        parts.push(self.nonce.to_le_bytes().to_vec());
        match &self.kind {
            TransactionKind::Transfer { to, amount } => {
                parts.push(b"transfer".to_vec());
                parts.push(to.0.as_bytes().to_vec());
                parts.push(amount.to_le_bytes().to_vec());
            }
            TransactionKind::Mint { to, amount } => {
                parts.push(b"mint".to_vec());
                parts.push(to.0.as_bytes().to_vec());
                parts.push(amount.to_le_bytes().to_vec());
            }
        }
        let refs: Vec<&[u8]> = parts.iter().map(|p| p.as_slice()).collect();
        Hash::of_parts(&refs)
    }
}
