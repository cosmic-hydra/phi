//! Accounts with native account abstraction.

use crate::hash::Hash;

/// Account identifier: hash of the account's initial auth policy + creation nonce.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct AccountId(pub Hash);

impl AccountId {
    /// Derive a deterministic account id from a human label (test/simulation
    /// helper; real accounts derive from auth policy + nonce).
    pub fn from_label(label: &str) -> Self {
        AccountId(Hash::of_parts(&[b"nex:account", label.as_bytes()]))
    }
}

/// How a transaction from this account is authorized.
///
/// In the full protocol every account is a contract; these variants are the
/// built-in policies of the default account module. The starter simulation
/// uses `Open` (no signature verification) — cryptographic verification is a
/// Phase 1b milestone (see docs/ROADMAP.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthPolicy {
    /// No verification (simulation only).
    Open,
    /// Single public key (placeholder bytes until nex-crypto lands).
    SingleKey(Vec<u8>),
    /// M-of-N threshold of keys, enabling social recovery.
    Threshold { m: u8, keys: Vec<Vec<u8>> },
}

/// Protocol-level account state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub id: AccountId,
    pub balance: u64,
    /// Strictly increasing per-account sequence number (replay protection).
    pub nonce: u64,
    pub auth: AuthPolicy,
}

impl Account {
    pub fn new(id: AccountId, balance: u64) -> Self {
        Self {
            id,
            balance,
            nonce: 0,
            auth: AuthPolicy::Open,
        }
    }

    /// Canonical byte encoding committed to by the state root.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(self.id.0.as_bytes());
        out.extend_from_slice(&self.balance.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }
}
