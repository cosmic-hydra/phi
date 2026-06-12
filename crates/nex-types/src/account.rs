//! Accounts with native account abstraction.

use nex_crypto::PublicKey;

use crate::hash::Hash;

/// Account identifier: hash of the account's initial auth policy + a salt
/// (the "creation nonce"), so an address *is* a commitment to who controls
/// it. Funds can be sent to an id before the account exists; the receiver
/// claims it on first spend by revealing the matching policy
/// (docs/SPECIFICATION.md §6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct AccountId(pub Hash);

impl AccountId {
    /// Derive an account id from its initial auth policy and salt.
    pub fn from_auth(policy: &AuthPolicy, salt: u64) -> Self {
        AccountId(Hash::of_tagged(
            b"nex:account:id",
            &[&policy.encode(), &salt.to_le_bytes()],
        ))
    }

    /// Derive a deterministic account id from a human label. Test/simulation
    /// helper only: ids made this way match no auth policy, so they are
    /// usable only with `AuthPolicy::Open` genesis accounts.
    pub fn from_label(label: &str) -> Self {
        AccountId(Hash::of_tagged(b"nex:account:label", &[label.as_bytes()]))
    }
}

/// How a transaction from this account is authorized.
///
/// In the full protocol every account is a contract; these variants are the
/// built-in policies of the default account module (passkeys and session keys
/// land with `nex-vm`). Signatures are verified over the transaction id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthPolicy {
    /// No verification. Simulation/test escape hatch only — never derivable
    /// from a claimed account id in the sim flows.
    Open,
    /// Single Ed25519 public key.
    SingleKey(PublicKey),
    /// M-of-N threshold of keys, enabling social recovery.
    Threshold { m: u8, keys: Vec<PublicKey> },
    /// Account was created by receiving funds; the controlling policy is
    /// committed to by the account id and revealed on first spend.
    Unclaimed,
}

impl AuthPolicy {
    /// Canonical byte encoding (variant tag + fixed-order fields). Feeds the
    /// account id derivation and the state commitment, so it must be
    /// injective.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            AuthPolicy::Open => vec![0],
            AuthPolicy::SingleKey(key) => {
                let mut out = vec![1];
                out.extend_from_slice(&key.0);
                out
            }
            AuthPolicy::Threshold { m, keys } => {
                let mut out = vec![2, *m];
                out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
                for key in keys {
                    out.extend_from_slice(&key.0);
                }
                out
            }
            AuthPolicy::Unclaimed => vec![3],
        }
    }
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
    /// Account with `Open` auth (test/simulation helper).
    pub fn new(id: AccountId, balance: u64) -> Self {
        Self::with_auth(id, balance, AuthPolicy::Open)
    }

    pub fn with_auth(id: AccountId, balance: u64, auth: AuthPolicy) -> Self {
        Self {
            id,
            balance,
            nonce: 0,
            auth,
        }
    }

    /// Canonical byte encoding committed to by the state root. Includes the
    /// auth policy: who controls an account is consensus state, and light
    /// clients must be able to prove it.
    pub fn encode(&self) -> Vec<u8> {
        let auth = self.auth.encode();
        let mut out = Vec::with_capacity(52 + auth.len());
        out.extend_from_slice(self.id.0.as_bytes());
        out.extend_from_slice(&self.balance.to_le_bytes());
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out.extend_from_slice(&(auth.len() as u32).to_le_bytes());
        out.extend_from_slice(&auth);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nex_crypto::Keypair;

    #[test]
    fn account_id_commits_to_policy_and_salt() {
        let key = Keypair::from_label("a").public();
        let policy = AuthPolicy::SingleKey(key);
        assert_eq!(
            AccountId::from_auth(&policy, 0),
            AccountId::from_auth(&policy, 0)
        );
        assert_ne!(
            AccountId::from_auth(&policy, 0),
            AccountId::from_auth(&policy, 1)
        );
        let other = AuthPolicy::SingleKey(Keypair::from_label("b").public());
        assert_ne!(
            AccountId::from_auth(&policy, 0),
            AccountId::from_auth(&other, 0)
        );
    }

    #[test]
    fn auth_encoding_distinguishes_variants() {
        let key = Keypair::from_label("a").public();
        let encodings = [
            AuthPolicy::Open.encode(),
            AuthPolicy::SingleKey(key).encode(),
            AuthPolicy::Threshold {
                m: 1,
                keys: vec![key],
            }
            .encode(),
            AuthPolicy::Unclaimed.encode(),
        ];
        for (i, a) in encodings.iter().enumerate() {
            for b in encodings.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn encode_commits_to_auth_changes() {
        let id = AccountId::from_label("x");
        let open = Account::new(id, 5);
        let keyed = Account::with_auth(
            id,
            5,
            AuthPolicy::SingleKey(Keypair::from_label("a").public()),
        );
        assert_ne!(open.encode(), keyed.encode());
    }
}
