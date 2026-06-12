//! Transaction format with declared access sets, signatures, and first-spend
//! account claiming.

use phi_crypto::{Keypair, Signature};

use crate::account::{AccountId, AuthPolicy};
use crate::hash::Hash;

/// The state a transaction declares it will touch. The scheduler uses this to
/// run non-conflicting transactions in parallel and to route owned-object
/// transactions onto the consensus-free fast path. Execution rejects any
/// transaction that would touch state outside its declaration
/// (`TxError::AccessViolation`), which is what makes parallel scheduling
/// by declared sets sound.
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

    /// Canonical encoding for hashing (counts + sorted-order-as-declared ids).
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32 * (self.reads.len() + self.writes.len()));
        out.extend_from_slice(&(self.reads.len() as u32).to_le_bytes());
        for id in &self.reads {
            out.extend_from_slice(id.0.as_bytes());
        }
        out.extend_from_slice(&(self.writes.len() as u32).to_le_bytes());
        for id in &self.writes {
            out.extend_from_slice(id.0.as_bytes());
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionKind {
    /// Move `amount` from `sender` to `to`.
    Transfer { to: AccountId, amount: u64 },
    /// Create `to` with `amount` minted (genesis/faucet; simulation only).
    Mint { to: AccountId, amount: u64 },
}

impl TransactionKind {
    fn encode(&self) -> Vec<u8> {
        let (tag, to, amount) = match self {
            TransactionKind::Transfer { to, amount } => (0u8, to, amount),
            TransactionKind::Mint { to, amount } => (1u8, to, amount),
        };
        let mut out = Vec::with_capacity(41);
        out.push(tag);
        out.extend_from_slice(to.0.as_bytes());
        out.extend_from_slice(&amount.to_le_bytes());
        out
    }
}

/// The auth policy revealed when spending from an `Unclaimed` account: the
/// state machine checks that `AccountId::from_auth(policy, salt)` equals the
/// sender id, then verifies signatures against the revealed policy and stores
/// it on the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthReveal {
    pub policy: AuthPolicy,
    pub salt: u64,
}

impl AuthReveal {
    pub fn account_id(&self) -> AccountId {
        AccountId::from_auth(&self.policy, self.salt)
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = self.policy.encode();
        out.extend_from_slice(&self.salt.to_le_bytes());
        out
    }
}

/// A Phi transaction.
///
/// Fees: the starter models the free lane only (fee = 0, quota enforcement in
/// the mempool). `max_fee` is carried so the standard-lane fee market can be
/// added without changing the format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub sender: AccountId,
    pub nonce: u64,
    /// Network this transaction is valid on. Bound into [`Transaction::id`]
    /// (and therefore into the signed message), so a transaction signed for
    /// one Phi instance cannot be replayed onto another — the classic
    /// cross-chain replay attack (cf. Ethereum EIP-155). The state machine
    /// rejects transactions whose `chain_id` does not match its own.
    pub chain_id: u64,
    pub kind: TransactionKind,
    pub access: AccessSet,
    pub max_fee: u64,
    /// Optional sponsor paying fees on the sender's behalf (native
    /// fee sponsorship; unused while fees are zero).
    pub sponsor: Option<AccountId>,
    /// First-spend reveal of the sender's auth policy (see [`AuthReveal`]).
    pub auth_reveal: Option<AuthReveal>,
    /// Signatures over `id()` satisfying the sender's auth policy. Not part
    /// of the id itself: the id is the message being signed, and a different
    /// signature over the same payload must not change the transaction's
    /// identity (signature malleability must not split the mempool).
    pub signatures: Vec<Signature>,
}

impl Transaction {
    pub fn transfer(sender: AccountId, nonce: u64, to: AccountId, amount: u64) -> Self {
        Self::build(sender, nonce, TransactionKind::Transfer { to, amount })
    }

    pub fn mint(sender: AccountId, nonce: u64, to: AccountId, amount: u64) -> Self {
        Self::build(sender, nonce, TransactionKind::Mint { to, amount })
    }

    fn build(sender: AccountId, nonce: u64, kind: TransactionKind) -> Self {
        let to = match &kind {
            TransactionKind::Transfer { to, .. } | TransactionKind::Mint { to, .. } => *to,
        };
        Self {
            sender,
            nonce,
            chain_id: 0,
            kind,
            access: AccessSet {
                reads: vec![],
                writes: vec![sender, to],
            },
            max_fee: 0,
            sponsor: None,
            auth_reveal: None,
            signatures: vec![],
        }
    }

    /// Bind this transaction to a specific network (builder; call before
    /// signing — `chain_id` is covered by the id).
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Attach the first-spend auth reveal (builder; call before signing —
    /// the reveal is covered by the id).
    pub fn with_reveal(mut self, policy: AuthPolicy, salt: u64) -> Self {
        self.auth_reveal = Some(AuthReveal { policy, salt });
        self
    }

    /// Append a signature over the transaction id (builder). Sign last:
    /// changing any other field changes the id and invalidates signatures.
    pub fn signed(mut self, keypair: &Keypair) -> Self {
        let id = self.id();
        self.signatures.push(keypair.sign(id.as_bytes()));
        self
    }

    /// Canonical transaction id: a domain-separated hash over every field
    /// except the signatures. This is both the dedup/Merkle identity and the
    /// message that auth-policy signatures cover.
    pub fn id(&self) -> Hash {
        let sponsor = match &self.sponsor {
            None => vec![0u8],
            Some(id) => {
                let mut out = vec![1u8];
                out.extend_from_slice(id.0.as_bytes());
                out
            }
        };
        let reveal = match &self.auth_reveal {
            None => vec![0u8],
            Some(r) => {
                let mut out = vec![1u8];
                out.extend_from_slice(&r.encode());
                out
            }
        };
        Hash::of_tagged(
            b"phi:tx",
            &[
                &self.chain_id.to_le_bytes(),
                self.sender.0.as_bytes(),
                &self.nonce.to_le_bytes(),
                &self.kind.encode(),
                &self.access.encode(),
                &self.max_fee.to_le_bytes(),
                &sponsor,
                &reveal,
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phi_crypto::Keypair;

    fn id(label: &str) -> AccountId {
        AccountId::from_label(label)
    }

    #[test]
    fn id_covers_every_payload_field() {
        let base = Transaction::transfer(id("a"), 0, id("b"), 10);
        let mut access_changed = base.clone();
        access_changed.access.writes.push(id("c"));
        let mut fee_changed = base.clone();
        fee_changed.max_fee = 1;
        let mut sponsor_changed = base.clone();
        sponsor_changed.sponsor = Some(id("s"));
        let reveal_changed = base.clone().with_reveal(AuthPolicy::Open, 0);
        let kind_changed = Transaction::mint(id("a"), 0, id("b"), 10);
        let chain_changed = base.clone().with_chain_id(1);

        let ids = [
            base.id(),
            access_changed.id(),
            fee_changed.id(),
            sponsor_changed.id(),
            reveal_changed.id(),
            kind_changed.id(),
            chain_changed.id(),
        ];
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn signatures_do_not_change_the_id() {
        let unsigned = Transaction::transfer(id("a"), 0, id("b"), 10);
        let signed = unsigned.clone().signed(&Keypair::from_label("a"));
        assert_eq!(unsigned.id(), signed.id());
        assert_eq!(signed.signatures.len(), 1);
    }

    #[test]
    fn disjoint_access_sets_detected() {
        let a = Transaction::transfer(id("a"), 0, id("b"), 1);
        let b = Transaction::transfer(id("c"), 0, id("d"), 1);
        let c = Transaction::transfer(id("b"), 0, id("e"), 1);
        assert!(a.access.disjoint_from(&b.access));
        assert!(!a.access.disjoint_from(&c.access));
    }
}
