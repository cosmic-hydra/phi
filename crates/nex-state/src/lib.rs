//! NexChain state machine: account store + deterministic state transition.
//!
//! The state commitment is a real Sparse Merkle Tree (see [`smt`]) over
//! canonical account encodings, so inclusion *and* exclusion of any account
//! is provable against a block's state root. The store itself is an
//! in-memory BTreeMap; the production design swaps in a versioned object
//! store (docs/SPECIFICATION.md §5) without changing the public interface
//! (`apply_tx`, `apply_block`, `root`, `prove_account`).

pub mod smt;

use std::collections::{BTreeMap, BTreeSet};

use nex_types::{Account, AccountId, AuthPolicy, Block, Hash, Transaction, TransactionKind};

/// Why a transaction failed validation or execution.
///
/// Two classes with different inclusion semantics (see [`State::apply_tx`]):
/// *invalid* transactions (bad nonce, failed auth, undeclared access) never
/// take effect at all, while *runtime* failures (insufficient balance,
/// overflow) consume the sender's nonce so the attempt is recorded and
/// unreplayable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TxError {
    UnknownSender,
    BadNonce {
        expected: u64,
        got: u64,
    },
    /// The transaction touches state outside its declared access set.
    AccessViolation,
    /// Signatures do not satisfy the sender's auth policy.
    AuthFailed,
    /// Spending from an unclaimed account requires revealing the auth policy
    /// committed to by the account id; the reveal is missing or mismatched
    /// (or present on an already-claimed account).
    RevealMismatch,
    InsufficientBalance {
        have: u64,
        need: u64,
    },
    Overflow,
}

impl TxError {
    /// Runtime failures are includable in a block (they consume the nonce);
    /// everything else marks the transaction invalid, as if never sent.
    pub fn consumes_nonce(&self) -> bool {
        matches!(
            self,
            TxError::InsufficientBalance { .. } | TxError::Overflow
        )
    }

    /// Stable variant code for canonical receipt encoding.
    fn encode(&self) -> Vec<u8> {
        match self {
            TxError::UnknownSender => vec![1],
            TxError::BadNonce { expected, got } => {
                let mut out = vec![2];
                out.extend_from_slice(&expected.to_le_bytes());
                out.extend_from_slice(&got.to_le_bytes());
                out
            }
            TxError::AccessViolation => vec![3],
            TxError::AuthFailed => vec![4],
            TxError::RevealMismatch => vec![5],
            TxError::InsufficientBalance { have, need } => {
                let mut out = vec![6];
                out.extend_from_slice(&have.to_le_bytes());
                out.extend_from_slice(&need.to_le_bytes());
                out
            }
            TxError::Overflow => vec![7],
        }
    }
}

/// Per-transaction outcome included in execution receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub tx_id: Hash,
    pub result: Result<(), TxError>,
}

impl Receipt {
    /// Canonical receipt hash (leaf of the block's receipts root).
    pub fn hash(&self) -> Hash {
        let encoded_result = match &self.result {
            Ok(()) => vec![0],
            Err(e) => e.encode(),
        };
        Hash::of_tagged(b"nex:receipt", &[self.tx_id.as_bytes(), &encoded_result])
    }
}

/// Merkle root over a block's receipts, committed in the block header.
pub fn receipts_root(receipts: &[Receipt]) -> Hash {
    let leaves: Vec<Hash> = receipts.iter().map(Receipt::hash).collect();
    nex_types::merkle::root(&leaves)
}

/// The ledger state.
#[derive(Clone, Debug, Default)]
pub struct State {
    accounts: BTreeMap<AccountId, Account>,
}

fn account_value_hash(account: &Account) -> Hash {
    Hash::of_tagged(b"nex:account:state", &[&account.encode()])
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an `Open`-auth account with an initial balance (genesis/test
    /// helper).
    pub fn genesis_account(&mut self, id: AccountId, balance: u64) {
        self.upsert_account(Account::new(id, balance));
    }

    /// Create a genesis account with an explicit auth policy.
    pub fn genesis_account_with_auth(&mut self, id: AccountId, balance: u64, auth: AuthPolicy) {
        self.upsert_account(Account::with_auth(id, balance, auth));
    }

    /// Insert or replace an account verbatim. Used by genesis construction
    /// and by the executor when merging sandbox writes; not a user-level
    /// operation.
    pub fn upsert_account(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    pub fn account(&self, id: &AccountId) -> Option<&Account> {
        self.accounts.get(id)
    }

    pub fn balance(&self, id: &AccountId) -> u64 {
        self.accounts.get(id).map(|a| a.balance).unwrap_or(0)
    }

    /// Total supply across all accounts (conservation invariant checks).
    /// u128 so the sum cannot overflow even with extreme balances.
    pub fn total_supply(&self) -> u128 {
        self.accounts.values().map(|a| a.balance as u128).sum()
    }

    /// SMT commitment to the full state: every account id maps to the hash
    /// of its canonical encoding (balance, nonce, *and* auth policy).
    pub fn root(&self) -> Hash {
        smt::root(&self.smt_entries())
    }

    fn smt_entries(&self) -> BTreeMap<smt::Key, Hash> {
        self.accounts
            .iter()
            .map(|(id, account)| (*id.0.as_bytes(), account_value_hash(account)))
            .collect()
    }

    /// Membership path for `id` against the current root: an inclusion proof
    /// if the account exists, an exclusion proof otherwise.
    pub fn prove_account(&self, id: &AccountId) -> smt::SmtProof {
        smt::prove(&self.smt_entries(), id.0.as_bytes())
    }

    /// Verify a light-client claim about an account against a state root.
    /// `account == None` claims the account does not exist.
    pub fn verify_account_proof(
        state_root: &Hash,
        id: &AccountId,
        account: Option<&Account>,
        proof: &smt::SmtProof,
    ) -> bool {
        let value_hash = account.map(account_value_hash);
        smt::verify(state_root, id.0.as_bytes(), value_hash.as_ref(), proof)
    }

    /// Validate a transaction against current state without applying it.
    pub fn validate(&self, tx: &Transaction) -> Result<(), TxError> {
        let sender = self
            .accounts
            .get(&tx.sender)
            .ok_or(TxError::UnknownSender)?;

        // The declared access set must cover everything execution touches:
        // the sender (nonce, balance, auth) and the credited account. This is
        // the invariant that makes scheduling by declared sets sound.
        let target = match &tx.kind {
            TransactionKind::Transfer { to, .. } | TransactionKind::Mint { to, .. } => to,
        };
        if !tx.access.writes.contains(&tx.sender) || !tx.access.writes.contains(target) {
            return Err(TxError::AccessViolation);
        }

        if sender.nonce != tx.nonce {
            return Err(TxError::BadNonce {
                expected: sender.nonce,
                got: tx.nonce,
            });
        }

        self.verify_auth(sender, tx)?;

        match &tx.kind {
            TransactionKind::Transfer { to, amount } => {
                if sender.balance < *amount {
                    return Err(TxError::InsufficientBalance {
                        have: sender.balance,
                        need: *amount,
                    });
                }
                // Pre-check the credit so execution never partially applies.
                // A self-transfer nets to zero and cannot overflow.
                if *to != tx.sender {
                    self.balance(to)
                        .checked_add(*amount)
                        .ok_or(TxError::Overflow)?;
                }
            }
            TransactionKind::Mint { to, amount } => {
                self.balance(to)
                    .checked_add(*amount)
                    .ok_or(TxError::Overflow)?;
            }
        }
        Ok(())
    }

    /// Check the transaction's signatures against the sender's auth policy
    /// (or, for unclaimed accounts, against the revealed policy the account
    /// id commits to).
    fn verify_auth(&self, sender: &Account, tx: &Transaction) -> Result<(), TxError> {
        let policy = match (&sender.auth, &tx.auth_reveal) {
            // First spend: the reveal must hash to the sender's id.
            (AuthPolicy::Unclaimed, Some(reveal)) => {
                if reveal.account_id() != sender.id {
                    return Err(TxError::RevealMismatch);
                }
                &reveal.policy
            }
            (AuthPolicy::Unclaimed, None) => return Err(TxError::RevealMismatch),
            // A reveal on an already-claimed account is malformed.
            (_, Some(_)) => return Err(TxError::RevealMismatch),
            (claimed, None) => claimed,
        };

        let message = tx.id();
        let satisfied = match policy {
            AuthPolicy::Open => true,
            AuthPolicy::SingleKey(key) => tx
                .signatures
                .iter()
                .any(|sig| key.verify(message.as_bytes(), sig)),
            AuthPolicy::Threshold { m, keys } => {
                // Count *distinct* verified keys: a key listed twice in the
                // policy must not let one signer satisfy the threshold
                // twice. `m == 0` (or m exceeding the distinct key count)
                // is malformed and never authorizes anything.
                let distinct: BTreeSet<_> = keys.iter().collect();
                let verified = distinct
                    .iter()
                    .filter(|key| {
                        tx.signatures
                            .iter()
                            .any(|sig| key.verify(message.as_bytes(), sig))
                    })
                    .count();
                *m >= 1 && verified >= *m as usize
            }
            // An account can never be claimed *as* unclaimed.
            AuthPolicy::Unclaimed => false,
        };
        if satisfied {
            Ok(())
        } else {
            Err(TxError::AuthFailed)
        }
    }

    /// Apply one transaction.
    ///
    /// Invalid transactions (bad nonce/auth/access) change nothing — in
    /// particular they do *not* consume the nonce, otherwise anyone could
    /// grief an account by spraying forged transactions that invalidate the
    /// owner's pending ones. Runtime failures consume the nonce (replay
    /// protection for an attempt that was genuinely authorized) but make no
    /// other state change.
    pub fn apply_tx(&mut self, tx: &Transaction) -> Receipt {
        let result = self.validate(tx);
        let consume_nonce = match &result {
            Ok(()) => true,
            Err(e) => e.consumes_nonce(),
        };
        if result.is_ok() {
            self.execute(tx);
        }
        if consume_nonce {
            let sender = self.accounts.get_mut(&tx.sender).expect("validated sender");
            sender.nonce += 1;
        }
        Receipt {
            tx_id: tx.id(),
            result,
        }
    }

    /// Apply a fully validated transaction. Infallible: every failure mode
    /// was pre-checked, so state can never be left half-mutated.
    fn execute(&mut self, tx: &Transaction) {
        // First spend from an unclaimed account stores the revealed policy.
        if let Some(reveal) = &tx.auth_reveal {
            let sender = self.accounts.get_mut(&tx.sender).expect("validated sender");
            sender.auth = reveal.policy.clone();
        }
        match &tx.kind {
            TransactionKind::Transfer { to, amount } => {
                let sender = self.accounts.get_mut(&tx.sender).expect("validated sender");
                sender.balance -= amount;
                let recipient = self
                    .accounts
                    .entry(*to)
                    .or_insert_with(|| Account::with_auth(*to, 0, AuthPolicy::Unclaimed));
                recipient.balance += amount;
            }
            TransactionKind::Mint { to, amount } => {
                let recipient = self
                    .accounts
                    .entry(*to)
                    .or_insert_with(|| Account::with_auth(*to, 0, AuthPolicy::Unclaimed));
                recipient.balance += amount;
            }
        }
    }

    /// Deterministic serial state transition for a whole block — the
    /// reference implementation the parallel executor (`nex-executor`) must
    /// match byte-for-byte; property tests assert that equivalence.
    pub fn apply_block(&mut self, block: &Block) -> Vec<Receipt> {
        block
            .transactions
            .iter()
            .map(|tx| self.apply_tx(tx))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nex_crypto::Keypair;

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
            Err(TxError::BadNonce {
                expected: 1,
                got: 0
            })
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

    #[test]
    fn recipient_overflow_makes_no_state_change() {
        // Regression: the old execute() debited the sender before the
        // recipient's checked_add, destroying funds on overflow.
        let mut state = State::new();
        state.genesis_account(id("alice"), 100);
        state.genesis_account(id("bob"), u64::MAX);
        let before = state.total_supply();

        let receipt = state.apply_tx(&Transaction::transfer(id("alice"), 0, id("bob"), 1));
        assert_eq!(receipt.result, Err(TxError::Overflow));
        assert_eq!(state.balance(&id("alice")), 100, "debit must not persist");
        assert_eq!(state.balance(&id("bob")), u64::MAX);
        assert_eq!(state.total_supply(), before);
        // Overflow is a runtime failure: nonce is consumed.
        assert_eq!(state.account(&id("alice")).unwrap().nonce, 1);
    }

    #[test]
    fn self_transfer_of_large_balance_is_not_a_false_overflow() {
        let mut state = State::new();
        state.genesis_account(id("alice"), u64::MAX);
        let receipt = state.apply_tx(&Transaction::transfer(id("alice"), 0, id("alice"), 5));
        assert!(receipt.result.is_ok());
        assert_eq!(state.balance(&id("alice")), u64::MAX);
    }

    #[test]
    fn undeclared_access_rejected_without_consuming_nonce() {
        let mut state = State::new();
        state.genesis_account(id("alice"), 100);
        let mut tx = Transaction::transfer(id("alice"), 0, id("bob"), 5);
        tx.access.writes = vec![tx.sender]; // hides the credit to bob
        assert_eq!(state.apply_tx(&tx).result, Err(TxError::AccessViolation));
        assert_eq!(state.account(&id("alice")).unwrap().nonce, 0);
    }

    #[test]
    fn single_key_auth_enforced() {
        let alice_kp = Keypair::from_label("alice-key");
        let policy = AuthPolicy::SingleKey(alice_kp.public());
        let alice = AccountId::from_auth(&policy, 0);
        let mut state = State::new();
        state.genesis_account_with_auth(alice, 100, policy);

        // Unsigned spend fails and must NOT consume the nonce (griefing).
        let unsigned = Transaction::transfer(alice, 0, id("bob"), 5);
        assert_eq!(state.apply_tx(&unsigned).result, Err(TxError::AuthFailed));
        assert_eq!(state.account(&alice).unwrap().nonce, 0);

        // Wrong key fails.
        let forged = Transaction::transfer(alice, 0, id("bob"), 5)
            .signed(&Keypair::from_label("mallory-key"));
        assert_eq!(state.apply_tx(&forged).result, Err(TxError::AuthFailed));

        // Owner's signature succeeds.
        let genuine = Transaction::transfer(alice, 0, id("bob"), 5).signed(&alice_kp);
        assert!(state.apply_tx(&genuine).result.is_ok());
        assert_eq!(state.balance(&id("bob")), 5);
    }

    #[test]
    fn threshold_auth_requires_m_signers() {
        let keys: Vec<Keypair> = (0..3)
            .map(|i| Keypair::from_label(&format!("guardian-{i}")))
            .collect();
        let policy = AuthPolicy::Threshold {
            m: 2,
            keys: keys.iter().map(|k| k.public()).collect(),
        };
        let acct = AccountId::from_auth(&policy, 0);
        let mut state = State::new();
        state.genesis_account_with_auth(acct, 100, policy);

        let one_sig = Transaction::transfer(acct, 0, id("bob"), 5).signed(&keys[0]);
        assert_eq!(state.apply_tx(&one_sig).result, Err(TxError::AuthFailed));

        // The same key twice is still one signer.
        let dup_sig = Transaction::transfer(acct, 0, id("bob"), 5)
            .signed(&keys[0])
            .signed(&keys[0]);
        assert_eq!(state.apply_tx(&dup_sig).result, Err(TxError::AuthFailed));

        let two_sigs = Transaction::transfer(acct, 0, id("bob"), 5)
            .signed(&keys[0])
            .signed(&keys[2]);
        assert!(state.apply_tx(&two_sigs).result.is_ok());
    }

    #[test]
    fn threshold_duplicate_policy_keys_count_as_one_signer() {
        // Regression: a key listed multiple times in the policy must not let
        // a single signature satisfy a 2-of-N threshold.
        let kp = Keypair::from_label("solo-guardian");
        let policy = AuthPolicy::Threshold {
            m: 2,
            keys: vec![kp.public(), kp.public(), kp.public()],
        };
        let acct = AccountId::from_auth(&policy, 0);
        let mut state = State::new();
        state.genesis_account_with_auth(acct, 100, policy);

        let one_signer = Transaction::transfer(acct, 0, id("bob"), 5).signed(&kp);
        assert_eq!(state.apply_tx(&one_signer).result, Err(TxError::AuthFailed));
    }

    #[test]
    fn zero_of_n_threshold_never_authorizes() {
        // A malformed 0-of-N policy must not behave like an Open account.
        let policy = AuthPolicy::Threshold { m: 0, keys: vec![] };
        let acct = AccountId::from_auth(&policy, 0);
        let mut state = State::new();
        state.genesis_account_with_auth(acct, 100, policy);

        let unsigned = Transaction::transfer(acct, 0, id("bob"), 5);
        assert_eq!(state.apply_tx(&unsigned).result, Err(TxError::AuthFailed));
    }

    #[test]
    fn unclaimed_account_claims_on_first_spend() {
        let owner_kp = Keypair::from_label("dave-key");
        let policy = AuthPolicy::SingleKey(owner_kp.public());
        let dave = AccountId::from_auth(&policy, 7);

        let mut state = State::new();
        state.genesis_account(id("alice"), 100);
        // Receiving funds creates the account as Unclaimed.
        assert!(state
            .apply_tx(&Transaction::transfer(id("alice"), 0, dave, 40))
            .result
            .is_ok());
        assert_eq!(state.account(&dave).unwrap().auth, AuthPolicy::Unclaimed);

        // Spending without a reveal fails.
        let no_reveal = Transaction::transfer(dave, 0, id("alice"), 10).signed(&owner_kp);
        assert_eq!(
            state.apply_tx(&no_reveal).result,
            Err(TxError::RevealMismatch)
        );

        // A reveal whose hash doesn't match the id fails (attacker policy).
        let mallory_kp = Keypair::from_label("mallory-key");
        let bad_reveal = Transaction::transfer(dave, 0, id("alice"), 10)
            .with_reveal(AuthPolicy::SingleKey(mallory_kp.public()), 7)
            .signed(&mallory_kp);
        assert_eq!(
            state.apply_tx(&bad_reveal).result,
            Err(TxError::RevealMismatch)
        );

        // Correct reveal + signature claims the account and transfers.
        let claim = Transaction::transfer(dave, 0, id("alice"), 10)
            .with_reveal(AuthPolicy::SingleKey(owner_kp.public()), 7)
            .signed(&owner_kp);
        assert!(state.apply_tx(&claim).result.is_ok());
        assert_eq!(
            state.account(&dave).unwrap().auth,
            AuthPolicy::SingleKey(owner_kp.public())
        );
        assert_eq!(state.balance(&dave), 30);

        // A reveal on the now-claimed account is malformed.
        let stale_reveal = Transaction::transfer(dave, 1, id("alice"), 1)
            .with_reveal(AuthPolicy::SingleKey(owner_kp.public()), 7)
            .signed(&owner_kp);
        assert_eq!(
            state.apply_tx(&stale_reveal).result,
            Err(TxError::RevealMismatch)
        );
    }

    #[test]
    fn account_proofs_verify_inclusion_and_exclusion() {
        let mut state = State::new();
        state.genesis_account(id("alice"), 100);
        state.genesis_account(id("bob"), 50);
        let root = state.root();

        let alice_proof = state.prove_account(&id("alice"));
        assert!(State::verify_account_proof(
            &root,
            &id("alice"),
            state.account(&id("alice")),
            &alice_proof
        ));
        // Claiming a different balance fails.
        let fake = Account::new(id("alice"), 1_000_000);
        assert!(!State::verify_account_proof(
            &root,
            &id("alice"),
            Some(&fake),
            &alice_proof
        ));

        // Absent account: exclusion proof.
        let mallory_proof = state.prove_account(&id("mallory"));
        assert!(State::verify_account_proof(
            &root,
            &id("mallory"),
            None,
            &mallory_proof
        ));
        assert!(!State::verify_account_proof(
            &root,
            &id("mallory"),
            Some(&Account::new(id("mallory"), 9)),
            &mallory_proof
        ));
    }

    #[test]
    fn receipts_root_commits_to_outcomes() {
        let ok = Receipt {
            tx_id: Hash::of(b"tx"),
            result: Ok(()),
        };
        let failed = Receipt {
            tx_id: Hash::of(b"tx"),
            result: Err(TxError::Overflow),
        };
        assert_ne!(
            receipts_root(std::slice::from_ref(&ok)),
            receipts_root(&[failed])
        );
        assert_ne!(receipts_root(&[]), receipts_root(&[ok]));
    }
}
