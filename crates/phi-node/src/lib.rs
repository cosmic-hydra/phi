//! A persistent, single-node Phi devnet — the smallest thing that makes the
//! protocol *usable*: a chain you can run, fund accounts on, move value
//! across, and that survives restarts.
//!
//! This is deliberately **not** a production node. It is a single sequencer
//! (no networking, no multi-validator consensus, no fork choice). What it does
//! provide is a real, end-to-end loop over the tested core: signed
//! transactions with account-abstraction auth, deterministic state transition,
//! block production with committed roots, and durable on-disk state. See
//! SECURITY.md for everything a real deployment would still require.
//!
//! Accounts are addressed by human labels: a label maps to an Ed25519 key
//! (`Keypair::from_label`) and a single-key account id. A built-in `treasury`
//! account holds the initial supply and is the issuance authority; `fund`
//! moves figs from it to a user account (creating that account, which is then
//! claimed on its first spend).

use std::fs;
use std::io;
use std::path::Path;

use phi_crypto::Keypair;
use phi_state::{receipts_root, Receipt, State, TxError};
use phi_types::{AccountId, AuthPolicy, Block, BlockHeader, Hash, Transaction};

/// The operator/treasury label: pre-funded at genesis and set as the issuance
/// authority.
pub const TREASURY: &str = "treasury";

const NODE_MAGIC: &[u8; 4] = b"PHIN";
const NODE_VERSION: u8 = 1;

/// Errors surfaced to the CLI.
#[derive(Debug)]
pub enum NodeError {
    /// A transaction was rejected by the state machine.
    Rejected(TxError),
    /// I/O while loading/saving the chain file.
    Io(String),
    /// The chain file is missing or malformed.
    BadChainFile(String),
    /// A user-facing usage problem (e.g. spending from an unknown account).
    Usage(String),
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeError::Rejected(e) => write!(f, "transaction rejected: {e:?}"),
            NodeError::Io(e) => write!(f, "io error: {e}"),
            NodeError::BadChainFile(e) => write!(f, "bad chain file: {e}"),
            NodeError::Usage(e) => write!(f, "{e}"),
        }
    }
}

/// A single-node chain: ledger state plus the head pointer.
pub struct Node {
    pub state: State,
    pub height: u64,
    pub parent: Hash,
}

impl Node {
    /// The key for a label (deterministic; a real wallet would use a keystore).
    pub fn keypair(label: &str) -> Keypair {
        Keypair::from_label(label)
    }

    /// The single-key account id for a label.
    pub fn address(label: &str) -> AccountId {
        AccountId::from_auth(&AuthPolicy::SingleKey(Self::keypair(label).public()), 0)
    }

    /// Create a fresh chain: `treasury` is funded with `initial_supply` and set
    /// as the issuance authority.
    pub fn init(chain_id: u64, initial_supply: u64) -> Self {
        let mut state = State::new();
        state.set_chain_id(chain_id);
        let treasury = Self::address(TREASURY);
        state.set_minter(Some(treasury));
        state.genesis_account_with_auth(
            treasury,
            initial_supply,
            AuthPolicy::SingleKey(Self::keypair(TREASURY).public()),
        );
        Self {
            state,
            height: 0,
            parent: Hash::ZERO,
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.state.chain_id()
    }

    pub fn balance(&self, label: &str) -> u64 {
        self.state.balance(&Self::address(label))
    }

    pub fn state_root(&self) -> Hash {
        self.state.root()
    }

    pub fn total_supply(&self) -> u128 {
        self.state.total_supply()
    }

    pub fn account_count(&self) -> usize {
        self.state.account_count()
    }

    /// Move `amount` figs from the treasury to `label`'s account.
    pub fn fund(
        &mut self,
        label: &str,
        amount: u64,
        timestamp_ms: u64,
    ) -> Result<Receipt, NodeError> {
        let tx = self.build_transfer(TREASURY, &Self::address(label), amount)?;
        self.submit(tx, timestamp_ms)
    }

    /// Move `amount` figs from `from` to `to` (both labels).
    pub fn transfer(
        &mut self,
        from: &str,
        to: &str,
        amount: u64,
        timestamp_ms: u64,
    ) -> Result<Receipt, NodeError> {
        let tx = self.build_transfer(from, &Self::address(to), amount)?;
        self.submit(tx, timestamp_ms)
    }

    /// Build a signed transfer from `from_label` to `to`, attaching the
    /// first-spend auth reveal if the sender account has not yet been claimed.
    fn build_transfer(
        &self,
        from_label: &str,
        to: &AccountId,
        amount: u64,
    ) -> Result<Transaction, NodeError> {
        let from = Self::address(from_label);
        let account = self.state.account(&from).ok_or_else(|| {
            NodeError::Usage(format!(
                "account '{from_label}' does not exist yet — fund it first"
            ))
        })?;
        let kp = Self::keypair(from_label);
        let mut tx =
            Transaction::transfer(from, account.nonce, *to, amount).with_chain_id(self.chain_id());
        // First spend from a received (Unclaimed) account: reveal the policy
        // the account id commits to so the ledger can verify and claim it.
        if account.auth == AuthPolicy::Unclaimed {
            tx = tx.with_reveal(AuthPolicy::SingleKey(kp.public()), 0);
        }
        Ok(tx.signed(&kp))
    }

    /// Validate, then produce a one-transaction block and apply it. Invalid
    /// transactions are reported without advancing the chain.
    fn submit(&mut self, tx: Transaction, timestamp_ms: u64) -> Result<Receipt, NodeError> {
        self.state.validate(&tx).map_err(NodeError::Rejected)?;
        let txs = vec![tx];
        let tx_root = Block::compute_tx_root(&txs);
        let receipts: Vec<Receipt> = txs.iter().map(|t| self.state.apply_tx(t)).collect();
        let header = BlockHeader {
            chain_id: self.chain_id(),
            height: self.height + 1,
            parent: self.parent,
            tx_root,
            state_root: self.state.root(),
            receipts_root: receipts_root(&receipts),
            proposer: 0,
            timestamp_ms,
        };
        self.height += 1;
        self.parent = header.hash();
        Ok(receipts.into_iter().next().expect("one receipt"))
    }

    /// Serialize the node (head pointer + ledger snapshot) to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(NODE_MAGIC);
        out.push(NODE_VERSION);
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(self.parent.as_bytes());
        out.extend_from_slice(&self.state.snapshot());
        out
    }

    /// Reconstruct a node from [`Node::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NodeError> {
        let bad = |m: &str| NodeError::BadChainFile(m.to_string());
        if bytes.len() < 4 + 1 + 8 + 32 {
            return Err(bad("too short"));
        }
        if &bytes[0..4] != NODE_MAGIC {
            return Err(bad("wrong magic"));
        }
        if bytes[4] != NODE_VERSION {
            return Err(bad("unsupported version"));
        }
        let height = u64::from_le_bytes(bytes[5..13].try_into().unwrap());
        let parent = Hash(bytes[13..45].try_into().unwrap());
        let state =
            State::from_snapshot(&bytes[45..]).ok_or_else(|| bad("corrupt state snapshot"))?;
        Ok(Self {
            state,
            height,
            parent,
        })
    }

    /// Load a node from a file.
    pub fn load(path: &Path) -> Result<Self, NodeError> {
        let bytes = fs::read(path).map_err(|e| NodeError::Io(e.to_string()))?;
        Self::from_bytes(&bytes)
    }

    /// Save the node to a file (atomically: write a temp file then rename).
    pub fn save(&self, path: &Path) -> Result<(), NodeError> {
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, self.to_bytes()).map_err(|e| NodeError::Io(e.to_string()))?;
        fs::rename(&tmp, path).map_err(|e| NodeError::Io(e.to_string()))
    }
}

/// Create a chain file at `path`, refusing to clobber an existing one.
pub fn init_chain(path: &Path, chain_id: u64, initial_supply: u64) -> Result<Node, NodeError> {
    if path.exists() {
        return Err(NodeError::Usage(format!(
            "chain already exists at {}; remove it to re-init",
            path.display()
        )));
    }
    let node = Node::init(chain_id, initial_supply);
    node.save(path)?;
    Ok(node)
}

/// Helper: does a path exist? (kept here so `main` doesn't import `std::fs`).
pub fn chain_exists(path: &Path) -> bool {
    path.exists()
}

/// Map an io error into a NodeError (exposed for `main`).
pub fn io_err(e: io::Error) -> NodeError {
    NodeError::Io(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: u64 = 1_700_000_000_000;

    #[test]
    fn fund_then_transfer_moves_value_and_claims_account() {
        let mut node = Node::init(1, 1_000_000);
        assert_eq!(node.balance(TREASURY), 1_000_000);

        // Fund alice from the treasury.
        let r = node.fund("alice", 1_000, TS).unwrap();
        assert!(r.result.is_ok());
        assert_eq!(node.balance("alice"), 1_000);
        assert_eq!(node.height, 1);

        // alice's account was created by receiving funds → Unclaimed.
        assert_eq!(
            node.state.account(&Node::address("alice")).unwrap().auth,
            AuthPolicy::Unclaimed
        );

        // alice transfers to bob: first spend reveals & claims her policy.
        let r = node.transfer("alice", "bob", 400, TS + 1).unwrap();
        assert!(r.result.is_ok());
        assert_eq!(node.balance("alice"), 600);
        assert_eq!(node.balance("bob"), 400);
        assert_eq!(
            node.state.account(&Node::address("alice")).unwrap().auth,
            AuthPolicy::SingleKey(Node::keypair("alice").public())
        );
        assert_eq!(node.height, 2, "one block for fund, one for transfer");
    }

    #[test]
    fn overspend_is_rejected_without_advancing_the_chain() {
        let mut node = Node::init(1, 100);
        node.fund("alice", 50, TS).unwrap();
        let height_before = node.height;
        let err = node.transfer("alice", "bob", 1_000, TS + 1).unwrap_err();
        assert!(matches!(
            err,
            NodeError::Rejected(TxError::InsufficientBalance { .. })
        ));
        assert_eq!(
            node.height, height_before,
            "rejected tx must not make a block"
        );
        assert_eq!(node.balance("alice"), 50);
    }

    #[test]
    fn spending_from_unknown_account_is_a_usage_error() {
        let mut node = Node::init(1, 100);
        let err = node.transfer("nobody", "bob", 1, TS).unwrap_err();
        assert!(matches!(err, NodeError::Usage(_)));
    }

    #[test]
    fn persistence_round_trips_through_bytes_and_preserves_head() {
        let mut node = Node::init(7, 5_000);
        node.fund("alice", 250, TS).unwrap();
        node.transfer("alice", "bob", 100, TS + 1).unwrap();

        let bytes = node.to_bytes();
        let restored = Node::from_bytes(&bytes).unwrap();
        assert_eq!(restored.height, node.height);
        assert_eq!(restored.parent, node.parent);
        assert_eq!(restored.state_root(), node.state_root());
        assert_eq!(restored.balance("alice"), 150);
        assert_eq!(restored.balance("bob"), 100);
        assert_eq!(restored.chain_id(), 7);

        // A restored node keeps producing valid blocks (chain continuity).
        let mut restored = restored;
        restored.transfer("bob", "carol", 40, TS + 2).unwrap();
        assert_eq!(restored.balance("carol"), 40);
    }

    #[test]
    fn bad_chain_files_are_rejected() {
        assert!(Node::from_bytes(b"").is_err());
        assert!(Node::from_bytes(b"XXXX\x01....").is_err());
    }

    #[test]
    fn save_and_load_via_tempfile() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("phi-node-test-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut node = Node::init(1, 1_000);
        node.fund("alice", 10, TS).unwrap();
        node.save(&path).unwrap();

        let loaded = Node::load(&path).unwrap();
        assert_eq!(loaded.balance("alice"), 10);
        assert_eq!(loaded.state_root(), node.state_root());

        // init_chain refuses to clobber.
        assert!(init_chain(&path, 1, 1).is_err());

        std::fs::remove_file(&path).unwrap();
    }
}
