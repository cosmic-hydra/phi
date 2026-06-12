//! BFT-shaped consensus: rotating proposer, signed votes, quorum
//! certificates, and view change on failed rounds.
//!
//! This models the shape of NexBFT (propose → vote → quorum → commit) so the
//! rest of the stack integrates against the right interface, while the real
//! pipelined HotStuff over libp2p is built in Phase 1b (docs/ROADMAP.md).
//! Already real here: Ed25519-signed votes, quorum certificates verifiable
//! by light clients, validators that re-execute proposals (via the parallel
//! executor) and refuse to vote for incorrect roots, Byzantine actors that
//! corrupt proposals and vote blindly, and view change so a failed round
//! rotates the proposer instead of stalling. Still simulated: networking,
//! the pacemaker, and slashing evidence.

use nex_crypto::{Keypair, PublicKey, Signature};
use nex_executor::ExecutionOutput;
use nex_state::{receipts_root, Receipt, State};
use nex_types::{Block, BlockHeader, Hash, Transaction};

/// Canonical message a validator signs when voting on a proposal.
pub fn vote_message(block_hash: &Hash, height: u64, approve: bool) -> Hash {
    Hash::of_tagged(
        b"nex:vote",
        &[
            block_hash.as_bytes(),
            &height.to_le_bytes(),
            &[approve as u8],
        ],
    )
}

/// A validator's signed vote on a proposed block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub validator: u32,
    pub block_hash: Hash,
    pub height: u64,
    pub approve: bool,
    pub signature: Signature,
}

impl Vote {
    /// Check the vote's signature against the claimed validator's key.
    pub fn verify(&self, validator_keys: &[PublicKey]) -> bool {
        let Some(key) = validator_keys.get(self.validator as usize) else {
            return false;
        };
        let message = vote_message(&self.block_hash, self.height, self.approve);
        key.verify(message.as_bytes(), &self.signature)
    }
}

/// Proof that >2/3 of validators approved a block: the committed chain is a
/// sequence of (block, QC) pairs any light client can verify against the
/// validator set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub block_hash: Hash,
    pub height: u64,
    pub signers: Vec<u32>,
    pub signatures: Vec<Signature>,
}

impl QuorumCertificate {
    /// Verify quorum size, signer distinctness, and every signature.
    pub fn verify(&self, validator_keys: &[PublicKey], quorum: usize) -> bool {
        if self.signers.len() != self.signatures.len() || self.signers.len() < quorum {
            return false;
        }
        let mut seen = self.signers.clone();
        seen.sort_unstable();
        seen.dedup();
        if seen.len() != self.signers.len() {
            return false;
        }
        let message = vote_message(&self.block_hash, self.height, true);
        self.signers
            .iter()
            .zip(&self.signatures)
            .all(|(signer, signature)| {
                validator_keys
                    .get(*signer as usize)
                    .is_some_and(|key| key.verify(message.as_bytes(), signature))
            })
    }
}

/// Result of running one consensus round.
#[derive(Debug)]
pub enum RoundOutcome {
    /// Quorum (>2/3) approved; the block is committed with its certificate
    /// and execution receipts. (Boxed: a committed block dwarfs the
    /// rejection arm.)
    Committed {
        block: Box<Block>,
        qc: QuorumCertificate,
        receipts: Vec<Receipt>,
    },
    /// Not enough approving votes; the proposal is discarded, the view
    /// advances (next proposer), and the batch is handed back to the caller
    /// for re-queuing — transactions must never die with a bad proposal.
    Rejected {
        proposer: u32,
        approvals: usize,
        needed: usize,
        txs: Vec<Transaction>,
    },
}

/// One simulated validator: each keeps an independent copy of state, signs
/// its votes, and only approves proposals whose declared roots match its own
/// re-execution. Byzantine validators corrupt their proposals and approve
/// everything — safety must hold anyway.
pub struct Validator {
    pub index: u32,
    pub state: State,
    pub byzantine: bool,
    keypair: Keypair,
}

impl Validator {
    pub fn new(index: u32, genesis: State) -> Self {
        Self {
            index,
            state: genesis,
            byzantine: false,
            // Simulation keys are label-derived; real validators load HSM/
            // keystore-backed keys (Phase 1b).
            keypair: Keypair::from_label(&format!("nex:validator:{index}")),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Verify a proposal by re-executing it on a copy of local state and
    /// checking every header commitment (txs, state, receipts).
    pub fn vote(&self, block: &Block) -> Vote {
        let approve = if self.byzantine {
            true // votes blindly for anything, including corrupt proposals
        } else {
            let mut scratch = self.state.clone();
            let out = nex_executor::execute(&mut scratch, &block.transactions);
            Block::compute_tx_root(&block.transactions) == block.header.tx_root
                && out.state_root == block.header.state_root
                && receipts_root(&out.receipts) == block.header.receipts_root
        };
        let block_hash = block.header.hash();
        let message = vote_message(&block_hash, block.header.height, approve);
        Vote {
            validator: self.index,
            block_hash,
            height: block.header.height,
            approve,
            signature: self.keypair.sign(message.as_bytes()),
        }
    }

    /// Apply a committed block to local state.
    pub fn commit(&mut self, block: &Block) -> Vec<Receipt> {
        let out = nex_executor::execute(&mut self.state, &block.transactions);
        debug_assert_eq!(out.state_root, block.header.state_root);
        out.receipts
    }
}

/// Round-based BFT-shaped consensus over a set of simulated validators.
pub struct ConsensusEngine {
    pub validators: Vec<Validator>,
    pub height: u64,
    pub parent: Hash,
    /// Monotonic view number; the proposer rotates with it, so a rejected
    /// round moves past a faulty proposer instead of retrying it forever.
    pub view: u64,
    /// Committed blocks with their quorum certificates (the light-client
    /// auditable chain).
    pub chain: Vec<(Block, QuorumCertificate)>,
}

impl ConsensusEngine {
    /// All validators start from the same genesis state.
    pub fn new(num_validators: u32, genesis: State) -> Self {
        let validators = (0..num_validators)
            .map(|i| Validator::new(i, genesis.clone()))
            .collect();
        Self {
            validators,
            height: 0,
            parent: Hash::ZERO,
            view: 0,
            chain: Vec::new(),
        }
    }

    /// Quorum threshold: strictly more than 2/3 of validators.
    pub fn quorum(&self) -> usize {
        (self.validators.len() * 2) / 3 + 1
    }

    pub fn validator_keys(&self) -> Vec<PublicKey> {
        self.validators.iter().map(Validator::public_key).collect()
    }

    /// Index of the proposer for the current view.
    /// Round-robin in the view number; production uses VRF sortition
    /// (docs/SPECIFICATION.md §3).
    pub fn proposer_index(&self) -> usize {
        (self.view % self.validators.len() as u64) as usize
    }

    /// Build a proposal for the next height from a transaction batch. The
    /// proposer executes the batch to compute the roots it commits to; a
    /// Byzantine proposer commits to a corrupted state root instead.
    pub fn propose(&self, txs: Vec<Transaction>, timestamp_ms: u64) -> Block {
        let proposer = &self.validators[self.proposer_index()];
        let mut scratch = proposer.state.clone();
        let ExecutionOutput {
            mut state_root,
            receipts,
        } = nex_executor::execute(&mut scratch, &txs);
        if proposer.byzantine {
            state_root.0[0] ^= 0xff; // claims a state it did not compute
        }
        Block {
            header: BlockHeader {
                height: self.height + 1,
                parent: self.parent,
                tx_root: Block::compute_tx_root(&txs),
                state_root,
                receipts_root: receipts_root(&receipts),
                proposer: proposer.index,
                timestamp_ms,
            },
            transactions: txs,
        }
    }

    /// Run one round: propose, gather signed votes, verify them, build and
    /// check the quorum certificate, commit on quorum. On failure the view
    /// advances and the batch is returned for re-queuing.
    pub fn run_round(&mut self, txs: Vec<Transaction>, timestamp_ms: u64) -> RoundOutcome {
        let block = self.propose(txs, timestamp_ms);
        let block_hash = block.header.hash();
        let keys = self.validator_keys();

        // Forged or mismatched votes are discarded before counting.
        let votes: Vec<Vote> = self
            .validators
            .iter()
            .map(|v| v.vote(&block))
            .filter(|vote| vote.block_hash == block_hash && vote.verify(&keys))
            .collect();
        let approving: Vec<&Vote> = votes.iter().filter(|v| v.approve).collect();
        let needed = self.quorum();
        self.view += 1;

        if approving.len() < needed {
            return RoundOutcome::Rejected {
                proposer: block.header.proposer,
                approvals: approving.len(),
                needed,
                txs: block.transactions,
            };
        }

        let qc = QuorumCertificate {
            block_hash,
            height: block.header.height,
            signers: approving.iter().map(|v| v.validator).collect(),
            signatures: approving.iter().map(|v| v.signature).collect(),
        };
        assert!(qc.verify(&keys, needed), "constructed QC must verify");

        let mut receipts = Vec::new();
        for validator in self.validators.iter_mut() {
            let r = validator.commit(&block);
            if validator.index == 0 {
                receipts = r;
            }
        }
        self.height = block.header.height;
        self.parent = block_hash;
        self.chain.push((block.clone(), qc.clone()));
        RoundOutcome::Committed {
            block: Box::new(block),
            qc,
            receipts,
        }
    }

    /// Reference to validator 0's state (all honest validators agree).
    pub fn canonical_state(&self) -> &State {
        &self.validators[0].state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nex_types::AccountId;

    fn id(label: &str) -> AccountId {
        AccountId::from_label(label)
    }

    fn genesis() -> State {
        let mut s = State::new();
        s.genesis_account(id("alice"), 1000);
        s.genesis_account(id("bob"), 0);
        s
    }

    #[test]
    fn honest_round_commits_and_all_validators_agree() {
        let mut engine = ConsensusEngine::new(4, genesis());
        let txs = vec![Transaction::transfer(id("alice"), 0, id("bob"), 100)];
        match engine.run_round(txs, 1) {
            RoundOutcome::Committed {
                block,
                qc,
                receipts,
            } => {
                assert_eq!(block.header.height, 1);
                assert!(receipts.iter().all(|r| r.result.is_ok()));
                assert!(qc.verify(&engine.validator_keys(), engine.quorum()));
                let roots: Vec<Hash> = engine.validators.iter().map(|v| v.state.root()).collect();
                assert!(roots.windows(2).all(|w| w[0] == w[1]));
                assert_eq!(engine.canonical_state().balance(&id("bob")), 100);
            }
            other => panic!("expected commit, got {other:?}"),
        }
    }

    #[test]
    fn bad_state_root_is_rejected_by_voters() {
        let engine = ConsensusEngine::new(4, genesis());
        let mut block =
            engine.propose(vec![Transaction::transfer(id("alice"), 0, id("bob"), 1)], 1);
        block.header.state_root = Hash::ZERO; // corrupt the proposal
        let approvals = engine
            .validators
            .iter()
            .filter(|v| v.vote(&block).approve)
            .count();
        assert_eq!(approvals, 0);
    }

    #[test]
    fn proposer_rotates_round_robin() {
        let mut engine = ConsensusEngine::new(3, genesis());
        let mut proposers = Vec::new();
        for i in 0..3 {
            if let RoundOutcome::Committed { block, .. } = engine.run_round(vec![], i) {
                proposers.push(block.header.proposer);
            }
        }
        assert_eq!(proposers, vec![0, 1, 2]);
    }

    #[test]
    fn byzantine_proposer_is_outvoted_then_view_change_recovers() {
        let mut engine = ConsensusEngine::new(4, genesis());
        engine.validators[0].byzantine = true;

        // View 0: the Byzantine validator proposes a corrupted root. Only
        // its own blind vote approves — safety holds.
        let txs = vec![Transaction::transfer(id("alice"), 0, id("bob"), 100)];
        let returned = match engine.run_round(txs, 1) {
            RoundOutcome::Rejected {
                proposer,
                approvals,
                needed,
                txs,
            } => {
                assert_eq!(proposer, 0);
                assert_eq!(approvals, 1);
                assert_eq!(needed, 3);
                txs
            }
            other => panic!("expected rejection, got {other:?}"),
        };
        assert_eq!(engine.height, 0, "nothing committed");
        assert_eq!(engine.canonical_state().balance(&id("bob")), 0);

        // View 1: an honest proposer commits the same batch (the Byzantine
        // validator's blind approval simply counts toward the honest block).
        match engine.run_round(returned, 2) {
            RoundOutcome::Committed { block, .. } => {
                assert_eq!(block.header.proposer, 1);
                assert_eq!(block.header.height, 1);
            }
            other => panic!("expected commit, got {other:?}"),
        }
        assert_eq!(engine.canonical_state().balance(&id("bob")), 100);
        let roots: Vec<Hash> = engine.validators.iter().map(|v| v.state.root()).collect();
        assert!(roots.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn quorum_certificate_tampering_detected() {
        let mut engine = ConsensusEngine::new(4, genesis());
        let RoundOutcome::Committed { qc, .. } =
            engine.run_round(vec![Transaction::transfer(id("alice"), 0, id("bob"), 1)], 1)
        else {
            panic!("expected commit");
        };
        let keys = engine.validator_keys();
        let quorum = engine.quorum();
        assert!(qc.verify(&keys, quorum));

        let mut wrong_block = qc.clone();
        wrong_block.block_hash = Hash::of(b"forged");
        assert!(!wrong_block.verify(&keys, quorum));

        let mut duplicated_signer = qc.clone();
        duplicated_signer.signers[1] = duplicated_signer.signers[0];
        duplicated_signer.signatures[1] = duplicated_signer.signatures[0];
        assert!(!duplicated_signer.verify(&keys, quorum));

        let mut truncated = qc.clone();
        truncated.signers.truncate(quorum - 1);
        truncated.signatures.truncate(quorum - 1);
        assert!(!truncated.verify(&keys, quorum));
    }

    #[test]
    fn committed_receipts_record_runtime_failures() {
        let mut engine = ConsensusEngine::new(4, genesis());
        let txs = vec![
            Transaction::transfer(id("alice"), 0, id("bob"), 10),
            Transaction::transfer(id("alice"), 1, id("bob"), 999_999), // fails in-block
        ];
        let RoundOutcome::Committed { receipts, .. } = engine.run_round(txs, 1) else {
            panic!("expected commit");
        };
        assert!(receipts[0].result.is_ok());
        assert!(matches!(
            receipts[1].result,
            Err(nex_state::TxError::InsufficientBalance { .. })
        ));
        // The failed attempt still consumed alice's nonce.
        assert_eq!(
            engine
                .canonical_state()
                .account(&id("alice"))
                .unwrap()
                .nonce,
            2
        );
    }
}
