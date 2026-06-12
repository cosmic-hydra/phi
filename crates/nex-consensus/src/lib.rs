//! Consensus stub: round-robin proposer with explicit >2/3 voting.
//!
//! This models the *shape* of NexBFT (propose → vote → quorum → commit) so
//! the rest of the stack integrates against the right interface, while the
//! real pipelined HotStuff with VRF sortition is built in Phase 1b
//! (docs/ROADMAP.md). There is no networking, cryptographic signing, or view
//! change here — validators are honest-by-construction simulation actors that
//! re-execute proposals and refuse to vote for incorrect state roots.

use nex_state::State;
use nex_types::{Block, BlockHeader, Hash, Transaction};

/// A validator's vote on a proposed block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub validator: u32,
    pub block_hash: Hash,
    pub approve: bool,
}

/// Result of running one consensus round.
#[derive(Debug)]
pub enum RoundOutcome {
    /// Quorum (>2/3) approved; block is committed.
    Committed(Block),
    /// Not enough approving votes; proposal is discarded.
    Rejected { approvals: usize, needed: usize },
}

/// One simulated validator: each keeps an independent copy of state and only
/// votes for proposals whose declared state root matches its own execution.
pub struct Validator {
    pub index: u32,
    pub state: State,
}

impl Validator {
    pub fn new(index: u32, genesis: State) -> Self {
        Self {
            index,
            state: genesis,
        }
    }

    /// Verify a proposal by re-executing it on a copy of local state.
    pub fn vote(&self, block: &Block) -> Vote {
        let tx_root_ok = Block::compute_tx_root(&block.transactions) == block.header.tx_root;
        let mut scratch = self.state.clone();
        scratch.apply_block(block);
        let state_root_ok = scratch.root() == block.header.state_root;
        Vote {
            validator: self.index,
            block_hash: block.header.hash(),
            approve: tx_root_ok && state_root_ok,
        }
    }

    /// Apply a committed block to local state.
    pub fn commit(&mut self, block: &Block) {
        self.state.apply_block(block);
        debug_assert_eq!(self.state.root(), block.header.state_root);
    }
}

/// Round-robin BFT-shaped consensus over a set of simulated validators.
pub struct ConsensusEngine {
    pub validators: Vec<Validator>,
    pub height: u64,
    pub parent: Hash,
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
        }
    }

    /// Quorum threshold: strictly more than 2/3 of validators.
    pub fn quorum(&self) -> usize {
        (self.validators.len() * 2) / 3 + 1
    }

    fn proposer_index(&self) -> usize {
        // Round-robin. Production: VRF sortition (docs/SPECIFICATION.md §3).
        (self.height % self.validators.len() as u64) as usize
    }

    /// Build a proposal for the next height from a transaction batch.
    pub fn propose(&self, txs: Vec<Transaction>, timestamp_ms: u64) -> Block {
        let proposer = &self.validators[self.proposer_index()];
        let mut scratch = proposer.state.clone();
        let header_height = self.height + 1;
        // Proposer executes to compute the post-state root it commits to.
        let provisional = Block {
            header: BlockHeader {
                height: header_height,
                parent: self.parent,
                tx_root: Block::compute_tx_root(&txs),
                state_root: Hash::ZERO,
                proposer: proposer.index,
                timestamp_ms,
            },
            transactions: txs,
        };
        scratch.apply_block(&provisional);
        let mut block = provisional;
        block.header.state_root = scratch.root();
        block
    }

    /// Run one round: propose, gather votes, commit on quorum.
    pub fn run_round(&mut self, txs: Vec<Transaction>, timestamp_ms: u64) -> RoundOutcome {
        let block = self.propose(txs, timestamp_ms);
        let votes: Vec<Vote> = self.validators.iter().map(|v| v.vote(&block)).collect();
        let approvals = votes.iter().filter(|v| v.approve).count();
        let needed = self.quorum();
        if approvals >= needed {
            for v in self.validators.iter_mut() {
                v.commit(&block);
            }
            self.height = block.header.height;
            self.parent = block.header.hash();
            RoundOutcome::Committed(block)
        } else {
            RoundOutcome::Rejected { approvals, needed }
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
            RoundOutcome::Committed(block) => {
                assert_eq!(block.header.height, 1);
                let roots: Vec<Hash> =
                    engine.validators.iter().map(|v| v.state.root()).collect();
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
            if let RoundOutcome::Committed(b) = engine.run_round(vec![], i) {
                proposers.push(b.header.proposer);
            }
        }
        assert_eq!(proposers, vec![0, 1, 2]);
    }
}
