//! Block structure.

use crate::hash::Hash;
use crate::merkle::{self, MerkleProof};
use crate::transaction::Transaction;

/// Block header: what light clients verify.
///
/// The full protocol adds a BFT quorum certificate reference, a DA blob
/// commitment, and an optional aggregated validity proof
/// (docs/SPECIFICATION.md §5). Quorum certificates over the header hash are
/// produced by `phi-consensus` and stored alongside the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub height: u64,
    pub parent: Hash,
    /// Merkle root of transactions in this block.
    pub tx_root: Hash,
    /// State root *after* executing this block.
    pub state_root: Hash,
    /// Merkle root of execution receipts, so light clients can verify not
    /// just that a transaction was included but what it did.
    pub receipts_root: Hash,
    /// Index of the proposing validator (VRF sortition in the full protocol).
    pub proposer: u32,
    pub timestamp_ms: u64,
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        Hash::of_tagged(
            b"phi:header",
            &[
                &self.height.to_le_bytes(),
                self.parent.as_bytes(),
                self.tx_root.as_bytes(),
                self.state_root.as_bytes(),
                self.receipts_root.as_bytes(),
                &self.proposer.to_le_bytes(),
                &self.timestamp_ms.to_le_bytes(),
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Merkle root over transaction ids (see `merkle` for the hardened
    /// construction: tagged leaves, odd-node promotion).
    pub fn compute_tx_root(txs: &[Transaction]) -> Hash {
        let ids: Vec<Hash> = txs.iter().map(|t| t.id()).collect();
        merkle::root(&ids)
    }

    /// Inclusion proof for the transaction at `index`, checkable against
    /// `header.tx_root` with [`Block::verify_tx_proof`].
    pub fn prove_tx(&self, index: usize) -> Option<MerkleProof> {
        let ids: Vec<Hash> = self.transactions.iter().map(|t| t.id()).collect();
        merkle::prove(&ids, index)
    }

    /// Verify that a transaction id sits at `index` in a block committing to
    /// `tx_root` with `tx_count` transactions.
    pub fn verify_tx_proof(
        tx_root: &Hash,
        tx_id: &Hash,
        index: usize,
        tx_count: usize,
        proof: &MerkleProof,
    ) -> bool {
        merkle::verify(tx_root, tx_id, index, tx_count, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountId;

    fn txs(n: u64) -> Vec<Transaction> {
        (0..n)
            .map(|i| {
                Transaction::transfer(
                    AccountId::from_label("sender"),
                    i,
                    AccountId::from_label("recipient"),
                    1,
                )
            })
            .collect()
    }

    #[test]
    fn tx_root_changes_with_contents() {
        assert_ne!(
            Block::compute_tx_root(&txs(2)),
            Block::compute_tx_root(&txs(3))
        );
    }

    #[test]
    fn tx_inclusion_proof_roundtrip() {
        let transactions = txs(5);
        let root = Block::compute_tx_root(&transactions);
        let block = Block {
            header: BlockHeader {
                height: 1,
                parent: Hash::ZERO,
                tx_root: root,
                state_root: Hash::ZERO,
                receipts_root: Hash::ZERO,
                proposer: 0,
                timestamp_ms: 0,
            },
            transactions,
        };
        let proof = block.prove_tx(3).unwrap();
        let tx_id = block.transactions[3].id();
        assert!(Block::verify_tx_proof(&root, &tx_id, 3, 5, &proof));
        assert!(!Block::verify_tx_proof(&root, &tx_id, 2, 5, &proof));
    }

    #[test]
    fn header_hash_commits_to_receipts_root() {
        let mut header = BlockHeader {
            height: 1,
            parent: Hash::ZERO,
            tx_root: Hash::ZERO,
            state_root: Hash::ZERO,
            receipts_root: Hash::ZERO,
            proposer: 0,
            timestamp_ms: 0,
        };
        let original = header.hash();
        header.receipts_root = Hash::of(b"different");
        assert_ne!(original, header.hash());
    }
}
