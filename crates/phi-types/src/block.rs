//! Block structure.

use crate::hash::Hash;
use crate::transaction::Transaction;

/// Block header: what light clients verify.
///
/// The full protocol adds a BFT quorum certificate, a DA blob commitment,
/// and an optional aggregated validity proof (docs/SPECIFICATION.md §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub height: u64,
    pub parent: Hash,
    /// Merkle root of transactions in this block.
    pub tx_root: Hash,
    /// State root *after* executing this block.
    pub state_root: Hash,
    /// Index of the proposing validator (VRF sortition in the full protocol).
    pub proposer: u32,
    pub timestamp_ms: u64,
}

impl BlockHeader {
    pub fn hash(&self) -> Hash {
        Hash::of_parts(&[
            b"phi:header",
            &self.height.to_le_bytes(),
            self.parent.as_bytes(),
            self.tx_root.as_bytes(),
            self.state_root.as_bytes(),
            &self.proposer.to_le_bytes(),
            &self.timestamp_ms.to_le_bytes(),
        ])
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Binary Merkle root over transaction ids (duplicates last leaf on odd
    /// levels). Empty block commits to the zero hash.
    pub fn compute_tx_root(txs: &[Transaction]) -> Hash {
        if txs.is_empty() {
            return Hash::ZERO;
        }
        let mut level: Vec<Hash> = txs.iter().map(|t| t.id()).collect();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|pair| {
                    let right = pair.get(1).unwrap_or(&pair[0]);
                    Hash::of_parts(&[b"phi:merkle", pair[0].as_bytes(), right.as_bytes()])
                })
                .collect();
        }
        level[0]
    }
}
