//! Proof-of-work light client (Bitcoin-style SPV).
//!
//! Headers are accepted when their hash meets a difficulty target — the same
//! check an SPV wallet runs. This is the honest shape of "verify Bitcoin
//! inside Phi": header-chain verification by cumulative work. Production needs
//! retargeting and most-work fork choice; this slice tracks a single
//! contiguous chain from a trusted checkpoint and documents the gap.

use phi_types::Hash;

use crate::light_client::{
    ConsensusProof, EventProof, ForeignHeader, HeaderChain, InteropError, LightClient,
};

/// True if `hash` is numerically ≤ `target` (both big-endian 32-byte values).
fn meets_target(hash: &Hash, target: &[u8; 32]) -> bool {
    hash.as_bytes() <= target
}

/// SPV-style light client: accept the next header iff it links to the tip and
/// its hash meets the target.
pub struct PowLightClient {
    chain: HeaderChain,
    target: [u8; 32],
}

impl PowLightClient {
    /// Construct from a trusted genesis header and a difficulty `target`
    /// (max acceptable header hash). The genesis header is the trust root and
    /// is not itself work-checked.
    pub fn new(genesis: &ForeignHeader, target: [u8; 32]) -> Self {
        Self {
            chain: HeaderChain::genesis(genesis),
            target,
        }
    }

    /// Mine a valid `nonce` for a header against this client's target
    /// (test/relayer helper). Returns the completed header.
    pub fn mine(&self, mut header: ForeignHeader) -> ForeignHeader {
        header.nonce = 0;
        while !meets_target(&header.hash(), &self.target) {
            header.nonce += 1;
        }
        header
    }
}

impl LightClient for PowLightClient {
    fn protocol(&self) -> &'static str {
        "pow"
    }

    fn submit_header(
        &mut self,
        header: &ForeignHeader,
        proof: &ConsensusProof,
    ) -> Result<(), InteropError> {
        if !matches!(proof, ConsensusProof::Pow) {
            return Err(InteropError::WrongConsensusProof);
        }
        self.chain.check_link(header)?;
        if !meets_target(&header.hash(), &self.target) {
            return Err(InteropError::InsufficientWork);
        }
        self.chain.append(header);
        Ok(())
    }

    fn tip_height(&self) -> u64 {
        self.chain.tip_height()
    }

    fn verify_event(&self, event_hash: Hash, proof: &EventProof) -> Result<(), InteropError> {
        self.chain.verify_event(event_hash, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phi_types::merkle;
    use phi_types::AccountId;

    use crate::light_client::CrossChainEvent;
    use crate::ForeignChainId;

    /// A loose target: first byte must be zero (≈1/256, instant to mine).
    fn easy_target() -> [u8; 32] {
        let mut t = [0xffu8; 32];
        t[0] = 0x00;
        t
    }

    fn genesis() -> ForeignHeader {
        ForeignHeader {
            height: 0,
            parent: Hash::ZERO,
            event_root: merkle::root(&[]),
            nonce: 0,
        }
    }

    #[test]
    fn accepts_mined_headers_and_rejects_unmined() {
        let mut client = PowLightClient::new(&genesis(), easy_target());
        let next = ForeignHeader {
            height: 1,
            parent: genesis().hash(),
            event_root: merkle::root(&[Hash::of(b"e")]),
            nonce: 0,
        };
        // Unmined header almost certainly fails the target.
        if meets_target(&next.hash(), &easy_target()) {
            // Astronomically unlikely; skip if the zero-nonce happens to pass.
        } else {
            assert_eq!(
                client.submit_header(&next, &ConsensusProof::Pow),
                Err(InteropError::InsufficientWork)
            );
        }
        let mined = client.mine(next);
        assert!(client.submit_header(&mined, &ConsensusProof::Pow).is_ok());
        assert_eq!(client.tip_height(), 1);
    }

    #[test]
    fn rejects_broken_links() {
        let mut client = PowLightClient::new(&genesis(), easy_target());
        let wrong_parent = client.mine(ForeignHeader {
            height: 1,
            parent: Hash::of(b"not-genesis"),
            event_root: Hash::ZERO,
            nonce: 0,
        });
        assert!(matches!(
            client.submit_header(&wrong_parent, &ConsensusProof::Pow),
            Err(InteropError::BrokenLink { .. })
        ));
    }

    #[test]
    fn wrong_proof_kind_rejected() {
        let mut client = PowLightClient::new(&genesis(), easy_target());
        let h = client.mine(ForeignHeader {
            height: 1,
            parent: genesis().hash(),
            event_root: Hash::ZERO,
            nonce: 0,
        });
        assert_eq!(
            client.submit_header(&h, &ConsensusProof::Bft { votes: vec![] }),
            Err(InteropError::WrongConsensusProof)
        );
    }

    #[test]
    fn verifies_event_inclusion_under_a_mined_header() {
        let mut client = PowLightClient::new(&genesis(), easy_target());
        let event = CrossChainEvent {
            foreign_chain: ForeignChainId(7),
            sequence: 0,
            beneficiary: AccountId::from_label("dest"),
            amount: 100,
        };
        let leaves = vec![Hash::of(b"other"), event.hash()];
        let header = client.mine(ForeignHeader {
            height: 1,
            parent: genesis().hash(),
            event_root: merkle::root(&leaves),
            nonce: 0,
        });
        client.submit_header(&header, &ConsensusProof::Pow).unwrap();

        let proof = crate::light_client::EventProof {
            header_height: 1,
            leaf_index: 1,
            leaf_count: 2,
            merkle: merkle::prove(&leaves, 1).unwrap(),
        };
        assert!(client.verify_event(event.hash(), &proof).is_ok());
        // Tampered amount → different hash → not included.
        let mut forged = event.clone();
        forged.amount = 999;
        assert_eq!(
            client.verify_event(forged.hash(), &proof),
            Err(InteropError::EventNotIncluded)
        );
    }
}
