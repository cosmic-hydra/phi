//! BFT light client (Tendermint / Cosmos / Solana-style validator sets).
//!
//! Headers are accepted when a quorum of the foreign chain's validators have
//! signed the header hash — the same check a Tendermint light client or a
//! Solana vote-based verifier runs. Signatures are verified with the same
//! strict Ed25519 used everywhere in Phi. This mirrors Phi's own
//! `QuorumCertificate` verification, applied to a *foreign* validator set.
//!
//! Out of scope for this slice (documented, not hidden): validator-set
//! rotation/epoch transitions, unbonding/weak-subjectivity windows, and stake
//! weighting. The genesis validator set is the trust root.

use phi_crypto::PublicKey;
use phi_types::Hash;

use crate::light_client::{
    ConsensusProof, EventProof, ForeignHeader, HeaderChain, InteropError, LightClient,
};

/// Light client for a foreign BFT chain with a fixed validator set.
pub struct BftLightClient {
    chain: HeaderChain,
    validators: Vec<PublicKey>,
    quorum: usize,
}

impl BftLightClient {
    /// Construct from a trusted genesis header, the foreign validator set, and
    /// the quorum threshold (e.g. `2*n/3 + 1`). Panics if `quorum` is zero or
    /// exceeds the validator count — a nonsensical configuration.
    pub fn new(genesis: &ForeignHeader, validators: Vec<PublicKey>, quorum: usize) -> Self {
        assert!(
            quorum > 0 && quorum <= validators.len(),
            "quorum must be in 1..=validators.len()"
        );
        Self {
            chain: HeaderChain::genesis(genesis),
            validators,
            quorum,
        }
    }
}

impl LightClient for BftLightClient {
    fn protocol(&self) -> &'static str {
        "bft"
    }

    fn submit_header(
        &mut self,
        header: &ForeignHeader,
        proof: &ConsensusProof,
    ) -> Result<(), InteropError> {
        let ConsensusProof::Bft { votes } = proof else {
            return Err(InteropError::WrongConsensusProof);
        };
        self.chain.check_link(header)?;

        let message = header.hash();
        // Count distinct valid signers, so the same validator's signature
        // cannot be replayed to fake a quorum (mirrors Phi's own QC rule).
        let mut counted: Vec<u32> = Vec::new();
        for vote in votes {
            if counted.contains(&vote.signer) {
                continue;
            }
            let key = self
                .validators
                .get(vote.signer as usize)
                .ok_or(InteropError::BadSignature)?;
            if !key.verify(message.as_bytes(), &vote.signature) {
                return Err(InteropError::BadSignature);
            }
            counted.push(vote.signer);
        }
        if counted.len() < self.quorum {
            return Err(InteropError::QuorumNotMet {
                have: counted.len(),
                need: self.quorum,
            });
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
    use phi_crypto::Keypair;
    use phi_types::merkle;

    use crate::light_client::{ForeignHeader, SignerVote};

    fn validators(n: usize) -> Vec<Keypair> {
        (0..n)
            .map(|i| Keypair::from_label(&format!("foreign-validator-{i}")))
            .collect()
    }

    fn genesis() -> ForeignHeader {
        ForeignHeader {
            height: 0,
            parent: Hash::ZERO,
            event_root: merkle::root(&[]),
            nonce: 0,
        }
    }

    fn header_at(parent: &ForeignHeader, event_root: Hash) -> ForeignHeader {
        ForeignHeader {
            height: parent.height + 1,
            parent: parent.hash(),
            event_root,
            nonce: 0,
        }
    }

    fn sign_all(header: &ForeignHeader, signers: &[(u32, &Keypair)]) -> ConsensusProof {
        let msg = header.hash();
        ConsensusProof::Bft {
            votes: signers
                .iter()
                .map(|(i, kp)| SignerVote {
                    signer: *i,
                    signature: kp.sign(msg.as_bytes()),
                })
                .collect(),
        }
    }

    #[test]
    fn accepts_quorum_signed_header() {
        let vs = validators(4);
        let keys: Vec<PublicKey> = vs.iter().map(|k| k.public()).collect();
        let mut client = BftLightClient::new(&genesis(), keys, 3);

        let h = header_at(&genesis(), merkle::root(&[Hash::of(b"e")]));
        let proof = sign_all(&h, &[(0, &vs[0]), (1, &vs[1]), (2, &vs[2])]);
        assert!(client.submit_header(&h, &proof).is_ok());
        assert_eq!(client.tip_height(), 1);
    }

    #[test]
    fn rejects_below_quorum() {
        let vs = validators(4);
        let keys: Vec<PublicKey> = vs.iter().map(|k| k.public()).collect();
        let mut client = BftLightClient::new(&genesis(), keys, 3);
        let h = header_at(&genesis(), Hash::ZERO);
        let proof = sign_all(&h, &[(0, &vs[0]), (1, &vs[1])]);
        assert_eq!(
            client.submit_header(&h, &proof),
            Err(InteropError::QuorumNotMet { have: 2, need: 3 })
        );
    }

    #[test]
    fn duplicate_signer_does_not_inflate_quorum() {
        let vs = validators(4);
        let keys: Vec<PublicKey> = vs.iter().map(|k| k.public()).collect();
        let mut client = BftLightClient::new(&genesis(), keys, 3);
        let h = header_at(&genesis(), Hash::ZERO);
        // Validator 0 signs three times.
        let proof = sign_all(&h, &[(0, &vs[0]), (0, &vs[0]), (0, &vs[0])]);
        assert_eq!(
            client.submit_header(&h, &proof),
            Err(InteropError::QuorumNotMet { have: 1, need: 3 })
        );
    }

    #[test]
    fn rejects_forged_signature() {
        let vs = validators(4);
        let keys: Vec<PublicKey> = vs.iter().map(|k| k.public()).collect();
        let mut client = BftLightClient::new(&genesis(), keys, 3);
        let h = header_at(&genesis(), Hash::ZERO);
        let mallory = Keypair::from_label("mallory");
        // Mallory signs but claims to be validator 2.
        let proof = ConsensusProof::Bft {
            votes: vec![
                SignerVote {
                    signer: 0,
                    signature: vs[0].sign(h.hash().as_bytes()),
                },
                SignerVote {
                    signer: 1,
                    signature: vs[1].sign(h.hash().as_bytes()),
                },
                SignerVote {
                    signer: 2,
                    signature: mallory.sign(h.hash().as_bytes()),
                },
            ],
        };
        assert_eq!(
            client.submit_header(&h, &proof),
            Err(InteropError::BadSignature)
        );
    }
}
