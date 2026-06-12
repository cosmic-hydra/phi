//! The verification core shared by every chain adapter.
//!
//! A *light client* tracks a foreign chain's header sequence and verifies its
//! consensus rules, so Phi can confirm "event E happened on chain C" from a
//! succinct proof rather than trusting a relayer. This is the structural
//! difference between Phi's interop and the multisig bridges that account for
//! most Web3 losses: there is no privileged signer set that can lie — a
//! relayer can only submit headers and proofs the adapter independently
//! checks (docs/SPECIFICATION.md §11).

use std::collections::BTreeMap;

use phi_crypto::Signature;
use phi_types::merkle::{self, MerkleProof};
use phi_types::{AccountId, Hash};

/// Identifier of a foreign chain tracked by the bridge.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ForeignChainId(pub u64);

/// Why a cross-chain verification step failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InteropError {
    /// No light client registered for this foreign chain.
    UnknownChain,
    /// A chain is already registered under this id.
    ChainAlreadyRegistered,
    /// Header does not extend the trusted tip (parent/height mismatch).
    BrokenLink { expected_parent: Hash, got: Hash },
    /// Header height is not exactly tip + 1.
    NonContiguousHeight { expected: u64, got: u64 },
    /// Proof-of-work header hash does not meet the target.
    InsufficientWork,
    /// Wrong consensus proof kind for this adapter (e.g. PoW proof to a BFT
    /// client).
    WrongConsensusProof,
    /// Fewer than the required distinct valid validator signatures.
    QuorumNotMet { have: usize, need: usize },
    /// A signature in the consensus proof did not verify.
    BadSignature,
    /// The proof references a header height this client has not verified.
    UnknownHeader { height: u64 },
    /// The event is not committed under the referenced header's event root.
    EventNotIncluded,
    /// This inbound event sequence was already redeemed (replay).
    AlreadyProcessed { sequence: u64 },
}

/// A foreign block header in Phi's common representation. Adapter-specific
/// validity (PoW target, BFT signatures) is supplied separately as a
/// [`ConsensusProof`]; the fields here are what every adapter commits to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignHeader {
    pub height: u64,
    pub parent: Hash,
    /// Merkle root of the cross-chain events committed in this block.
    pub event_root: Hash,
    /// Free nonce; the proof-of-work adapter varies it to meet its target,
    /// other adapters leave it zero.
    pub nonce: u64,
}

impl ForeignHeader {
    /// Canonical header hash — the proof-of-work value *and* the message BFT
    /// validators sign. Domain-separated and length-prefixed like every other
    /// consensus hash in Phi.
    pub fn hash(&self) -> Hash {
        Hash::of_tagged(
            b"phi:interop:header",
            &[
                &self.height.to_le_bytes(),
                self.parent.as_bytes(),
                self.event_root.as_bytes(),
                &self.nonce.to_le_bytes(),
            ],
        )
    }
}

/// One validator's signature over a foreign header (BFT adapters).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerVote {
    pub signer: u32,
    pub signature: Signature,
}

/// Adapter-specific evidence that a header is canonical on its chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsensusProof {
    /// Proof of work lives in the header itself (its hash meets the target).
    Pow,
    /// A quorum of foreign validator signatures over the header hash.
    Bft { votes: Vec<SignerVote> },
}

/// A cross-chain transfer event emitted by a foreign chain: "`amount` units
/// were locked on `foreign_chain`, to be credited to Phi account
/// `beneficiary`". `sequence` is the chain's monotonic event counter and the
/// replay key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossChainEvent {
    pub foreign_chain: ForeignChainId,
    pub sequence: u64,
    pub beneficiary: AccountId,
    pub amount: u64,
}

impl CrossChainEvent {
    /// Leaf hash committed into a foreign header's `event_root`.
    pub fn hash(&self) -> Hash {
        Hash::of_tagged(
            b"phi:interop:event",
            &[
                &self.foreign_chain.0.to_le_bytes(),
                &self.sequence.to_le_bytes(),
                self.beneficiary.0.as_bytes(),
                &self.amount.to_le_bytes(),
            ],
        )
    }
}

/// Merkle inclusion proof that an event sits in a specific verified header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventProof {
    pub header_height: u64,
    pub leaf_index: usize,
    pub leaf_count: usize,
    pub merkle: MerkleProof,
}

/// A foreign-chain verifier. Object-safe so [`crate::BridgeHub`] can hold a
/// heterogeneous registry of `Box<dyn LightClient>`.
pub trait LightClient: Send {
    /// Adapter name, e.g. `"pow"` or `"bft"`.
    fn protocol(&self) -> &'static str;

    /// Verify `header` under `proof` and adopt it as the new tip. Must reject
    /// anything that does not extend the trusted chain.
    fn submit_header(
        &mut self,
        header: &ForeignHeader,
        proof: &ConsensusProof,
    ) -> Result<(), InteropError>;

    /// Height of the trusted tip (the genesis header is height 0).
    fn tip_height(&self) -> u64;

    /// Verify that `event_hash` is committed under the trusted header named by
    /// `proof`.
    fn verify_event(&self, event_hash: Hash, proof: &EventProof) -> Result<(), InteropError>;
}

/// Shared header bookkeeping reused by every adapter: tip tracking, linkage
/// checks, and the committed event roots needed for inclusion proofs.
pub(crate) struct HeaderChain {
    tip_height: u64,
    tip_hash: Hash,
    event_roots: BTreeMap<u64, Hash>,
}

impl HeaderChain {
    /// Start from a trusted genesis header (its validity is assumed — this is
    /// the light client's trust root / weak-subjectivity checkpoint).
    pub(crate) fn genesis(header: &ForeignHeader) -> Self {
        let mut event_roots = BTreeMap::new();
        event_roots.insert(header.height, header.event_root);
        Self {
            tip_height: header.height,
            tip_hash: header.hash(),
            event_roots,
        }
    }

    /// Check that `header` cleanly extends the current tip.
    pub(crate) fn check_link(&self, header: &ForeignHeader) -> Result<(), InteropError> {
        if header.height != self.tip_height + 1 {
            return Err(InteropError::NonContiguousHeight {
                expected: self.tip_height + 1,
                got: header.height,
            });
        }
        if header.parent != self.tip_hash {
            return Err(InteropError::BrokenLink {
                expected_parent: self.tip_hash,
                got: header.parent,
            });
        }
        Ok(())
    }

    /// Adopt a header that has already passed linkage and consensus checks.
    pub(crate) fn append(&mut self, header: &ForeignHeader) {
        self.tip_height = header.height;
        self.tip_hash = header.hash();
        self.event_roots.insert(header.height, header.event_root);
    }

    pub(crate) fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// Verify an event inclusion proof against the stored event root.
    pub(crate) fn verify_event(
        &self,
        event_hash: Hash,
        proof: &EventProof,
    ) -> Result<(), InteropError> {
        let root =
            self.event_roots
                .get(&proof.header_height)
                .ok_or(InteropError::UnknownHeader {
                    height: proof.header_height,
                })?;
        let ok = merkle::verify(
            root,
            &event_hash,
            proof.leaf_index,
            proof.leaf_count,
            &proof.merkle,
        );
        if ok {
            Ok(())
        } else {
            Err(InteropError::EventNotIncluded)
        }
    }
}
