//! Trust-minimized asset bridge built on the light clients.
//!
//! Inbound (lock → release): a foreign chain locks an asset and commits a
//! [`CrossChainEvent`]. A relayer submits the foreign headers and an
//! inclusion proof; the bridge verifies the event against the foreign chain's
//! own consensus (no trusted signer set) and, once, releases the matching
//! amount from a pre-funded **reserve account** to the beneficiary. Using a
//! reserve (rather than minting) keeps total fig supply constant, so the Cargo
//! issuance audit is unaffected — the bridge moves figs, it does not create
//! them.
//!
//! Outbound (burn → release): a user transfers figs into the reserve on Phi;
//! the bridge emits a sequenced [`ReleaseInstruction`] the foreign chain's
//! contract honors.
//!
//! Replay is prevented on both directions by monotonic sequences: inbound by
//! recording redeemed foreign sequences, outbound by a strictly increasing
//! counter the foreign side tracks.

use std::collections::{BTreeMap, BTreeSet};

use phi_crypto::Keypair;
use phi_types::{AccountId, AuthPolicy, Transaction};

use crate::light_client::{
    ConsensusProof, CrossChainEvent, EventProof, ForeignChainId, ForeignHeader, InteropError,
    LightClient,
};

/// An instruction for a foreign chain to release `amount` to
/// `foreign_beneficiary`, in response to figs locked into the reserve on Phi.
/// `outbound_sequence` is strictly increasing per foreign chain; the foreign
/// contract must honor each sequence at most once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseInstruction {
    pub foreign_chain: ForeignChainId,
    pub outbound_sequence: u64,
    pub foreign_beneficiary: [u8; 32],
    pub amount: u64,
}

/// The bridge: a registry of foreign light clients plus the Phi-side reserve
/// account that backs wrapped balances.
pub struct BridgeHub {
    phi_chain_id: u64,
    reserve_keypair: Keypair,
    reserve_account: AccountId,
    clients: BTreeMap<ForeignChainId, Box<dyn LightClient>>,
    /// Redeemed inbound sequences per foreign chain (replay protection).
    redeemed: BTreeMap<ForeignChainId, BTreeSet<u64>>,
    /// Next outbound sequence per foreign chain.
    outbound_seq: BTreeMap<ForeignChainId, u64>,
}

impl BridgeHub {
    /// Create a bridge whose reserve is controlled by `reserve_keypair` on the
    /// Phi network `phi_chain_id`. The reserve account id is derived from the
    /// key's single-key auth policy; fund it at genesis up to the wrapped-asset
    /// ceiling.
    pub fn new(phi_chain_id: u64, reserve_keypair: Keypair) -> Self {
        let reserve_account =
            AccountId::from_auth(&AuthPolicy::SingleKey(reserve_keypair.public()), 0);
        Self {
            phi_chain_id,
            reserve_keypair,
            reserve_account,
            clients: BTreeMap::new(),
            redeemed: BTreeMap::new(),
            outbound_seq: BTreeMap::new(),
        }
    }

    /// The reserve account id (fund this at genesis; its auth policy is
    /// `SingleKey` over the reserve key).
    pub fn reserve_account(&self) -> AccountId {
        self.reserve_account
    }

    /// Register a foreign chain's light client. Fails if one already exists.
    pub fn register_chain<C: LightClient + 'static>(
        &mut self,
        id: ForeignChainId,
        client: C,
    ) -> Result<(), InteropError> {
        if self.clients.contains_key(&id) {
            return Err(InteropError::ChainAlreadyRegistered);
        }
        self.clients.insert(id, Box::new(client));
        self.redeemed.entry(id).or_default();
        self.outbound_seq.entry(id).or_default();
        Ok(())
    }

    /// Forward a foreign header to its light client for verification.
    pub fn submit_foreign_header(
        &mut self,
        id: ForeignChainId,
        header: &ForeignHeader,
        proof: &ConsensusProof,
    ) -> Result<(), InteropError> {
        self.clients
            .get_mut(&id)
            .ok_or(InteropError::UnknownChain)?
            .submit_header(header, proof)
    }

    /// Trusted tip height of a registered foreign chain.
    pub fn tip_height(&self, id: ForeignChainId) -> Result<u64, InteropError> {
        Ok(self
            .clients
            .get(&id)
            .ok_or(InteropError::UnknownChain)?
            .tip_height())
    }

    /// Verify a foreign lock event and produce the signed Phi transfer that
    /// releases the matching amount from the reserve to the beneficiary.
    ///
    /// `reserve_nonce` is the reserve account's current nonce (the caller
    /// applies the returned transaction). Verifying and recording the event
    /// here makes a second redemption of the same `sequence` fail, so a
    /// relayer cannot double-spend a single foreign lock.
    pub fn redeem(
        &mut self,
        event: &CrossChainEvent,
        proof: &EventProof,
        reserve_nonce: u64,
    ) -> Result<Transaction, InteropError> {
        let client = self
            .clients
            .get(&event.foreign_chain)
            .ok_or(InteropError::UnknownChain)?;
        client.verify_event(event.hash(), proof)?;

        let seen = self.redeemed.entry(event.foreign_chain).or_default();
        if seen.contains(&event.sequence) {
            return Err(InteropError::AlreadyProcessed {
                sequence: event.sequence,
            });
        }
        seen.insert(event.sequence);

        Ok(Transaction::transfer(
            self.reserve_account,
            reserve_nonce,
            event.beneficiary,
            event.amount,
        )
        .with_chain_id(self.phi_chain_id)
        .signed(&self.reserve_keypair))
    }

    /// Emit a release instruction for the foreign chain after the caller has
    /// moved `amount` figs into the reserve on Phi (a normal transfer the
    /// caller verifies committed). Sequencing is monotonic per chain.
    pub fn export(
        &mut self,
        foreign_chain: ForeignChainId,
        foreign_beneficiary: [u8; 32],
        amount: u64,
    ) -> Result<ReleaseInstruction, InteropError> {
        if !self.clients.contains_key(&foreign_chain) {
            return Err(InteropError::UnknownChain);
        }
        let seq = self.outbound_seq.entry(foreign_chain).or_default();
        let outbound_sequence = *seq;
        *seq += 1;
        Ok(ReleaseInstruction {
            foreign_chain,
            outbound_sequence,
            foreign_beneficiary,
            amount,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phi_crypto::PublicKey;
    use phi_types::{merkle, Hash};

    use crate::bft::BftLightClient;
    use crate::pow::PowLightClient;

    fn easy_target() -> [u8; 32] {
        let mut t = [0xffu8; 32];
        t[0] = 0x00;
        t
    }

    fn foreign_genesis() -> ForeignHeader {
        ForeignHeader {
            height: 0,
            parent: Hash::ZERO,
            event_root: merkle::root(&[]),
            nonce: 0,
        }
    }

    /// Build a foreign block committing `events`, plus inclusion proofs.
    fn block_with_events(
        parent: &ForeignHeader,
        events: &[CrossChainEvent],
    ) -> (ForeignHeader, Vec<EventProof>) {
        let leaves: Vec<Hash> = events.iter().map(CrossChainEvent::hash).collect();
        let header = ForeignHeader {
            height: parent.height + 1,
            parent: parent.hash(),
            event_root: merkle::root(&leaves),
            nonce: 0,
        };
        let proofs = (0..events.len())
            .map(|i| EventProof {
                header_height: header.height,
                leaf_index: i,
                leaf_count: events.len(),
                merkle: merkle::prove(&leaves, i).unwrap(),
            })
            .collect();
        (header, proofs)
    }

    #[test]
    fn pow_inbound_lock_releases_from_reserve_once() {
        let reserve_kp = Keypair::from_label("phi-bridge-reserve");
        let mut hub = BridgeHub::new(1, reserve_kp);
        let chain = ForeignChainId(100);
        let pow = PowLightClient::new(&foreign_genesis(), easy_target());

        let event = CrossChainEvent {
            foreign_chain: chain,
            sequence: 0,
            beneficiary: AccountId::from_label("alice"),
            amount: 250,
        };
        let (header, proofs) = block_with_events(&foreign_genesis(), std::slice::from_ref(&event));
        let mined = pow.mine(header);
        // Recompute the proof against the mined header height (still height 1).
        hub.register_chain(chain, pow).unwrap();
        hub.submit_foreign_header(chain, &mined, &ConsensusProof::Pow)
            .unwrap();

        let tx = hub.redeem(&event, &proofs[0], 0).unwrap();
        // The release is a signed reserve→beneficiary transfer on Phi.
        assert_eq!(tx.sender, hub.reserve_account());
        assert_eq!(tx.chain_id, 1);
        assert!(!tx.signatures.is_empty());
        match tx.kind {
            phi_types::TransactionKind::Transfer { to, amount } => {
                assert_eq!(to, AccountId::from_label("alice"));
                assert_eq!(amount, 250);
            }
            _ => panic!("expected transfer"),
        }

        // Replaying the same foreign lock fails.
        assert_eq!(
            hub.redeem(&event, &proofs[0], 1),
            Err(InteropError::AlreadyProcessed { sequence: 0 })
        );
    }

    #[test]
    fn bft_inbound_lock_verified_against_foreign_validators() {
        let reserve_kp = Keypair::from_label("phi-bridge-reserve");
        let mut hub = BridgeHub::new(9, reserve_kp);
        let chain = ForeignChainId(200);

        let foreign_vs: Vec<Keypair> = (0..4)
            .map(|i| Keypair::from_label(&format!("cosmos-val-{i}")))
            .collect();
        let keys: Vec<PublicKey> = foreign_vs.iter().map(|k| k.public()).collect();
        let bft = BftLightClient::new(&foreign_genesis(), keys, 3);
        hub.register_chain(chain, bft).unwrap();

        let event = CrossChainEvent {
            foreign_chain: chain,
            sequence: 0,
            beneficiary: AccountId::from_label("bob"),
            amount: 77,
        };
        let (header, proofs) = block_with_events(&foreign_genesis(), std::slice::from_ref(&event));
        let msg = header.hash();
        let votes = (0..3)
            .map(|i| crate::light_client::SignerVote {
                signer: i,
                signature: foreign_vs[i as usize].sign(msg.as_bytes()),
            })
            .collect();
        hub.submit_foreign_header(chain, &header, &ConsensusProof::Bft { votes })
            .unwrap();

        let tx = hub.redeem(&event, &proofs[0], 0).unwrap();
        match tx.kind {
            phi_types::TransactionKind::Transfer { amount, .. } => assert_eq!(amount, 77),
            _ => panic!("expected transfer"),
        }
    }

    #[test]
    fn redeeming_an_unincluded_event_fails() {
        let reserve_kp = Keypair::from_label("phi-bridge-reserve");
        let mut hub = BridgeHub::new(1, reserve_kp);
        let chain = ForeignChainId(100);
        let pow = PowLightClient::new(&foreign_genesis(), easy_target());
        hub.register_chain(chain, pow).unwrap();

        // A header committing event A...
        let included = CrossChainEvent {
            foreign_chain: chain,
            sequence: 0,
            beneficiary: AccountId::from_label("alice"),
            amount: 10,
        };
        let (header, proofs) =
            block_with_events(&foreign_genesis(), std::slice::from_ref(&included));
        // Re-mine via a throwaway client to get a valid header.
        let miner = PowLightClient::new(&foreign_genesis(), easy_target());
        let mined = miner.mine(header);
        hub.submit_foreign_header(chain, &mined, &ConsensusProof::Pow)
            .unwrap();

        // ...cannot be used to redeem a different (forged) event with the
        // included event's proof.
        let forged = CrossChainEvent {
            foreign_chain: chain,
            sequence: 0,
            beneficiary: AccountId::from_label("attacker"),
            amount: 1_000_000,
        };
        assert_eq!(
            hub.redeem(&forged, &proofs[0], 0),
            Err(InteropError::EventNotIncluded)
        );
    }

    #[test]
    fn unknown_chain_rejected() {
        let mut hub = BridgeHub::new(1, Keypair::from_label("r"));
        let event = CrossChainEvent {
            foreign_chain: ForeignChainId(404),
            sequence: 0,
            beneficiary: AccountId::from_label("x"),
            amount: 1,
        };
        let proof = EventProof {
            header_height: 1,
            leaf_index: 0,
            leaf_count: 1,
            merkle: merkle::MerkleProof { siblings: vec![] },
        };
        assert_eq!(
            hub.redeem(&event, &proof, 0),
            Err(InteropError::UnknownChain)
        );
        assert_eq!(
            hub.export(ForeignChainId(404), [0u8; 32], 1),
            Err(InteropError::UnknownChain)
        );
    }

    #[test]
    fn outbound_export_sequences_monotonically() {
        let mut hub = BridgeHub::new(1, Keypair::from_label("r"));
        let chain = ForeignChainId(100);
        hub.register_chain(
            chain,
            PowLightClient::new(&foreign_genesis(), easy_target()),
        )
        .unwrap();
        let a = hub.export(chain, [1u8; 32], 5).unwrap();
        let b = hub.export(chain, [2u8; 32], 6).unwrap();
        assert_eq!(a.outbound_sequence, 0);
        assert_eq!(b.outbound_sequence, 1);
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut hub = BridgeHub::new(1, Keypair::from_label("r"));
        let chain = ForeignChainId(100);
        hub.register_chain(
            chain,
            PowLightClient::new(&foreign_genesis(), easy_target()),
        )
        .unwrap();
        assert_eq!(
            hub.register_chain(
                chain,
                PowLightClient::new(&foreign_genesis(), easy_target())
            ),
            Err(InteropError::ChainAlreadyRegistered)
        );
    }
}
