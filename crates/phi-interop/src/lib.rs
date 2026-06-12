//! Phi interoperability: trust-minimized cross-chain verification.
//!
//! Phi connects to other chains the way the spec demands (docs/SPECIFICATION.md
//! §11): **no multisig bridges**. Instead, Phi runs a *light client* of each
//! foreign chain and verifies that chain's own consensus, so a cross-chain
//! transfer is accepted only against a cryptographic proof a relayer cannot
//! forge. Multisig bridges — where a privileged signer set can simply assert
//! "this happened" — are the single largest source of losses in Web3; this
//! crate is the structural answer.
//!
//! ## What's here
//!
//! - A [`LightClient`] trait and two genuinely different reference adapters,
//!   showing the abstraction is real rather than chain-specific:
//!   - [`PowLightClient`] — proof-of-work SPV header verification
//!     (Bitcoin-style).
//!   - [`BftLightClient`] — validator-set quorum-signature verification
//!     (Tendermint / Cosmos / Solana-style).
//! - A [`BridgeHub`] that verifies foreign lock events against the right light
//!   client and releases figs from a pre-funded reserve (so total supply is
//!   conserved and the Cargo issuance audit is untouched), with monotonic
//!   replay protection in both directions.
//!
//! ## Adding a chain (and the honest limit)
//!
//! Supporting a new chain means implementing [`LightClient`] for its consensus
//! rules — there is no automatic "works with every blockchain" switch, because
//! each chain's finality is different. The two adapters here cover the two
//! dominant families (Nakamoto PoW and BFT validator sets); a specific chain
//! needs an adapter encoding its exact header format and rules. Out of scope
//! for this slice, and not to be relied upon: ZK-SNARK proof aggregation
//! (Phase 3), validator-set rotation / weak-subjectivity windows, PoW
//! retargeting and most-work fork choice, and the foreign-side contracts that
//! honor [`ReleaseInstruction`]s. See SECURITY.md.

mod bft;
mod bridge;
mod light_client;
mod pow;

pub use bft::BftLightClient;
pub use bridge::{BridgeHub, ReleaseInstruction};
pub use light_client::{
    ConsensusProof, CrossChainEvent, EventProof, ForeignChainId, ForeignHeader, InteropError,
    LightClient, SignerVote,
};
pub use pow::PowLightClient;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use phi_crypto::{Keypair, PublicKey};
    use phi_types::{merkle, AccountId, Hash};

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

    /// A relayer round trip across two foreign chains of different consensus
    /// families into one Phi bridge, ending in Phi-applicable transfers.
    #[test]
    fn two_chain_families_bridge_into_phi() {
        let phi_chain_id = 1;
        let mut hub = BridgeHub::new(phi_chain_id, Keypair::from_label("reserve"));

        // Foreign chain A: proof of work (Bitcoin-style).
        let btc = ForeignChainId(0xB7C);
        let pow = PowLightClient::new(&foreign_genesis(), easy_target());
        // Foreign chain B: BFT validator set (Cosmos/Solana-style).
        let cosmos = ForeignChainId(0xC05);
        let vs: Vec<Keypair> = (0..4)
            .map(|i| Keypair::from_label(&format!("val-{i}")))
            .collect();
        let keys: Vec<PublicKey> = vs.iter().map(|k| k.public()).collect();
        let bft = BftLightClient::new(&foreign_genesis(), keys, 3);

        // Build each chain's block-1 committing one lock event.
        let btc_event = CrossChainEvent {
            foreign_chain: btc,
            sequence: 0,
            beneficiary: AccountId::from_label("alice"),
            amount: 500,
        };
        let cosmos_event = CrossChainEvent {
            foreign_chain: cosmos,
            sequence: 0,
            beneficiary: AccountId::from_label("bob"),
            amount: 300,
        };

        let btc_leaves = vec![btc_event.hash()];
        let btc_header = pow.mine(ForeignHeader {
            height: 1,
            parent: foreign_genesis().hash(),
            event_root: merkle::root(&btc_leaves),
            nonce: 0,
        });
        let cosmos_leaves = vec![cosmos_event.hash()];
        let cosmos_header = ForeignHeader {
            height: 1,
            parent: foreign_genesis().hash(),
            event_root: merkle::root(&cosmos_leaves),
            nonce: 0,
        };
        let cosmos_votes = (0..3)
            .map(|i| SignerVote {
                signer: i,
                signature: vs[i as usize].sign(cosmos_header.hash().as_bytes()),
            })
            .collect();

        hub.register_chain(btc, pow).unwrap();
        hub.register_chain(cosmos, bft).unwrap();
        hub.submit_foreign_header(btc, &btc_header, &ConsensusProof::Pow)
            .unwrap();
        hub.submit_foreign_header(
            cosmos,
            &cosmos_header,
            &ConsensusProof::Bft {
                votes: cosmos_votes,
            },
        )
        .unwrap();
        assert_eq!(hub.tip_height(btc).unwrap(), 1);
        assert_eq!(hub.tip_height(cosmos).unwrap(), 1);

        let btc_proof = EventProof {
            header_height: 1,
            leaf_index: 0,
            leaf_count: 1,
            merkle: merkle::prove(&btc_leaves, 0).unwrap(),
        };
        let cosmos_proof = EventProof {
            header_height: 1,
            leaf_index: 0,
            leaf_count: 1,
            merkle: merkle::prove(&cosmos_leaves, 0).unwrap(),
        };

        // Reserve account redeems both, with its own nonce advancing.
        let tx_a = hub.prepare_redemption(&btc_event, &btc_proof, 0).unwrap();
        let tx_b = hub
            .prepare_redemption(&cosmos_event, &cosmos_proof, 1)
            .unwrap();
        assert_eq!(tx_a.sender, hub.reserve_account());
        assert_eq!(tx_b.sender, hub.reserve_account());

        // Outbound: alice sends 120 figs back out to chain A.
        let release = hub.export(btc, [0x11; 32], 120).unwrap();
        assert_eq!(release.outbound_sequence, 0);
        assert_eq!(release.amount, 120);
    }
}
