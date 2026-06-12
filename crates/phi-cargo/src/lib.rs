//! Cargo: Phi's guard sub-protocol.
//!
//! Cargo governs **figs** — the native asset units of Phi — and hardens the
//! protocol's outer surfaces with layered, deterministic defenses:
//!
//! 1. **Issuance governance** ([`FigGovernor`]): only the designated minter
//!    account may create figs, within a per-block cap. Edge nodes screen
//!    submissions ([`FigGovernor::screen_tx`]); validators enforce the same
//!    rules when voting ([`FigGovernor::audit_block`]), so an exploit the
//!    bare state machine would accept still cannot reach quorum.
//! 2. **Supply invariant tripwire**: the block audit recomputes the expected
//!    fig supply (pre-supply + authorized issuance) and refuses any block
//!    whose post-state conjures or destroys figs — catching whole classes of
//!    execution bugs and exploits, not just known ones.
//! 3. **Brute-force throttling** ([`Throttle`]): per-peer exponential
//!    cooldowns on repeated authentication failures, so forged-signature
//!    probing and credential-guessing spam is cut off at the admission edge
//!    before it costs verification work. Keyed by the *submitting peer*,
//!    never by the claimed sender — an attacker spraying forged transactions
//!    must not be able to lock the victim out of their own account.
//!
//! Scope, stated honestly: brute-forcing Ed25519 keys is computationally
//! infeasible with or without Cargo; what the throttle removes is the cheap
//! spam/probe surface, and what the audits provide are invariant tripwires
//! validators enforce before voting. Cargo is defense in depth, not a
//! substitute for the cryptography underneath it.

use std::collections::HashMap;

use phi_state::{Receipt, State, TxError};
use phi_types::{AccountId, Hash, Transaction, TransactionKind};

/// Why the guard refused a submission at the admission edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardError {
    /// The submitting peer is in an auth-failure cooldown window.
    CoolingDown { until_ms: u64 },
    /// A mint from an account that is not the authorized minter.
    UnauthorizedMint { sender: AccountId },
    /// A mint larger than the per-block issuance cap.
    MintCapExceeded { requested: u64, cap: u64 },
}

/// Why a validator's block audit failed (the block must not be voted for).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditViolation {
    /// A successful mint by an account that is not the authorized minter.
    UnauthorizedMint { tx_id: Hash },
    /// Successful mints in this block exceed the per-block issuance cap.
    MintCapExceeded { minted: u64, cap: u64 },
    /// Post-state fig supply differs from pre-supply + authorized issuance:
    /// somewhere, figs were conjured or destroyed.
    SupplyMismatch { expected: u128, actual: u128 },
}

/// Issuance policy for figs. The default freezes issuance entirely.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FigGovernor {
    /// The only account allowed to mint figs (`None` = issuance frozen).
    pub minter: Option<AccountId>,
    /// Upper bound on figs minted per block.
    pub max_mint_per_block: u64,
}

impl FigGovernor {
    /// Edge-node screening: refuse obviously unauthorized issuance before it
    /// occupies mempool space. Transfers are never screened — moving one's
    /// own figs is not governed, only creating new ones.
    pub fn screen_tx(&self, tx: &Transaction) -> Result<(), GuardError> {
        let TransactionKind::Mint { amount, .. } = &tx.kind else {
            return Ok(());
        };
        if self.minter != Some(tx.sender) {
            return Err(GuardError::UnauthorizedMint { sender: tx.sender });
        }
        if *amount > self.max_mint_per_block {
            return Err(GuardError::MintCapExceeded {
                requested: *amount,
                cap: self.max_mint_per_block,
            });
        }
        Ok(())
    }

    /// Validator-side audit, run against a proposal before voting:
    /// every *successful* mint must come from the authorized minter and fit
    /// the per-block cap, and the supply delta must equal authorized
    /// issuance exactly. `txs` and `receipts` must correspond pairwise (both
    /// come from the validator's own re-execution).
    pub fn audit_block(
        &self,
        pre_supply: u128,
        post_supply: u128,
        txs: &[Transaction],
        receipts: &[Receipt],
    ) -> Result<(), AuditViolation> {
        let mut minted: u64 = 0;
        for (tx, receipt) in txs.iter().zip(receipts) {
            let TransactionKind::Mint { amount, .. } = &tx.kind else {
                continue;
            };
            if receipt.result.is_err() {
                continue; // failed mints created nothing
            }
            if self.minter != Some(tx.sender) {
                return Err(AuditViolation::UnauthorizedMint { tx_id: tx.id() });
            }
            minted = minted.saturating_add(*amount);
        }
        if minted > self.max_mint_per_block {
            return Err(AuditViolation::MintCapExceeded {
                minted,
                cap: self.max_mint_per_block,
            });
        }
        let expected = pre_supply + minted as u128;
        if expected != post_supply {
            return Err(AuditViolation::SupplyMismatch {
                expected,
                actual: post_supply,
            });
        }
        Ok(())
    }

    /// Convenience: audit a proposal by re-executing it on a scratch copy of
    /// `pre_state` (callers that already re-executed should use
    /// [`FigGovernor::audit_block`] directly with their own receipts).
    pub fn audit_executed(
        &self,
        pre_state: &State,
        post_state: &State,
        txs: &[Transaction],
        receipts: &[Receipt],
    ) -> Result<(), AuditViolation> {
        self.audit_block(
            pre_state.total_supply(),
            post_state.total_supply(),
            txs,
            receipts,
        )
    }
}

/// Identity of a submitting peer at the admission edge (network identity,
/// not an on-chain account — see module docs on why throttling must never
/// key on the claimed sender).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PeerId(pub [u8; 32]);

impl PeerId {
    /// Deterministic peer id from a label (test/simulation helper; real
    /// edges derive this from the transport identity).
    pub fn from_label(label: &str) -> Self {
        PeerId(*Hash::of_tagged(b"phi:peer", &[label.as_bytes()]).as_bytes())
    }
}

/// Throttle configuration. Failures up to `free_failures` are tolerated
/// (legitimate users fat-finger things); each failure beyond that doubles
/// the cooldown, capped at `max_cooldown_ms`.
#[derive(Clone, Copy, Debug)]
pub struct ThrottleConfig {
    pub free_failures: u32,
    pub base_cooldown_ms: u64,
    pub max_cooldown_ms: u64,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            free_failures: 3,
            base_cooldown_ms: 1_000,
            max_cooldown_ms: 3_600_000, // 1h ceiling
        }
    }
}

#[derive(Clone, Copy, Default)]
struct PeerRecord {
    consecutive_failures: u32,
    cooldown_until_ms: u64,
}

/// Per-peer exponential-backoff throttle on authentication failures.
/// Deterministic: time is supplied by the caller, so simulations and tests
/// replay exactly.
pub struct Throttle {
    config: ThrottleConfig,
    peers: HashMap<PeerId, PeerRecord>,
}

impl Throttle {
    pub fn new(config: ThrottleConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// Gate a submission from `peer` at time `now_ms`. Call before doing any
    /// signature or stateful work.
    pub fn check(&self, peer: &PeerId, now_ms: u64) -> Result<(), GuardError> {
        match self.peers.get(peer) {
            Some(record) if record.cooldown_until_ms > now_ms => Err(GuardError::CoolingDown {
                until_ms: record.cooldown_until_ms,
            }),
            _ => Ok(()),
        }
    }

    /// Record an authentication failure (e.g. `TxError::AuthFailed` or
    /// `RevealMismatch` at admission) from `peer`.
    pub fn record_failure(&mut self, peer: PeerId, now_ms: u64) {
        let record = self.peers.entry(peer).or_default();
        record.consecutive_failures += 1;
        if record.consecutive_failures > self.config.free_failures {
            let exponent = record.consecutive_failures - self.config.free_failures - 1;
            let cooldown = self
                .config
                .base_cooldown_ms
                .saturating_shl(exponent)
                .min(self.config.max_cooldown_ms);
            record.cooldown_until_ms = now_ms.saturating_add(cooldown);
        }
    }

    /// Record a successful authenticated submission: the peer's failure
    /// streak resets.
    pub fn record_success(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }

    /// True when this admission error should count against the submitting
    /// peer's failure budget (authentication-shaped failures only — an
    /// honest user's insufficient balance is not a probe).
    pub fn counts_as_auth_failure(error: &TxError) -> bool {
        matches!(error, TxError::AuthFailed | TxError::RevealMismatch)
    }
}

trait SaturatingShl {
    fn saturating_shl(self, exponent: u32) -> Self;
}

impl SaturatingShl for u64 {
    fn saturating_shl(self, exponent: u32) -> Self {
        if exponent >= u64::BITS || self.leading_zeros() < exponent {
            u64::MAX
        } else {
            self << exponent
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phi_types::AccountId;

    fn id(label: &str) -> AccountId {
        AccountId::from_label(label)
    }

    fn config() -> ThrottleConfig {
        ThrottleConfig {
            free_failures: 2,
            base_cooldown_ms: 100,
            max_cooldown_ms: 1_000,
        }
    }

    #[test]
    fn throttle_tolerates_free_failures_then_backs_off_exponentially() {
        let peer = PeerId::from_label("eve");
        let mut throttle = Throttle::new(config());

        // Two free failures: still admitted.
        throttle.record_failure(peer, 0);
        throttle.record_failure(peer, 0);
        assert_eq!(throttle.check(&peer, 0), Ok(()));

        // Third failure: 100ms cooldown.
        throttle.record_failure(peer, 0);
        assert_eq!(
            throttle.check(&peer, 50),
            Err(GuardError::CoolingDown { until_ms: 100 })
        );
        assert_eq!(throttle.check(&peer, 100), Ok(()));

        // Fourth and fifth failures: 200ms, then 400ms.
        throttle.record_failure(peer, 100);
        assert_eq!(
            throttle.check(&peer, 250),
            Err(GuardError::CoolingDown { until_ms: 300 })
        );
        throttle.record_failure(peer, 300);
        assert_eq!(
            throttle.check(&peer, 600),
            Err(GuardError::CoolingDown { until_ms: 700 })
        );
    }

    #[test]
    fn throttle_caps_cooldown_and_resets_on_success() {
        let peer = PeerId::from_label("eve");
        let mut throttle = Throttle::new(config());
        for t in 0..40 {
            throttle.record_failure(peer, t);
        }
        // Capped at max_cooldown_ms past the last failure, not 2^37 ms.
        assert_eq!(
            throttle.check(&peer, 40),
            Err(GuardError::CoolingDown {
                until_ms: 39 + 1_000
            })
        );

        throttle.record_success(&peer);
        assert_eq!(throttle.check(&peer, 40), Ok(()));
    }

    #[test]
    fn throttle_is_per_peer_so_victims_are_never_locked_out() {
        let attacker = PeerId::from_label("eve");
        let victim = PeerId::from_label("bob");
        let mut throttle = Throttle::new(config());
        for _ in 0..10 {
            throttle.record_failure(attacker, 0);
        }
        assert!(throttle.check(&attacker, 0).is_err());
        assert_eq!(throttle.check(&victim, 0), Ok(()));
    }

    #[test]
    fn shift_saturates() {
        assert_eq!(u64::MAX.saturating_shl(1), u64::MAX);
        assert_eq!(1u64.saturating_shl(63), 1 << 63);
        assert_eq!(1u64.saturating_shl(64), u64::MAX);
        assert_eq!(2u64.saturating_shl(63), u64::MAX);
    }

    #[test]
    fn screen_rejects_unauthorized_or_oversized_mints() {
        let governor = FigGovernor {
            minter: Some(id("treasury")),
            max_mint_per_block: 100,
        };
        assert_eq!(
            governor.screen_tx(&Transaction::transfer(id("eve"), 0, id("eve"), 1_000)),
            Ok(())
        );
        assert_eq!(
            governor.screen_tx(&Transaction::mint(id("eve"), 0, id("eve"), 10)),
            Err(GuardError::UnauthorizedMint { sender: id("eve") })
        );
        assert_eq!(
            governor.screen_tx(&Transaction::mint(id("treasury"), 0, id("eve"), 500)),
            Err(GuardError::MintCapExceeded {
                requested: 500,
                cap: 100
            })
        );
        assert_eq!(
            governor.screen_tx(&Transaction::mint(id("treasury"), 0, id("eve"), 100)),
            Ok(())
        );
        // The default governor freezes issuance entirely.
        assert!(FigGovernor::default()
            .screen_tx(&Transaction::mint(id("treasury"), 0, id("eve"), 1))
            .is_err());
    }

    /// Execute `txs` serially and audit the block with `governor`.
    fn run_audit(
        governor: &FigGovernor,
        state: &mut State,
        txs: &[Transaction],
    ) -> Result<(), AuditViolation> {
        let pre = state.total_supply();
        let receipts: Vec<Receipt> = txs.iter().map(|tx| state.apply_tx(tx)).collect();
        governor.audit_block(pre, state.total_supply(), txs, &receipts)
    }

    #[test]
    fn audit_passes_transfer_blocks_and_authorized_mints() {
        let mut state = State::new();
        state.genesis_account(id("treasury"), 0);
        state.genesis_account(id("alice"), 100);
        let governor = FigGovernor {
            minter: Some(id("treasury")),
            max_mint_per_block: 1_000,
        };
        let txs = vec![
            Transaction::transfer(id("alice"), 0, id("bob"), 30),
            Transaction::mint(id("treasury"), 0, id("alice"), 500),
        ];
        assert_eq!(run_audit(&governor, &mut state, &txs), Ok(()));
        assert_eq!(state.total_supply(), 600);
    }

    #[test]
    fn audit_catches_unauthorized_mint_the_state_machine_accepts() {
        // The bare state machine happily lets eve mint to herself — exactly
        // the hole Cargo closes at the voting stage.
        let mut state = State::new();
        state.genesis_account(id("eve"), 5);
        let txs = vec![Transaction::mint(id("eve"), 0, id("eve"), 1_000_000)];
        let outcome = run_audit(&FigGovernor::default(), &mut state, &txs);
        assert!(matches!(
            outcome,
            Err(AuditViolation::UnauthorizedMint { .. })
        ));
    }

    #[test]
    fn audit_ignores_failed_mints_but_enforces_the_block_cap() {
        let mut state = State::new();
        state.genesis_account(id("treasury"), 0);
        let governor = FigGovernor {
            minter: Some(id("treasury")),
            max_mint_per_block: 100,
        };
        // A mint with a bad nonce fails and creates nothing: not issuance.
        let failed = vec![Transaction::mint(id("treasury"), 99, id("alice"), 50)];
        assert_eq!(run_audit(&governor, &mut state, &failed), Ok(()));

        // Two successful mints summing over the cap are refused.
        let over_cap = vec![
            Transaction::mint(id("treasury"), 0, id("alice"), 60),
            Transaction::mint(id("treasury"), 1, id("bob"), 60),
        ];
        assert_eq!(
            run_audit(&governor, &mut state, &over_cap),
            Err(AuditViolation::MintCapExceeded {
                minted: 120,
                cap: 100
            })
        );
    }

    #[test]
    fn audit_trips_on_any_supply_mismatch() {
        // Simulates an execution exploit that conjures figs out of thin air:
        // the audit's recomputed expectation must catch it regardless of how
        // the figs appeared.
        let governor = FigGovernor::default();
        let outcome = governor.audit_block(1_000, 1_500, &[], &[]);
        assert_eq!(
            outcome,
            Err(AuditViolation::SupplyMismatch {
                expected: 1_000,
                actual: 1_500
            })
        );
        assert_eq!(governor.audit_block(1_000, 1_000, &[], &[]), Ok(()));
    }
}
