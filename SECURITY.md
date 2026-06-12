# Phi Security Model

This document states, honestly, what the current implementation defends
against and what it does **not**. No software is "unhackable," and this
project does not claim to be. What follows is a concrete threat model and the
specific mitigations in the code, so the guarantees can be checked rather than
trusted.

## What is enforced today (with tests)

| Threat | Mitigation | Where |
|---|---|---|
| **Unauthorized issuance** (minting figs from nothing) | The base ledger rejects any `Mint` not from the configured issuance authority (`TxError::UnauthorizedIssuance`); issuance is frozen by default. The Cargo guard adds a per-block cap and a supply-conservation audit enforced at voting. | `phi-state` `validate`, `phi-cargo` |
| **Cross-chain / cross-instance replay** | Every transaction carries a `chain_id` bound into its id (and thus the signed message); the ledger rejects foreign-chain transactions. Block headers carry a `chain_id` bound into the header hash, so votes and quorum certificates cannot be replayed across networks. | `phi-types`, `phi-state` |
| **Signature forgery / malleability** | Ed25519 with strict verification (rejects malleable encodings and low-order points). Transaction ids exclude signatures, so re-signing cannot change identity. | `phi-crypto`, `phi-types` |
| **Threshold-auth bypass via duplicate keys** | Threshold verification counts *distinct* verified keys; `m = 0` policies never authorize. | `phi-state` `verify_auth` |
| **CPU exhaustion via huge transactions** | Access-set size, signature count, and revealed-key count are bounded as consensus rules, checked before any signature work. | `phi-state::limits` |
| **Memory exhaustion via mempool flooding** | Global pending-capacity bound plus per-sender free-lane quota and balance/nonce projection. | `phi-mempool` |
| **Supply corruption via arithmetic bugs** | Checked arithmetic everywhere; on any invariant violation the node halts (panics) rather than silently wrapping — safety over liveness. Supply is tracked in `u128`. | `phi-state` |
| **Equivocation / forged votes** | Votes are Ed25519-signed; quorum certificates require `> 2/3` *distinct* signers, each signature verified against the validator set. | `phi-consensus` |
| **Byzantine proposer** (corrupt state root, blind votes) | Validators independently re-execute and refuse incorrect roots; a failed round triggers view change and re-queues the batch. | `phi-consensus` |
| **State/ledger transition bugs** | The parallel executor is property- and fuzz-tested to be byte-identical to serial execution; sandboxes inherit consensus config so they cannot diverge. | `phi-executor` |
| **Light-client deception** | Sparse-Merkle-Tree state commitment with inclusion *and* exclusion proofs; Merkle transaction-inclusion proofs; QC chain verification. | `phi-state::smt`, `phi-types::merkle` |
| **Nonce griefing** | Invalid transactions (bad auth/nonce/access/chain/oversize) consume nothing; only genuinely authorized runtime failures consume the nonce. | `phi-state` |
| **Empty/degenerate validator set** | Constructing a consensus engine with zero validators panics rather than producing a chain with no quorum. | `phi-consensus` |
| **Cross-chain bridge forgery / double-redeem** | No multisig bridge: foreign events are verified against the foreign chain's own consensus via a light client (PoW SPV or BFT quorum), plus a Merkle inclusion proof. Redeemed foreign sequences are recorded, so a lock cannot be redeemed twice. The bridge releases from a reserve (never mints), conserving supply. | `phi-interop` |

## What is explicitly NOT yet covered

This is a Phase-1a/1b simulation slice (see `docs/ROADMAP.md`). The following
are designed-for but **not implemented**, and must not be relied on:

- **Real networking and its attacks** (eclipse, partition, gossip-level DoS,
  adaptive-adversary timing). Consensus runs in-process with honest message
  delivery.
- **Slashing** of equivocating/unavailable validators (evidence is not yet
  produced or punished).
- **Pacemaker / liveness under asynchrony** beyond the simple view-change
  shown here.
- **Key management** (HSM/keystore, rotation, forward security). Simulation
  keys are label-derived and deterministic — never use them anywhere real.
- **Long-range / weak-subjectivity attacks**, checkpoint anchoring, and the
  ZK/privacy layers (Phase 3 in the spec).
- **Interop hardening beyond light-client basics**: the `phi-interop` adapters
  do SPV/quorum header verification, but ZK-SNARK aggregation, validator-set
  rotation, PoW retargeting / most-work fork choice, and the foreign-side
  release contracts are not implemented. Do not bridge real value on it.
- **VM-level exploits** — there is no smart-contract VM yet; only fixed
  transfer/mint transaction kinds.
- **Side channels, supply-chain, and dependency vulnerabilities.**

## Honest bottom line

The hardening above closes the concrete, demonstrable vulnerabilities present
in the ledger, mempool, and consensus *shapes* implemented so far, and each is
backed by a test. It does **not** make the system "impossible to hack." A
production deployment would still require: independent audits, a real
networking stack with its own threat model, slashing, formal verification of
the BFT core (the spec calls for TLA+), fuzzing at scale, and a bug-bounty
program. Treat this as a well-tested research implementation, not a hardened
mainnet.

## Reporting

This is a research repository. Open an issue for suspected problems; do not
assume any property holds that is not asserted by a test in the suite.
