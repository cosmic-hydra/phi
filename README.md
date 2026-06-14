# Phi

A from-scratch design for a modular, agent-centric blockchain protocol aimed
at powering a decentralized web — plus a working Rust implementation with a
local consensus + transaction-processing simulation.

## Documentation

| Document | Contents |
|---|---|
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Full protocol spec: vision, architecture diagram, consensus (PhiBFT), PhiVM, state model, native account abstraction, fees, tokenomics, governance, privacy, interoperability, security model, and how each of the 10 major Web3 issues is patched |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Language choices, full codebase layout, core modules, data flow diagrams, concurrency and testing strategy |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased implementation plan, milestones, risks and mitigations |

## Repository Layout

```
crates/
├── phi-crypto/     # Ed25519 keys & signatures behind protocol newtypes
├── phi-types/      # core types: tagged hashing, hardened Merkle trees with
│                   # inclusion proofs, auth-bound accounts, signed transactions
│                   # carrying fee caps and optional sponsors
├── phi-state/      # deterministic state machine committed by a real Sparse
│                   # Merkle Tree (inclusion AND exclusion proofs), with an
│                   # EIP-1559-style burned base fee and native fee sponsorship
├── phi-cargo/      # Cargo guard sub-protocol: fig issuance governance, supply
│                   # invariant audits (reconciling burned fees), per-peer
│                   # brute-force throttling
├── phi-executor/   # parallel executor: conflict-wave scheduling over declared
│                   # access sets, property-tested equal to serial execution
├── phi-mempool/    # admission control: signature pre-validation, nonce/balance
│                   # projection, free-lane quotas, fee-priority standard lane,
│                   # requeue on failed rounds
├── phi-consensus/  # BFT-shaped consensus: view-scoped signed votes, verifiable
│                   # quorum certificates, view change, Byzantine simulation, and
│                   # provable equivocation (double-sign) slashing evidence
└── phi-sim/        # local simulation binary demonstrating the full pipeline
```

This is the Phase 1a vertical slice from the roadmap plus the first Phase 1b
milestones (validator keys, signature verification, view-bound votes with
equivocation evidence, a burned base fee with native sponsorship): real
networking, pipelined HotStuff with VRF sortition, persistence, stake-weighted
slashing, and PhiVM replace the remaining stubs in later phases without
changing module boundaries.

## Quickstart

Requires a recent Rust toolchain (`rustup`).

```bash
# Run the local simulation: genesis → mempool admission → BFT rounds
# (including a Byzantine proposer) → light-client audit
cargo run -p phi-sim

# Run the test suite
cargo test --workspace
```

The simulation demonstrates:

1. Genesis accounts whose **ids commit to real Ed25519 auth policies**
   (single-key and 2-of-3 threshold), under an SMT state root.
2. Mempool admission: signature pre-validation, nonce *and balance*
   projection across queued transactions, free-lane quotas, duplicate
   rejection.
3. Consensus rounds with **signed votes and verifiable quorum certificates**:
   a rotating proposer builds blocks, every validator independently
   re-executes with the parallel executor and only votes for correct
   transaction/state/receipts roots; >2/3 quorum commits.
4. A **Byzantine proposer** whose corrupted block is outvoted, followed by a
   view change — the batch is re-queued, never lost.
5. **First-spend account claiming**: funds sent to a fresh id are spendable
   only by revealing the auth policy the id commits to.
6. Execution **receipts committed in block headers**, including an in-block
   runtime failure recorded identically by every validator.
7. The **Cargo guard sub-protocol** governing figs (the native asset):
   per-peer exponential throttling cuts brute-force probing off at the
   admission edge, and an issuance audit refuses quorum to any block that
   mints without authority or breaks supply conservation — even when the
   bare state machine would accept it.
8. A light-client audit: quorum-certificate verification for the whole chain,
   a Merkle transaction inclusion proof, and SMT inclusion/exclusion proofs
   for accounts.
9. Byte-identical state roots across validators, audited supply, and a
   serial replay that matches the parallel executor exactly.
10. **Provable slashing**: validator votes are bound to their consensus view,
    so a Byzantine validator that double-signs (equivocates) produces
    cryptographic evidence any light client can verify against the validator
    set — caught here from a single gossiped conflicting vote.
11. A **burned base fee** (EIP-1559 style) with **native fee sponsorship**: a
    sponsor can pay a transaction's fee so the sender spends its full balance.
    Burning keeps execution parallel (no account every transaction must
    write), and the Cargo supply audit reconciles it (`post = pre + minted -
    burned`), refusing any block that leaks figs.
12. A **fee-priority standard lane** in the mempool: the highest tip is
    included first while every sender's transactions stay in strict nonce
    order, turning `max_fee` into inclusion priority under congestion.

## Security

The base ledger enforces issuance authority, `chain_id` replay protection,
bounded transaction sizes, checked arithmetic, a burned base fee reconciled by
the Cargo supply audit, and signed/quorum-verified consensus with view-bound
votes and verifiable equivocation evidence — each backed by tests. None of
this makes Phi "unhackable."
[SECURITY.md](SECURITY.md) is the honest threat model: what is enforced today,
and the substantial surface (real networking, stake-weighted slashing, key
management, audits, formal verification) a production deployment still
requires.

## License

MIT OR Apache-2.0
