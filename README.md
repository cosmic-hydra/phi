# NexChain

A from-scratch design for a modular, agent-centric blockchain protocol aimed
at powering a decentralized web — plus a working Rust implementation with a
local consensus + transaction-processing simulation.

## Documentation

| Document | Contents |
|---|---|
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Full protocol spec: vision, architecture diagram, consensus (NexBFT), NexVM, state model, native account abstraction, fees, tokenomics, governance, privacy, interoperability, security model, and how each of the 10 major Web3 issues is patched |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Language choices, full codebase layout, core modules, data flow diagrams, concurrency and testing strategy |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased implementation plan, milestones, risks and mitigations |

## Repository Layout

```
crates/
├── nex-crypto/     # Ed25519 keys & signatures behind protocol newtypes
├── nex-types/      # core types: tagged hashing, hardened Merkle trees with
│                   # inclusion proofs, auth-bound accounts, signed transactions
├── nex-state/      # deterministic state machine committed by a real Sparse
│                   # Merkle Tree (inclusion AND exclusion proofs)
├── nex-executor/   # parallel executor: conflict-wave scheduling over declared
│                   # access sets, property-tested equal to serial execution
├── nex-mempool/    # admission control: signature pre-validation, nonce/balance
│                   # projection, free-lane quotas, requeue on failed rounds
├── nex-consensus/  # BFT-shaped consensus: signed votes, verifiable quorum
│                   # certificates, view change, Byzantine validator simulation
└── nex-sim/        # local simulation binary demonstrating the full pipeline
```

This is the Phase 1a vertical slice from the roadmap plus the first Phase 1b
milestones (validator keys, signature verification): networking, pipelined
HotStuff with VRF sortition, persistence, and NexVM replace the remaining
stubs in later phases without changing module boundaries.

## Quickstart

Requires a recent Rust toolchain (`rustup`).

```bash
# Run the local simulation: genesis → mempool admission → BFT rounds
# (including a Byzantine proposer) → light-client audit
cargo run -p nex-sim

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
7. A light-client audit: quorum-certificate verification for the whole chain,
   a Merkle transaction inclusion proof, and SMT inclusion/exclusion proofs
   for accounts.
8. Byte-identical state roots across validators, supply conservation, and a
   serial replay that matches the parallel executor exactly.

## License

MIT OR Apache-2.0
