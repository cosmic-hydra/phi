# NexChain

A from-scratch design for a modular, agent-centric blockchain protocol aimed
at powering a decentralized web — plus a working Rust starter implementation
with a local consensus + transaction-processing simulation.

## Documentation

| Document | Contents |
|---|---|
| [docs/SPECIFICATION.md](docs/SPECIFICATION.md) | Full protocol spec: vision, architecture diagram, consensus (NexBFT), NexVM, state model, native account abstraction, fees, tokenomics, governance, privacy, interoperability, security model, and how each of the 10 major Web3 issues is patched |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Language choices, full codebase layout, core modules, data flow diagrams, concurrency and testing strategy |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phased implementation plan, milestones, risks and mitigations |

## Starter Repository Layout

```
crates/
├── nex-types/      # core types: hashes, accounts, transactions (with access sets), blocks
├── nex-state/      # deterministic state machine with Merkle state commitment
├── nex-mempool/    # admission control, free-lane quotas, parallel conflict grouping
├── nex-consensus/  # BFT-shaped consensus stub: rotating proposer, re-execution voting, >2/3 quorum
└── nex-sim/        # local simulation binary demonstrating the full pipeline
```

This is the Phase 1a vertical slice from the roadmap: real consensus (pipelined
HotStuff with VRF sortition), networking, NexVM, and the parallel executor
replace the stubs in later phases without changing module boundaries.

## Quickstart

Requires a recent Rust toolchain (`rustup`).

```bash
# Run the local simulation: genesis → mempool admission → BFT rounds → agreed state roots
cargo run -p nex-sim

# Run the test suite
cargo test --workspace
```

The simulation demonstrates:

1. Genesis state with funded accounts and a deterministic state root.
2. Mempool admission: nonce projection, free-lane quotas, duplicate rejection.
3. Consensus rounds: a rotating proposer builds blocks; every validator
   independently re-executes and only votes for correct state roots; >2/3
   quorum commits.
4. Access-set analysis showing which transactions could run in parallel.
5. Byte-identical final state roots across all validators, with supply
   conservation asserted.

## License

MIT OR Apache-2.0
