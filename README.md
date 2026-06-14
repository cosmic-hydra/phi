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
├── phi-state/      # deterministic state machine committed by a real Sparse
│                   # Merkle Tree (inclusion AND exclusion proofs)
├── phi-cargo/      # Cargo guard sub-protocol: fig issuance governance, supply
│                   # invariant audits, per-peer brute-force throttling
├── phi-executor/   # parallel executor: conflict-wave scheduling over declared
│                   # access sets, property-tested equal to serial execution
├── phi-mempool/    # admission control: signature pre-validation, nonce/balance
│                   # projection, free-lane quotas, requeue on failed rounds
├── phi-consensus/  # BFT-shaped consensus: signed votes, verifiable quorum
│                   # certificates, view change, Byzantine validator simulation
├── phi-interop/    # trust-minimized cross-chain bridge: pluggable light-client
│                   # verifiers (PoW + BFT adapters), no multisig bridges
├── phi-vm/         # PhiVM: deterministic, gas-metered bytecode VM for smart
│                   # contracts (atomic revert-on-trap, bounded resources)
├── phi-node/       # persistent single-node devnet + CLI (init/fund/transfer)
└── phi-sim/        # local simulation binary demonstrating the full pipeline
```

This is the Phase 1a vertical slice from the roadmap plus the first Phase 1b
milestones (validator keys, signature verification): networking, pipelined
HotStuff with VRF sortition, persistence, and PhiVM replace the remaining
stubs in later phases without changing module boundaries.

## Quickstart

Requires a recent Rust toolchain (`rustup`).

```bash
# Run the local simulation: genesis → mempool admission → BFT rounds
# (including a Byzantine proposer) → light-client audit
cargo run -p phi-sim

# Run the test suite
cargo test --workspace
```

### Run a local devnet you can actually use

`phi-node` is a persistent single-node devnet — a real, runnable chain (not a
test). State is written to `./phi-chain.snapshot` (override with `$PHI_CHAIN`)
and survives between commands:

```bash
cargo run -p phi-node -- init --chain-id 1 --supply 1000000
cargo run -p phi-node -- address alice
cargo run -p phi-node -- fund alice 1000          # treasury -> alice
cargo run -p phi-node -- transfer alice bob 400   # signed; first spend claims alice
cargo run -p phi-node -- balance bob              # 400
cargo run -p phi-node -- state                    # height, supply, state root
```

Every command signs with real Ed25519 keys, runs the same state machine the
tests cover, produces a block with committed roots, and conserves supply.
**This is a local devnet, not a deployable network** — see "Is it production
ready?" below.

## Is it production ready?

**No.** Phi is a well-tested research implementation, not a deployable
blockchain. It has no peer-to-peer networking (the devnet is a single
sequencer), no multi-validator consensus liveness/pacemaker, no slashing, no
persistence beyond the local snapshot, no audits, and the smart-contract VM is
not yet wired into the ledger. It is genuinely *usable* locally — you can run
it, move value, and inspect committed state — but it must not be used to hold
real value. [SECURITY.md](SECURITY.md) is the authoritative threat model and
gap list.

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
8. **Trust-minimized interop**: a foreign proof-of-work chain's header is
   verified by a light client (no trusted relayer or multisig), and a
   committed lock event releases figs from the bridge reserve through
   consensus — replay of the same foreign lock rejected.
9. **Smart contracts** on PhiVM: a deterministic, gas-metered token contract
   runs a transfer and an atomically-reverted overspend.
10. A light-client audit: quorum-certificate verification for the whole chain,
    a Merkle transaction inclusion proof, and SMT inclusion/exclusion proofs
    for accounts.
11. Byte-identical state roots across validators, audited supply, and a
    serial replay that matches the parallel executor exactly.

## Interoperability

Phi connects to other chains the way the spec demands (§11): **no multisig
bridges**. `phi-interop` runs a light client of each foreign chain and verifies
that chain's own consensus, so cross-chain transfers are accepted only against
proofs a relayer cannot forge. Two reference adapters cover the dominant
families — `PowLightClient` (Bitcoin-style SPV) and `BftLightClient`
(Tendermint/Cosmos/Solana-style validator sets). Supporting a specific chain
means implementing the `LightClient` trait for its rules; there is no automatic
"works with every blockchain" switch, because each chain's finality differs.

## Smart contracts

`phi-vm` is a deterministic, gas-metered bytecode VM — the programmability
layer that makes Phi a platform rather than a payments ledger. It is
integer-only (no float nondeterminism), bounded by gas (so every call
terminates) and stack depth, and calls are atomic (a trap reverts all storage
writes, like an EVM revert). The spec's long-term target is a WASM VM; this
self-contained engine proves the execution-model properties (determinism, gas,
atomicity) without a heavy dependency. It is **not yet wired into the ledger** —
the next step is `Deploy`/`Call` transaction kinds, contract storage committed
in the SMT, and access-set declarations so contract calls schedule on the
parallel executor.

## Security

The base ledger enforces issuance authority, `chain_id` replay protection,
bounded transaction sizes, checked arithmetic, and signed/quorum-verified
consensus — each backed by tests. None of this makes Phi "unhackable."
[SECURITY.md](SECURITY.md) is the honest threat model: what is enforced today,
and the substantial surface (real networking, slashing, key management, audits,
formal verification) a production deployment still requires.

## License

MIT OR Apache-2.0
