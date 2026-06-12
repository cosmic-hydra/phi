# Phi Implementation Roadmap

> Companion to [SPECIFICATION.md](./SPECIFICATION.md) and [ARCHITECTURE.md](./ARCHITECTURE.md).

## Phase 0 — Design hardening (now)

- Specification review, threat-model workshops, TLA+ model of PhiBFT safety.
- **Exit criteria:** spec v1.0 frozen for testnet scope; consensus model checked.

## Phase 1 — Core protocol simulation → local cluster

**1a. Single-node simulation — ✅ implemented in this repo:**
- Core types (blocks, transactions, accounts) with domain-separated hashing.
- In-memory state store committed by a Sparse Merkle Tree (inclusion and
  exclusion proofs).
- Round-based consensus producing blocks from a mempool, with view change
  and Byzantine-proposer fault injection.
- Serial state-transition function with balance/nonce/auth semantics, plus
  the parallel executor property-tested equivalent to it.
- The Cargo guard sub-protocol: fig issuance governance and supply audits
  enforced at voting, per-peer brute-force throttling at the edge.
- Deterministic local simulation: N virtual validators, scripted tx load.

**1b. Multi-node local cluster (partially implemented):**
- ✅ Ed25519 validator keys, signed votes, verifiable quorum certificates,
  signature verification for account auth policies (single-key, threshold,
  first-spend claiming).
- Replace round driver with real PhiBFT (pacemaker, pipelining) over libp2p.
- Slashing evidence from conflicting signed votes.
- Persistent storage (RocksDB or redb), crash-restart recovery, state sync.
- Deterministic simulation testing harness (seeded scheduler, fault injection:
  partitions, crashes, Byzantine voters).

**Exit criteria:** 4–100 node local cluster sustains load with one-third
faults injected, zero safety violations across 10^6 randomized sim runs.

## Phase 2 — Minimal viable implementation of key components

1. **PhiVM:** wasmtime embedding, determinism enforcement, gas metering,
   object host API, bytecode verifier for resource rules.
2. **Parallel executor:** declared access sets, Block-STM optimistic engine,
   serial-equivalence property tests.
3. **Native account abstraction:** default account module, passkey (WebAuthn
   P-256) verification, session keys, fee sponsorship path.
4. **Fee model:** multidimensional gas, per-lane base fee, free-lane quota.
5. **Owned-object fast path:** execution certificates + lane checkpointing.
6. **DA v0:** erasure-coded blobs with commitments (sampling comes later).
7. **Public devnet → incentivized testnet.**

**Exit criteria:** end-to-end dApp (wallet with passkeys + token + name
registry) running on a public testnet; audited consensus + VM core.

## Phase 3 — Trust-minimization & privacy (post-MVP)

- ZK validity-proof aggregation for light clients; checkpoint anchoring to an
  established chain for bootstrap security.
- Shielded balances (note commitments + Poseidon2 circuits), viewing keys.
- Threshold-encrypted mempool; randomness beacon via threshold BLS.
- Interop: upgrade the `phi-interop` light clients (PoW + BFT adapters already
  implemented) to ZK-SNARK-aggregated verification; add validator-set rotation
  / weak-subjectivity handling and Ethereum sync-committee support.
- Governance modules (bicameral), storage deposits, mainnet genesis.

## Key Milestones

| Milestone | Signal |
|---|---|
| M1 | Local sim: blocks + txs + deterministic state root (starter code) |
| M2 | 4-node BFT cluster with finality and recovery |
| M3 | PhiVM executes user WASM contracts with gas |
| M4 | Parallel executor beats serial baseline ≥5x on disjoint workloads |
| M5 | Passkey wallet end-to-end on devnet |
| M6 | Public testnet with fast path + consensus path |
| M7 | First external audit complete |
| M8 | ZK light client verified on Ethereum testnet |
| M9 | Mainnet genesis with checkpoint anchoring |

## Risks & Mitigations

| Challenge | Risk | Mitigation |
|---|---|---|
| BFT implementation bugs | Safety violation = catastrophic | TLA+ model first, deterministic sim testing, fuzzing, two independent audits |
| Parallel executor nondeterminism | Consensus splits | Serial-equivalence property tests run in CI on every commit; deterministic re-execution fallback |
| WASM determinism gaps | Divergent state roots | Strict feature gating (no floats/threads/SIMD), instruction-level metering, cross-runtime differential testing |
| ZK proving cost/maturity | Phase-3 slip | ZK is additive, not load-bearing for MVP; chain is fully functional without proofs (BFT light clients as fallback) |
| Encrypted mempool latency | UX regression | Ship after MVP; feature-flag per lane; measure before default-on |
| Bootstrap security | Low-stake attacks at genesis | Checkpoint anchoring, conservative initial validator set, delayed unbonding from day one |
| Scope creep | Never shipping | Strict phase exit criteria; privacy and interop explicitly deferred to Phase 3 |
