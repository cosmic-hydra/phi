//! Local NexChain simulation: demonstrates transaction processing and
//! consensus end-to-end with simulated validators.
//!
//! Run with: `cargo run -p nex-sim`
//!
//! What it shows:
//! 1. Genesis state with funded accounts.
//! 2. Transactions admitted through the mempool (free-lane quotas, nonce
//!    projection, duplicate rejection).
//! 3. BFT-shaped rounds: a rotating proposer builds a block, every validator
//!    independently re-executes and votes, >2/3 quorum commits.
//! 4. Deterministic state roots agreed by all validators each block.
//! 5. Access-set conflict analysis showing the parallelism available to the
//!    future Block-STM executor.

use nex_consensus::{ConsensusEngine, RoundOutcome};
use nex_mempool::Mempool;
use nex_state::State;
use nex_types::{AccountId, Transaction};

fn main() {
    println!("=== NexChain local simulation ===\n");

    // --- Genesis -----------------------------------------------------------
    let alice = AccountId::from_label("alice");
    let bob = AccountId::from_label("bob");
    let carol = AccountId::from_label("carol");
    let dave = AccountId::from_label("dave");

    let mut genesis = State::new();
    genesis.genesis_account(alice, 1_000);
    genesis.genesis_account(bob, 500);
    genesis.genesis_account(carol, 250);
    println!("Genesis state root: {:?}", genesis.root());
    println!(
        "Balances: alice={} bob={} carol={} (supply={})\n",
        genesis.balance(&alice),
        genesis.balance(&bob),
        genesis.balance(&carol),
        genesis.total_supply()
    );

    let num_validators = 4;
    let mut engine = ConsensusEngine::new(num_validators, genesis);
    let mut mempool = Mempool::new(8);
    println!(
        "Started {num_validators} validators (quorum = {} votes)\n",
        engine.quorum()
    );

    // --- Submit transactions ------------------------------------------------
    let txs = vec![
        Transaction::transfer(alice, 0, bob, 100),
        Transaction::transfer(bob, 0, carol, 50),
        Transaction::transfer(carol, 0, dave, 25), // creates dave's account
        Transaction::transfer(alice, 1, dave, 10),
        Transaction::transfer(alice, 2, carol, 999_999), // will fail in-block: insufficient
    ];
    for tx in txs {
        match mempool.submit(tx.clone(), engine.canonical_state()) {
            Ok(()) => println!("mempool: admitted   {:?}", tx.kind),
            Err(e) => println!("mempool: rejected   {:?} ({e:?})", tx.kind),
        }
    }
    // Demonstrate admission failures.
    let dup = Transaction::transfer(bob, 0, carol, 50);
    println!(
        "mempool: duplicate resubmission -> {:?}",
        mempool.submit(dup, engine.canonical_state())
    );
    println!();

    // --- Consensus rounds ----------------------------------------------------
    let mut round_time: u64 = 1_700_000_000_000;
    while !mempool.is_empty() {
        let batch = mempool.take_batch(3);
        let groups = Mempool::parallel_groups(&batch);
        println!(
            "round {}: proposing {} txs ({} parallel group(s) by access sets)",
            engine.height + 1,
            batch.len(),
            groups.len()
        );
        match engine.run_round(batch, round_time) {
            RoundOutcome::Committed(block) => {
                println!(
                    "  committed block #{} by proposer {} | tx_root={:?}",
                    block.header.height, block.header.proposer, block.header.tx_root
                );
                println!("  state root: {:?}", block.header.state_root);
            }
            RoundOutcome::Rejected { approvals, needed } => {
                println!("  REJECTED: {approvals}/{needed} approvals");
            }
        }
        round_time += 500;
    }
    mempool.reset_window();

    // --- Final state ---------------------------------------------------------
    let state = engine.canonical_state();
    println!("\n=== Final state at height {} ===", engine.height);
    for (name, id) in [("alice", alice), ("bob", bob), ("carol", carol), ("dave", dave)] {
        println!("  {name:6} balance={}", state.balance(&id));
    }
    println!("  total supply = {} (conserved)", state.total_supply());
    println!("  final state root: {:?}", state.root());

    // All validators must agree byte-for-byte.
    let roots: Vec<_> = engine.validators.iter().map(|v| v.state.root()).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "validator state divergence!"
    );
    println!("\nAll {num_validators} validators agree on the state root. ✓");
}
