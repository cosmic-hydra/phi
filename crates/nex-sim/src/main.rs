//! Local NexChain simulation: the full Phase-1a pipeline end to end.
//!
//! Run with: `cargo run -p nex-sim`
//!
//! What it shows:
//! 1. Genesis accounts whose ids commit to real Ed25519 auth policies
//!    (single-key and 2-of-3 threshold), with an SMT state root.
//! 2. Mempool admission: signature pre-validation, nonce + balance
//!    projection over the queue, quotas, duplicate rejection.
//! 3. BFT rounds with signed votes and verifiable quorum certificates;
//!    every validator re-executes proposals with the parallel executor.
//! 4. A Byzantine proposer whose corrupted block is outvoted, followed by a
//!    view change — the batch is re-queued, never lost.
//! 5. First-spend account claiming: funds sent to a fresh id are spendable
//!    only by revealing the auth policy the id commits to.
//! 6. Receipts committed in headers, including an in-block runtime failure.
//! 7. A light-client audit: QC chain verification, a Merkle transaction
//!    inclusion proof, and SMT inclusion/exclusion proofs for accounts.
//! 8. Serial replay equality: the parallel executor's chain state matches
//!    byte-for-byte a serial re-execution of every committed block.

use std::collections::HashMap;

use nex_consensus::{ConsensusEngine, RoundOutcome};
use nex_crypto::Keypair;
use nex_mempool::Mempool;
use nex_state::State;
use nex_types::{AccountId, AuthPolicy, Block, Hash, Transaction};

fn main() {
    println!("=== NexChain local simulation ===\n");

    // --- Keys and accounts --------------------------------------------------
    let alice_kp = Keypair::from_label("alice");
    let bob_kp = Keypair::from_label("bob");
    let carol_guardians: Vec<Keypair> = (0..3)
        .map(|i| Keypair::from_label(&format!("carol-guardian-{i}")))
        .collect();
    let dave_kp = Keypair::from_label("dave");
    let eve_kp = Keypair::from_label("eve");

    let alice_policy = AuthPolicy::SingleKey(alice_kp.public());
    let bob_policy = AuthPolicy::SingleKey(bob_kp.public());
    let carol_policy = AuthPolicy::Threshold {
        m: 2,
        keys: carol_guardians.iter().map(|k| k.public()).collect(),
    };
    let dave_policy = AuthPolicy::SingleKey(dave_kp.public());
    const DAVE_SALT: u64 = 7;

    let alice = AccountId::from_auth(&alice_policy, 0);
    let bob = AccountId::from_auth(&bob_policy, 0);
    let carol = AccountId::from_auth(&carol_policy, 0);
    let dave = AccountId::from_auth(&dave_policy, DAVE_SALT);

    let names: HashMap<AccountId, &str> = [
        (alice, "alice"),
        (bob, "bob"),
        (carol, "carol"),
        (dave, "dave"),
    ]
    .into_iter()
    .collect();
    let name = |id: &AccountId| names.get(id).copied().unwrap_or("?");
    let describe = |tx: &Transaction| -> String {
        match &tx.kind {
            nex_types::TransactionKind::Transfer { to, amount } => {
                format!(
                    "{}->{} {:>3} (nonce {})",
                    name(&tx.sender),
                    name(to),
                    amount,
                    tx.nonce
                )
            }
            nex_types::TransactionKind::Mint { to, amount } => {
                format!("mint {} to {}", amount, name(to))
            }
        }
    };

    // --- Genesis ------------------------------------------------------------
    let mut genesis = State::new();
    genesis.genesis_account_with_auth(alice, 1_000, alice_policy);
    genesis.genesis_account_with_auth(bob, 500, bob_policy);
    genesis.genesis_account_with_auth(carol, 250, carol_policy.clone());
    println!("Genesis (account ids commit to their auth policies):");
    println!("  alice  {:?}  single-key, balance 1000", alice.0);
    println!("  bob    {:?}  single-key, balance  500", bob.0);
    println!("  carol  {:?}  2-of-3 threshold, balance 250", carol.0);
    println!("  SMT state root: {:?}", genesis.root());
    println!("  total supply: {}\n", genesis.total_supply());

    let num_validators = 4;
    let mut engine = ConsensusEngine::new(num_validators, genesis.clone());
    engine.validators[2].byzantine = true;
    let mut mempool = Mempool::new(8);
    println!(
        "Started {num_validators} validators (quorum = {}); validator 2 is BYZANTINE\n",
        engine.quorum()
    );

    // --- Mempool admission ----------------------------------------------------
    println!("--- mempool admission ---");
    let submissions: Vec<(&str, Transaction)> = vec![
        (
            "forged: unsigned spend from bob",
            Transaction::transfer(bob, 0, carol, 400),
        ),
        (
            "forged: bob spend signed by eve",
            Transaction::transfer(bob, 0, carol, 400).signed(&eve_kp),
        ),
        (
            "alice -> bob 100",
            Transaction::transfer(alice, 0, bob, 100).signed(&alice_kp),
        ),
        (
            "bob -> carol 50",
            Transaction::transfer(bob, 0, carol, 50).signed(&bob_kp),
        ),
        (
            "carol -> dave 25 (2-of-3 threshold)",
            Transaction::transfer(carol, 0, dave, 25)
                .signed(&carol_guardians[0])
                .signed(&carol_guardians[2]),
        ),
        (
            "alice -> dave 10",
            Transaction::transfer(alice, 1, dave, 10).signed(&alice_kp),
        ),
        (
            "alice overspend (projected balance)",
            Transaction::transfer(alice, 2, carol, 999_999).signed(&alice_kp),
        ),
        (
            "alice nonce gap",
            Transaction::transfer(alice, 5, bob, 1).signed(&alice_kp),
        ),
    ];
    for (label, tx) in submissions {
        match mempool.submit(tx, engine.canonical_state()) {
            Ok(()) => println!("  admitted   {label}"),
            Err(e) => println!("  rejected   {label}  ({e:?})"),
        }
    }
    let duplicate = Transaction::transfer(bob, 0, carol, 50).signed(&bob_kp);
    println!(
        "  rejected   duplicate of 'bob -> carol 50'  ({:?})",
        mempool
            .submit(duplicate, engine.canonical_state())
            .unwrap_err()
    );
    println!("  {} transactions pending\n", mempool.len());

    // --- Consensus rounds -----------------------------------------------------
    let mut round_time: u64 = 1_700_000_000_000;
    let mut run_round =
        |engine: &mut ConsensusEngine, mempool: &mut Mempool, batch: Vec<Transaction>| {
            round_time += 500;
            let waves = nex_executor::conflict_groups(&batch);
            println!(
                "view {} (proposer {}): {} tx(s) in {} parallel wave(s) {:?}",
                engine.view,
                engine.proposer_index(),
                batch.len(),
                waves.len(),
                waves
            );
            match engine.run_round(batch, round_time) {
                RoundOutcome::Committed {
                    block,
                    qc,
                    receipts,
                } => {
                    println!(
                        "  COMMITTED block #{} by proposer {} | QC signers {:?}",
                        block.header.height, block.header.proposer, qc.signers
                    );
                    println!("  state root: {:?}", block.header.state_root);
                    for (tx, receipt) in block.transactions.iter().zip(&receipts) {
                        match &receipt.result {
                            Ok(()) => println!("    ok    {}", describe(tx)),
                            Err(e) => println!("    FAIL  {}  ({e:?})", describe(tx)),
                        }
                    }
                    mempool.reset_window();
                }
                RoundOutcome::Rejected {
                    proposer,
                    approvals,
                    needed,
                    txs,
                } => {
                    println!(
                        "  REJECTED: proposer {proposer} got {approvals}/{needed} approvals; \
                     view change, batch re-queued"
                    );
                    mempool.requeue_front(txs);
                }
            }
            println!();
        };

    // Rounds 1-2: drain the honest queue; the proposer of round 2 also
    // includes a doomed transaction directly — receipts must record the
    // in-block failure deterministically on every validator.
    let batch = mempool.take_batch(3);
    run_round(&mut engine, &mut mempool, batch);

    let mut batch = mempool.take_batch(3);
    let doomed = Transaction::transfer(alice, 2, carol, 999_999).signed(&alice_kp);
    println!(
        "(proposer slips an over-spend into the next block: receipts will record the failure)"
    );
    batch.push(doomed);
    run_round(&mut engine, &mut mempool, batch);

    // --- First-spend claim of an unclaimed account ----------------------------
    println!("--- claiming an unclaimed account ---");
    println!(
        "dave's account was created by receiving funds; auth = {:?}",
        engine.canonical_state().account(&dave).unwrap().auth
    );
    let theft = Transaction::transfer(dave, 0, alice, 35)
        .with_reveal(AuthPolicy::SingleKey(eve_kp.public()), DAVE_SALT)
        .signed(&eve_kp);
    println!(
        "  rejected   eve claims dave's id with her own key  ({:?})",
        mempool.submit(theft, engine.canonical_state()).unwrap_err()
    );
    let claim = Transaction::transfer(dave, 0, alice, 5)
        .with_reveal(AuthPolicy::SingleKey(dave_kp.public()), DAVE_SALT)
        .signed(&dave_kp);
    println!("  admitted   dave reveals the policy his id commits to\n");
    mempool.submit(claim, engine.canonical_state()).unwrap();

    // Round 3 hits the Byzantine proposer (view 2): its corrupted block is
    // outvoted, the batch is re-queued, and round 4 commits it.
    let batch = mempool.take_batch(3);
    run_round(&mut engine, &mut mempool, batch);
    let batch = mempool.take_batch(3);
    run_round(&mut engine, &mut mempool, batch);
    assert!(mempool.is_empty());
    println!(
        "dave's account after first spend: auth = {:?}\n",
        engine.canonical_state().account(&dave).unwrap().auth
    );

    // --- Final state ----------------------------------------------------------
    let state = engine.canonical_state();
    println!("=== Final state at height {} ===", engine.height);
    for id in [alice, bob, carol, dave] {
        let account = state.account(&id).unwrap();
        println!(
            "  {:6} balance={:<5} nonce={}",
            name(&id),
            account.balance,
            account.nonce
        );
    }
    println!("  total supply = {} (conserved)", state.total_supply());
    println!("  final state root: {:?}", state.root());

    let roots: Vec<Hash> = engine.validators.iter().map(|v| v.state.root()).collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "validator state divergence!"
    );
    println!("\nAll {num_validators} validators agree on the state root. ✓");

    // --- Light-client audit -----------------------------------------------------
    println!("\n=== Light-client audit ===");
    let keys = engine.validator_keys();
    let mut parent = Hash::ZERO;
    for (block, qc) in &engine.chain {
        assert_eq!(block.header.parent, parent, "broken parent link");
        assert_eq!(qc.block_hash, block.header.hash(), "QC for wrong block");
        assert!(qc.verify(&keys, engine.quorum()), "invalid QC");
        parent = block.header.hash();
    }
    println!(
        "  quorum certificates verify for all {} committed blocks ✓",
        engine.chain.len()
    );

    let (block, _) = &engine.chain[0];
    let tx_proof = block.prove_tx(0).expect("block 1 has transactions");
    assert!(Block::verify_tx_proof(
        &block.header.tx_root,
        &block.transactions[0].id(),
        0,
        block.transactions.len(),
        &tx_proof,
    ));
    println!(
        "  Merkle inclusion proof for '{}' in block #1 ✓",
        describe(&block.transactions[0])
    );

    let committed_root = engine.chain.last().unwrap().0.header.state_root;
    let alice_proof = state.prove_account(&alice);
    assert!(State::verify_account_proof(
        &committed_root,
        &alice,
        state.account(&alice),
        &alice_proof
    ));
    println!("  SMT inclusion proof: alice's balance against the committed state root ✓");

    let mallory = AccountId::from_label("mallory");
    let exclusion = state.prove_account(&mallory);
    assert!(State::verify_account_proof(
        &committed_root,
        &mallory,
        None,
        &exclusion
    ));
    println!("  SMT exclusion proof: 'mallory' provably has no account ✓");

    // --- Serial replay equivalence ----------------------------------------------
    let mut replay = genesis;
    for (block, _) in &engine.chain {
        let receipts = replay.apply_block(block);
        assert_eq!(
            nex_state::receipts_root(&receipts),
            block.header.receipts_root,
            "serial receipts diverge from committed receipts root"
        );
    }
    assert_eq!(replay.root(), state.root());
    println!("  serial replay of the chain matches the parallel executor byte-for-byte ✓");

    println!("\nSimulation complete.");
}
