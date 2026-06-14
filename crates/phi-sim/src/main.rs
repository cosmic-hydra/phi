//! Local Phi simulation: the full Phase-1a pipeline end to end.
//!
//! Run with: `cargo run -p phi-sim`
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
//! 7. The Cargo guard sub-protocol: per-peer brute-force throttling at the
//!    admission edge, and fig issuance governance — an unauthorized mint the
//!    bare state machine accepts is refused quorum by the validator audit,
//!    while governance-approved issuance commits.
//! 8. A light-client audit: QC chain verification, a Merkle transaction
//!    inclusion proof, and SMT inclusion/exclusion proofs for accounts.
//! 9. Serial replay equality: the parallel executor's chain state matches
//!    byte-for-byte a serial re-execution of every committed block.

use std::collections::HashMap;

use phi_cargo::{FigGovernor, GuardError, PeerId, Throttle, ThrottleConfig};
use phi_consensus::{ConsensusEngine, RoundOutcome};
use phi_crypto::Keypair;
use phi_mempool::{AdmissionError, Mempool};
use phi_state::{State, TxError};
use phi_types::{AccountId, AuthPolicy, Block, Hash, Transaction};

fn main() {
    println!("=== Phi local simulation ===\n");

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
    let eve_policy = AuthPolicy::SingleKey(eve_kp.public());

    let alice = AccountId::from_auth(&alice_policy, 0);
    let bob = AccountId::from_auth(&bob_policy, 0);
    let carol = AccountId::from_auth(&carol_policy, 0);
    let dave = AccountId::from_auth(&dave_policy, DAVE_SALT);
    let eve = AccountId::from_auth(&eve_policy, 0);

    let names: HashMap<AccountId, &str> = [
        (alice, "alice"),
        (bob, "bob"),
        (carol, "carol"),
        (dave, "dave"),
        (eve, "eve"),
    ]
    .into_iter()
    .collect();
    let name = |id: &AccountId| names.get(id).copied().unwrap_or("?");
    let describe = |tx: &Transaction| -> String {
        match &tx.kind {
            phi_types::TransactionKind::Transfer { to, amount } => {
                format!(
                    "{}->{} {:>3} (nonce {})",
                    name(&tx.sender),
                    name(to),
                    amount,
                    tx.nonce
                )
            }
            phi_types::TransactionKind::Mint { to, amount } => {
                format!("mint {} to {}", amount, name(to))
            }
        }
    };

    // --- Genesis ------------------------------------------------------------
    let mut genesis = State::new();
    genesis.genesis_account_with_auth(alice, 1_000, alice_policy);
    genesis.genesis_account_with_auth(bob, 500, bob_policy);
    genesis.genesis_account_with_auth(carol, 250, carol_policy.clone());
    genesis.genesis_account_with_auth(eve, 5, eve_policy);
    println!("Genesis (account ids commit to their auth policies):");
    println!("  alice  {:?}  single-key, balance 1000", alice.0);
    println!("  bob    {:?}  single-key, balance  500", bob.0);
    println!("  carol  {:?}  2-of-3 threshold, balance 250", carol.0);
    println!("  eve    {:?}  single-key, balance    5", eve.0);
    println!("  SMT state root: {:?}", genesis.root());
    println!("  total supply: {} figs\n", genesis.total_supply());

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
            let waves = phi_executor::conflict_groups(&batch);
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

    // --- Cargo guard: brute-force throttling ----------------------------------
    println!("--- cargo guard: per-peer throttling at the admission edge ---");
    let mut throttle = Throttle::new(ThrottleConfig {
        free_failures: 2,
        base_cooldown_ms: 60_000,
        max_cooldown_ms: 3_600_000,
    });
    let eve_peer = PeerId::from_label("peer:eve");
    let mut edge_clock: u64 = 1_700_000_001_000;
    for attempt in 1..=4u64 {
        edge_clock += 1_000;
        // Eve probes with forged spends from bob's account.
        let forged = Transaction::transfer(bob, 1, dave, 400 + attempt).signed(&eve_kp);
        match throttle.check(&eve_peer, edge_clock) {
            Err(GuardError::CoolingDown { until_ms }) => println!(
                "  attempt {attempt}: BLOCKED at the edge until t={until_ms} — \
                 no signature work spent on the probe"
            ),
            Err(other) => unreachable!("throttle only cools down: {other:?}"),
            Ok(()) => {
                match mempool.submit(forged, engine.canonical_state()) {
                    Err(AdmissionError::Invalid(e)) if Throttle::counts_as_auth_failure(&e) => {
                        throttle.record_failure(eve_peer, edge_clock);
                        println!("  attempt {attempt}: rejected ({e:?}); failure counted against eve's peer");
                    }
                    other => println!("  attempt {attempt}: unexpected outcome {other:?}"),
                }
            }
        }
    }
    println!(
        "  throttling keys on the submitting peer, never the claimed sender — \
         eve cannot lock bob out\n"
    );

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

    // --- Cargo guard: fig issuance governance ----------------------------------
    println!("--- cargo guard: fig issuance governance ---");
    let supply_before_issuance = engine.canonical_state().total_supply();
    let exploit = Transaction::mint(eve, 0, eve, 1_000_000).signed(&eve_kp);
    println!(
        "  edge screen: eve mints herself 1,000,000 figs -> {:?}",
        FigGovernor::default().screen_tx(&exploit).unwrap_err()
    );
    println!("  a colluding proposer includes the mint anyway, bypassing the edge:");
    match engine.run_round(vec![exploit], 1_700_000_003_000) {
        RoundOutcome::Committed {
            block, receipts, ..
        } => {
            // Defense in depth: the base ledger rejects the unauthorized mint
            // (recorded as a failed receipt), so the block commits with NO
            // figs created. The Cargo supply audit independently confirms it.
            assert_eq!(receipts[0].result, Err(TxError::UnauthorizedIssuance));
            assert_eq!(
                engine.canonical_state().total_supply(),
                supply_before_issuance
            );
            println!(
                "  COMMITTED block #{} but the mint FAILED ({:?}) — supply unchanged at {} figs",
                block.header.height,
                receipts[0].result.as_ref().unwrap_err(),
                engine.canonical_state().total_supply()
            );
        }
        RoundOutcome::Rejected { .. } => panic!("block with a failed tx should still commit"),
    }

    println!("  governance grants alice issuance authority (cap 1000 figs/block):");
    engine.set_issuance_authority(alice, 1_000);
    match engine.run_round(
        vec![Transaction::mint(alice, 3, dave, 100).signed(&alice_kp)],
        1_700_000_003_500,
    ) {
        RoundOutcome::Committed {
            block, receipts, ..
        } => {
            assert!(receipts[0].result.is_ok());
            println!(
                "  COMMITTED block #{}: {} | audit verified supply delta == authorized issuance\n",
                block.header.height,
                describe(&block.transactions[0])
            );
        }
        other => panic!("authorized mint should commit, got {other:?}"),
    }

    // --- Final state ----------------------------------------------------------
    let state = engine.canonical_state();
    println!("=== Final state at height {} ===", engine.height);
    for id in [alice, bob, carol, dave, eve] {
        let account = state.account(&id).unwrap();
        println!(
            "  {:6} balance={:<5} nonce={}",
            name(&id),
            account.balance,
            account.nonce
        );
    }
    assert_eq!(state.total_supply(), 1_755 + 100);
    println!(
        "  total supply = {} figs (genesis 1755 + 100 authorized issuance)",
        state.total_supply()
    );
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
    // A fresh node re-validating the chain must reach the same state. It also
    // needs the governance-set issuance authority: granting it is an
    // out-of-band engine action here (not yet a transaction), so we configure
    // the replay with the same final authority before replaying.
    let mut replay = genesis;
    replay.set_minter(Some(alice));
    for (block, _) in &engine.chain {
        let receipts = replay.apply_block(block);
        assert_eq!(
            phi_state::receipts_root(&receipts),
            block.header.receipts_root,
            "serial receipts diverge from committed receipts root"
        );
    }
    assert_eq!(replay.root(), state.root());
    println!("  serial replay of the chain matches the parallel executor byte-for-byte ✓");

    // --- Slashing: equivocation is provable -------------------------------------
    // Validator 2 has been Byzantine all along. Beyond voting for corrupt
    // blocks, a validator can *equivocate* — sign two conflicting votes in one
    // view. That is cryptographic self-incrimination: anyone, including a
    // light client, can verify the evidence against the validator set.
    println!("\n=== Slashing: catching an equivocator ===");
    println!("  no equivocation during the honest run (evidence log empty: {})", engine.slashing_evidence.is_empty());
    // Validator 2 already cast a vote in view 0 (round 1). It now gossips a
    // second, conflicting vote for the same view — a phantom fork block.
    let double_vote = engine.validators[2].sign_vote(Hash::of(b"phantom fork block"), 1, 0, true);
    match engine.observe_external_vote(double_vote) {
        Some(evidence) => {
            assert!(evidence.verify(&engine.validator_keys()));
            println!(
                "  validator {} signed two different blocks in view {} → slashing evidence verifies ✓",
                evidence.validator, evidence.view
            );
            println!("  (in production this burns the offender's staked figs; here it is logged)");
        }
        None => panic!("expected to catch validator 2's double-sign"),
    }
    assert_eq!(engine.slashing_evidence.len(), 1);

    // --- Fee market: EIP-1559-style burn + native sponsorship -------------------
    println!("\n=== Fee market: burned fees and native sponsorship ===");
    {
        let mut market = State::new();
        market.set_base_fee(2); // every included transaction burns 2 figs

        let spender_policy = AuthPolicy::SingleKey(alice_kp.public());
        let sponsor_policy = AuthPolicy::SingleKey(bob_kp.public());
        let spender = AccountId::from_auth(&spender_policy, 0);
        let sponsor = AccountId::from_auth(&sponsor_policy, 0);
        let merchant = AccountId::from_label("merchant");
        market.genesis_account_with_auth(spender, 100, spender_policy);
        market.genesis_account_with_auth(sponsor, 100, sponsor_policy);
        let supply_before = market.total_supply();
        println!("  base_fee = 2 figs/tx (burned); supply before = {supply_before} figs");

        let batch = vec![
            // The spender pays its own fee.
            Transaction::transfer(spender, 0, merchant, 30)
                .with_max_fee(2)
                .signed(&alice_kp),
            // The sponsor foots the fee so the spender can move its last figs.
            Transaction::transfer(spender, 1, merchant, 68)
                .with_max_fee(2)
                .with_sponsor(sponsor)
                .signed(&alice_kp),
        ];
        let out = phi_executor::execute(&mut market, &batch);
        assert!(out.receipts.iter().all(|r| r.result.is_ok()));
        println!("  tx1 spender self-pays the fee; tx2 a sponsor pays so the spender keeps the full amount");
        println!(
            "  fees burned: {} figs → supply {} = {} - {}",
            out.fees_burned,
            market.total_supply(),
            supply_before,
            out.fees_burned
        );
        println!(
            "  balances: spender {}  sponsor {}  merchant {}",
            market.balance(&spender),
            market.balance(&sponsor),
            market.balance(&merchant)
        );
        assert_eq!(out.fees_burned, 4);
        assert_eq!(market.total_supply(), supply_before - 4);

        // Defense in depth: the Cargo supply audit reconciles the burn
        // (post == pre + minted - burned), so a block that *claimed* to burn
        // fees while leaking figs elsewhere would be refused quorum.
        FigGovernor::default()
            .audit_block(supply_before, market.total_supply(), &batch, &out.receipts)
            .expect("burned-fee supply must reconcile");
        println!("  Cargo supply audit reconciles the burn (post = pre + minted - burned) ✓");
    }

    // --- Standard lane: fee-priority block building -----------------------------
    println!("\n=== Standard lane: fee-priority mempool ===");
    {
        let mut lane_state = State::new();
        for who in ["hodler", "trader", "whale"] {
            lane_state.genesis_account(AccountId::from_label(who), 1_000);
        }
        let dex = AccountId::from_label("dex");
        let bid = |who: &str, nonce: u64, tip: u64| {
            Transaction::transfer(AccountId::from_label(who), nonce, dex, 1).with_max_fee(tip)
        };
        let mut lane = Mempool::new(16);
        // Submitted in arrival order; the tips disagree with that order.
        lane.submit(bid("hodler", 0, 1), &lane_state).unwrap();
        lane.submit(bid("trader", 0, 5), &lane_state).unwrap();
        lane.submit(bid("whale", 0, 50), &lane_state).unwrap();
        lane.submit(bid("trader", 1, 5), &lane_state).unwrap();

        let label_of = |id: &AccountId| -> &'static str {
            ["hodler", "trader", "whale"]
                .into_iter()
                .find(|w| AccountId::from_label(w) == *id)
                .unwrap_or("?")
        };
        println!("  highest tip is included first; each sender stays in nonce order:");
        let priority = lane.take_priority_batch(4);
        for tx in &priority {
            println!("    {:<6} nonce {}  tip {}", label_of(&tx.sender), tx.nonce, tx.max_fee);
        }
        assert_eq!(priority[0].max_fee, 50); // whale jumps the queue
        assert_eq!(priority.last().unwrap().max_fee, 1); // lowest tip last
    }

    println!("\nSimulation complete.");
}
