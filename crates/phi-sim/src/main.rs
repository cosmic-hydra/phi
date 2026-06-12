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
//! 8. Trust-minimized interop: a foreign proof-of-work chain's header is
//!    verified by a light client (no trusted relayer), and a committed lock
//!    event releases figs from the bridge reserve via consensus — replay of
//!    the same foreign lock rejected.
//! 9. Smart contracts: a deterministic, gas-metered PhiVM token contract runs
//!    a transfer and an atomically-reverted overspend (standalone; ledger
//!    integration is the next step).
//! 10. A light-client audit: QC chain verification, a Merkle transaction
//!     inclusion proof, and SMT inclusion/exclusion proofs for accounts.
//! 11. Serial replay equality: the parallel executor's chain state matches
//!     byte-for-byte a serial re-execution of every committed block.

use std::collections::HashMap;

use phi_cargo::{FigGovernor, GuardError, PeerId, Throttle, ThrottleConfig};
use phi_consensus::{ConsensusEngine, RoundOutcome};
use phi_crypto::Keypair;
use phi_interop::{
    BridgeHub, ConsensusProof, CrossChainEvent, EventProof, ForeignChainId, ForeignHeader,
    PowLightClient,
};
use phi_mempool::{AdmissionError, Mempool};
use phi_state::{State, TxError};
use phi_types::{merkle, AccountId, AuthPolicy, Block, Hash, Transaction};

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

    // The cross-chain bridge reserve: a pre-funded account backing wrapped
    // balances, controlled by the bridge key (see the interop section). And
    // `frank`, a beneficiary who receives figs bridged in from a foreign chain.
    let reserve_kp = Keypair::from_label("phi-bridge-reserve");
    let reserve = AccountId::from_auth(&AuthPolicy::SingleKey(reserve_kp.public()), 0);
    let frank = AccountId::from_label("frank");

    let names: HashMap<AccountId, &str> = [
        (alice, "alice"),
        (bob, "bob"),
        (carol, "carol"),
        (dave, "dave"),
        (eve, "eve"),
        (reserve, "reserve"),
        (frank, "frank"),
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
    genesis.genesis_account_with_auth(reserve, 10_000, AuthPolicy::SingleKey(reserve_kp.public()));
    println!("Genesis (account ids commit to their auth policies):");
    println!("  alice   {:?}  single-key, balance 1000", alice.0);
    println!("  bob     {:?}  single-key, balance  500", bob.0);
    println!("  carol   {:?}  2-of-3 threshold, balance 250", carol.0);
    println!("  eve     {:?}  single-key, balance    5", eve.0);
    println!("  reserve {:?}  bridge reserve, balance 10000", reserve.0);
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

    // --- Cross-chain interop: trust-minimized bridge ---------------------------
    println!("--- interop: bridging in from a foreign proof-of-work chain ---");
    let mut bridge = BridgeHub::new(engine.chain_id, Keypair::from_label("phi-bridge-reserve"));
    let btc = ForeignChainId(0xB7C);
    // An easy difficulty target (first byte zero) keeps the demo instant.
    let mut pow_target = [0xffu8; 32];
    pow_target[0] = 0x00;
    let foreign_genesis = ForeignHeader {
        height: 0,
        parent: Hash::ZERO,
        event_root: merkle::root(&[]),
        nonce: 0,
    };
    let pow = PowLightClient::new(&foreign_genesis, pow_target);

    // The foreign chain locks 250 units destined for frank on Phi, committing
    // the event in its block 1.
    let lock = CrossChainEvent {
        foreign_chain: btc,
        sequence: 0,
        beneficiary: frank,
        amount: 250,
    };
    let leaves = vec![lock.hash()];
    let foreign_block = pow.mine(ForeignHeader {
        height: 1,
        parent: foreign_genesis.hash(),
        event_root: merkle::root(&leaves),
        nonce: 0,
    });
    bridge.register_chain(btc, pow).unwrap();
    bridge
        .submit_foreign_header(btc, &foreign_block, &ConsensusProof::Pow)
        .unwrap();
    println!(
        "  verified foreign PoW header at height {} (no trusted relayer)",
        bridge.tip_height(btc).unwrap()
    );

    // A relayer presents the lock + an inclusion proof; the bridge verifies it
    // against the foreign chain's own work and releases figs from the reserve.
    let proof = EventProof {
        header_height: 1,
        leaf_index: 0,
        leaf_count: 1,
        merkle: merkle::prove(&leaves, 0).unwrap(),
    };
    let reserve_nonce = engine.canonical_state().account(&reserve).unwrap().nonce;
    // Phase 1: verify the lock and build the release (not yet marked done).
    let release_tx = bridge
        .prepare_redemption(&lock, &proof, reserve_nonce)
        .unwrap();
    mempool
        .submit(release_tx, engine.canonical_state())
        .unwrap();
    println!("  release verified; submitting reserve->frank transfer to consensus:");
    while !mempool.is_empty() {
        let batch = mempool.take_batch(1);
        run_round(&mut engine, &mut mempool, batch);
    }
    assert_eq!(engine.canonical_state().balance(&frank), 250);
    // Phase 2: the release committed, so mark the lock settled.
    bridge
        .confirm_redemption(lock.foreign_chain, lock.sequence)
        .unwrap();

    // The same foreign lock cannot be redeemed again.
    match bridge.prepare_redemption(&lock, &proof, reserve_nonce + 1) {
        Err(phi_interop::InteropError::AlreadyProcessed { .. }) => {
            println!("  replay of the same foreign lock rejected ✓\n")
        }
        other => panic!("expected replay rejection, got {other:?}"),
    }

    // --- Smart contracts: PhiVM (deterministic, gas-metered) -------------------
    // Standalone VM demo: contracts run here but are not yet wired into the
    // ledger's state transition (the next integration step — see phi-vm docs).
    println!("--- smart contracts: PhiVM (deterministic, gas-metered) ---");
    let mut token = phi_vm::Contract::new(phi_vm::token_contract());
    let (vm_alice, vm_bob) = (0xA11CE_u64, 0xB0B_u64);
    token.storage.insert(vm_alice, 100); // seed alice with 100 tokens
    let gas = 10_000;
    let ok = token
        .call(
            &phi_vm::CallContext {
                caller: vm_alice,
                args: vec![phi_vm::token::TRANSFER, vm_bob, 30],
                ..Default::default()
            },
            gas,
        )
        .unwrap();
    println!(
        "  token.transfer(alice->bob, 30) -> ret={:?}, gas_used={}",
        ok.return_value, ok.gas_used
    );
    println!(
        "  balances: alice={} bob={}",
        token.storage[&vm_alice], token.storage[&vm_bob]
    );
    let before = token.storage.clone();
    let overspend = token.call(
        &phi_vm::CallContext {
            caller: vm_alice,
            args: vec![phi_vm::token::TRANSFER, vm_bob, 1_000],
            ..Default::default()
        },
        gas,
    );
    println!("  token.transfer(alice->bob, 1000) -> {overspend:?} (atomic revert)");
    assert_eq!(
        token.storage, before,
        "reverted call must not change balances"
    );
    println!("  contract code hash: {:?}\n", token.code_hash());

    // --- Final state ----------------------------------------------------------
    let state = engine.canonical_state();
    println!("=== Final state at height {} ===", engine.height);
    for id in [alice, bob, carol, dave, eve, reserve, frank] {
        let account = state.account(&id).unwrap();
        println!(
            "  {:8} balance={:<6} nonce={}",
            name(&id),
            account.balance,
            account.nonce
        );
    }
    // Genesis 11,755 figs (incl. 10k reserve) + 100 authorized issuance.
    // The bridge release moves figs within Phi, so supply is unchanged by it.
    assert_eq!(state.total_supply(), 11_755 + 100);
    println!(
        "  total supply = {} figs (genesis 11,755 + 100 issuance; bridge moves, never mints)",
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

    println!("\nSimulation complete.");
}
