//! PhiVM: a deterministic, gas-metered virtual machine for Phi smart contracts.
//!
//! This is the programmability layer — the piece that lets Phi run user logic
//! (tokens, escrows, governance), which is what makes a chain a *Web3* platform
//! rather than just a payments ledger. It is a small stack machine with:
//!
//! - **Determinism by construction**: integer-only operands, ordered
//!   (`BTreeMap`) storage, no host nondeterminism — every node computes the
//!   identical result, which consensus requires.
//! - **Gas metering**: every instruction has a fixed cost and execution is
//!   bounded by a gas limit, so a contract (even an infinite loop) always
//!   terminates. This is the halting guarantee a contract VM must provide.
//! - **Atomic calls**: a trap (out-of-gas, overflow, failed assertion via
//!   `Abort`, …) reverts all storage writes, like an EVM revert.
//!
//! ## Honest scope
//!
//! The spec's long-term target is a WASM VM (wasmtime) with a bytecode
//! verifier and resource-typed standard library. This crate is a self-contained
//! bytecode VM that proves the *execution-model* properties (determinism, gas,
//! atomicity, bounded resources) without a heavyweight dependency. It is **not**
//! yet wired into the ledger: the next integration step is `Deploy`/`Call`
//! transaction kinds in `phi-types`, contract storage committed in the
//! `phi-state` SMT, and access-set declarations so contract calls schedule on
//! the parallel executor. Until then, contracts run via [`Contract::call`] but
//! do not yet change on-chain state.

mod asm;
mod contract;
mod examples;
mod instr;
mod vm;

pub use asm::{assemble, AsmError, Op};
pub use contract::Contract;
pub use examples::{counter, token, token_contract, COUNTER_SLOT};
pub use instr::Instr;
pub use vm::{execute, CallContext, Outcome, Trap, MAX_STACK};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments_across_calls() {
        let mut c = Contract::new(counter());
        let gas = 10_000;
        assert_eq!(
            c.call(&CallContext::default(), gas).unwrap().return_value,
            Some(1)
        );
        assert_eq!(
            c.call(&CallContext::default(), gas).unwrap().return_value,
            Some(2)
        );
        assert_eq!(
            c.call(&CallContext::default(), gas).unwrap().return_value,
            Some(3)
        );
        assert_eq!(c.storage.get(&COUNTER_SLOT), Some(&3));
    }

    #[test]
    fn token_transfer_moves_balance_and_checks_funds() {
        let mut tok = Contract::new(token_contract());
        let alice = 0xA11CE;
        let bob = 0xB0B;
        let gas = 10_000;

        // Seed alice with 100 by writing storage directly (a mint host call
        // would do this in the integrated version).
        tok.storage.insert(alice, 100);

        // balanceOf(alice) == 100
        let bal = tok
            .call(
                &CallContext {
                    caller: alice,
                    args: vec![token::BALANCE_OF, alice],
                    ..Default::default()
                },
                gas,
            )
            .unwrap();
        assert_eq!(bal.return_value, Some(100));

        // alice transfers 30 to bob
        let ok = tok
            .call(
                &CallContext {
                    caller: alice,
                    args: vec![token::TRANSFER, bob, 30],
                    ..Default::default()
                },
                gas,
            )
            .unwrap();
        assert_eq!(ok.return_value, Some(1));
        assert_eq!(tok.storage.get(&alice), Some(&70));
        assert_eq!(tok.storage.get(&bob), Some(&30));

        // overspend: alice tries to send 1000, reverts atomically
        let snapshot = tok.storage.clone();
        let fail = tok.call(
            &CallContext {
                caller: alice,
                args: vec![token::TRANSFER, bob, 1000],
                ..Default::default()
            },
            gas,
        );
        assert_eq!(fail, Err(Trap::Aborted));
        assert_eq!(
            tok.storage, snapshot,
            "failed transfer must not change balances"
        );
    }

    #[test]
    fn token_conserves_supply_under_transfers() {
        let mut tok = Contract::new(token_contract());
        let (a, b, c) = (1u64, 2u64, 3u64);
        tok.storage.insert(a, 1_000);
        let gas = 10_000;
        let supply = |t: &Contract| t.storage.values().sum::<u64>();
        let before = supply(&tok);

        for (caller, to, amt) in [(a, b, 400u64), (b, c, 150), (c, a, 50)] {
            tok.call(
                &CallContext {
                    caller,
                    args: vec![token::TRANSFER, to, amt],
                    ..Default::default()
                },
                gas,
            )
            .unwrap();
        }
        assert_eq!(supply(&tok), before, "transfers conserve token supply");
    }

    #[test]
    fn gas_limit_bounds_execution_deterministically() {
        let mut c = Contract::new(counter());
        // Too little gas to finish: traps OutOfGas, and the storage write is
        // reverted (atomic), so the counter does not advance.
        assert_eq!(c.call(&CallContext::default(), 3), Err(Trap::OutOfGas));
        assert!(c.storage.is_empty());
    }
}
