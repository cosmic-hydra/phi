//! Example contracts, used by tests and the simulation. They show that the
//! instruction set is expressive enough for real contract logic — a stateful
//! counter and a balance-checked token transfer with atomic revert.

use crate::asm::{assemble, Op};
use crate::instr::Instr;

/// Storage slot holding the counter value.
pub const COUNTER_SLOT: u64 = 0;

/// A counter contract: each call increments `storage[COUNTER_SLOT]` and
/// returns the new value.
pub fn counter() -> Vec<Instr> {
    // storage[0] = storage[0] + 1; return storage[0]
    vec![
        Instr::Push(COUNTER_SLOT), // key for the eventual SStore
        Instr::Push(COUNTER_SLOT),
        Instr::SLoad, // [key, count]
        Instr::Push(1),
        Instr::Add,    // [key, count+1]
        Instr::SStore, // storage[0] = count+1
        Instr::Push(COUNTER_SLOT),
        Instr::SLoad,
        Instr::Return,
    ]
}

/// Token selectors (passed as `args[0]`).
pub mod token {
    /// `balanceOf(account=args[1]) -> balance`
    pub const BALANCE_OF: u64 = 0;
    /// `transfer(to=args[1], amount=args[2]) -> 1`, debiting the caller.
    pub const TRANSFER: u64 = 1;
}

/// A minimal fungible-token contract. Balances live in storage keyed by
/// account handle. `transfer` checks the caller's balance and reverts
/// (atomically) on insufficient funds or overflow.
pub fn token_contract() -> Vec<Instr> {
    // Label ids
    const L_BALANCE: u32 = 0;
    const L_TRANSFER: u32 = 1;
    const L_FAIL: u32 = 2;

    assemble(&[
        // dispatch on selector
        Op::I(Instr::Arg(0)),
        Op::I(Instr::Push(token::BALANCE_OF)),
        Op::I(Instr::Eq),
        Op::JumpIf(L_BALANCE),
        Op::I(Instr::Arg(0)),
        Op::I(Instr::Push(token::TRANSFER)),
        Op::I(Instr::Eq),
        Op::JumpIf(L_TRANSFER),
        Op::I(Instr::Abort), // unknown selector
        // balanceOf(args[1]) -> storage[args[1]]
        Op::Label(L_BALANCE),
        Op::I(Instr::Arg(1)),
        Op::I(Instr::SLoad),
        Op::I(Instr::Return),
        // transfer(to=args[1], amount=args[2])
        Op::Label(L_TRANSFER),
        Op::I(Instr::Caller),
        Op::I(Instr::SLoad), // [bal]
        Op::I(Instr::Arg(2)),
        Op::I(Instr::Lt), // bal < amount ?
        Op::JumpIf(L_FAIL),
        // debit: storage[caller] = bal - amount
        Op::I(Instr::Caller),
        Op::I(Instr::Caller),
        Op::I(Instr::SLoad),
        Op::I(Instr::Arg(2)),
        Op::I(Instr::Sub),
        Op::I(Instr::SStore),
        // credit: storage[to] = storage[to] + amount  (checked add reverts on overflow)
        Op::I(Instr::Arg(1)),
        Op::I(Instr::Arg(1)),
        Op::I(Instr::SLoad),
        Op::I(Instr::Arg(2)),
        Op::I(Instr::Add),
        Op::I(Instr::SStore),
        Op::I(Instr::Push(1)),
        Op::I(Instr::Return),
        Op::Label(L_FAIL),
        Op::I(Instr::Abort),
    ])
    .expect("token contract assembles")
}
