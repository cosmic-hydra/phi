//! The PhiVM execution engine: a bounded, deterministic interpreter.

use std::collections::BTreeMap;

use crate::instr::Instr;

/// Maximum operand-stack depth. Bounds per-call memory independently of gas.
pub const MAX_STACK: usize = 1024;

/// Inputs to a contract call.
#[derive(Clone, Debug, Default)]
pub struct CallContext {
    /// A stable handle for the calling account (the integration layer derives
    /// it from the caller's `AccountId`; see crate docs).
    pub caller: u64,
    /// Figs attached to the call.
    pub value: u64,
    /// Call arguments (e.g. `[selector, arg0, arg1, ...]`).
    pub args: Vec<u64>,
}

/// Why a contract call aborted. Every variant reverts all storage writes —
/// the call is atomic, like an EVM revert.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Trap {
    /// Ran out of gas.
    OutOfGas,
    /// Operand stack exceeded [`MAX_STACK`].
    StackOverflow,
    /// Popped from an empty stack.
    StackUnderflow,
    /// Division or modulo by zero.
    DivByZero,
    /// Checked arithmetic overflowed/underflowed.
    Overflow,
    /// Jump target outside the code.
    InvalidJump,
    /// `Arg(i)` with `i` past the supplied arguments.
    BadArg,
    /// Executed the `Abort` instruction.
    Aborted,
}

/// Result of a successful call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// Value returned via `Return`, if any.
    pub return_value: Option<u64>,
    /// Total gas consumed.
    pub gas_used: u64,
}

/// Execute `code` against `storage`, mutating it in place. Returns the call
/// outcome, or a [`Trap`] (in which case the caller is responsible for
/// discarding any storage changes — see [`crate::Contract::call`], which makes
/// the call atomic).
///
/// Deterministic: integer-only, ordered `BTreeMap` storage, no host
/// nondeterminism, and bounded by `gas_limit` and [`MAX_STACK`].
pub fn execute(
    code: &[Instr],
    storage: &mut BTreeMap<u64, u64>,
    ctx: &CallContext,
    gas_limit: u64,
) -> Result<Outcome, Trap> {
    let mut stack: Vec<u64> = Vec::new();
    let mut pc: usize = 0;
    let mut gas_used: u64 = 0;

    macro_rules! pop {
        () => {
            stack.pop().ok_or(Trap::StackUnderflow)?
        };
    }
    macro_rules! push {
        ($v:expr) => {{
            if stack.len() >= MAX_STACK {
                return Err(Trap::StackOverflow);
            }
            stack.push($v);
        }};
    }

    while pc < code.len() {
        let instr = &code[pc];

        // Charge gas before executing; a step you can't afford traps.
        let cost = instr.gas_cost();
        if gas_used + cost > gas_limit {
            return Err(Trap::OutOfGas);
        }
        gas_used += cost;

        // Default: advance to the next instruction. Jumps override `next_pc`.
        let mut next_pc = pc + 1;

        match instr {
            Instr::Push(v) => push!(*v),
            Instr::Pop => {
                pop!();
            }
            Instr::Dup => {
                let v = *stack.last().ok_or(Trap::StackUnderflow)?;
                push!(v);
            }
            Instr::Swap => {
                let n = stack.len();
                if n < 2 {
                    return Err(Trap::StackUnderflow);
                }
                stack.swap(n - 1, n - 2);
            }
            Instr::Add => {
                let (b, a) = (pop!(), pop!());
                push!(a.checked_add(b).ok_or(Trap::Overflow)?);
            }
            Instr::Sub => {
                let (b, a) = (pop!(), pop!());
                push!(a.checked_sub(b).ok_or(Trap::Overflow)?);
            }
            Instr::Mul => {
                let (b, a) = (pop!(), pop!());
                push!(a.checked_mul(b).ok_or(Trap::Overflow)?);
            }
            Instr::Div => {
                let (b, a) = (pop!(), pop!());
                push!(a.checked_div(b).ok_or(Trap::DivByZero)?);
            }
            Instr::Mod => {
                let (b, a) = (pop!(), pop!());
                push!(a.checked_rem(b).ok_or(Trap::DivByZero)?);
            }
            Instr::Eq => {
                let (b, a) = (pop!(), pop!());
                push!((a == b) as u64);
            }
            Instr::Lt => {
                let (b, a) = (pop!(), pop!());
                push!((a < b) as u64);
            }
            Instr::Gt => {
                let (b, a) = (pop!(), pop!());
                push!((a > b) as u64);
            }
            Instr::And => {
                let (b, a) = (pop!(), pop!());
                push!((a != 0 && b != 0) as u64);
            }
            Instr::Or => {
                let (b, a) = (pop!(), pop!());
                push!((a != 0 || b != 0) as u64);
            }
            Instr::Not => {
                let a = pop!();
                push!((a == 0) as u64);
            }
            Instr::Jump(target) => {
                if *target >= code.len() {
                    return Err(Trap::InvalidJump);
                }
                next_pc = *target;
            }
            Instr::JumpIf(target) => {
                let cond = pop!();
                if cond != 0 {
                    if *target >= code.len() {
                        return Err(Trap::InvalidJump);
                    }
                    next_pc = *target;
                }
            }
            Instr::Arg(i) => {
                let v = *ctx.args.get(*i).ok_or(Trap::BadArg)?;
                push!(v);
            }
            Instr::Caller => push!(ctx.caller),
            Instr::Value => push!(ctx.value),
            Instr::SLoad => {
                let key = pop!();
                push!(storage.get(&key).copied().unwrap_or(0));
            }
            Instr::SStore => {
                let value = pop!();
                let key = pop!();
                storage.insert(key, value);
            }
            Instr::Return => {
                let v = pop!();
                return Ok(Outcome {
                    return_value: Some(v),
                    gas_used,
                });
            }
            Instr::Halt => {
                return Ok(Outcome {
                    return_value: None,
                    gas_used,
                });
            }
            Instr::Abort => return Err(Trap::Aborted),
        }

        pc = next_pc;
    }

    // Ran off the end: equivalent to Halt.
    Ok(Outcome {
        return_value: None,
        gas_used,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(code: &[Instr], gas: u64) -> Result<Outcome, Trap> {
        execute(code, &mut BTreeMap::new(), &CallContext::default(), gas)
    }

    #[test]
    fn arithmetic_and_return() {
        // (2 + 3) * 4 = 20
        let code = vec![
            Instr::Push(2),
            Instr::Push(3),
            Instr::Add,
            Instr::Push(4),
            Instr::Mul,
            Instr::Return,
        ];
        assert_eq!(run(&code, 1000).unwrap().return_value, Some(20));
    }

    #[test]
    fn out_of_gas_halts_infinite_loop() {
        // Jump(0) forever — gas is the termination guarantee.
        let code = vec![Instr::Jump(0)];
        assert_eq!(run(&code, 1000), Err(Trap::OutOfGas));
    }

    #[test]
    fn checked_arithmetic_traps() {
        assert_eq!(
            run(&[Instr::Push(1), Instr::Push(0), Instr::Div], 100),
            Err(Trap::DivByZero)
        );
        assert_eq!(
            run(&[Instr::Push(u64::MAX), Instr::Push(1), Instr::Add], 100),
            Err(Trap::Overflow)
        );
        assert_eq!(
            run(&[Instr::Push(0), Instr::Push(1), Instr::Sub], 100),
            Err(Trap::Overflow)
        );
    }

    #[test]
    fn stack_underflow_and_overflow_trap() {
        assert_eq!(run(&[Instr::Add], 100), Err(Trap::StackUnderflow));
        // Dup forever overflows the stack before anything else.
        let code = vec![Instr::Push(1), Instr::Dup, Instr::Jump(1)];
        assert_eq!(run(&code, 1_000_000), Err(Trap::StackOverflow));
    }

    #[test]
    fn invalid_jump_traps() {
        assert_eq!(run(&[Instr::Jump(99)], 100), Err(Trap::InvalidJump));
    }

    #[test]
    fn storage_round_trips() {
        let mut storage = BTreeMap::new();
        // storage[7] = 42
        let store = vec![Instr::Push(7), Instr::Push(42), Instr::SStore, Instr::Halt];
        execute(&store, &mut storage, &CallContext::default(), 1000).unwrap();
        assert_eq!(storage.get(&7), Some(&42));
        // load it back
        let load = vec![Instr::Push(7), Instr::SLoad, Instr::Return];
        let out = execute(&load, &mut storage, &CallContext::default(), 1000).unwrap();
        assert_eq!(out.return_value, Some(42));
    }

    #[test]
    fn conditional_branch() {
        // if arg0 != 0 { return 111 } else { return 222 }
        let code = vec![
            Instr::Arg(0),    // 0
            Instr::JumpIf(4), // 1 -> to 4 if true
            Instr::Push(222), // 2
            Instr::Return,    // 3
            Instr::Push(111), // 4
            Instr::Return,    // 5
        ];
        let truthy = execute(
            &code,
            &mut BTreeMap::new(),
            &CallContext {
                args: vec![1],
                ..Default::default()
            },
            100,
        )
        .unwrap();
        assert_eq!(truthy.return_value, Some(111));
        let falsy = execute(
            &code,
            &mut BTreeMap::new(),
            &CallContext {
                args: vec![0],
                ..Default::default()
            },
            100,
        )
        .unwrap();
        assert_eq!(falsy.return_value, Some(222));
    }

    #[test]
    fn bad_arg_traps() {
        assert_eq!(
            execute(
                &[Instr::Arg(5)],
                &mut BTreeMap::new(),
                &CallContext::default(),
                100
            ),
            Err(Trap::BadArg)
        );
    }

    #[test]
    fn gas_used_is_reported_and_deterministic() {
        let code = vec![Instr::Push(1), Instr::Push(2), Instr::Add, Instr::Return];
        let a = run(&code, 100).unwrap();
        let b = run(&code, 100).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.gas_used, 4); // 3 pushes/add at 1 each + return
    }
}
