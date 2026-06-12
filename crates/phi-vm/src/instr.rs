//! PhiVM instruction set: a small, deterministic stack machine.
//!
//! Operands and storage are `u64`; there are no floats (the classic source of
//! cross-platform consensus divergence). Control flow uses absolute
//! instruction indices, which the assembler ([`crate::asm`]) resolves from
//! labels. Every instruction has a fixed gas cost, so execution always
//! terminates within the gas limit — the determinism-of-termination guarantee
//! a contract VM must provide.

/// A single PhiVM instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instr {
    /// Push a constant.
    Push(u64),
    /// Drop the top of stack.
    Pop,
    /// Duplicate the top of stack.
    Dup,
    /// Swap the top two stack items.
    Swap,

    // Checked integer arithmetic: overflow/underflow traps rather than wraps.
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    // Comparisons push 1 (true) or 0 (false).
    Eq,
    Lt,
    Gt,

    // Boolean logic on 0/non-zero.
    And,
    Or,
    Not,

    /// Unconditional jump to an instruction index.
    Jump(usize),
    /// Pop a condition; jump to an index if it is non-zero.
    JumpIf(usize),

    /// Push call argument `i` (traps if out of range).
    Arg(usize),
    /// Push the caller handle.
    Caller,
    /// Push the figs value attached to the call.
    Value,

    /// Pop a key, push `storage[key]` (0 if absent).
    SLoad,
    /// Pop a value then a key; set `storage[key] = value`.
    SStore,

    /// Halt, returning the top of stack to the caller.
    Return,
    /// Halt with no return value.
    Halt,
    /// Abort: revert all storage writes and fail the call.
    Abort,
}

impl Instr {
    /// Gas charged to execute this instruction. Storage writes are the most
    /// expensive (they grow consensus state); reads cost more than pure stack
    /// ops.
    pub fn gas_cost(&self) -> u64 {
        match self {
            Instr::SStore => 100,
            Instr::SLoad => 20,
            Instr::Mul | Instr::Div | Instr::Mod => 5,
            _ => 1,
        }
    }
}
