//! A deployed contract: code plus persistent storage, with atomic calls.

use std::collections::BTreeMap;

use phi_types::Hash;

use crate::instr::Instr;
use crate::vm::{execute, CallContext, Outcome, Trap};

/// A contract instance: immutable `code` and mutable `storage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    pub code: Vec<Instr>,
    pub storage: BTreeMap<u64, u64>,
}

impl Contract {
    /// A fresh contract with empty storage.
    pub fn new(code: Vec<Instr>) -> Self {
        Self {
            code,
            storage: BTreeMap::new(),
        }
    }

    /// Content hash of the code — a deterministic contract-class identity the
    /// integration layer can use as (part of) a contract address.
    pub fn code_hash(&self) -> Hash {
        let mut bytes = Vec::new();
        for instr in &self.code {
            encode_instr(instr, &mut bytes);
        }
        Hash::of_tagged(b"phi:vm:code", &[&bytes])
    }

    /// Execute a call **atomically**: if it traps, all storage writes are
    /// reverted, exactly as if the call never ran (EVM-style revert). On
    /// success the storage mutations persist and the outcome is returned.
    pub fn call(&mut self, ctx: &CallContext, gas_limit: u64) -> Result<Outcome, Trap> {
        let snapshot = self.storage.clone();
        match execute(&self.code, &mut self.storage, ctx, gas_limit) {
            Ok(outcome) => Ok(outcome),
            Err(trap) => {
                self.storage = snapshot; // revert
                Err(trap)
            }
        }
    }
}

/// Deterministic byte encoding of one instruction (tag + operands), for the
/// code hash. Distinct opcodes get distinct tags, and operands are
/// little-endian, so the encoding is injective.
fn encode_instr(instr: &Instr, out: &mut Vec<u8>) {
    match instr {
        Instr::Push(v) => {
            out.push(0x01);
            out.extend_from_slice(&v.to_le_bytes());
        }
        Instr::Pop => out.push(0x02),
        Instr::Dup => out.push(0x03),
        Instr::Swap => out.push(0x04),
        Instr::Add => out.push(0x10),
        Instr::Sub => out.push(0x11),
        Instr::Mul => out.push(0x12),
        Instr::Div => out.push(0x13),
        Instr::Mod => out.push(0x14),
        Instr::Eq => out.push(0x20),
        Instr::Lt => out.push(0x21),
        Instr::Gt => out.push(0x22),
        Instr::And => out.push(0x23),
        Instr::Or => out.push(0x24),
        Instr::Not => out.push(0x25),
        Instr::Jump(t) => {
            out.push(0x30);
            out.extend_from_slice(&(*t as u64).to_le_bytes());
        }
        Instr::JumpIf(t) => {
            out.push(0x31);
            out.extend_from_slice(&(*t as u64).to_le_bytes());
        }
        Instr::Arg(i) => {
            out.push(0x40);
            out.extend_from_slice(&(*i as u64).to_le_bytes());
        }
        Instr::Caller => out.push(0x41),
        Instr::Value => out.push(0x42),
        Instr::SLoad => out.push(0x50),
        Instr::SStore => out.push(0x51),
        Instr::Return => out.push(0x60),
        Instr::Halt => out.push(0x61),
        Instr::Abort => out.push(0x62),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trap_reverts_storage() {
        // Write storage[1]=5, then Abort. The write must not persist.
        let code = vec![Instr::Push(1), Instr::Push(5), Instr::SStore, Instr::Abort];
        let mut c = Contract::new(code);
        assert_eq!(c.call(&CallContext::default(), 1000), Err(Trap::Aborted));
        assert!(c.storage.is_empty(), "aborted call must revert writes");
    }

    #[test]
    fn success_persists_storage() {
        let code = vec![Instr::Push(1), Instr::Push(5), Instr::SStore, Instr::Halt];
        let mut c = Contract::new(code);
        assert!(c.call(&CallContext::default(), 1000).is_ok());
        assert_eq!(c.storage.get(&1), Some(&5));
    }

    #[test]
    fn code_hash_is_stable_and_distinguishes_code() {
        let a = Contract::new(vec![Instr::Push(1), Instr::Return]);
        let b = Contract::new(vec![Instr::Push(2), Instr::Return]);
        assert_eq!(
            a.code_hash(),
            Contract::new(vec![Instr::Push(1), Instr::Return]).code_hash()
        );
        assert_ne!(a.code_hash(), b.code_hash());
    }
}
