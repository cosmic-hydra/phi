//! A tiny label-resolving assembler, so contracts can be written with named
//! jump targets instead of hand-counted instruction indices.

use crate::instr::Instr;

/// An assembler operation: either a literal instruction, a label definition,
/// or a jump to a label (resolved to an absolute index by [`assemble`]).
#[derive(Clone, Debug)]
pub enum Op {
    /// A literal instruction. Use [`Op::Jump`]/[`Op::JumpIf`] for control flow
    /// rather than `Instr::Jump`/`Instr::JumpIf` directly.
    I(Instr),
    /// Define label `id` at the current position (emits no instruction).
    Label(u32),
    /// Unconditional jump to label `id`.
    Jump(u32),
    /// Conditional jump to label `id` (pops a condition).
    JumpIf(u32),
}

/// Assembly errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsmError {
    DuplicateLabel(u32),
    UndefinedLabel(u32),
}

/// Resolve labels and produce executable bytecode.
pub fn assemble(ops: &[Op]) -> Result<Vec<Instr>, AsmError> {
    // First pass: map each label to the index of the next emitted instruction.
    let mut label_at: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
    let mut index = 0usize;
    for op in ops {
        match op {
            Op::Label(id) => {
                if label_at.insert(*id, index).is_some() {
                    return Err(AsmError::DuplicateLabel(*id));
                }
            }
            _ => index += 1,
        }
    }

    // Second pass: emit, resolving jump targets.
    let mut code = Vec::with_capacity(index);
    for op in ops {
        match op {
            Op::I(instr) => code.push(instr.clone()),
            Op::Label(_) => {}
            Op::Jump(id) => {
                let target = *label_at.get(id).ok_or(AsmError::UndefinedLabel(*id))?;
                code.push(Instr::Jump(target));
            }
            Op::JumpIf(id) => {
                let target = *label_at.get(id).ok_or(AsmError::UndefinedLabel(*id))?;
                code.push(Instr::JumpIf(target));
            }
        }
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_forward_and_backward_labels() {
        // Jump forward over a Push, land on a label.
        let code = assemble(&[
            Op::Jump(1),
            Op::I(Instr::Push(99)),
            Op::Label(1),
            Op::I(Instr::Push(7)),
            Op::I(Instr::Return),
        ])
        .unwrap();
        // Emitted: [Jump, Push(99), Push(7), Return]. Label(1) is at index 2.
        assert_eq!(
            code,
            vec![
                Instr::Jump(2),
                Instr::Push(99),
                Instr::Push(7),
                Instr::Return,
            ]
        );
    }

    #[test]
    fn undefined_and_duplicate_labels_error() {
        assert_eq!(assemble(&[Op::Jump(5)]), Err(AsmError::UndefinedLabel(5)));
        assert_eq!(
            assemble(&[Op::Label(1), Op::Label(1)]),
            Err(AsmError::DuplicateLabel(1))
        );
    }
}
