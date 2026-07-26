use iced_x86::{
    Code, Decoder, DecoderOptions, FlowControl, Formatter, Instruction, NasmFormatter, OpKind,
};

/// Coarse flow-control classification of an instruction, distilled from
/// iced-x86's finer [`FlowControl`] so the dissector/analysis layer can reason
/// about a function's control flow without depending on iced-x86 types.
///
/// The mapping folds the direct/indirect distinction into the [`Call`]/[`Jump`]
/// kinds — the indirection instead shows up as a `None`
/// [`InstructionData::target`], since only direct near branches carry a
/// resolvable target.
///
/// [`Call`]: FlowKind::Call
/// [`Jump`]: FlowKind::Jump
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    /// Sequential execution — the next instruction runs (iced-x86 `Next`).
    Seq,
    /// A `call` (direct or indirect / near or far).
    Call,
    /// An unconditional `jmp` (direct or indirect / near or far).
    Jump,
    /// A conditional branch: `Jcc`, `LOOP`, `LOOPcc`, `JRCXZ`, ...
    CondJump,
    /// A return: `ret`, `retf`, `iret`, `sysret`, ...
    Ret,
    /// A software breakpoint: `int3` (`0xCC`). A distinct kind because it both
    /// terminates a function walk *and* marks padding between functions.
    Int3,
    /// An interrupt / exception / invalid / anything else not covered above.
    Other,
}

/// Idiomatic, safe Rust struct for the UI to consume.
#[derive(Debug, Clone)]
pub struct InstructionData {
    /// The virtual address of the instruction
    pub address: u64,
    /// The length of the instruction in bytes
    pub length: usize,
    /// The actual bytes that make up the instruction
    pub data: Vec<u8>,
    /// How many bytes are considered "static" (-1 if not determined or invalid)
    pub static_instruction_bytes: i32,
    /// The formatted assembly string (e.g., "mov eax, 1")
    pub instruction: String,
    /// Coarse flow-control class of this instruction (call / jump / ret / ...),
    /// derived from iced-x86's [`FlowControl`]. `Seq` for ordinary instructions.
    pub kind: FlowKind,
    /// The resolved branch/call target for a *direct near* `call`/`jmp`/`jcc`
    /// (`E8`/`E9`/`0F 8x`/`7x` and friends). `None` for indirect targets
    /// (register/memory operands) and for non-branch instructions — those carry
    /// no statically resolvable destination.
    pub target: Option<u64>,
    /// The effective address of a RIP-relative memory operand, e.g. the `[rip+x]`
    /// in `lea rdi, [rip+x]` or `mov rax, [rip+x]` — the common form of a
    /// data/string reference in position-independent code. Used by the dissector
    /// to build cross-reference maps (which strings/data an instruction loads).
    /// `None` for instructions without a RIP-relative memory operand.
    pub mem_target: Option<u64>,
}

/// Maps an iced-x86 [`FlowControl`] to our coarse [`FlowKind`].
///
/// `int3` is special-cased ahead of this (it is `FlowControl::Interrupt`, which
/// we would otherwise fold into `Other`) so a function walk can stop on it.
fn flow_kind_of(instruction: &Instruction) -> FlowKind {
    // `int3` (0xCC) reports as `FlowControl::Interrupt`; surface it as its own
    // kind since it both ends a function and pads the gaps between functions.
    if instruction.code() == Code::Int3 {
        return FlowKind::Int3;
    }

    match instruction.flow_control() {
        FlowControl::Next => FlowKind::Seq,
        FlowControl::Call | FlowControl::IndirectCall => FlowKind::Call,
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => FlowKind::Jump,
        FlowControl::ConditionalBranch => FlowKind::CondJump,
        FlowControl::Return => FlowKind::Ret,
        // `Interrupt` (other than `int3`, handled above), `Exception` (invalid),
        // and `XbeginXabortXend` all fold into `Other` — none is a target the
        // dissector follows, and the catch-all keeps us forward-compatible with
        // any future iced-x86 `FlowControl` variant.
        _ => FlowKind::Other,
    }
}

/// Extracts the direct near-branch target of a `call`/`jmp`/`jcc`, if any.
///
/// Only *direct* near branches carry a statically resolvable destination: their
/// first operand is a `NearBranch16/32/64` immediate. Indirect forms
/// (`call rax`, `jmp [rip+x]`) put a register/memory operand there instead, so
/// we return `None` — iced-x86's [`Instruction::near_branch_target`] would
/// report `0` for those, which is indistinguishable from a legitimate target.
fn near_branch_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        _ => None,
    }
}

/// Extracts the effective address of a RIP-relative memory operand, if any.
///
/// `lea reg, [rip+disp]` / `mov reg, [rip+disp]` and friends encode a
/// data/string reference relative to the *next* instruction's address; iced-x86
/// resolves it for us. Non-RIP memory operands (base/index register forms) have
/// no statically resolvable address, so we return `None`.
fn ip_rel_memory_target(instruction: &Instruction) -> Option<u64> {
    instruction
        .is_ip_rel_memory_operand()
        .then(|| instruction.ip_rel_memory_address())
}

fn are_operands_static(instruction: &Instruction) -> bool {
    // Check for unconditional and conditional branches. Kept as nested `if`s
    // (not collapsed) to mirror the two distinct conditions being reasoned about.
    #[allow(clippy::collapsible_if)]
    if instruction.is_jcc_short_or_near() || instruction.is_jmp_short_or_near() {
        if instruction.len() < 5 {
            return true;
        }
    }

    for i in 0..instruction.op_count() {
        // The final `_ =>` arm is a deliberate, defensive catch-all: `OpKind` is
        // `#[non_exhaustive]`-in-spirit and iced-x86 adds variants across
        // versions, so a future kind must default to "not static" rather than
        // silently fall through. `unreachable_patterns` fires only because the
        // current enum happens to be fully covered above.
        #[allow(unreachable_patterns)]
        match instruction.op_kind(i) {
            // Static length operands
            OpKind::Register
            | OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            // String instruction memory operands (no dynamic displacement)
            | OpKind::MemorySegSI
            | OpKind::MemorySegESI
            | OpKind::MemorySegRSI
            | OpKind::MemorySegDI
            | OpKind::MemorySegEDI
            | OpKind::MemorySegRDI
            | OpKind::MemoryESDI
            | OpKind::MemoryESEDI
            | OpKind::MemoryESRDI => continue,

            // Dynamic length immediates
            OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => return false,

            OpKind::Memory => {
                if instruction.memory_displ_size() < 4 {
                    continue;
                }

                // On x64, RIP-relative memory references are often considered static
                // relative to the instruction block.
                #[cfg(target_pointer_width = "64")]
                if instruction.is_ip_rel_memory_operand() {
                    continue;
                }

                return false;
            }

            // Dynamic branches
            OpKind::NearBranch16
            | OpKind::NearBranch32
            | OpKind::NearBranch64
            | OpKind::FarBranch16
            | OpKind::FarBranch32 => return false,

            _ => return false,
        }
    }

    true
}

fn get_static_instruction_bytes(instruction: &Instruction) -> i32 {
    if are_operands_static(instruction) {
        return instruction.len() as i32;
    }

    let mut dynamic_bytes = 0;
    for i in 0..instruction.op_count() {
        match instruction.op_kind(i) {
            OpKind::Memory => {
                // For RIP/EIP-relative operands iced reports an 8-byte
                // `memory_displ_size` (the effective-address width) even though
                // only a 4-byte displacement is actually encoded. Counting 8
                // here would over-count and underflow the subtraction below.
                if instruction.is_ip_rel_memory_operand() {
                    dynamic_bytes += 4;
                } else {
                    dynamic_bytes += instruction.memory_displ_size();
                }
            }
            OpKind::Immediate32 | OpKind::Immediate32to64 => {
                dynamic_bytes += 4;
            }
            OpKind::Immediate64 => {
                dynamic_bytes += 8;
            }
            OpKind::NearBranch32 | OpKind::FarBranch32 => {
                dynamic_bytes += 4;
            }
            _ => {}
        }
    }

    // Saturating: a mis-sized displacement/immediate estimate must never panic
    // the disassembly loop — clamp to zero static bytes instead.
    (instruction.len() as u32).saturating_sub(dynamic_bytes) as i32
}

/// Disassembles a safe slice of bytes.
///
/// `code`: The machine code to disassemble.
/// `virtual_address`: The base address where this code conceptually lives in memory.
/// `determine_static_bytes`: Whether to calculate static vs dynamic byte length.
/// `callback`: A closure called for each instruction. If it returns `false`, disassembly stops.
/// Decode instructions from `code` (starting at `virtual_address`) covering at
/// least `min_len` bytes, returning a per-byte "wildcard" mask: `true` where the
/// byte is part of a displacement or immediate operand (i.e. it varies with
/// relocation / base) and `false` for opcode/modrm/prefix bytes.
///
/// This is the basis for robust AOB signature generation: wildcarding the
/// operand bytes yields a pattern that survives a rebased image, where an
/// exact-byte signature would break. The returned mask length is the sum of the
/// decoded instruction lengths (≥ `min_len`, or shorter if the code runs out /
/// an invalid instruction is hit).
pub fn operand_wildcard_mask(code: &[u8], virtual_address: u64, min_len: usize) -> Vec<bool> {
    let bitness = if cfg!(target_pointer_width = "64") { 64 } else { 32 };
    let mut decoder = Decoder::with_ip(bitness, code, virtual_address, DecoderOptions::NONE);
    let mut mask: Vec<bool> = Vec::new();
    let mut instruction = Instruction::default();

    while decoder.can_decode() && mask.len() < min_len {
        decoder.decode_out(&mut instruction);
        let len = instruction.len();
        if instruction.is_invalid() && len == 0 {
            break;
        }
        let co = decoder.get_constant_offsets(&instruction);
        let mut instr_mask = vec![false; len];
        let mut wildcard = |off: usize, size: usize| {
            for b in instr_mask.iter_mut().skip(off).take(size) {
                *b = true;
            }
        };
        if co.has_displacement() {
            wildcard(co.displacement_offset(), co.displacement_size());
        }
        if co.has_immediate() {
            wildcard(co.immediate_offset(), co.immediate_size());
        }
        if co.has_immediate2() {
            wildcard(co.immediate_offset2(), co.immediate_size2());
        }
        mask.extend(instr_mask);
    }
    mask
}

/// Generate a **robust** AOB signature for the code at `offset` in `haystack` (a
/// module image), wildcarding operand bytes via [`operand_wildcard_mask`] so the
/// signature survives a rebased image. Returns an IDA-style string with `??` for
/// wildcarded bytes (e.g. `"48 8B 05 ?? ?? ?? ?? C3"`) that is unique within
/// `haystack`, or `None` if no unique masked run exists within `max_len`.
///
/// Uniqueness is found by candidate narrowing seeded on the (exact) opcode byte,
/// so it stays close to O(n) rather than O(n·len²).
pub fn make_masked_signature(
    haystack: &[u8],
    offset: usize,
    min_len: usize,
    max_len: usize,
) -> Option<String> {
    if offset >= haystack.len() {
        return None;
    }
    let max_len = max_len.min(haystack.len() - offset);
    let full_mask = operand_wildcard_mask(&haystack[offset..], offset as u64, max_len);
    if full_mask.is_empty() {
        return None;
    }
    let span = full_mask.len();
    let needle = &haystack[offset..offset + span];
    let last_start = haystack.len() - span;

    // Seed on the first byte when it's exact (an opcode/prefix — almost always).
    let mut candidates: Vec<usize> = if full_mask[0] {
        (0..=last_start).collect()
    } else {
        let b0 = needle[0];
        (0..=last_start).filter(|&p| haystack[p] == b0).collect()
    };

    let mut len = 1usize;
    loop {
        let i = len - 1;
        if !full_mask[i] {
            let bi = needle[i];
            candidates.retain(|&p| haystack[p + i] == bi);
        }
        let unique = candidates.len() == 1 && candidates[0] == offset;
        if unique && len >= min_len {
            return Some(format_masked(&needle[..len], &full_mask[..len]));
        }
        if len >= span {
            return unique.then(|| format_masked(&needle[..len], &full_mask[..len]));
        }
        len += 1;
    }
}

/// Scan `code` (mapped at `virtual_address`) for instructions whose direct
/// branch target or RIP-relative memory target equals `target`, returning the
/// addresses of those instructions. This is the basis for "find references to
/// this address / function" — call it over a module's executable regions.
pub fn find_code_refs(code: &[u8], virtual_address: u64, target: u64) -> Vec<u64> {
    let mut refs = Vec::new();
    disassemble_instructions(code, virtual_address, false, |ins| {
        if ins.target == Some(target) || ins.mem_target == Some(target) {
            refs.push(ins.address);
        }
        true // keep scanning the whole range
    });
    refs
}

/// Format a byte slice as an IDA hex signature, emitting `??` where `mask[i]`.
fn format_masked(bytes: &[u8], mask: &[bool]) -> String {
    bytes
        .iter()
        .zip(mask)
        .map(|(&b, &m)| if m { "??".to_string() } else { format!("{b:02X}") })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn disassemble_instructions<F>(
    code: &[u8],
    virtual_address: u64,
    determine_static_bytes: bool,
    mut callback: F,
) where
    F: FnMut(InstructionData) -> bool,
{
    if code.is_empty() {
        return;
    }

    let bitness = if cfg!(target_pointer_width = "64") {
        64
    } else {
        32
    };

    let mut decoder = Decoder::with_ip(bitness, code, virtual_address, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);

    // Track our position in the `code` slice to extract the raw bytes safely
    let mut offset = 0;

    while decoder.can_decode() {
        let mut instruction = Instruction::default();
        decoder.decode_out(&mut instruction);

        let len = instruction.len();

        // Fail-safe to prevent infinite loops on completely unreadable memory
        if instruction.is_invalid() && len == 0 {
            break;
        }

        // Safely extract the exact bytes for this instruction from the slice
        let instruction_bytes = if offset + len <= code.len() {
            &code[offset..offset + len]
        } else {
            &code[offset..]
        };

        let (instruction_str, static_bytes, kind, target, mem_target) = if instruction.is_invalid()
        {
            // An invalid decode carries no meaningful flow: `Other`, no target.
            (String::from("???"), -1, FlowKind::Other, None, None)
        } else {
            let mut formatted_str = String::new();
            formatter.format(&instruction, &mut formatted_str);

            let static_b = if determine_static_bytes {
                get_static_instruction_bytes(&instruction)
            } else {
                -1
            };

            (
                formatted_str,
                static_b,
                flow_kind_of(&instruction),
                near_branch_target(&instruction),
                ip_rel_memory_target(&instruction),
            )
        };

        let data = InstructionData {
            address: instruction.ip(),
            length: len,
            data: instruction_bytes.to_vec(),
            static_instruction_bytes: static_bytes,
            instruction: instruction_str,
            kind,
            target,
            mem_target,
        };

        // Pass to the UI/caller closure. Stop if it returns false.
        if !callback(data) {
            break;
        }

        offset += len;

        if offset >= code.len() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VA: u64 = 0x1000;

    /// Decodes exactly one instruction at [`VA`] and returns its
    /// [`InstructionData`]. Panics if `code` yields no instruction.
    fn decode_one(code: &[u8]) -> InstructionData {
        let mut out = None;
        disassemble_instructions(code, VA, false, |ins| {
            out = Some(ins);
            false // stop after the first instruction
        });
        out.expect("expected one decoded instruction")
    }

    #[test]
    fn find_code_refs_locates_a_call_to_target() {
        // At VA (0x1000): `call rel32` where rel32 = 0x2000 - (0x1000+5) = 0xFFB,
        // so the call targets 0x2000. Pad with NOPs that reference nothing.
        let code = [
            0xE8, 0xFB, 0x0F, 0x00, 0x00, // call 0x2000
            0x90, 0x90, 0x90, // nops
        ];
        let refs = find_code_refs(&code, VA, 0x2000);
        assert_eq!(refs, vec![VA]);
        // No references to an unrelated address.
        assert!(find_code_refs(&code, VA, 0xDEAD).is_empty());
    }

    #[test]
    fn operand_wildcard_mask_flags_displacement() {
        // 48 8B 05 <disp32> = mov rax, [rip+disp32] (7 bytes). The 4 displacement
        // bytes (offset 3..7) must be wildcarded; the opcode/modrm must not.
        let code = [0x48, 0x8B, 0x05, 0xDE, 0xAD, 0xBE, 0xEF];
        let mask = operand_wildcard_mask(&code, VA, code.len());
        assert_eq!(mask, vec![false, false, false, true, true, true, true]);
    }

    #[test]
    fn masked_signature_wildcards_call_rel32() {
        // The most common signature target: a call site. The rel32 (an immediate)
        // must be wildcarded so the signature survives a rebased image.
        let mut buf = vec![0u8; 128];
        let instr = [0xE8, 0x11, 0x22, 0x33, 0x44, 0xC3]; // call rel32; ret
        buf[50..50 + instr.len()].copy_from_slice(&instr);
        let sig = make_masked_signature(&buf, 50, 6, 32).expect("signature");
        assert!(sig.starts_with("E8 ?? ?? ?? ??"), "sig = {sig}");
    }

    #[test]
    fn make_masked_signature_wildcards_operands_and_is_unique() {
        // Build a haystack: the rip-relative mov (with a distinctive opcode run)
        // followed by a ret, embedded in zero padding so it's locally unique.
        let mut buf = vec![0u8; 128];
        let instr = [0x48, 0x8B, 0x05, 0x11, 0x22, 0x33, 0x44, 0xC3];
        buf[40..40 + instr.len()].copy_from_slice(&instr);

        // min_len 8 forces the full mov+ret so the displacement masking shows.
        let sig = make_masked_signature(&buf, 40, 8, 32).expect("signature");
        // The displacement bytes must be wildcards; the opcode bytes exact.
        assert!(sig.starts_with("48 8B 05 ?? ?? ?? ??"), "sig = {sig}");
        // And it must not contain the literal displacement bytes.
        assert!(!sig.contains("11 22 33 44"), "operands should be masked: {sig}");
    }

    #[test]
    fn call_rel32_is_call_with_direct_target() {
        // E8 00000000: `call rel32` with rel = 0 → target = ip + len (5).
        let ins = decode_one(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(ins.kind, FlowKind::Call);
        assert_eq!(ins.length, 5);
        assert_eq!(ins.target, Some(VA + 5));
    }

    #[test]
    fn jmp_rel32_is_jump_with_direct_target() {
        // E9 00000000: `jmp rel32` with rel = 0 → target = ip + len (5).
        let ins = decode_one(&[0xE9, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(ins.kind, FlowKind::Jump);
        assert_eq!(ins.length, 5);
        assert_eq!(ins.target, Some(VA + 5));
    }

    #[test]
    fn jcc_near_is_cond_jump_with_direct_target() {
        // 0F 84 00000000: `je rel32` (near) with rel = 0 → target = ip + len (6).
        let ins = decode_one(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(ins.kind, FlowKind::CondJump);
        assert_eq!(ins.length, 6);
        assert_eq!(ins.target, Some(VA + 6));
    }

    #[test]
    fn jcc_short_is_cond_jump_with_direct_target() {
        // 74 00: `je rel8` (short) with rel = 0 → target = ip + len (2).
        let ins = decode_one(&[0x74, 0x00]);
        assert_eq!(ins.kind, FlowKind::CondJump);
        assert_eq!(ins.length, 2);
        assert_eq!(ins.target, Some(VA + 2));
    }

    #[test]
    fn ret_is_ret_without_target() {
        // C3: `ret`.
        let ins = decode_one(&[0xC3]);
        assert_eq!(ins.kind, FlowKind::Ret);
        assert_eq!(ins.target, None);
    }

    #[test]
    fn int3_is_int3_without_target() {
        // CC: `int3`. Reported as its own kind, not `Other`.
        let ins = decode_one(&[0xCC]);
        assert_eq!(ins.kind, FlowKind::Int3);
        assert_eq!(ins.target, None);
    }

    #[test]
    fn mov_is_sequential_without_target() {
        // B8 01000000: `mov eax, 1` — ordinary sequential instruction.
        let ins = decode_one(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(ins.kind, FlowKind::Seq);
        assert_eq!(ins.target, None);
    }

    #[test]
    fn indirect_call_is_call_without_target() {
        // FF D0: `call rax` — indirect, so it is a Call but has no static target.
        let ins = decode_one(&[0xFF, 0xD0]);
        assert_eq!(ins.kind, FlowKind::Call);
        assert_eq!(ins.target, None);
    }

    #[test]
    fn lea_rip_relative_yields_mem_target() {
        // 48 8D 05 78 56 34 12: `lea rax, [rip+0x12345678]`.
        // Effective address = next-insn IP (VA + 7) + disp (0x12345678).
        let ins = decode_one(&[0x48, 0x8D, 0x05, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(ins.length, 7);
        assert_eq!(ins.mem_target, Some(VA + 7 + 0x1234_5678));
        // A data reference is not a branch.
        assert_eq!(ins.target, None);
    }

    #[test]
    fn register_operand_has_no_mem_target() {
        // B8 01000000: `mov eax, 1` — no memory operand.
        let ins = decode_one(&[0xB8, 0x01, 0x00, 0x00, 0x00]);
        assert_eq!(ins.mem_target, None);
    }
}
