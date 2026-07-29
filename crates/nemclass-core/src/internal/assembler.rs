//! A text assembler for x86-64 patching.
//!
//! `iced-x86` decodes, and it *builds* instructions programmatically, but it has
//! no text assembler — there is no `assemble("mov rax, 1")` anywhere in its API,
//! and none in the Rust ecosystem's other x86 crates either. So writing a patch
//! meant typing raw bytes.
//!
//! This parses the subset of x86-64 that patching actually uses: the flow
//! control you redirect (`jmp`, `call`, the conditional jumps), the register and
//! memory moves you use to force a value, the arithmetic and comparisons you
//! neutralise, and the stack ops a trampoline needs. It is deliberately **not** a
//! complete assembler — an unrecognised mnemonic is a clear error naming what
//! was not understood, not a wrong encoding.
//!
//! Branch targets are absolute addresses; the encoder resolves them against the
//! address the code is being assembled *at*, so `jmp 0x401000` written at
//! `0x400000` emits the right displacement.

use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Instruction, InstructionBlock, MemoryOperand,
    Register,
};

/// Why a line could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsmError {
    /// The mnemonic is not in the supported subset.
    UnknownMnemonic(String),
    /// The mnemonic is supported but not with these operands.
    BadOperands { mnemonic: String, detail: String },
    /// An operand could not be parsed at all.
    BadOperand(String),
    /// The instruction is supported but the encoder rejected it.
    Encode(String),
    /// Nothing to assemble.
    Empty,
}

impl core::fmt::Display for AsmError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownMnemonic(m) => write!(
                f,
                "'{m}' is not one of the instructions this assembler understands"
            ),
            Self::BadOperands { mnemonic, detail } => {
                write!(f, "{mnemonic}: {detail}")
            }
            Self::BadOperand(o) => write!(f, "'{o}' is not a register, number or [memory] operand"),
            Self::Encode(e) => write!(f, "the encoder rejected the instruction: {e}"),
            Self::Empty => write!(f, "nothing to assemble"),
        }
    }
}

impl std::error::Error for AsmError {}

/// One assembled run of instructions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    /// The encoded bytes.
    pub bytes: Vec<u8>,
    /// How many instructions were encoded.
    pub count: usize,
}

/// Assemble `source` as if it were placed at `ip`.
///
/// Statements are separated by newlines or `;`. `ip` matters: a relative branch
/// is encoded as a displacement from the instruction that follows it, so the
/// same text assembles to different bytes at different addresses.
pub fn assemble(source: &str, ip: u64) -> Result<Assembled, AsmError> {
    let mut instructions = Vec::new();
    for statement in source.split(['\n', ';']) {
        // Everything after a `#` is a comment, so a patch can be annotated.
        let statement = statement.split('#').next().unwrap_or("").trim();
        if statement.is_empty() {
            continue;
        }
        instructions.push(parse_statement(statement)?);
    }
    if instructions.is_empty() {
        return Err(AsmError::Empty);
    }
    let count = instructions.len();

    let block = InstructionBlock::new(&instructions, ip);
    let encoded = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(|e| AsmError::Encode(e.to_string()))?;
    Ok(Assembled { bytes: encoded.code_buffer, count })
}

/// The number of bytes `source` assembles to at `ip`, without keeping them.
///
/// Used to check a patch fits before anything is written.
pub fn assembled_len(source: &str, ip: u64) -> Result<usize, AsmError> {
    Ok(assemble(source, ip)?.bytes.len())
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// A parsed operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    Reg(Register),
    Imm(i64),
    /// `[base + displacement]`, with `base` optionally absent for `[0x1000]`.
    Mem { base: Register, displacement: i64 },
}

fn parse_statement(statement: &str) -> Result<Instruction, AsmError> {
    let (mnemonic, rest) = match statement.split_once(char::is_whitespace) {
        Some((m, r)) => (m.to_ascii_lowercase(), r.trim()),
        None => (statement.to_ascii_lowercase(), ""),
    };

    // The mnemonic is checked first. Parsing operands first meant an AVX
    // instruction was reported as "'xmm0' is not a register" — technically true
    // of this assembler, but it names the wrong thing: the register is fine, the
    // instruction is the part that is not supported.
    if !is_supported(&mnemonic) {
        return Err(AsmError::UnknownMnemonic(mnemonic));
    }

    let operands: Vec<Operand> = if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(',')
            .map(|o| parse_operand(o.trim()))
            .collect::<Result<_, _>>()?
    };

    build(&mnemonic, &operands)
}

/// Whether the assembler knows this mnemonic at all.
fn is_supported(mnemonic: &str) -> bool {
    const NO_OPERAND: &[&str] =
        &["nop", "ret", "retn", "int3", "leave", "cdq", "cqo", "pushfq", "popfq"];
    const WITH_OPERANDS: &[&str] =
        &["mov", "lea", "push", "pop", "inc", "dec", "neg", "not"];
    NO_OPERAND.contains(&mnemonic)
        || WITH_OPERANDS.contains(&mnemonic)
        || branch_code(mnemonic).is_some()
        || alu_code(mnemonic, 64).is_some()
}

fn parse_operand(text: &str) -> Result<Operand, AsmError> {
    if let Some(inner) = text.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
        return parse_memory(inner.trim());
    }
    if let Some(reg) = parse_register(text) {
        return Ok(Operand::Reg(reg));
    }
    parse_number(text).map(Operand::Imm).ok_or_else(|| AsmError::BadOperand(text.to_string()))
}

fn parse_memory(inner: &str) -> Result<Operand, AsmError> {
    // `[rax]`, `[rax+0x10]`, `[rax-8]`.
    let (base_text, displacement) = match inner.find(['+', '-']) {
        Some(i) => {
            let sign = if inner.as_bytes()[i] == b'-' { -1 } else { 1 };
            let value = parse_number(inner[i + 1..].trim())
                .ok_or_else(|| AsmError::BadOperand(inner.to_string()))?;
            (inner[..i].trim(), sign * value)
        }
        None => (inner, 0),
    };
    let base = parse_register(base_text)
        .ok_or_else(|| AsmError::BadOperand(base_text.to_string()))?;
    Ok(Operand::Mem { base, displacement })
}

/// Parse a signed literal: decimal, or `0x`-prefixed hex.
fn parse_number(text: &str) -> Option<i64> {
    let text = text.trim();
    let (neg, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, text),
    };
    let magnitude = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        // `u64` then reinterpret: an address like 0xFFFFFFFFFFFFFFF0 does not fit
        // an `i64` as a magnitude but is a perfectly ordinary operand.
        Some(hex) => u64::from_str_radix(hex, 16).ok()? as i64,
        None => body.parse::<i64>().ok()?,
    };
    Some(if neg { magnitude.wrapping_neg() } else { magnitude })
}

/// Every 8/16/32/64-bit general-purpose register, by name.
fn parse_register(text: &str) -> Option<Register> {
    const NAMES: &[(&str, Register)] = &[
        ("rax", Register::RAX), ("rbx", Register::RBX), ("rcx", Register::RCX),
        ("rdx", Register::RDX), ("rsi", Register::RSI), ("rdi", Register::RDI),
        ("rbp", Register::RBP), ("rsp", Register::RSP),
        ("r8", Register::R8), ("r9", Register::R9), ("r10", Register::R10),
        ("r11", Register::R11), ("r12", Register::R12), ("r13", Register::R13),
        ("r14", Register::R14), ("r15", Register::R15),
        ("eax", Register::EAX), ("ebx", Register::EBX), ("ecx", Register::ECX),
        ("edx", Register::EDX), ("esi", Register::ESI), ("edi", Register::EDI),
        ("ebp", Register::EBP), ("esp", Register::ESP),
        ("r8d", Register::R8D), ("r9d", Register::R9D), ("r10d", Register::R10D),
        ("r11d", Register::R11D), ("r12d", Register::R12D), ("r13d", Register::R13D),
        ("r14d", Register::R14D), ("r15d", Register::R15D),
        ("ax", Register::AX), ("bx", Register::BX), ("cx", Register::CX),
        ("dx", Register::DX), ("si", Register::SI), ("di", Register::DI),
        ("bp", Register::BP), ("sp", Register::SP),
        ("al", Register::AL), ("bl", Register::BL), ("cl", Register::CL),
        ("dl", Register::DL), ("sil", Register::SIL), ("dil", Register::DIL),
        ("r8b", Register::R8L), ("r9b", Register::R9L),
    ];
    let lower = text.trim().to_ascii_lowercase();
    NAMES.iter().find(|(n, _)| *n == lower).map(|(_, r)| *r)
}

/// The register's width in bits, for picking the right `Code`.
fn width_bits(reg: Register) -> u32 {
    reg.size() as u32 * 8
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

fn mem_operand(base: Register, displacement: i64) -> MemoryOperand {
    MemoryOperand::with_base_displ(base, displacement)
}

fn bad(mnemonic: &str, detail: &str) -> AsmError {
    AsmError::BadOperands { mnemonic: mnemonic.to_string(), detail: detail.to_string() }
}

fn encode_err(mnemonic: &str) -> impl Fn(iced_x86::IcedError) -> AsmError + '_ {
    move |e| AsmError::BadOperands { mnemonic: mnemonic.to_string(), detail: e.to_string() }
}

/// `(reg-reg, reg-imm, mem-reg)` codes for one ALU mnemonic at one width.
fn alu_code(mnemonic: &str, bits: u32) -> Option<(Code, Code, Code)> {
    macro_rules! by_width {
        ($r64:ident, $i64_:ident, $m64:ident, $r32:ident, $i32_:ident, $m32:ident) => {
            match bits {
                64 => Some((Code::$r64, Code::$i64_, Code::$m64)),
                32 => Some((Code::$r32, Code::$i32_, Code::$m32)),
                _ => None,
            }
        };
    }
    match mnemonic {
        "add" => by_width!(Add_r64_rm64, Add_rm64_imm32, Add_rm64_r64,
                           Add_r32_rm32, Add_rm32_imm32, Add_rm32_r32),
        "sub" => by_width!(Sub_r64_rm64, Sub_rm64_imm32, Sub_rm64_r64,
                           Sub_r32_rm32, Sub_rm32_imm32, Sub_rm32_r32),
        "and" => by_width!(And_r64_rm64, And_rm64_imm32, And_rm64_r64,
                           And_r32_rm32, And_rm32_imm32, And_rm32_r32),
        "or" => by_width!(Or_r64_rm64, Or_rm64_imm32, Or_rm64_r64,
                          Or_r32_rm32, Or_rm32_imm32, Or_rm32_r32),
        "xor" => by_width!(Xor_r64_rm64, Xor_rm64_imm32, Xor_rm64_r64,
                           Xor_r32_rm32, Xor_rm32_imm32, Xor_rm32_r32),
        "cmp" => by_width!(Cmp_r64_rm64, Cmp_rm64_imm32, Cmp_rm64_r64,
                           Cmp_r32_rm32, Cmp_rm32_imm32, Cmp_rm32_r32),
        "test" => by_width!(Test_rm64_r64, Test_rm64_imm32, Test_rm64_r64,
                            Test_rm32_r32, Test_rm32_imm32, Test_rm32_r32),
        _ => None,
    }
}

/// The `Code` for a conditional or unconditional branch.
fn branch_code(mnemonic: &str) -> Option<Code> {
    Some(match mnemonic {
        "jmp" => Code::Jmp_rel32_64,
        "call" => Code::Call_rel32_64,
        "je" | "jz" => Code::Je_rel32_64,
        "jne" | "jnz" => Code::Jne_rel32_64,
        "jg" | "jnle" => Code::Jg_rel32_64,
        "jge" | "jnl" => Code::Jge_rel32_64,
        "jl" | "jnge" => Code::Jl_rel32_64,
        "jle" | "jng" => Code::Jle_rel32_64,
        "ja" | "jnbe" => Code::Ja_rel32_64,
        "jae" | "jnb" => Code::Jae_rel32_64,
        "jb" | "jnae" => Code::Jb_rel32_64,
        "jbe" | "jna" => Code::Jbe_rel32_64,
        "js" => Code::Js_rel32_64,
        "jns" => Code::Jns_rel32_64,
        _ => return None,
    })
}

fn build(mnemonic: &str, operands: &[Operand]) -> Result<Instruction, AsmError> {
    // No operands.
    if operands.is_empty() {
        let code = match mnemonic {
            "nop" => Code::Nopd,
            "ret" | "retn" => Code::Retnq,
            "int3" => Code::Int3,
            "leave" => Code::Leaveq,
            "cdq" => Code::Cdq,
            "cqo" => Code::Cqo,
            "pushfq" => Code::Pushfq,
            "popfq" => Code::Popfq,
            other => return Err(AsmError::UnknownMnemonic(other.to_string())),
        };
        return Ok(Instruction::with(code));
    }

    // Branches take one absolute target.
    if let Some(code) = branch_code(mnemonic) {
        let [Operand::Imm(target)] = operands else {
            return Err(bad(mnemonic, "expected one absolute target address"));
        };
        return Instruction::with_branch(code, *target as u64).map_err(encode_err(mnemonic));
    }

    match (mnemonic, operands) {
        // push / pop / inc / dec / neg / not — one register.
        ("push", [Operand::Reg(r)]) => {
            Instruction::with1(Code::Push_r64, *r).map_err(encode_err(mnemonic))
        }
        ("pop", [Operand::Reg(r)]) => {
            Instruction::with1(Code::Pop_r64, *r).map_err(encode_err(mnemonic))
        }
        ("inc", [Operand::Reg(r)]) => one_reg(mnemonic, *r, Code::Inc_rm64, Code::Inc_rm32),
        ("dec", [Operand::Reg(r)]) => one_reg(mnemonic, *r, Code::Dec_rm64, Code::Dec_rm32),
        ("neg", [Operand::Reg(r)]) => one_reg(mnemonic, *r, Code::Neg_rm64, Code::Neg_rm32),
        ("not", [Operand::Reg(r)]) => one_reg(mnemonic, *r, Code::Not_rm64, Code::Not_rm32),

        // mov reg, imm
        ("mov", [Operand::Reg(r), Operand::Imm(v)]) => {
            let code = match width_bits(*r) {
                64 => Code::Mov_r64_imm64,
                32 => Code::Mov_r32_imm32,
                16 => Code::Mov_r16_imm16,
                8 => Code::Mov_r8_imm8,
                _ => return Err(bad(mnemonic, "unsupported register width")),
            };
            Instruction::with2(code, *r, *v).map_err(encode_err(mnemonic))
        }
        // mov reg, reg
        ("mov", [Operand::Reg(dst), Operand::Reg(src)]) => {
            if width_bits(*dst) != width_bits(*src) {
                return Err(bad(mnemonic, "both registers must be the same width"));
            }
            let code = match width_bits(*dst) {
                64 => Code::Mov_r64_rm64,
                32 => Code::Mov_r32_rm32,
                16 => Code::Mov_r16_rm16,
                8 => Code::Mov_r8_rm8,
                _ => return Err(bad(mnemonic, "unsupported register width")),
            };
            Instruction::with2(code, *dst, *src).map_err(encode_err(mnemonic))
        }
        // mov reg, [mem]
        ("mov", [Operand::Reg(dst), Operand::Mem { base, displacement }]) => {
            let code = match width_bits(*dst) {
                64 => Code::Mov_r64_rm64,
                32 => Code::Mov_r32_rm32,
                16 => Code::Mov_r16_rm16,
                8 => Code::Mov_r8_rm8,
                _ => return Err(bad(mnemonic, "unsupported register width")),
            };
            Instruction::with2(code, *dst, mem_operand(*base, *displacement))
                .map_err(encode_err(mnemonic))
        }
        // mov [mem], reg
        ("mov", [Operand::Mem { base, displacement }, Operand::Reg(src)]) => {
            let code = match width_bits(*src) {
                64 => Code::Mov_rm64_r64,
                32 => Code::Mov_rm32_r32,
                16 => Code::Mov_rm16_r16,
                8 => Code::Mov_rm8_r8,
                _ => return Err(bad(mnemonic, "unsupported register width")),
            };
            Instruction::with2(code, mem_operand(*base, *displacement), *src)
                .map_err(encode_err(mnemonic))
        }
        // lea reg, [mem]
        ("lea", [Operand::Reg(dst), Operand::Mem { base, displacement }]) => {
            let code = match width_bits(*dst) {
                64 => Code::Lea_r64_m,
                32 => Code::Lea_r32_m,
                _ => return Err(bad(mnemonic, "lea needs a 32- or 64-bit destination")),
            };
            Instruction::with2(code, *dst, mem_operand(*base, *displacement))
                .map_err(encode_err(mnemonic))
        }

        // ALU: reg, reg / reg, imm / [mem], reg
        (m, [Operand::Reg(dst), Operand::Reg(src)]) if alu_code(m, 64).is_some() => {
            if width_bits(*dst) != width_bits(*src) {
                return Err(bad(m, "both registers must be the same width"));
            }
            let (rr, _, _) = alu_code(m, width_bits(*dst))
                .ok_or_else(|| bad(m, "only 32- and 64-bit forms are supported"))?;
            Instruction::with2(rr, *dst, *src).map_err(encode_err(m))
        }
        (m, [Operand::Reg(dst), Operand::Imm(v)]) if alu_code(m, 64).is_some() => {
            let (_, ri, _) = alu_code(m, width_bits(*dst))
                .ok_or_else(|| bad(m, "only 32- and 64-bit forms are supported"))?;
            let imm = i32::try_from(*v)
                .map_err(|_| bad(m, "the immediate does not fit in 32 bits"))?;
            Instruction::with2(ri, *dst, imm).map_err(encode_err(m))
        }
        (m, [Operand::Mem { base, displacement }, Operand::Reg(src)])
            if alu_code(m, 64).is_some() =>
        {
            let (_, _, mr) = alu_code(m, width_bits(*src))
                .ok_or_else(|| bad(m, "only 32- and 64-bit forms are supported"))?;
            Instruction::with2(mr, mem_operand(*base, *displacement), *src).map_err(encode_err(m))
        }

        (m, _) if alu_code(m, 64).is_some()
            || matches!(m, "mov" | "lea" | "push" | "pop" | "inc" | "dec" | "neg" | "not") =>
        {
            Err(bad(m, "unsupported operand combination"))
        }
        (m, _) => Err(AsmError::UnknownMnemonic(m.to_string())),
    }
}

fn one_reg(
    mnemonic: &str,
    reg: Register,
    code64: Code,
    code32: Code,
) -> Result<Instruction, AsmError> {
    let code = match width_bits(reg) {
        64 => code64,
        32 => code32,
        _ => return Err(bad(mnemonic, "needs a 32- or 64-bit register")),
    };
    Instruction::with1(code, reg).map_err(encode_err(mnemonic))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(source: &str) -> Vec<u8> {
        assemble(source, 0x1000).expect("assembles").bytes
    }

    /// Round-trip through the decoder, which is the only check that actually
    /// proves the encoding: comparing against hand-written bytes only proves
    /// the test author and the code agree.
    fn disasm(bytes: &[u8], ip: u64) -> Vec<String> {
        let mut decoder = iced_x86::Decoder::with_ip(64, bytes, ip, iced_x86::DecoderOptions::NONE);
        let mut formatter = iced_x86::NasmFormatter::new();
        let mut out = Vec::new();
        while decoder.can_decode() {
            let insn = decoder.decode();
            let mut text = String::new();
            iced_x86::Formatter::format(&mut formatter, &insn, &mut text);
            out.push(text);
        }
        out
    }

    #[test]
    fn the_no_operand_instructions_encode_to_their_canonical_bytes() {
        assert_eq!(asm("nop"), [0x90]);
        assert_eq!(asm("ret"), [0xC3]);
        assert_eq!(asm("int3"), [0xCC]);
        assert_eq!(asm("leave"), [0xC9]);
    }

    #[test]
    fn statements_are_separated_by_newlines_and_semicolons() {
        let out = assemble("nop; nop\nret", 0x1000).unwrap();
        assert_eq!(out.count, 3);
        assert_eq!(out.bytes, [0x90, 0x90, 0xC3]);
    }

    #[test]
    fn comments_are_stripped() {
        let out = assemble("nop  # keep the alignment\n# a whole line\nret", 0x1000).unwrap();
        assert_eq!(out.bytes, [0x90, 0xC3]);
    }

    #[test]
    fn a_register_move_round_trips_through_the_decoder() {
        for (source, expected) in [
            ("mov rax, rbx", "mov rax,rbx"),
            ("mov eax, 1", "mov eax,1"),
            ("mov rcx, 0x1234", "mov rcx,1234h"),
            ("xor eax, eax", "xor eax,eax"),
            ("add rsp, 8", "add rsp,8"),
            ("sub rsp, 0x20", "sub rsp,20h"),
            ("cmp rax, 0", "cmp rax,0"),
            ("push rbp", "push rbp"),
            ("pop rbp", "pop rbp"),
            ("inc rax", "inc rax"),
        ] {
            let bytes = asm(source);
            let text = disasm(&bytes, 0x1000);
            assert_eq!(text, [expected], "{source} assembled to {bytes:02X?}");
        }
    }

    #[test]
    fn memory_operands_carry_their_displacement() {
        assert_eq!(disasm(&asm("mov [rax], rbx"), 0x1000), ["mov [rax],rbx"]);
        assert_eq!(disasm(&asm("mov rbx, [rax+0x10]"), 0x1000), ["mov rbx,[rax+10h]"]);
        // A negative displacement is not the same instruction as a positive one,
        // and a sign dropped in parsing writes to the wrong address silently.
        assert_eq!(disasm(&asm("mov rbx, [rax-8]"), 0x1000), ["mov rbx,[rax-8]"]);
        assert_eq!(disasm(&asm("lea rax, [rbx+0x20]"), 0x1000), ["lea rax,[rbx+20h]"]);
    }

    #[test]
    fn a_branch_target_is_absolute_and_resolves_against_the_assembly_address() {
        // The same text at two addresses must encode different displacements —
        // that is the entire reason `ip` is a parameter.
        let at_1000 = assemble("jmp 0x2000", 0x1000).unwrap().bytes;
        let at_5000 = assemble("jmp 0x2000", 0x5000).unwrap().bytes;
        assert_ne!(at_1000, at_5000);
        assert_eq!(disasm(&at_1000, 0x1000), ["jmp 0000000000002000h"]);
        assert_eq!(disasm(&at_5000, 0x5000), ["jmp 0000000000002000h"]);
    }

    #[test]
    fn conditional_branches_and_their_aliases_encode_the_same_instruction() {
        let je = assemble("je 0x2000", 0x1000).unwrap().bytes;
        let jz = assemble("jz 0x2000", 0x1000).unwrap().bytes;
        assert_eq!(je, jz, "jz is the same instruction as je");
        // "near" is the NASM formatter's spelling of a rel32 branch.
        assert_eq!(disasm(&je, 0x1000), ["je near 0000000000002000h"]);
        assert_eq!(disasm(&asm("call 0x2000"), 0x1000), ["call 0000000000002000h"]);
    }

    #[test]
    fn a_multi_instruction_patch_assembles_as_one_block() {
        let out = assemble("push rbp\nmov rbp, rsp\nxor eax, eax\npop rbp\nret", 0x400000)
            .unwrap();
        assert_eq!(out.count, 5);
        assert_eq!(
            disasm(&out.bytes, 0x400000),
            ["push rbp", "mov rbp,rsp", "xor eax,eax", "pop rbp", "ret"]
        );
    }

    #[test]
    fn an_unknown_mnemonic_names_itself_rather_than_encoding_something_else() {
        let Err(e) = assemble("vfmadd132ps xmm0, xmm1, xmm2", 0x1000) else {
            panic!("an unsupported instruction must not silently assemble");
        };
        assert!(matches!(e, AsmError::UnknownMnemonic(ref m) if m == "vfmadd132ps"), "{e}");
        assert!(e.to_string().contains("vfmadd132ps"));
    }

    #[test]
    fn mismatched_operands_are_refused_with_the_reason() {
        let Err(e) = assemble("mov rax, ebx", 0x1000) else {
            panic!("a width mismatch must not assemble");
        };
        assert!(e.to_string().contains("same width"), "{e}");

        let Err(e) = assemble("push 5", 0x1000) else {
            panic!("push of an immediate is not in the subset");
        };
        assert!(e.to_string().contains("operand"), "{e}");
    }

    #[test]
    fn empty_input_is_an_error_rather_than_a_zero_byte_patch() {
        assert_eq!(assemble("   \n # nothing \n", 0x1000), Err(AsmError::Empty));
    }

    #[test]
    fn a_hex_operand_larger_than_i64_max_is_read_as_a_bit_pattern() {
        // An address with the top bit set is an ordinary operand, not an
        // overflow; parsing it as a magnitude would reject it.
        let out = assemble("mov rax, 0xFFFFFFFFFFFFFFF0", 0x1000).unwrap();
        assert_eq!(disasm(&out.bytes, 0x1000), ["mov rax,0FFFFFFFFFFFFFFF0h"]);
    }

    #[test]
    fn assembled_len_agrees_with_what_assemble_produces() {
        for source in ["nop", "mov rax, 1", "jmp 0x2000", "push rbp\nmov rbp, rsp"] {
            assert_eq!(
                assembled_len(source, 0x1000).unwrap(),
                assemble(source, 0x1000).unwrap().bytes.len(),
                "{source}"
            );
        }
    }
}
