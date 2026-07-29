//! Code injection: divert execution at an address into code of your own, then
//! return to where it left off.
//!
//! This is Cheat Engine's "auto assemble → code injection", and the shape is the
//! same: overwrite the instruction at the hook with a `jmp` into a **code cave**,
//! put the payload there, follow it with the instructions the `jmp` displaced,
//! and end with a `jmp` back.
//!
//! # Why a cave rather than an allocation
//!
//! Allocating in the target needs `mmap` executed *in* the target — a remote
//! thread, an `__libc_dlopen` call, or the kernel module doing it on your
//! behalf. None of that is wired up, and a detour is useful without it: every
//! real binary has runs of alignment padding between functions, and that padding
//! is already mapped executable. [`find_code_cave`] finds one.
//!
//! The trade is honest and bounded: the cave is finite, and a payload that does
//! not fit is refused rather than allowed to run off the end of the padding into
//! a real function.

use iced_x86::{BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, InstructionBlock};

use crate::internal::assembler::{AsmError, assemble};

/// The bytes for one detour: what to write at the hook, and what to write in
/// the cave.
///
/// Nothing is written by this module. It produces the bytes and the caller
/// decides — which keeps the whole thing testable without a live process and
/// lets the patch list record both writes so both can be reverted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detour {
    /// Address the `jmp` is written at.
    pub hook: usize,
    /// Address the payload is written at.
    pub cave: usize,
    /// How many bytes at the hook the `jmp` displaces — always whole
    /// instructions, never a partial one.
    pub stolen_len: usize,
    /// What to write at `hook`: the `jmp`, padded with `nop` to `stolen_len`.
    pub hook_bytes: Vec<u8>,
    /// What to write at `cave`: the payload, the displaced instructions, and the
    /// `jmp` back.
    pub cave_bytes: Vec<u8>,
}

/// Why a detour could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectError {
    /// The payload did not assemble.
    Payload(AsmError),
    /// The instructions at the hook could not be decoded.
    Undecodable(usize),
    /// The cave is not big enough for the payload plus the relocated
    /// instructions plus the jump back.
    CaveTooSmall { needed: usize, available: usize },
    /// The hook or the cave is further than a `rel32` can reach.
    TooFar { from: usize, to: usize },
    /// A displaced instruction cannot be moved (it is position-dependent in a
    /// way the encoder cannot fix up).
    NotRelocatable(String),
}

impl core::fmt::Display for InjectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Payload(e) => write!(f, "{e}"),
            Self::Undecodable(a) => write!(f, "the code at {a:#x} could not be decoded"),
            Self::CaveTooSmall { needed, available } => write!(
                f,
                "the injected code needs {needed} bytes but the cave has {available}"
            ),
            Self::TooFar { from, to } => write!(
                f,
                "{to:#x} is more than 2 GiB from {from:#x}, so a 5-byte jmp cannot reach it"
            ),
            Self::NotRelocatable(what) => {
                write!(f, "'{what}' cannot be moved out of the hook")
            }
        }
    }
}

impl std::error::Error for InjectError {}

impl From<AsmError> for InjectError {
    fn from(e: AsmError) -> Self {
        Self::Payload(e)
    }
}

/// The length of the `jmp rel32` a detour writes at the hook.
pub const JMP_LEN: usize = 5;

/// Bytes a code cave must have spare beyond the payload: the relocated
/// instructions can grow (a short jump becoming a near one) plus the jump back.
const CAVE_HEADROOM: usize = 32;

/// The byte values that count as padding when looking for a cave.
///
/// `0xCC` is the `int3` compilers pad with, `0x90` is `nop`, and `0x00` is the
/// zero fill at the end of a section. A run of any *one* of them is padding; a
/// mixture is not, because that is what real code between two functions looks
/// like.
const PADDING: [u8; 3] = [0xCC, 0x90, 0x00];

/// Find a run of at least `needed` padding bytes in `[start, end)`.
///
/// `read` supplies the bytes. Returns the address of the run, or `None`.
/// The search is forward from `start`, so it prefers the first cave — caves near
/// the hook are the ones a `rel32` can reach.
pub fn find_code_cave(
    start: usize,
    end: usize,
    needed: usize,
    read: impl Fn(usize, &mut [u8]) -> crate::Result<usize>,
) -> Option<usize> {
    if needed == 0 || start >= end {
        return None;
    }
    const WINDOW: usize = 64 * 1024;
    let mut buf = vec![0u8; WINDOW];
    let mut pos = start;

    // Runs are tracked across window boundaries so a cave that straddles one is
    // still found.
    let mut run_value: Option<u8> = None;
    let mut run_start = start;
    let mut run_len = 0usize;

    while pos < end {
        let want = WINDOW.min(end - pos);
        let Ok(read_len) = read(pos, &mut buf[..want]) else {
            // An unreadable span breaks any run in progress: whatever is on the
            // other side is not contiguous with what came before it.
            run_value = None;
            run_len = 0;
            pos = pos.saturating_add(want.max(1));
            continue;
        };
        if read_len == 0 {
            break;
        }
        for (i, &byte) in buf[..read_len].iter().enumerate() {
            let addr = pos + i;
            if PADDING.contains(&byte) && run_value == Some(byte) {
                run_len += 1;
            } else if PADDING.contains(&byte) {
                run_value = Some(byte);
                run_start = addr;
                run_len = 1;
            } else {
                run_value = None;
                run_len = 0;
                continue;
            }
            if run_len >= needed {
                return Some(run_start);
            }
        }
        pos += read_len;
    }
    None
}

/// Build the bytes for a detour from `hook` into `cave`.
///
/// `payload` is assembled at the cave's address, so a branch in it resolves
/// correctly. The instructions the `jmp` displaces are decoded, re-encoded at
/// their new address (which fixes their relative branches and RIP-relative
/// operands), and followed by a `jmp` back to just after the hook.
pub fn build_detour(
    hook: usize,
    cave: usize,
    cave_size: usize,
    payload: &str,
    read: impl Fn(usize, &mut [u8]) -> crate::Result<usize>,
) -> Result<Detour, InjectError> {
    check_reach(hook, cave)?;

    // Decode whole instructions at the hook until at least a jmp fits. A partial
    // instruction left behind would decode as garbage and execute.
    const MAX_STOLEN: usize = JMP_LEN + 16;
    let mut window = vec![0u8; MAX_STOLEN];
    let read_len = read(hook, &mut window).map_err(|_| InjectError::Undecodable(hook))?;
    if read_len < JMP_LEN {
        return Err(InjectError::Undecodable(hook));
    }
    window.truncate(read_len);

    let mut decoder = Decoder::with_ip(64, &window, hook as u64, DecoderOptions::NONE);
    let mut stolen = Vec::new();
    let mut stolen_len = 0usize;
    while stolen_len < JMP_LEN {
        if !decoder.can_decode() {
            return Err(InjectError::Undecodable(hook + stolen_len));
        }
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Err(InjectError::Undecodable(hook + stolen_len));
        }
        // A `ret` or an unconditional `jmp` inside the stolen span means the
        // hook is at the very end of a function; relocating those is legal but
        // the detour would never return, which is not what was asked for.
        if matches!(insn.flow_control(), iced_x86::FlowControl::Return) {
            return Err(InjectError::NotRelocatable(format!("{insn}")));
        }
        stolen_len += insn.len();
        stolen.push(insn);
    }

    let resume = hook + stolen_len;
    check_reach(cave, resume)?;

    // The payload goes first, at the cave's address.
    let payload_bytes = assemble(payload, cave as u64)?.bytes;

    // Then the displaced instructions, re-encoded where they now live. The
    // block encoder fixes their branch displacements and RIP-relative operands;
    // an instruction it cannot move is reported rather than emitted wrong.
    let relocated_ip = (cave + payload_bytes.len()) as u64;
    let block = InstructionBlock::new(&stolen, relocated_ip);
    let relocated = BlockEncoder::encode(64, block, BlockEncoderOptions::NONE)
        .map_err(|e| InjectError::NotRelocatable(e.to_string()))?
        .code_buffer;

    // Then the jump back.
    let return_ip = relocated_ip as usize + relocated.len();
    let return_jmp = assemble(&format!("jmp {resume:#x}"), return_ip as u64)?.bytes;

    let mut cave_bytes = payload_bytes;
    cave_bytes.extend_from_slice(&relocated);
    cave_bytes.extend_from_slice(&return_jmp);
    if cave_bytes.len() > cave_size {
        return Err(InjectError::CaveTooSmall {
            needed: cave_bytes.len(),
            available: cave_size,
        });
    }

    // Finally the hook itself, padded so the next instruction still starts where
    // the decoder expects.
    let mut hook_bytes = assemble(&format!("jmp {cave:#x}"), hook as u64)?.bytes;
    hook_bytes.resize(stolen_len.max(hook_bytes.len()), 0x90);

    Ok(Detour { hook, cave, stolen_len, hook_bytes, cave_bytes })
}

/// How much cave a payload needs, so a caller can size its search.
pub fn cave_size_for(payload: &str, cave_guess: usize) -> Result<usize, InjectError> {
    Ok(assemble(payload, cave_guess as u64)?.bytes.len() + CAVE_HEADROOM)
}

/// A `rel32` reaches ±2 GiB. Beyond that the 5-byte jump simply cannot encode
/// the displacement, and finding that out from a wrong encoding is much worse
/// than finding it out here.
fn check_reach(from: usize, to: usize) -> Result<(), InjectError> {
    let delta = (to as i64).wrapping_sub(from as i64);
    if i32::try_from(delta).is_err() {
        return Err(InjectError::TooFar { from, to });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reader over a flat buffer mapped at `base`.
    fn reader(base: usize, bytes: Vec<u8>) -> impl Fn(usize, &mut [u8]) -> crate::Result<usize> {
        move |addr, buf| {
            let offset = addr.checked_sub(base).ok_or(crate::Error::InvalidAddress)?;
            if offset >= bytes.len() {
                return Err(crate::Error::InvalidAddress);
            }
            let n = buf.len().min(bytes.len() - offset);
            buf[..n].copy_from_slice(&bytes[offset..offset + n]);
            Ok(n)
        }
    }

    fn disasm(bytes: &[u8], ip: u64) -> Vec<String> {
        let mut decoder = Decoder::with_ip(64, bytes, ip, DecoderOptions::NONE);
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

    const BASE: usize = 0x400000;

    /// `mov eax, 1` (5 bytes) then `ret`, then a run of int3 padding.
    ///
    /// The filler either side of the cave is `0x55` (`push rbp`) rather than
    /// zero: a long run of zeroes is itself legitimate padding, so a zero-filled
    /// gap would be found as a cave before the int3 one and the test would be
    /// asserting the wrong thing about the wrong run.
    fn target() -> Vec<u8> {
        let mut code = vec![0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        code.resize(0x100, 0x55);
        // A 64-byte int3 cave at +0x100.
        code.extend(std::iter::repeat_n(0xCCu8, 64));
        code.resize(0x200, 0x55);
        code
    }

    #[test]
    fn a_padding_run_is_found_and_a_short_one_is_not() {
        let read = reader(BASE, target());
        assert_eq!(find_code_cave(BASE, BASE + 0x200, 64, &read), Some(BASE + 0x100));
        // 65 int3s do not exist, and the zero fill either side is a different
        // byte value so it does not extend the run.
        assert_eq!(find_code_cave(BASE, BASE + 0x100 + 64, 65, &read), None);
    }

    #[test]
    fn a_run_of_mixed_padding_bytes_is_not_a_cave() {
        // Alternating 0x90/0xCC is what real code between two functions can look
        // like; treating it as padding would overwrite something.
        let bytes: Vec<u8> = (0..128).map(|i| if i % 2 == 0 { 0x90 } else { 0xCC }).collect();
        let read = reader(BASE, bytes);
        assert_eq!(find_code_cave(BASE, BASE + 128, 8, &read), None);
    }

    #[test]
    fn a_detour_steals_whole_instructions_and_returns_after_them() {
        let read = reader(BASE, target());
        let cave = BASE + 0x100;
        let detour = build_detour(BASE, cave, 64, "mov ecx, 0x2a", &read).unwrap();

        // `mov eax, 1` is exactly 5 bytes, so nothing extra is displaced.
        assert_eq!(detour.stolen_len, 5);
        assert_eq!(detour.hook_bytes.len(), 5, "the jmp fills the span exactly");
        assert_eq!(disasm(&detour.hook_bytes, BASE as u64), ["jmp 0000000000400100h"]);

        // Payload, then the displaced instruction re-encoded where it now lives,
        // then the jump back to just after the hook.
        assert_eq!(
            disasm(&detour.cave_bytes, cave as u64),
            ["mov ecx,2Ah", "mov eax,1", "jmp 0000000000400005h"]
        );
    }

    #[test]
    fn a_short_instruction_at_the_hook_displaces_the_next_one_too() {
        // `nop` (1) + `nop` (1) + `mov eax,1` (5): stealing 5 bytes has to take
        // whole instructions, so all three go.
        let mut code = vec![0x90, 0x90, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        code.resize(0x100, 0x55);
        code.extend(std::iter::repeat_n(0xCCu8, 64));
        let read = reader(BASE, code);
        let detour = build_detour(BASE, BASE + 0x100, 64, "nop", &read).unwrap();

        assert_eq!(detour.stolen_len, 7, "1 + 1 + 5, not a partial instruction");
        assert_eq!(detour.hook_bytes.len(), 7);
        // The two trailing bytes are padded so the next instruction still starts
        // where the decoder expects.
        assert_eq!(&detour.hook_bytes[5..], &[0x90, 0x90]);
        assert_eq!(
            disasm(&detour.cave_bytes, (BASE + 0x100) as u64).last().unwrap(),
            "jmp 0000000000400007h"
        );
    }

    #[test]
    fn a_relative_branch_in_the_stolen_span_is_re_targeted_not_copied() {
        // `jmp +0x10` at the hook. Copied verbatim into the cave it would land
        // 0x10 past the *cave*, which is nowhere near where it meant to go.
        let mut code = vec![0xEB, 0x0E]; // jmp short +0x0E → 0x400010
        code.resize(0x100, 0x55);
        code.extend(std::iter::repeat_n(0xCCu8, 64));
        let read = reader(BASE, code);
        let detour = build_detour(BASE, BASE + 0x100, 64, "nop", &read).unwrap();

        let text = disasm(&detour.cave_bytes, (BASE + 0x100) as u64);
        assert!(
            text.iter().any(|t| t.contains("0000000000400010")),
            "the branch still points at its original target: {text:?}"
        );
    }

    #[test]
    fn a_payload_that_does_not_fit_the_cave_is_refused() {
        let read = reader(BASE, target());
        // Eight `mov rax, imm64`s are 80 bytes, well past a 16-byte cave.
        let payload = "mov rax, 0x1111111111111111\n".repeat(8);
        let err = build_detour(BASE, BASE + 0x100, 16, &payload, &read).unwrap_err();
        assert!(
            matches!(err, InjectError::CaveTooSmall { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("cave"), "{err}");
    }

    #[test]
    fn a_cave_out_of_jmp_range_is_refused_rather_than_mis_encoded() {
        let read = reader(BASE, target());
        let far = BASE + 0x8000_0000;
        let err = build_detour(BASE, far, 4096, "nop", &read).unwrap_err();
        assert!(matches!(err, InjectError::TooFar { .. }), "{err}");
        assert!(err.to_string().contains("2 GiB"), "{err}");
    }

    #[test]
    fn hooking_a_ret_is_refused_because_the_detour_could_never_return() {
        let mut code = vec![0xC3]; // ret
        code.resize(0x100, 0x55);
        code.extend(std::iter::repeat_n(0xCCu8, 64));
        let read = reader(BASE, code);
        let err = build_detour(BASE, BASE + 0x100, 64, "nop", &read).unwrap_err();
        assert!(matches!(err, InjectError::NotRelocatable(_)), "{err}");
    }

    #[test]
    fn a_bad_payload_reports_the_assembler_error() {
        let read = reader(BASE, target());
        let err = build_detour(BASE, BASE + 0x100, 64, "frobnicate rax", &read).unwrap_err();
        assert!(matches!(err, InjectError::Payload(_)), "{err}");
        assert!(err.to_string().contains("frobnicate"), "{err}");
    }

    #[test]
    fn the_required_cave_size_covers_the_payload_and_the_return() {
        let needed = cave_size_for("mov eax, 1", 0x400100).unwrap();
        assert!(needed > 5, "the payload alone is 5 bytes; the jump back needs room too");
        let read = reader(BASE, target());
        let detour = build_detour(BASE, BASE + 0x100, needed, "mov eax, 1", &read).unwrap();
        assert!(detour.cave_bytes.len() <= needed);
    }
}
