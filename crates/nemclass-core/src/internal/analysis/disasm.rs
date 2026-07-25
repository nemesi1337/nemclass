//! Process-driven linear disassembly of a single function.
//!
//! This is the ReClass.NET `DisassembleRemoteCode` analog: read a run of bytes
//! from a live target at a function's entry point, decode them linearly, and
//! stop at the first natural end of the function (a `ret` or `int3` — the latter
//! being the typical inter-function padding). It also collects the direct
//! targets of every `call` so the caller can walk the call graph outward.
//!
//! Linux-only, because it reads from a live [`crate::Process`]. The flow-kind /
//! target logic it relies on lives in the platform-neutral decoder and is
//! covered by that module's unit tests, so there is no live-process unit test
//! here (see the ignored placeholder below).

#![cfg(target_os = "linux")]

use crate::internal::decoder::{FlowKind, InstructionData, disassemble_instructions};

/// The result of disassembling one function: its decoded instructions and the
/// de-duplicated, in-order list of direct `call` targets found within it.
#[derive(Debug, Clone, Default)]
pub struct FunctionDisasm {
    /// The decoded instructions, in address order, from the entry up to and
    /// including the terminating `ret`/`int3` (or the `max_bytes` cap).
    pub instructions: Vec<InstructionData>,
    /// The direct near-call targets found in `instructions`, de-duplicated and
    /// kept in first-seen order — the callee entry points to walk next.
    pub call_targets: Vec<u64>,
}

/// Disassembles the function at `addr` in `process`, reading at most `max_bytes`
/// of code.
///
/// Reads up to `max_bytes` via [`crate::Process::read_buf`] (tolerating a short
/// read — an unmapped tail simply bounds the buffer), decodes the bytes
/// linearly, and stops after the first instruction whose [`FlowKind`] is
/// [`FlowKind::Ret`] or [`FlowKind::Int3`], on an invalid/zero-length decode, or
/// once `max_bytes` is consumed. Direct `call` targets (those with a resolvable
/// [`InstructionData::target`]) are collected into
/// [`FunctionDisasm::call_targets`], de-duplicated in first-seen order.
///
/// Note this is *linear* disassembly: it does not follow jumps or model basic
/// blocks. It faithfully mirrors ReClass.NET's single-pass remote disassembler,
/// which is enough to render a function view and seed call-graph traversal.
pub fn disassemble_function(
    process: &crate::Process,
    addr: u64,
    max_bytes: usize,
) -> crate::Result<FunctionDisasm> {
    let mut result = FunctionDisasm::default();
    if max_bytes == 0 {
        return Ok(result);
    }

    // Snapshot up to `max_bytes` of the function. A short read (partly unmapped
    // region, target died) just gives us fewer bytes to decode — not an error.
    let start = usize::try_from(addr).map_err(|_| crate::Error::InvalidAddress)?;
    let mut buf = vec![0u8; max_bytes];
    let read = process.read_buf(start, &mut buf)?;
    buf.truncate(read);
    if buf.is_empty() {
        return Ok(result);
    }

    // Decode linearly. The closure drives termination: we keep each instruction,
    // record call targets, and return `false` (stop) after a ret/int3 or an
    // invalid/zero-length decode.
    disassemble_instructions(&buf, addr, true, |ins| {
        // An invalid or zero-length decode means we've run off the end of real
        // code (e.g. into data); keep nothing more and stop.
        if ins.length == 0 || ins.instruction == "???" {
            return false;
        }

        if ins.kind == FlowKind::Call
            && let Some(target) = ins.target
            && !result.call_targets.contains(&target)
        {
            result.call_targets.push(target);
        }

        let terminates = matches!(ins.kind, FlowKind::Ret | FlowKind::Int3);
        result.instructions.push(ins);
        !terminates
    });

    Ok(result)
}

/// Disassembles a *range* of code at `addr` in `process`, reading up to `len`
/// bytes and decoding them linearly.
///
/// Unlike [`disassemble_function`], this does **not** stop at the first
/// `ret`/`int3` — it decodes the whole window, which is what a module-level
/// (continuous) disassembly view wants: `.text` is full of `ret`s between
/// functions, and stopping at the first one would show only a single function.
///
/// It still tolerates a short read (an unmapped tail simply bounds the buffer)
/// and stops on an invalid / zero-length decode, since that means we have run
/// off the end of real code (e.g. into data or a hole in the mapping).
///
/// Windowing / paging over a large module is the caller's job: pass a bounded
/// `len` (a screenful) and advance `addr` past the last decoded instruction.
pub fn disassemble_range(
    process: &crate::Process,
    addr: u64,
    len: usize,
) -> crate::Result<Vec<InstructionData>> {
    let mut out = Vec::new();
    if len == 0 {
        return Ok(out);
    }

    // Snapshot up to `len` bytes. A short read (partly-unmapped region, target
    // died) just gives us fewer bytes to decode — not an error.
    let start = usize::try_from(addr).map_err(|_| crate::Error::InvalidAddress)?;
    let mut buf = vec![0u8; len];
    let read = process.read_buf(start, &mut buf)?;
    buf.truncate(read);
    if buf.is_empty() {
        return Ok(out);
    }

    // Decode linearly, keeping every instruction. Stop only on an invalid /
    // zero-length decode (running off the end of code), never on ret/int3.
    disassemble_instructions(&buf, addr, true, |ins| {
        if ins.length == 0 || ins.instruction == "???" {
            return false;
        }
        out.push(ins);
        true
    });

    Ok(out)
}

#[cfg(test)]
mod tests {
    // `disassemble_function` needs a live target, so it has no self-contained
    // unit test. Its two moving parts are tested elsewhere:
    //   * flow-kind / call-target extraction — `internal::decoder::tests`;
    //   * short-read tolerance — `Process::read_buf`'s own coverage.
    // This ignored test documents the intended end-to-end shape for a future
    // fixture-process harness.
    #[test]
    #[ignore = "requires a live target process; covered indirectly by decoder tests"]
    fn disassemble_function_walks_to_ret() {}
}
