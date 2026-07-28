//! "Dissect Code" cross-reference analysis (the PINCE `DissectCode` analog).
//!
//! Given the executable regions of a module, this walks them with a linear
//! disassembler and builds three inbound-reference maps:
//!
//! - `calls`   — target address → the `call` sites that reference it.
//! - `jumps`   — target address → the `jmp`/`jcc` sites that reference it.
//! - `strings` — string address → the RIP-relative loads (`lea`/`mov`) that
//!   reference it, plus a short text preview.
//!
//! These let the disassembly view annotate an address with "{N} references" and
//! offer a click-through list of referrers — the same navigation aid PINCE gives.
//!
//! Linux-only: it reads from a live [`crate::Process`] and parses `/proc`.

#![cfg(target_os = "linux")]

use std::collections::HashMap;

use crate::internal::decoder::disassemble_instructions;
use crate::internal::process::parse_maps_sections;
use crate::{FlowKind, Pid, Process, RegionIndex, string_at};

// ---------------------------------------------------------------------------
// Tuning constants
// ---------------------------------------------------------------------------

/// How much of a region to disassemble per read. Big enough to swallow a whole
/// `.text` in a couple of passes without allocating tens of MB at once.
const CHUNK_BYTES: usize = 256 * 1024;
/// Extra bytes read past the chunk boundary so an instruction that straddles the
/// boundary still decodes fully (x86 instructions are ≤ 15 bytes).
const CHUNK_OVERLAP: usize = 16;
/// Bytes probed at a candidate string address.
const STRING_PROBE_BYTES: usize = 128;
/// Minimum printable characters for a memory reference to count as a string.
const MIN_STRING_LEN: usize = 4;
/// Maximum characters kept in a stored string preview.
const PREVIEW_MAX: usize = 64;

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/// The cross-reference maps produced by [`dissect_regions`]. Every referrer list
/// is sorted ascending and de-duplicated.
#[derive(Debug, Clone, Default)]
pub struct DissectResult {
    /// `call` target → referrer instruction addresses.
    pub calls: HashMap<u64, Vec<u64>>,
    /// `jmp`/`jcc` target → referrer instruction addresses.
    pub jumps: HashMap<u64, Vec<u64>>,
    /// String address → referrer instruction addresses.
    pub strings: HashMap<u64, Vec<u64>>,
    /// String address → short decoded preview (for tooltips).
    pub string_previews: HashMap<u64, String>,
}

impl DissectResult {
    /// Total inbound references at `addr` across calls, jumps and strings.
    pub fn ref_count(&self, addr: u64) -> usize {
        self.calls.get(&addr).map_or(0, Vec::len)
            + self.jumps.get(&addr).map_or(0, Vec::len)
            + self.strings.get(&addr).map_or(0, Vec::len)
    }

    fn sort_dedup(&mut self) {
        for map in [&mut self.calls, &mut self.jumps, &mut self.strings] {
            for referrers in map.values_mut() {
                referrers.sort_unstable();
                referrers.dedup();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Region discovery
// ---------------------------------------------------------------------------

/// The executable sub-regions of the module spanning `[base, base + size)`,
/// discovered by parsing `/proc/<pid>/maps` and clipping the `x`-flagged
/// mappings to the module span. Returned as half-open `(start, end)` address
/// ranges sorted ascending.
pub fn module_exec_regions(pid: Pid, base: usize, size: usize) -> crate::Result<Vec<(u64, u64)>> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|_| crate::Error::ProcessDied)?;
    let end = base.saturating_add(size);

    let mut regions: Vec<(u64, u64)> = parse_maps_sections(&maps)
        .into_iter()
        .filter(|s| s.prot.execute())
        .filter_map(|s| {
            // Clip the section to the module span.
            let rs = s.base.max(base);
            let re = s.base.saturating_add(s.size).min(end);
            (rs < re).then_some((rs as u64, re as u64))
        })
        .collect();

    regions.sort_unstable_by_key(|(start, _)| *start);
    Ok(regions)
}

// ---------------------------------------------------------------------------
// The scan
// ---------------------------------------------------------------------------

/// Disassembles every `(start, end)` region and builds the cross-reference maps.
///
/// Reads each region in [`CHUNK_BYTES`] passes (with a small tail overlap so a
/// boundary-straddling instruction decodes fully) and records, per instruction:
/// direct `call`/`jmp`/`jcc` targets that land in executable memory, and
/// RIP-relative memory operands that point at a printable string.
///
/// Garbage from data mis-decoded as code is filtered by requiring branch targets
/// to fall inside an executable mapping and string references to actually read as
/// a printable run of at least [`MIN_STRING_LEN`] characters.
pub fn dissect_regions(process: &Process, regions: &[(u64, u64)]) -> crate::Result<DissectResult> {
    let mut result = DissectResult::default();
    let region_index = RegionIndex::from_pid(process.pid())?;

    for &(start, end) in regions {
        if end <= start {
            continue;
        }
        let total = (end - start) as usize;
        let mut pos: usize = 0;

        while pos < total {
            let chunk_addr = start + pos as u64;
            // Bytes we intend to *cover* this pass, plus overlap we actually read.
            let want = (total - pos).min(CHUNK_BYTES);
            let read_len = (total - pos).min(CHUNK_BYTES + CHUNK_OVERLAP);

            let mut buf = vec![0u8; read_len];
            let read = process.read_buf(chunk_addr as usize, &mut buf).unwrap_or(0);
            if read == 0 {
                break; // region became unreadable (target died / unmapped)
            }
            buf.truncate(read);

            let is_last = pos + want >= total;
            // Offset (relative to the chunk) just past the last decoded instruction;
            // drives how far `pos` advances so the next chunk starts on a boundary.
            let mut last_end: usize = 0;

            disassemble_instructions(&buf, chunk_addr, false, |ins| {
                let rel = (ins.address - chunk_addr) as usize;
                // On a non-final chunk, instructions starting at/after `want` belong
                // to the next chunk — stop so we don't double-count them.
                if !is_last && rel >= want {
                    return false;
                }
                record_instruction(process, &region_index, &mut result, &ins);
                last_end = rel + ins.length;
                true
            });

            if last_end == 0 {
                break; // nothing decoded — avoid an infinite loop
            }
            pos += last_end;
        }
    }

    result.sort_dedup();
    Ok(result)
}

/// Buckets one instruction's outbound references into `result`.
fn record_instruction(
    process: &Process,
    region_index: &RegionIndex,
    result: &mut DissectResult,
    ins: &crate::InstructionData,
) {
    let site = ins.address;

    match ins.kind {
        FlowKind::Call => {
            if let Some(target) = ins.target
                && is_executable(target, region_index)
            {
                result.calls.entry(target).or_default().push(site);
            }
        }
        FlowKind::Jump | FlowKind::CondJump => {
            if let Some(target) = ins.target
                && is_executable(target, region_index)
            {
                result.jumps.entry(target).or_default().push(site);
            }
        }
        _ => {}
    }

    // RIP-relative data reference → is it a printable string?
    if let Some(mem) = ins.mem_target
        && let Some(text) = read_string_at(process, mem)
    {
        result.strings.entry(mem).or_default().push(site);
        result.string_previews.entry(mem).or_insert(text);
    }
}

/// `true` if `addr` falls inside an executable mapping (cheap, no memory read).
fn is_executable(addr: u64, index: &RegionIndex) -> bool {
    usize::try_from(addr)
        .map(|a| index.is_executable(a))
        .unwrap_or(false)
}

/// Reads up to [`STRING_PROBE_BYTES`] at `addr` and, if it begins with a
/// printable run of ≥ [`MIN_STRING_LEN`] chars, returns a truncated preview.
fn read_string_at(process: &Process, addr: u64) -> Option<String> {
    let start = usize::try_from(addr).ok()?;
    let mut buf = vec![0u8; STRING_PROBE_BYTES];
    let read = process.read_buf(start, &mut buf).ok()?;
    if read == 0 {
        return None;
    }
    buf.truncate(read);

    let run = string_at(&buf, 0, MIN_STRING_LEN)?;
    let mut text = run.text;
    if text.chars().count() > PREVIEW_MAX {
        text = text.chars().take(PREVIEW_MAX).collect::<String>();
        text.push('…');
    }
    Some(text)
}
