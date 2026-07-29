//! "Find what accesses this address" — the most-used feature in both Cheat
//! Engine and ReClass.NET, built on the watchpoints the kernel module already
//! provides.
//!
//! The primitives were all there — hardware watchpoints, register capture, an
//! event queue — but nothing turned a stream of hits into the thing a user
//! actually wants: *which instructions touch this field, and how often*.
//!
//! # The RIP caveat
//!
//! A data watchpoint on x86 is a **trap**, not a fault: the debug exception is
//! delivered *after* the accessing instruction retires, so the captured `RIP`
//! points at the **next** instruction, not the one that did the access. Cheat
//! Engine hides this by walking back one instruction, which is a heuristic —
//! x86 has no reliable way to decode backwards. [`AccessSite::rip`] is the raw
//! captured value; [`preceding_instruction`] implements the walk-back and says
//! plainly when it could not find one.

use std::collections::HashMap;

use super::abi::HwBreakpointType;
use super::debugger::{BreakpointId, BreakpointSpec, Debugger, Registers};

/// What kind of access a watch reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    /// Only writes.
    Write,
    /// Only reads. Note that x86 debug registers cannot watch for reads alone —
    /// this arms a read-or-write watchpoint, so writes are reported too.
    Read,
    /// Reads and writes.
    ReadWrite,
}

impl AccessKind {
    fn hw_type(self) -> HwBreakpointType {
        match self {
            AccessKind::Write => HwBreakpointType::Write,
            // `Read` maps to the same condition: `DR7`'s R/W bits have no
            // read-only encoding on x86, which is a CPU limitation rather than
            // a choice this code makes.
            AccessKind::Read | AccessKind::ReadWrite => HwBreakpointType::ReadWrite,
        }
    }
}

/// One instruction that touched the watched address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessSite {
    /// The `RIP` captured at the hit. See the module docs: for a data
    /// watchpoint this is the instruction *after* the access.
    pub rip: u64,
    /// How many times this site has been seen.
    pub hits: u64,
    /// The thread the first hit came from.
    pub first_tid: i32,
    /// Registers as of the most recent hit from this site.
    ///
    /// The most recent rather than the first: the interesting question is
    /// usually "what was in the registers just now", and a stale snapshot from
    /// thousands of hits ago answers nothing.
    pub last_registers: Registers,
}

/// The per-instruction tally, with no session behind it.
///
/// Separate from [`AccessWatch`] because a caller that already owns a
/// [`Debugger`] — a UI polling one event queue for several purposes — cannot
/// hand it over, but still wants the aggregation. Feed it
/// [`DebugEvent`](super::DebugEvent) registers with [`Self::record`].
#[derive(Debug, Default, Clone)]
pub struct AccessTally {
    sites: HashMap<u64, AccessSite>,
    total: u64,
    /// Hits dropped because the site table hit [`Self::MAX_SITES`].
    dropped: u64,
}

impl AccessTally {
    /// Distinct instruction addresses tracked before new ones are dropped.
    ///
    /// A watch left running over a busy field sees a handful of instructions
    /// millions of times, not millions of instructions — so this is far above
    /// any real workload, and a bound is still wanted because the table grows
    /// from data the target controls.
    pub const MAX_SITES: usize = 4096;

    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one hit into the tally.
    pub fn record(&mut self, registers: Registers, tid: i32) {
        self.total += 1;
        let rip = registers.rip;
        match self.sites.get_mut(&rip) {
            Some(site) => {
                site.hits += 1;
                site.last_registers = registers;
            }
            None => {
                if self.sites.len() >= Self::MAX_SITES {
                    self.dropped += 1;
                    return;
                }
                self.sites.insert(
                    rip,
                    AccessSite { rip, hits: 1, first_tid: tid, last_registers: registers },
                );
            }
        }
    }

    /// Total hits seen, including any whose site was dropped.
    pub fn total_hits(&self) -> u64 {
        self.total
    }

    /// Hits whose instruction address was not recorded because the site table
    /// was full. Non-zero means the site list is incomplete.
    pub fn dropped_hits(&self) -> u64 {
        self.dropped
    }

    /// How many distinct instructions have been seen.
    pub fn site_count(&self) -> usize {
        self.sites.len()
    }

    /// The recorded sites, busiest first.
    ///
    /// Busiest first because the instruction that touches a field most is
    /// almost always the one being looked for, and because a list in hash order
    /// re-shuffles itself on every poll.
    pub fn sites(&self) -> Vec<AccessSite> {
        let mut out: Vec<AccessSite> = self.sites.values().copied().collect();
        out.sort_by(|a, b| b.hits.cmp(&a.hits).then(a.rip.cmp(&b.rip)));
        out
    }

    /// Forget everything recorded so far.
    pub fn clear(&mut self) {
        self.sites.clear();
        self.total = 0;
        self.dropped = 0;
    }
}

/// An armed watchpoint plus the per-instruction tally of what has hit it.
///
/// The target is never halted — the module's engine records and continues — so
/// this can be left running while the game plays and polled from the UI thread.
pub struct AccessWatch {
    debugger: Debugger,
    breakpoint: BreakpointId,
    address: u64,
    length: u32,
    kind: AccessKind,
    tally: AccessTally,
}

impl AccessWatch {

    /// Arm a watchpoint on `[addr, addr+len)` and start tallying.
    ///
    /// `len` must be 1, 2, 4 or 8 — the debug-register-legal spans.
    pub fn arm(
        mut debugger: Debugger,
        addr: u64,
        len: u32,
        kind: AccessKind,
    ) -> crate::Result<Self> {
        let spec = BreakpointSpec::hardware(addr, len, kind.hw_type())?;
        let breakpoint = debugger.set_breakpoint(spec)?;
        Ok(Self {
            debugger,
            breakpoint,
            address: addr,
            length: len,
            kind,
            tally: AccessTally::new(),
        })
    }

    /// The watched address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// The watched span in bytes.
    pub fn length(&self) -> u32 {
        self.length
    }

    /// What the watch was armed for.
    pub fn kind(&self) -> AccessKind {
        self.kind
    }

    /// The tally, for the read-only queries.
    pub fn tally(&self) -> &AccessTally {
        &self.tally
    }

    /// Total hits seen, including any whose site was dropped.
    pub fn total_hits(&self) -> u64 {
        self.tally.total_hits()
    }

    /// Hits whose instruction address was not recorded because the site table
    /// was full. Non-zero means the site list is incomplete.
    pub fn dropped_hits(&self) -> u64 {
        self.tally.dropped_hits()
    }

    /// Drain every event currently queued, without blocking.
    ///
    /// Returns how many hits were folded in. Safe to call from a frame loop:
    /// the underlying wait is a non-blocking poll, and the module's queue is
    /// what absorbs the burst between calls.
    pub fn poll(&mut self) -> crate::Result<usize> {
        self.drain(Some(core::time::Duration::ZERO), usize::MAX)
    }

    /// Wait up to `timeout` for hits, folding in at most `budget` of them.
    ///
    /// `budget` bounds how long one call can spend on a target that is hitting
    /// the watchpoint continuously — without it, a field written every frame
    /// would keep this loop fed forever and the caller would never regain
    /// control.
    pub fn drain(
        &mut self,
        timeout: Option<core::time::Duration>,
        budget: usize,
    ) -> crate::Result<usize> {
        let mut folded = 0usize;
        while folded < budget {
            // Only the first wait may block: once a hit is in hand the rest of
            // the queue is drained non-blocking, so a quiet target does not sit
            // here for the whole timeout on every iteration.
            let wait = if folded == 0 { timeout } else { Some(core::time::Duration::ZERO) };
            let Some(event) = self.debugger.wait_event(wait)? else {
                break;
            };
            // Another breakpoint on the same session — not this watch's.
            if event.breakpoint != self.breakpoint {
                continue;
            }
            self.tally.record(event.registers, event.tid);
            folded += 1;
        }
        Ok(folded)
    }

    /// The recorded sites, busiest first.
    pub fn sites(&self) -> Vec<AccessSite> {
        self.tally.sites()
    }

    /// How many distinct instructions have been seen.
    pub fn site_count(&self) -> usize {
        self.tally.site_count()
    }

    /// Forget the tally without disarming.
    pub fn clear(&mut self) {
        self.tally.clear();
    }

    /// Read target memory through the same session.
    pub fn read_memory(&self, addr: usize, buf: &mut [u8]) -> crate::Result<usize> {
        self.debugger.read_memory(addr, buf)
    }

    /// Disarm and hand the debugger back, so the session can be reused.
    ///
    /// A failure to clear is reported rather than swallowed: the breakpoint
    /// stays armed in the kernel until the fd closes, and silently leaving a
    /// debug register occupied is how the next watch fails for no visible
    /// reason.
    pub fn disarm(mut self) -> crate::Result<Debugger> {
        self.debugger.clear_breakpoint(self.breakpoint)?;
        Ok(self.debugger)
    }
}

/// The address of the instruction ending exactly at `rip`, if one can be found.
///
/// A data watchpoint reports the instruction *after* the access, so naming the
/// accessing instruction means decoding backwards — which x86 does not support.
/// This tries every start in `[rip - 16, rip)` and accepts the one whose decode
/// ends exactly at `rip`; `read` supplies the bytes.
///
/// Returns `None` when nothing decodes to that boundary, which is a real
/// outcome (unreadable memory, or a byte sequence that happens to decode
/// several ways) and not something to paper over with a guess.
pub fn preceding_instruction(
    rip: u64,
    read: impl Fn(usize, &mut [u8]) -> crate::Result<usize>,
) -> Option<u64> {
    /// The longest an x86-64 instruction can be.
    const MAX_INSN_LEN: usize = 15;

    let start = rip.checked_sub(MAX_INSN_LEN as u64)?;
    let mut window = [0u8; MAX_INSN_LEN];
    let read_len = read(start as usize, &mut window).ok()?;
    if read_len < MAX_INSN_LEN {
        return None;
    }

    // Longest-first: a shorter decode that happens to land on the boundary is
    // usually a misparse of the tail of a longer instruction.
    for back in (1..=MAX_INSN_LEN).rev() {
        let candidate = rip - back as u64;
        let offset = MAX_INSN_LEN - back;
        let mut decoder = iced_x86::Decoder::with_ip(
            64,
            &window[offset..],
            candidate,
            iced_x86::DecoderOptions::NONE,
        );
        let insn = decoder.decode();
        if !insn.is_invalid() && insn.next_ip() == rip {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs(rip: u64) -> Registers {
        Registers {
            rip,
            rsp: 0,
            rflags: 0,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        }
    }

    use AccessTally as Tally;

    #[test]
    fn hits_aggregate_by_instruction_and_sort_busiest_first() {
        let mut tally = Tally::new();
        for _ in 0..5 {
            tally.record(regs(0x4000), 100);
        }
        tally.record(regs(0x5000), 101);
        for _ in 0..12 {
            tally.record(regs(0x6000), 100);
        }

        let sites = tally.sites();
        assert_eq!(sites.len(), 3);
        assert_eq!((sites[0].rip, sites[0].hits), (0x6000, 12));
        assert_eq!((sites[1].rip, sites[1].hits), (0x4000, 5));
        assert_eq!((sites[2].rip, sites[2].hits), (0x5000, 1));
        assert_eq!(tally.total_hits(), 18);
        assert_eq!(sites[1].first_tid, 100);
    }

    #[test]
    fn the_last_registers_are_the_most_recent_not_the_first() {
        let mut tally = Tally::new();
        let mut first = regs(0x4000);
        first.rax = 1;
        tally.record(first, 1);
        let mut later = regs(0x4000);
        later.rax = 99;
        tally.record(later, 1);
        assert_eq!(tally.sites()[0].last_registers.rax, 99);
    }

    #[test]
    fn a_flood_of_distinct_sites_is_bounded_and_reported() {
        let mut tally = Tally::new();
        for i in 0..(AccessTally::MAX_SITES as u64 + 10) {
            tally.record(regs(0x4000 + i * 4), 1);
        }
        assert_eq!(tally.site_count(), AccessTally::MAX_SITES);
        assert_eq!(tally.dropped_hits(), 10, "the drops are counted, not hidden");
        assert_eq!(tally.total_hits(), AccessTally::MAX_SITES as u64 + 10);
    }

    #[test]
    fn a_read_watch_uses_the_read_write_condition_because_x86_has_no_other() {
        assert_eq!(AccessKind::Write.hw_type(), HwBreakpointType::Write);
        assert_eq!(AccessKind::Read.hw_type(), HwBreakpointType::ReadWrite);
        assert_eq!(AccessKind::ReadWrite.hw_type(), HwBreakpointType::ReadWrite);
    }

    #[test]
    fn the_preceding_instruction_is_found_by_decoding_up_to_the_boundary() {
        // `mov [rcx], eax` (2 bytes) followed by `nop`. A write watchpoint on
        // the store reports the RIP of the nop; the accessing instruction is
        // the one that ends there.
        let code: [u8; 16] = [
            0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // padding
            0x90, 0x90, 0x90, 0x90, 0x90, // more padding
            0x89, 0x01, // mov [rcx], eax  — at rip-3..rip-1
            0x90, // nop — the reported RIP
        ];
        let base = 0x1000u64;
        let reported_rip = base + 15;
        let found = preceding_instruction(reported_rip, |addr, buf| {
            let offset = (addr as u64).checked_sub(base).ok_or(crate::Error::InvalidAddress)?
                as usize;
            let n = buf.len().min(code.len().saturating_sub(offset));
            buf[..n].copy_from_slice(&code[offset..offset + n]);
            Ok(n)
        });
        assert_eq!(found, Some(base + 13), "the two-byte store ends at the reported RIP");
    }

    #[test]
    fn an_unreadable_window_yields_no_guess() {
        let found = preceding_instruction(0x1000, |_, _| Err(crate::Error::InvalidAddress));
        assert_eq!(found, None, "better no answer than a fabricated one");
    }
}
