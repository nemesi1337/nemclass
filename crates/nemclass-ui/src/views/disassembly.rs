//! Disassembly panel — a navigable disassembly for the attached process.
//!
//! The listing is always *linear*: a continuous, scrollable run of instructions
//! over the target's executable memory. Decoding starts at real `.text` regions
//! (never an ELF header) and grows incrementally as the user scrolls toward the
//! bottom — "infinite scroll" over the whole code, virtualized so even a
//! multi-megabyte module stays smooth.
//!
//! Which code is browsable comes from the Modules panel's selection, plus any
//! region pulled in on demand by navigation: following a call into an unselected
//! module, or jumping to an address elsewhere, extends the browsable set instead
//! of dead-ending.
//!
//! Navigating (address bar, "Disassemble here", a followed branch, the
//! Navigator) **keeps the code around the target**. If the address is already
//! decoded the listing is only scrolled; otherwise the session is rebuilt from a
//! *back-synced* start a few hundred bytes earlier, so the instructions before
//! and after the target are both on screen. The sync matters because x86 is
//! variable-length — see [`nemclass_core::sync_backward_start`].
//!
//! Call/jump targets are clickable (and follow with SPACE); a right-click menu
//! copies bytes, follows targets, sets the class base, adds an address node, or
//! NOPs the instruction. A dissected module shows inbound-reference badges.
//!
//! On non-Linux platforms the panel shows a static notice — the underlying
//! disassembly is Linux-only.

use std::sync::Arc;

use eframe::egui;
#[cfg(target_os = "linux")]
use eframe::egui::{Color32, RichText};
#[cfg(target_os = "linux")]
use egui_extras::{Column, TableBuilder};

#[cfg(target_os = "linux")]
use super::tasks::{BackgroundJob, Poll as JobPoll};

use nemclass_core::Process;
#[cfg(target_os = "linux")]
use nemclass_core::{
    DissectResult, FlowKind, InstructionData, ModuleInfoWithName, disassemble_range,
    dissect_regions, module_exec_regions, sync_backward_start,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Navigation history depth cap.
const HISTORY_CAP: usize = 64;

/// Bytes of code decoded *before* a navigation target, so the listing shows what
/// leads up to it instead of starting abruptly at the address. Kept small enough
/// that the back-sync search (up to this many candidate starts) stays sub-frame,
/// while still yielding a screenful of preceding instructions.
#[cfg(target_os = "linux")]
const BACK_CONTEXT_BYTES: u64 = 512;

/// The longest an x86 instruction can be.
#[cfg(target_os = "linux")]
const MAX_INSN_BYTES: usize = 15;

/// Chunks decoded eagerly when re-centring, so the target itself is on screen in
/// the same frame. Bounded — the infinite scroll takes over from there.
#[cfg(target_os = "linux")]
const RECENTER_MAX_CHUNKS: usize = 4;

/// Span browsed around an address that belongs to no loaded module (JIT code, an
/// anonymous executable mapping): there is no module span to clip to, so the
/// session is bounded by hand. Reads past the mapping simply come up short.
#[cfg(target_os = "linux")]
const ADHOC_REGION_BACK: u64 = 4 * 1024;
#[cfg(target_os = "linux")]
const ADHOC_REGION_FORWARD: u64 = 64 * 1024;

/// Bytes decoded per "extend" step in linear mode. The session grows
/// incrementally as the user scrolls toward the bottom.
#[cfg(target_os = "linux")]
const LINEAR_CHUNK_BYTES: usize = 48 * 1024;

/// Decode another chunk when the last visible row is within this many rows of
/// the end of the decoded session (keeps scrolling ahead of the viewport).
#[cfg(target_os = "linux")]
const LINEAR_EXTEND_ROWS: usize = 400;

/// Hard cap on instructions retained in one linear session (bounds memory on a
/// huge module); the user re-navigates to see beyond it.
#[cfg(target_os = "linux")]
const LINEAR_MAX_INSNS: usize = 400_000;

// ---------------------------------------------------------------------------
// DisassemblyPanel
// ---------------------------------------------------------------------------

pub struct DisassemblyPanel {
    // ── navigation ────────────────────────────────────────────────────────
    /// Current focus address (function entry, or the address the user jumped to
    /// in linear mode).
    address: usize,
    address_input: String,
    address_error: Option<String>,
    back: Vec<usize>,
    forward: Vec<usize>,

    // ── module / linear mode ──────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    modules: Vec<ModuleInfoWithName>,
    /// Modules whose executable regions are unioned into the linear view, as
    /// ascending indices into `modules`. Driven by the Modules panel.
    #[cfg(target_os = "linux")]
    selected_modules: Vec<usize>,
    /// Browsable executable `(start, end)` regions, sorted and non-overlapping.
    /// Seeded from the selected modules and extended on demand when navigation
    /// lands outside them. Linear decoding walks these and skips non-executable
    /// gaps (ELF headers, data) so the view shows real code, not zero padding.
    #[cfg(target_os = "linux")]
    linear_regions: Vec<(u64, u64)>,
    /// Instructions decoded so far this linear session — grows as the user
    /// scrolls toward the bottom.
    #[cfg(target_os = "linux")]
    linear_insns: Vec<InstructionData>,
    /// Next address to decode when extending; `None` once every region is done.
    #[cfg(target_os = "linux")]
    linear_next: Option<u64>,

    // ── dissect (cross-references) ────────────────────────────────────────
    /// Aggregate cross-references across all selected modules (merged when more
    /// than one module is dissected).
    #[cfg(target_os = "linux")]
    dissect: Option<DissectResult>,
    #[cfg(target_os = "linux")]
    dissect_status: Option<String>,
    /// In-flight dissect running on the background pool (scanning a module's code
    /// can take seconds; several modules are scanned and merged off-thread).
    #[cfg(target_os = "linux")]
    dissect_job: BackgroundJob<Result<DissectResult, String>>,
    /// Set by the "Dissect" button during the draw; the spawn (which needs the
    /// `Arc<Process>` + runtime) happens after the top bar returns.
    #[cfg(target_os = "linux")]
    pending_dissect: bool,
    /// Bumped on each successful dissect so the Navigator panel knows when to
    /// rebuild its cached lists.
    #[cfg(target_os = "linux")]
    dissect_epoch: u64,

    /// Symbol at the current focus address, for the "This is: …" label.
    #[cfg(target_os = "linux")]
    entry_symbol: Option<String>,

    pub status_msg: Option<String>,

    // ── per-frame deferred state ──────────────────────────────────────────
    /// Address to bring into view; resolved at the top of the next draw, where
    /// the `Process` needed to decode around it is in hand.
    #[cfg(target_os = "linux")]
    pending_focus: Option<usize>,
    pending_navigate: Option<usize>,
    selected_row: Option<usize>,
    /// When set, the table scrolls this row into view next frame.
    scroll_to_row: Option<usize>,
    pending_action: Option<DisasmAction>,

    // ── signature generation ──────────────────────────────────────────────
    /// Address for which a signature was requested; resolved after the draw.
    #[cfg(target_os = "linux")]
    pending_signature: Option<usize>,
    /// Most recently computed signature: Ok(ida_hex) or Err(reason).
    #[cfg(target_os = "linux")]
    last_signature: Option<Result<String, String>>,
}

/// A cross-panel request from the disassembler's row context menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisasmAction {
    SetClassAddress(usize),
    AddAddressToClass(usize),
    /// Arm an execute breakpoint here. The debugger's address had to be typed
    /// by hand, which meant copying it out of this very view.
    SetBreakpoint(usize),
}

impl DisassemblyPanel {
    pub fn new() -> Self {
        Self {
            address: 0,
            address_input: String::new(),
            address_error: None,
            back: Vec::new(),
            forward: Vec::new(),
            #[cfg(target_os = "linux")]
            modules: Vec::new(),
            #[cfg(target_os = "linux")]
            selected_modules: Vec::new(),
            #[cfg(target_os = "linux")]
            linear_regions: Vec::new(),
            #[cfg(target_os = "linux")]
            linear_insns: Vec::new(),
            #[cfg(target_os = "linux")]
            linear_next: None,
            #[cfg(target_os = "linux")]
            dissect: None,
            #[cfg(target_os = "linux")]
            dissect_status: None,
            #[cfg(target_os = "linux")]
            dissect_job: BackgroundJob::default(),
            #[cfg(target_os = "linux")]
            pending_dissect: false,
            #[cfg(target_os = "linux")]
            dissect_epoch: 0,
            #[cfg(target_os = "linux")]
            entry_symbol: None,
            status_msg: None,
            #[cfg(target_os = "linux")]
            pending_focus: None,
            pending_navigate: None,
            selected_row: None,
            scroll_to_row: None,
            pending_action: None,
            #[cfg(target_os = "linux")]
            pending_signature: None,
            #[cfg(target_os = "linux")]
            last_signature: None,
        }
    }

    /// Drains a pending row-context-menu action for the app to apply.
    pub fn take_action(&mut self) -> Option<DisasmAction> {
        self.pending_action.take()
    }

    /// The current dissect result (call/jump/string cross-references), if a
    /// module has been dissected. Consumed by the Navigator side panel.
    #[cfg(target_os = "linux")]
    pub fn dissect_result(&self) -> Option<&DissectResult> {
        self.dissect.as_ref()
    }

    /// Monotonic counter bumped on each successful dissect (lets the Navigator
    /// know when to rebuild its cached lists).
    #[cfg(target_os = "linux")]
    pub fn dissect_epoch(&self) -> u64 {
        self.dissect_epoch
    }

    /// Drain a completed background dissect. Call each frame from the parent's
    /// `logic()` so results land even when the Disassembly tab is not visible.
    #[cfg(target_os = "linux")]
    pub fn poll(&mut self) {
        if let JobPoll::Done(result) = self.dissect_job.poll() {
            self.apply_dissect(result);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn poll(&mut self) {}

    /// Run a dissect over the currently-selected module (public entry point for
    /// the Navigator's "Scan" button). Async — spawns on the background pool.
    #[cfg(target_os = "linux")]
    pub fn dissect_selected(
        &mut self,
        process: Arc<Process>,
        rt: &tokio::runtime::Handle,
        ctx: egui::Context,
    ) {
        self.do_dissect(process, rt, ctx);
    }

    /// Debug/screenshot hook: refresh modules and enter linear mode over the
    /// first module whose name contains `substr` (or the first sizeable module).
    pub fn debug_enter_module(&mut self, process: &Process, substr: Option<&str>) {
        #[cfg(target_os = "linux")]
        {
            self.on_attach(process);
            let idx = match substr {
                Some(s) => self.modules.iter().position(|m| m.name.contains(s)),
                None => self.modules.iter().position(|m| m.size > 0x2000),
            };
            if let Some(idx) = idx {
                self.set_selected_modules(&[idx], process);
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (process, substr);
    }

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    pub fn on_attach(&mut self, process: &Process) {
        #[cfg(target_os = "linux")]
        {
            self.modules = match process.modules() {
                Ok(it) => {
                    let mut v: Vec<ModuleInfoWithName> = it.collect();
                    v.sort_by_key(|m| m.base);
                    v
                }
                Err(_) => Vec::new(),
            };
            self.reset_state();
        }
        #[cfg(not(target_os = "linux"))]
        let _ = process;
    }

    pub fn on_detach(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.modules.clear();
            self.reset_state();
        }
    }

    #[cfg(target_os = "linux")]
    fn reset_state(&mut self) {
        self.selected_modules.clear();
        self.linear_regions.clear();
        self.linear_insns.clear();
        self.linear_next = None;
        self.dissect = None;
        self.dissect_status = None;
        // Discard any in-flight dissect so a stale result can't land post-detach.
        self.dissect_job = BackgroundJob::default();
        self.pending_dissect = false;
        self.entry_symbol = None;
        self.selected_row = None;
        self.scroll_to_row = None;
        self.pending_focus = None;
        self.pending_signature = None;
        self.last_signature = None;
    }

    // -----------------------------------------------------------------------
    // Public navigation API (called from other panels)
    // -----------------------------------------------------------------------

    /// Navigate to `addr`, keeping the code around it (used by "Disassemble
    /// here", the Navigator, and the memory viewer).
    pub fn goto(&mut self, addr: usize) {
        if self.address != 0 && self.address != addr {
            self.push_back(self.address);
        }
        self.forward.clear();
        self.set_focus(addr);
    }

    // -----------------------------------------------------------------------
    // Internal navigation
    // -----------------------------------------------------------------------

    fn push_back(&mut self, addr: usize) {
        if self.back.len() >= HISTORY_CAP {
            self.back.remove(0);
        }
        self.back.push(addr);
    }

    fn push_forward(&mut self, addr: usize) {
        if self.forward.len() >= HISTORY_CAP {
            self.forward.remove(0);
        }
        self.forward.push(addr);
    }

    /// Move the focus address. The view update itself needs the `Process` (to
    /// decode around the address), so it is deferred to the next draw via
    /// [`Self::focus_now`].
    fn set_focus(&mut self, addr: usize) {
        self.address = addr;
        self.address_input = format!("{addr:#018x}");
        self.address_error = None;
        self.selected_row = None;
        // A decode error from wherever we were is stale now.
        self.status_msg = None;

        #[cfg(target_os = "linux")]
        {
            self.pending_focus = Some(addr);
        }
    }

    fn navigate(&mut self, target: usize) {
        if target == self.address {
            return;
        }
        self.push_back(self.address);
        self.forward.clear();
        self.set_focus(target);
    }

    fn go_back(&mut self) {
        if let Some(prev) = self.back.pop() {
            self.push_forward(self.address);
            self.set_focus(prev);
        }
    }

    fn go_forward(&mut self) {
        if let Some(next) = self.forward.pop() {
            self.push_back(self.address);
            self.set_focus(next);
        }
    }

    fn try_parse_address(&mut self) {
        // Shared with every other address box in the app — see
        // `super::parse_address`. Bare digits are hex, not decimal.
        match super::parse_address(&self.address_input) {
            // Go navigates *within* the listing, keeping the surrounding
            // disassembly. An address outside the browsed regions is not an
            // error — the region is discovered on demand (see `ensure_region_for`).
            Ok(addr) => {
                self.address_error = None;
                self.navigate(addr);
            }
            Err(e) => self.address_error = Some(e),
        }
    }

    // -----------------------------------------------------------------------
    // Linear-mode engine (Linux-only)
    // -----------------------------------------------------------------------

    /// Browse `indices` (into `modules`): union every selected module's
    /// executable regions into one address-sorted list and start decoding at the
    /// first one (real `.text`, never an ELF header). The Modules panel calls
    /// this whenever its checkbox selection changes.
    #[cfg(target_os = "linux")]
    pub fn set_selected_modules(&mut self, indices: &[usize], process: &Process) {
        self.selected_modules = indices.to_vec();
        self.selected_modules.sort_unstable();
        self.selected_modules.dedup();

        // Dissect results are tied to the selection; drop them when it changes.
        self.dissect = None;
        self.dissect_status = None;

        // Union the executable regions of every selected module. Regions
        // discovered by earlier navigation are dropped: the selection defines
        // the browsable set afresh.
        let pid = process.pid();
        let mut regions: Vec<(u64, u64)> = Vec::new();
        for &idx in &self.selected_modules {
            if let Some(m) = self.modules.get(idx) {
                regions.extend(module_exec_regions(pid, m.base, m.size).unwrap_or_default());
            }
        }
        merge_regions(&mut regions);
        self.linear_regions = regions;

        // The previous session's instructions are no longer in the browsed set.
        self.linear_insns.clear();
        self.linear_next = None;
        self.selected_row = None;

        // No modules selected → clear the view and leave a hint.
        if self.linear_regions.is_empty() {
            return;
        }

        if self.address != 0 {
            self.push_back(self.address);
        }
        self.forward.clear();

        // Decode immediately so the view is populated this frame.
        let start = self.linear_regions[0].0 as usize;
        self.address = start;
        self.address_input = format!("{start:#018x}");
        self.address_error = None;
        self.focus_now(process, start);
    }

    /// Brings `addr` into view, **keeping the code around it**.
    ///
    /// Already decoded in this session → the listing is untouched and merely
    /// scrolled, so everything before and after stays put. Otherwise the session
    /// restarts from a back-synced start (see [`Self::back_context_start`]) far
    /// enough ahead of `addr` that the instructions leading up to it are decoded
    /// too, and enough chunks are pulled to put `addr` itself on screen now.
    #[cfg(target_os = "linux")]
    fn focus_now(&mut self, process: &Process, addr: usize) {
        self.entry_symbol = process.resolve_symbol(addr).unwrap_or(None);

        // Mark where we landed: with context on both sides the target is no
        // longer simply the top row.
        if let Some(idx) = self.linear_index_of(addr as u64) {
            self.scroll_to_row = Some(idx);
            self.selected_row = Some(idx);
            return;
        }

        self.ensure_region_for(process, addr as u64);
        let start = self.back_context_start(process, addr as u64);
        self.linear_reset(start);
        for _ in 0..RECENTER_MAX_CHUNKS {
            self.extend_linear(process);
            if self.linear_next.is_none() || self.linear_index_of(addr as u64).is_some() {
                break;
            }
        }
        // A decode that never reached `addr` (unreadable code, a desync) still
        // shows the window we did get, from the top.
        let row = self.linear_index_of(addr as u64);
        self.scroll_to_row = Some(row.unwrap_or(0));
        self.selected_row = row;
    }

    /// Where to start decoding so the listing shows real code *before* `addr`.
    ///
    /// x86 is variable-length, so a window that simply begins `BACK_CONTEXT_BYTES`
    /// earlier would print garbage until it happened to re-sync. This reads that
    /// window and asks the decoder which start actually steps onto `addr`; if
    /// none does (or the bytes are unreadable), it falls back to `addr` itself —
    /// no preceding context beats invented context.
    #[cfg(target_os = "linux")]
    fn back_context_start(&self, process: &Process, addr: u64) -> u64 {
        // Never reach behind the region: that is unmapped or non-code.
        let floor = self.region_of(addr).map_or(0, |(s, _)| s);
        let lo = addr.saturating_sub(BACK_CONTEXT_BYTES).max(floor);
        if lo >= addr {
            return addr;
        }
        let len = (addr - lo) as usize;
        // Over-read by one maximum-length instruction so the one *covering* the
        // address (a hand-typed address is often mid-instruction) decodes whole.
        let mut buf = vec![0u8; len + MAX_INSN_BYTES];
        match process.read_buf(lo as usize, &mut buf) {
            // Anything shorter than the run up to `addr` means the bytes next to
            // it are missing, so nothing can sync onto it.
            Ok(n) if n >= len => sync_backward_start(&buf[..n], lo, addr).unwrap_or(addr),
            _ => addr,
        }
    }

    /// Makes sure `addr` falls inside a browsable region, discovering one if it
    /// does not — following a call into an unselected module, or jumping to an
    /// address outside the selection, should widen the view rather than fail.
    #[cfg(target_os = "linux")]
    fn ensure_region_for(&mut self, process: &Process, addr: u64) {
        if self.region_of(addr).is_some() {
            return;
        }

        let a = addr as usize;
        let owner = self
            .modules
            .iter()
            .find(|m| a >= m.base && a < m.base + m.size)
            .map(|m| (m.base, m.size));
        let mut added = match owner {
            Some((base, size)) => module_exec_regions(process.pid(), base, size).unwrap_or_default(),
            None => Vec::new(),
        };

        // Not in any module's executable mapping (JIT, anonymous exec memory, or
        // a module whose maps we could not read): browse a bounded window.
        if !added.iter().any(|(s, e)| addr >= *s && addr < *e) {
            added.push((
                addr.saturating_sub(ADHOC_REGION_BACK),
                addr.saturating_add(ADHOC_REGION_FORWARD),
            ));
        }

        self.linear_regions.append(&mut added);
        merge_regions(&mut self.linear_regions);
    }

    /// The executable region containing `addr`, if any.
    #[cfg(target_os = "linux")]
    fn region_of(&self, addr: u64) -> Option<(u64, u64)> {
        self.linear_regions
            .iter()
            .copied()
            .find(|(s, e)| addr >= *s && addr < *e)
    }

    /// The start of the first region at or after `addr`.
    #[cfg(target_os = "linux")]
    fn next_region_start(&self, addr: u64) -> Option<u64> {
        self.linear_regions
            .iter()
            .map(|(s, _)| *s)
            .filter(|s| *s >= addr)
            .min()
    }

    /// `addr` if it lies in a region, else the next region start.
    #[cfg(target_os = "linux")]
    fn clamp_into_regions(&self, addr: u64) -> Option<u64> {
        if self.region_of(addr).is_some() {
            Some(addr)
        } else {
            self.next_region_start(addr)
        }
    }

    /// Restart the linear session decoding from `start` (clamped into a region).
    #[cfg(target_os = "linux")]
    fn linear_reset(&mut self, start: u64) {
        self.linear_insns.clear();
        self.selected_row = None;
        self.linear_next = self.clamp_into_regions(start);
    }

    /// Index of the instruction at (or containing) `addr` in `linear_insns`.
    #[cfg(target_os = "linux")]
    fn linear_index_of(&self, addr: u64) -> Option<usize> {
        if self.linear_insns.is_empty() {
            return None;
        }
        match self.linear_insns.binary_search_by(|i| i.address.cmp(&addr)) {
            Ok(i) => Some(i),
            Err(i) => {
                if i == 0 {
                    return None;
                }
                let prev = &self.linear_insns[i - 1];
                (addr < prev.address + prev.length as u64).then_some(i - 1)
            }
        }
    }

    /// Decode the next chunk of linear code and append it, advancing across
    /// region boundaries. A no-op once `linear_next` is `None` or the cap is hit.
    #[cfg(target_os = "linux")]
    fn extend_linear(&mut self, process: &Process) {
        if self.linear_insns.len() >= LINEAR_MAX_INSNS {
            self.linear_next = None;
            return;
        }
        let Some(start) = self.linear_next else {
            return;
        };
        let Some((_rs, re)) = self.region_of(start) else {
            // `start` isn't in a region — skip to the next one, if any.
            self.linear_next = self.next_region_start(start);
            return;
        };
        let len = LINEAR_CHUNK_BYTES.min((re - start) as usize);
        if len == 0 {
            self.linear_next = self.next_region_start(re);
            return;
        }
        match disassemble_range(process, start, len) {
            Ok(mut insns) => {
                let last_end = insns.last().map(|i| i.address + i.length as u64);
                self.linear_insns.append(&mut insns);
                self.linear_next = match last_end {
                    // Continue within this region…
                    Some(end) if end < re => Some(end),
                    // …or move on to the next region.
                    _ => self.next_region_start(re),
                };
            }
            Err(e) => {
                self.status_msg = Some(format!("Disassembly failed: {e}"));
                self.linear_next = None;
            }
        }
    }

    /// Launch a Dissect Code scan over the selected module's executable regions on
    /// the background pool (scanning a whole module can take seconds). The result
    /// lands via [`Self::poll`].
    #[cfg(target_os = "linux")]
    fn do_dissect(
        &mut self,
        process: Arc<Process>,
        rt: &tokio::runtime::Handle,
        ctx: egui::Context,
    ) {
        if self.dissect_job.is_running() {
            return;
        }
        let targets = self.dissect_targets();
        if targets.is_empty() {
            self.dissect_status = Some("Select modules in the Modules panel first.".to_owned());
            return;
        }
        self.dissect_status = Some("Dissecting…".to_owned());
        self.dissect_job
            .spawn(rt, ctx, move || compute_dissect_many(&process, &targets));
    }

    /// `(base, size)` of every currently-selected module, for a dissect scan.
    #[cfg(target_os = "linux")]
    fn dissect_targets(&self) -> Vec<(usize, usize)> {
        self.selected_modules
            .iter()
            .filter_map(|&i| self.modules.get(i).map(|m| (m.base, m.size)))
            .collect()
    }

    /// Synchronous dissect of the selected module (blocks the caller). Only for
    /// the `--screenshot` debug hooks, where the capture must see the result in
    /// the same frame; interactive dissects go through [`Self::do_dissect`].
    #[cfg(target_os = "linux")]
    pub fn dissect_selected_blocking(&mut self, process: &Process) {
        let targets = self.dissect_targets();
        if targets.is_empty() {
            self.dissect_status = Some("Select modules in the Modules panel first.".to_owned());
            return;
        }
        let result = compute_dissect_many(process, &targets);
        self.apply_dissect(result);
    }

    /// Merge a completed dissect (from the worker or the sync debug path) into
    /// panel state, bumping the epoch so the Navigator rebuilds its lists.
    #[cfg(target_os = "linux")]
    fn apply_dissect(&mut self, result: Result<DissectResult, String>) {
        match result {
            Ok(result) => {
                self.dissect_status = Some(format!(
                    "{} call targets, {} jump targets, {} strings",
                    result.calls.len(),
                    result.jumps.len(),
                    result.strings.len(),
                ));
                self.dissect = Some(result);
                self.dissect_epoch = self.dissect_epoch.wrapping_add(1);
            }
            Err(e) => {
                self.dissect = None;
                self.dissect_status = Some(format!("Dissect failed: {e}"));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Draw
    // -----------------------------------------------------------------------

    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<Arc<Process>>,
        rt: &tokio::runtime::Handle,
    ) {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (process, rt);
            ui.centered_and_justified(|ui| {
                ui.label("Disassembly is Linux-only for now.");
            });
            return;
        }

        #[cfg(target_os = "linux")]
        self.show_linux(ui, process, rt);
    }

    #[cfg(target_os = "linux")]
    fn show_linux(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<Arc<Process>>,
        rt: &tokio::runtime::Handle,
    ) {
        let Some(proc_arc) = process else {
            ui.centered_and_justified(|ui| {
                ui.colored_label(Color32::YELLOW, "Attach to a process to disassemble.");
            });
            return;
        };
        let process: &Process = &proc_arc;

        // Resolve a navigation requested last frame (or by another panel) before
        // drawing, so the target and its surroundings are on screen this frame.
        if let Some(addr) = self.pending_focus.take() {
            self.focus_now(process, addr);
        }
        self.show_top_bar(ui, process);
        ui.separator();
        self.handle_keyboard(ui);
        self.show_table(ui, process);

        // Spawn a deferred dissect (the "Dissect" button set the flag; we have the
        // shared handle + runtime here).
        if std::mem::take(&mut self.pending_dissect) {
            self.do_dissect(Arc::clone(&proc_arc), rt, ui.ctx().clone());
        }

        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(Color32::from_rgb(220, 160, 40), msg);
        }

        if let Some(sig_result) = &self.last_signature {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                match sig_result {
                    Ok(sig) => {
                        ui.colored_label(Color32::from_rgb(100, 220, 100), "Signature:");
                        ui.monospace(sig);
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(sig.clone());
                        }
                    }
                    Err(msg) => {
                        ui.colored_label(Color32::RED, format!("Signature: {msg}"));
                    }
                }
            });
        }

        if let Some(target) = self.pending_navigate.take() {
            self.navigate(target);
        }
        // A focus queued during this frame is applied at the top of the next one.
        if self.pending_focus.is_some() {
            ui.ctx().request_repaint();
        }
    }

    /// Keyboard: BACKSPACE = back, arrows move the selection, SPACE follows the
    /// selected instruction's branch target. Ignored while a text field is focused.
    #[cfg(target_os = "linux")]
    fn handle_keyboard(&mut self, ui: &egui::Ui) {
        if ui.memory(|m| m.focused().is_some()) {
            return;
        }
        let (space, backspace, up, down) = ui.input(|i| {
            (
                i.key_pressed(egui::Key::Space),
                i.key_pressed(egui::Key::Backspace),
                i.key_pressed(egui::Key::ArrowUp),
                i.key_pressed(egui::Key::ArrowDown),
            )
        });

        let active_len = self.linear_insns.len();
        let space_target = self
            .selected_row
            .and_then(|r| self.linear_insns.get(r))
            .and_then(|ins| ins.target);

        if backspace {
            self.go_back();
        }
        if active_len > 0 {
            if down {
                let r = Some(self.selected_row.map_or(0, |r| (r + 1).min(active_len - 1)));
                self.selected_row = r;
                if let Some(r) = r {
                    self.scroll_to_row = Some(r);
                }
            }
            if up {
                let r = Some(self.selected_row.map_or(0, |r| r.saturating_sub(1)));
                self.selected_row = r;
                if let Some(r) = r {
                    self.scroll_to_row = Some(r);
                }
            }
        }
        if space && let Some(tgt) = space_target {
            self.pending_navigate = Some(tgt as usize);
        }
    }

    // -----------------------------------------------------------------------
    // Top bar
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn show_top_bar(&mut self, ui: &mut egui::Ui, process: &Process) {
        let _ = process;
        let mut dissect_clicked = false;

        ui.horizontal(|ui| {
            let n_sel = self.selected_modules.len();
            ui.label(match n_sel {
                0 => "No modules selected".to_owned(),
                1 => "1 module".to_owned(),
                n => format!("{n} modules"),
            });
            ui.weak("— pick modules in the Modules panel");

            let can_dissect = !self.selected_modules.is_empty();
            if ui
                .add_enabled(can_dissect, egui::Button::new("Dissect"))
                .on_hover_text(
                    "Scan the selected modules' code for call/jump/string cross-references",
                )
                .on_disabled_hover_text("Select modules in the Modules panel first")
                .clicked()
            {
                dissect_clicked = true;
            }

            if !self.linear_insns.is_empty() {
                let n = self.linear_insns.len();
                let more = if self.linear_next.is_some() { "+" } else { "" };
                ui.separator();
                ui.weak(format!("{n}{more} instructions"));
            }

            if let Some(status) = &self.dissect_status {
                ui.separator();
                ui.colored_label(Color32::from_rgb(140, 180, 220), status);
            }
        });

        ui.horizontal(|ui| {
            let can_back = !self.back.is_empty();
            let can_fwd = !self.forward.is_empty();
            if ui.add_enabled(can_back, egui::Button::new("◀ Back")).clicked() {
                self.go_back();
            }
            if ui
                .add_enabled(can_fwd, egui::Button::new("▶ Forward"))
                .clicked()
            {
                self.go_forward();
            }

            ui.separator();
            ui.label("Address:");
            if self.address_input.is_empty() {
                self.address_input = format!("{:#018x}", self.address);
            }
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.address_input)
                    .desired_width(200.0)
                    .font(egui::TextStyle::Monospace),
            );
            let go = ui.button("Go").clicked();
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if go || enter {
                self.try_parse_address();
            }
            if let Some(err) = &self.address_error {
                ui.colored_label(Color32::RED, err);
            }
            if let Some(sym) = self.entry_symbol.as_deref() {
                ui.separator();
                ui.colored_label(Color32::from_rgb(100, 200, 100), format!("This is: {sym}"));
            }
        });

        if dissect_clicked {
            // Defer: the actual spawn needs the `Arc<Process>` + runtime, which
            // `show_linux` has. Applied right after the top bar returns.
            self.pending_dissect = true;
        }
    }

    // -----------------------------------------------------------------------
    // Instruction table (virtualized; borrows the active list, never clones it)
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn show_table(&mut self, ui: &mut egui::Ui, process: &Process) {
        // Actions collected during the (borrow-free-of-self) table draw.
        let mut nav_target: Option<usize> = None;
        let mut new_selection: Option<usize> = None;
        let mut nop_target: Option<(usize, usize)> = None;
        let mut queued_action: Option<DisasmAction> = None;
        let mut copy_text: Option<String> = None;
        let mut pending_sig_addr: Option<usize> = None;
        let mut max_visible: usize = 0;
        let len = self.linear_insns.len();

        {
            // Disjoint field borrows: `insns`/`dissect` (shared) coexist with the
            // `scroll_to_row.take()` (mut, different field) because they are all
            // direct field paths.
            let insns: &[InstructionData] = &self.linear_insns;
            let dissect = self.dissect.as_ref();
            let modules: &[ModuleInfoWithName] = &self.modules;
            let selected_row = self.selected_row;
            let scroll_to = self.scroll_to_row.take();

            if insns.is_empty() {
                if self.linear_regions.is_empty() {
                    ui.label("Select modules in the Modules panel, or enter an address, to disassemble.");
                } else if self.linear_next.is_some() {
                    ui.weak("Decoding…");
                } else {
                    ui.label("No instructions decoded.");
                }
            } else {
                let default_text = ui.visuals().text_color();
                let row_height = ui.text_style_height(&egui::TextStyle::Body) + 4.0;

                let mut table = TableBuilder::new(ui)
                    .id_salt("disassembly_table")
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .column(Column::initial(180.0).at_least(120.0)) // Address
                    .column(Column::initial(120.0).at_least(70.0)) // Module
                    .column(Column::initial(150.0).at_least(80.0)) // Bytes
                    .column(Column::initial(230.0).at_least(140.0)) // Instruction
                    .column(Column::remainder().at_least(120.0)); // Comment
                if let Some(row) = scroll_to {
                    table = table.scroll_to_row(row, Some(egui::Align::Center));
                }
                table
                    .header(row_height + 2.0, |mut h| {
                        h.col(|ui| {
                            ui.strong("Address");
                        });
                        h.col(|ui| {
                            ui.strong("Module");
                        });
                        h.col(|ui| {
                            ui.strong("Bytes");
                        });
                        h.col(|ui| {
                            ui.strong("Instruction");
                        });
                        h.col(|ui| {
                            ui.strong("Comment");
                        });
                    })
                    .body(|body| {
                        body.rows(row_height, insns.len(), |mut row| {
                            let idx = row.index();
                            if idx > max_visible {
                                max_visible = idx;
                            }
                            let Some(ins) = insns.get(idx) else {
                                return;
                            };
                            let addr = ins.address;
                            let length = ins.length;
                            let bytes = &ins.data[..length.min(ins.data.len())];
                            let hex: String = bytes
                                .iter()
                                .map(|b| format!("{b:02x}"))
                                .collect::<Vec<_>>()
                                .join(" ");
                            let mnemonic = &ins.instruction;
                            let kind = ins.kind;
                            let target = ins.target;

                            // Comment: symbol / string preview / data reference.
                            let describe = |a: u64| -> Option<String> {
                                if let Some(name) =
                                    process.resolve_symbol(a as usize).ok().flatten()
                                {
                                    return Some(name);
                                }
                                dissect
                                    .and_then(|d| d.string_previews.get(&a))
                                    .map(|p| format!("\"{p}\""))
                            };
                            let comment = if let Some(t) = target {
                                describe(t)
                            } else {
                                ins.mem_target
                                    .map(|m| describe(m).unwrap_or_else(|| format!("[{m:#x}]")))
                            };

                            // Inbound references (from a dissect scan).
                            let referrers: Vec<u64> = dissect
                                .map(|d| {
                                    let mut v = Vec::new();
                                    if let Some(x) = d.calls.get(&addr) {
                                        v.extend(x);
                                    }
                                    if let Some(x) = d.jumps.get(&addr) {
                                        v.extend(x);
                                    }
                                    if let Some(x) = d.strings.get(&addr) {
                                        v.extend(x);
                                    }
                                    v.sort_unstable();
                                    v.dedup();
                                    v
                                })
                                .unwrap_or_default();

                            row.set_selected(selected_row == Some(idx));

                            // Address (+ xref badge).
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    ui.monospace(format!("{addr:#018x}"));
                                    if !referrers.is_empty() {
                                        ui.menu_button(
                                            RichText::new(format!("⟵{}", referrers.len()))
                                                .small()
                                                .color(Color32::from_rgb(200, 160, 90)),
                                            |ui| {
                                                ui.weak("Referenced by:");
                                                for &r in &referrers {
                                                    if ui.button(format!("{r:#018x}")).clicked() {
                                                        nav_target = Some(r as usize);
                                                        ui.close();
                                                    }
                                                }
                                            },
                                        );
                                    }
                                });
                            });
                            // Module (basename of the module owning this address).
                            row.col(|ui| {
                                if let Some(name) = module_name_at(modules, addr) {
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(name)
                                                .monospace()
                                                .color(Color32::from_rgb(150, 160, 180)),
                                        )
                                        .truncate(),
                                    )
                                    .on_hover_text(name);
                                }
                            });
                            // Bytes.
                            row.col(|ui| {
                                ui.monospace(&hex);
                            });
                            // Instruction (colour-coded; clickable if it branches).
                            row.col(|ui| {
                                let color = flow_color(kind, default_text);
                                let is_branch = matches!(
                                    kind,
                                    FlowKind::Call | FlowKind::Jump | FlowKind::CondJump
                                );
                                if is_branch && target.is_some() {
                                    let resp = ui.add(
                                        egui::Label::new(
                                            RichText::new(mnemonic).color(color).monospace(),
                                        )
                                        .sense(egui::Sense::click()),
                                    );
                                    if resp.clicked() {
                                        nav_target = target.map(|t| t as usize);
                                    }
                                } else {
                                    ui.monospace(RichText::new(mnemonic).color(color));
                                }
                            });
                            // Comment.
                            row.col(|ui| {
                                if let Some(c) = &comment {
                                    ui.monospace(
                                        RichText::new(format!("; {c}"))
                                            .color(Color32::from_rgb(120, 160, 120)),
                                    );
                                }
                            });

                            // Row select + context menu.
                            let resp = row.response();
                            if resp.clicked() {
                                new_selection = Some(idx);
                            }
                            resp.context_menu(|ui| {
                                ui.label(RichText::new(format!("{addr:#018x}")).monospace().weak());
                                ui.separator();
                                if ui.button("Copy address").clicked() {
                                    copy_text = Some(format!("{addr:#x}"));
                                    ui.close();
                                }
                                if ui.button("Copy bytes").clicked() {
                                    copy_text = Some(hex.clone());
                                    ui.close();
                                }
                                if ui.button("Copy instruction").clicked() {
                                    copy_text = Some(mnemonic.clone());
                                    ui.close();
                                }
                                if let Some(t) = target {
                                    ui.separator();
                                    if ui.button(format!("Follow → {t:#x}")).clicked() {
                                        nav_target = Some(t as usize);
                                        ui.close();
                                    }
                                }
                                ui.separator();
                                if ui.button("Set as class base").clicked() {
                                    queued_action =
                                        Some(DisasmAction::SetClassAddress(addr as usize));
                                    ui.close();
                                }
                                if ui.button("Add address to class").clicked() {
                                    queued_action =
                                        Some(DisasmAction::AddAddressToClass(addr as usize));
                                    ui.close();
                                }
                                ui.separator();
                                if ui
                                    .button(
                                        RichText::new("NOP out (write 0x90)")
                                            .color(Color32::from_rgb(230, 140, 120)),
                                    )
                                    .clicked()
                                {
                                    nop_target = Some((addr as usize, length));
                                    ui.close();
                                }
                                ui.separator();
                                if ui
                                    .button("Set breakpoint here")
                                    .on_hover_text("Arm an execute breakpoint in the debugger")
                                    .clicked()
                                {
                                    queued_action = Some(DisasmAction::SetBreakpoint(addr as usize));
                                    ui.close();
                                }
                                ui.separator();
                                if ui.button("Generate signature").clicked() {
                                    pending_sig_addr = Some(addr as usize);
                                    ui.close();
                                }
                            });
                        });
                    });
            }
        }

        // ── apply collected actions (self borrows are free again) ──────────
        if let Some(sel) = new_selection {
            self.selected_row = Some(sel);
        }
        if let Some(text) = copy_text {
            ui.ctx().copy_text(text);
        }
        if let Some(tgt) = nav_target {
            self.pending_navigate = Some(tgt);
        }
        if let Some(act) = queued_action {
            self.pending_action = Some(act);
        }
        if let Some((addr, l)) = nop_target {
            let mut ok = true;
            for i in 0..l {
                if process.write::<u8>(addr + i, 0x90u8).is_err() {
                    ok = false;
                    break;
                }
            }
            if ok {
                self.status_msg = Some(format!("Wrote {l} NOP byte(s) at {addr:#x}"));
                // Drop the session so the focus rebuilds it from the patched
                // bytes (a plain re-focus would just scroll the stale listing).
                self.linear_insns.clear();
                self.linear_next = None;
                self.pending_focus = Some(self.address);
                ui.ctx().request_repaint();
            } else {
                self.status_msg = Some(format!("NOP write failed at {addr:#x}"));
            }
        }

        // ── resolve pending signature request ─────────────────────────────
        if let Some(target_addr) = pending_sig_addr {
            self.pending_signature = Some(target_addr);
        }
        if let Some(sig_addr) = self.pending_signature.take() {
            let module = self
                .modules
                .iter()
                .find(|m| sig_addr >= m.base && sig_addr < m.base + m.size);
            if let Some(m) = module {
                let offset = sig_addr - m.base;
                let mut buf = vec![0u8; m.size];
                match process.read_buf(m.base, &mut buf) {
                    Ok(n) => {
                        buf.truncate(n);
                        // Operand-masked signature: wildcards displacement/immediate
                        // bytes so it survives a rebased image.
                        let result = nemclass_core::make_masked_signature(&buf, offset, 8, 128);
                        self.last_signature = Some(match result {
                            Some(sig) => Ok(sig),
                            None => Err(
                                "Not unique within module (try longer max_len)".to_owned(),
                            ),
                        });
                    }
                    Err(e) => {
                        self.last_signature = Some(Err(format!("Read failed: {e}")));
                    }
                }
            } else {
                self.last_signature = Some(Err(format!(
                    "{sig_addr:#x} not found in any loaded module"
                )));
            }
        }

        // ── infinite scroll: decode more as the viewport nears the end ─────
        if self.linear_next.is_some() && (len == 0 || max_visible + LINEAR_EXTEND_ROWS >= len) {
            self.extend_linear(process);
            ui.ctx().request_repaint();
        }
    }
}

/// Scan a module's executable regions for call/jump/string cross-references.
/// Runs off the UI thread (from `do_dissect`'s worker) or inline (debug path).
#[cfg(target_os = "linux")]
fn compute_dissect(process: &Process, base: usize, size: usize) -> Result<DissectResult, String> {
    module_exec_regions(process.pid(), base, size)
        .and_then(|regions| dissect_regions(process, &regions))
        .map_err(|e| e.to_string())
}

/// Dissect every `(base, size)` target and merge the results into one aggregate,
/// so cross-references resolve across all selected modules (e.g. a call from one
/// module into another).
#[cfg(target_os = "linux")]
fn compute_dissect_many(
    process: &Process,
    targets: &[(usize, usize)],
) -> Result<DissectResult, String> {
    let mut merged = DissectResult::default();
    for &(base, size) in targets {
        merge_dissect(&mut merged, compute_dissect(process, base, size)?);
    }
    // Restore the per-map "sorted + de-duplicated referrers" invariant that
    // callers (the Navigator, xref badges) rely on.
    for v in merged
        .calls
        .values_mut()
        .chain(merged.jumps.values_mut())
        .chain(merged.strings.values_mut())
    {
        v.sort_unstable();
        v.dedup();
    }
    Ok(merged)
}

/// Fold `from`'s cross-reference maps into `into` (referrer lists concatenated;
/// re-sorting is done once by the caller after all modules are merged).
#[cfg(target_os = "linux")]
fn merge_dissect(into: &mut DissectResult, from: DissectResult) {
    for (k, mut v) in from.calls {
        into.calls.entry(k).or_default().append(&mut v);
    }
    for (k, mut v) in from.jumps {
        into.jumps.entry(k).or_default().append(&mut v);
    }
    for (k, mut v) in from.strings {
        into.strings.entry(k).or_default().append(&mut v);
    }
    into.string_previews.extend(from.string_previews);
}

/// Sorts `regions` by start and coalesces touching/overlapping ones, so the
/// browsable set stays a partition: `region_of` then has exactly one answer and
/// the linear walk cannot decode the same bytes twice at a seam.
#[cfg(target_os = "linux")]
fn merge_regions(regions: &mut Vec<(u64, u64)>) {
    regions.retain(|(s, e)| s < e);
    regions.sort_unstable_by_key(|(s, _)| *s);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(regions.len());
    for (start, end) in regions.drain(..) {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    *regions = merged;
}

/// Basename of the module containing `addr`, if any. Binary-searches the
/// base-sorted `modules` slice so the Module table column is cheap per row.
#[cfg(target_os = "linux")]
fn module_name_at(modules: &[ModuleInfoWithName], addr: u64) -> Option<&str> {
    let addr = addr as usize;
    let i = modules.partition_point(|m| m.base <= addr);
    let m = modules.get(i.checked_sub(1)?)?;
    (addr < m.base + m.size).then_some(m.name.as_str())
}

/// Distinct colour per control-flow class.
#[cfg(target_os = "linux")]
fn flow_color(kind: FlowKind, default: Color32) -> Color32 {
    match kind {
        FlowKind::Call => Color32::from_rgb(120, 170, 255),
        FlowKind::Jump => Color32::from_rgb(230, 150, 90),
        FlowKind::CondJump => Color32::from_rgb(220, 200, 90),
        FlowKind::Ret => Color32::from_rgb(255, 120, 90),
        FlowKind::Int3 => Color32::from_rgb(170, 110, 190),
        FlowKind::Seq | FlowKind::Other => default,
    }
}

impl Default for DisassemblyPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Navigation keeps the code *around* the target — the property that "go to
/// address" / "Disassemble here" used to lose by collapsing the listing to a
/// single function starting at the address.
#[cfg(all(test, target_os = "linux"))]
mod navigation_tests {
    use super::*;
    use nemclass_core::MockMemoryBackend;

    const BASE: usize = 0x1_0000;
    const TARGET: usize = BASE + 0x800;

    /// A page of `nop`s with a recognisable 3-byte instruction at [`TARGET`],
    /// served at [`BASE`]. There is no `/proc/1/maps` we can read, so the panel
    /// falls back to its ad-hoc browsing window — the same path a JIT address
    /// takes.
    fn panel_focused_on_target() -> (DisassemblyPanel, Process) {
        let mut bytes = vec![0x90u8; 0x1000];
        bytes[0x800..0x803].copy_from_slice(&[0x48, 0x89, 0xE5]); // mov rbp, rsp
        let process = Process::from_backend_for_test(1, Box::new(MockMemoryBackend::new(BASE, bytes)));

        let mut panel = DisassemblyPanel::new();
        panel.goto(TARGET);
        let addr = panel.pending_focus.take().expect("goto queues a focus");
        panel.focus_now(&process, addr);
        (panel, process)
    }

    #[test]
    fn navigating_to_an_address_decodes_the_code_before_it() {
        let (panel, _process) = panel_focused_on_target();

        let idx = panel
            .linear_index_of(TARGET as u64)
            .expect("the target itself should be decoded");

        assert!(idx > 0, "expected preceding context, target is the first row");
        assert_eq!(
            panel.scroll_to_row,
            Some(idx),
            "the target row is what gets scrolled into view"
        );

        // The context is *sequential*: the row above ends exactly where the
        // target begins (a desynced back-window would not line up).
        let prev = &panel.linear_insns[idx - 1];
        assert_eq!(prev.address + prev.length as u64, TARGET as u64);

        // …and the code after the target is there too, not cut off at a `ret`.
        assert!(
            panel.linear_insns.len() > idx + 1,
            "expected instructions after the target"
        );
    }

    #[test]
    fn navigating_within_the_listing_keeps_it_intact() {
        let (mut panel, process) = panel_focused_on_target();
        let first = panel.linear_insns[0].address;
        let count = panel.linear_insns.len();

        // A second hop to an address already on screen must scroll, not re-decode:
        // re-decoding is what threw away the surrounding disassembly.
        panel.goto(TARGET + 0x20);
        let addr = panel.pending_focus.take().expect("goto queues a focus");
        panel.focus_now(&process, addr);

        assert_eq!(panel.linear_insns[0].address, first, "listing was rebuilt");
        assert_eq!(panel.linear_insns.len(), count, "listing was rebuilt");
        assert_eq!(
            panel.scroll_to_row,
            panel.linear_index_of((TARGET + 0x20) as u64)
        );
    }
}
