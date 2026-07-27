//! Disassembly panel — a navigable disassembly for the attached process.
//!
//! Two modes:
//! - **Function**: decode a single function from an entry point (stops at the
//!   first `ret`/`int3`). This is what "Disassemble here" and the address bar do.
//! - **Linear** (module): a continuous, *scrollable* disassembly of a module's
//!   executable code. Decoding starts at the module's real `.text` regions (not
//!   the ELF header) and grows incrementally as the user scrolls toward the
//!   bottom — "infinite scroll" over the whole code, virtualized so even a
//!   multi-megabyte module stays smooth.
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
    DissectResult, FlowKind, InstructionData, ModuleInfoWithName, disassemble_function,
    disassemble_range, dissect_regions, module_exec_regions,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum bytes to read for a single function disassembly.
const DEFAULT_MAX_BYTES: usize = 4096;

/// Navigation history depth cap.
const HISTORY_CAP: usize = 64;

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
// Mode / cache
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisasmMode {
    /// Single-function view: decode from the entry point, stop at `ret`/`int3`.
    Function,
    /// Module view: continuous, scrollable linear disassembly of the code.
    Linear,
}

/// Cached single-function disassembly (Function mode).
#[cfg(target_os = "linux")]
struct DisasmCache {
    addr: usize,
    instructions: Vec<InstructionData>,
    entry_symbol: Option<String>,
}

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
    #[cfg(target_os = "linux")]
    mode: DisasmMode,
    /// Executable `(start, end)` regions of the module being browsed, sorted.
    /// Linear decoding walks these and skips non-executable gaps (ELF headers,
    /// data) so the view starts at real code, not zero padding.
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

    // ── function-mode cache ───────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    cache: Option<DisasmCache>,

    max_bytes: usize,
    pub status_msg: Option<String>,

    // ── per-frame deferred state ──────────────────────────────────────────
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
            mode: DisasmMode::Function,
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
            cache: None,
            max_bytes: DEFAULT_MAX_BYTES,
            status_msg: None,
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
        self.mode = DisasmMode::Function;
        self.linear_regions.clear();
        self.linear_insns.clear();
        self.linear_next = None;
        self.dissect = None;
        self.dissect_status = None;
        // Discard any in-flight dissect so a stale result can't land post-detach.
        self.dissect_job = BackgroundJob::default();
        self.pending_dissect = false;
        self.cache = None;
        self.selected_row = None;
        self.scroll_to_row = None;
        self.pending_signature = None;
        self.last_signature = None;
    }

    // -----------------------------------------------------------------------
    // Public navigation API (called from other panels)
    // -----------------------------------------------------------------------

    /// Navigate to `addr` in single-function mode (used by "Disassemble here").
    pub fn goto(&mut self, addr: usize) {
        #[cfg(target_os = "linux")]
        {
            self.mode = DisasmMode::Function;
        }
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

    /// Move the focus address, updating the view: in Function mode this triggers
    /// a re-decode of the function; in Linear mode it scrolls to the address if
    /// already decoded, else restarts the linear session there.
    fn set_focus(&mut self, addr: usize) {
        self.address = addr;
        self.address_input = format!("{addr:#018x}");
        self.address_error = None;
        self.selected_row = None;

        #[cfg(target_os = "linux")]
        match self.mode {
            DisasmMode::Function => {
                if self.cache.as_ref().map(|c| c.addr) != Some(addr) {
                    self.cache = None;
                }
            }
            DisasmMode::Linear => {
                if let Some(idx) = self.linear_index_of(addr as u64) {
                    self.scroll_to_row = Some(idx);
                } else {
                    self.linear_reset(addr as u64);
                    self.scroll_to_row = Some(0);
                }
            }
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
        let s = self.address_input.trim();
        let result = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            usize::from_str_radix(hex, 16).map_err(|e| e.to_string())
        } else {
            s.parse::<usize>().map_err(|e| e.to_string())
        };
        match result {
            Ok(addr) => {
                self.address_error = None;
                // Typing a raw address opens it as a single function.
                #[cfg(target_os = "linux")]
                {
                    self.mode = DisasmMode::Function;
                }
                self.navigate(addr);
            }
            Err(e) => self.address_error = Some(format!("Bad address: {e}")),
        }
    }

    // -----------------------------------------------------------------------
    // Linear-mode engine (Linux-only)
    // -----------------------------------------------------------------------

    /// Enter linear mode over `indices` (into `modules`): union every selected
    /// module's executable regions into one address-sorted list and start decoding
    /// at the first one (real `.text`, never an ELF header). The Modules panel
    /// calls this whenever its checkbox selection changes.
    #[cfg(target_os = "linux")]
    pub fn set_selected_modules(&mut self, indices: &[usize], process: &Process) {
        self.selected_modules = indices.to_vec();
        self.selected_modules.sort_unstable();
        self.selected_modules.dedup();

        // Dissect results are tied to the selection; drop them when it changes.
        self.dissect = None;
        self.dissect_status = None;

        // Union the executable regions of every selected module, sorted by start.
        let pid = process.pid();
        let mut regions: Vec<(u64, u64)> = Vec::new();
        for &idx in &self.selected_modules {
            if let Some(m) = self.modules.get(idx) {
                regions.extend(module_exec_regions(pid, m.base, m.size).unwrap_or_default());
            }
        }
        regions.sort_unstable_by_key(|r| r.0);
        self.linear_regions = regions;

        // No modules selected → clear the view and leave a hint.
        if self.linear_regions.is_empty() {
            self.mode = DisasmMode::Linear;
            self.linear_insns.clear();
            self.linear_next = None;
            self.selected_row = None;
            return;
        }

        self.mode = DisasmMode::Linear;

        if self.address != 0 {
            self.push_back(self.address);
        }
        self.forward.clear();

        let start = self.linear_regions[0].0;
        self.address = start as usize;
        self.address_input = format!("{start:#018x}");
        self.address_error = None;
        self.selected_row = None;
        self.linear_reset(start);
        self.scroll_to_row = Some(0);

        // Decode the first chunk immediately so the view is populated this frame.
        self.extend_linear(process);
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
    // Function-mode decode
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn ensure_function_disasm(&mut self, process: &Process) {
        if self.mode != DisasmMode::Function || self.address == 0 {
            return;
        }
        if self.cache.as_ref().map(|c| c.addr) == Some(self.address) {
            return;
        }
        match disassemble_function(process, self.address as u64, self.max_bytes) {
            Ok(d) => {
                let entry_symbol = process.resolve_symbol(self.address).unwrap_or(None);
                self.cache = Some(DisasmCache {
                    addr: self.address,
                    instructions: d.instructions,
                    entry_symbol,
                });
                self.status_msg = None;
            }
            Err(e) => {
                self.cache = None;
                self.status_msg = Some(format!("Disassembly failed: {e}"));
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

        self.ensure_function_disasm(process);
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

        let active_len = self.active_len();
        let space_target = self
            .selected_row
            .and_then(|r| self.active_get(r))
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

    /// Number of instructions in the currently-active list (linear or function).
    #[cfg(target_os = "linux")]
    fn active_len(&self) -> usize {
        match self.mode {
            DisasmMode::Linear => self.linear_insns.len(),
            DisasmMode::Function => self.cache.as_ref().map_or(0, |c| c.instructions.len()),
        }
    }

    #[cfg(target_os = "linux")]
    fn active_get(&self, idx: usize) -> Option<&InstructionData> {
        match self.mode {
            DisasmMode::Linear => self.linear_insns.get(idx),
            DisasmMode::Function => self.cache.as_ref().and_then(|c| c.instructions.get(idx)),
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

            let can_dissect = self.mode == DisasmMode::Linear && !self.selected_modules.is_empty();
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

            if self.mode == DisasmMode::Linear {
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
            if let Some(sym) = self.cache.as_ref().and_then(|c| c.entry_symbol.as_deref()) {
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
        let is_linear = self.mode == DisasmMode::Linear;

        // Actions collected during the (borrow-free-of-self) table draw.
        let mut nav_target: Option<usize> = None;
        let mut new_selection: Option<usize> = None;
        let mut nop_target: Option<(usize, usize)> = None;
        let mut queued_action: Option<DisasmAction> = None;
        let mut copy_text: Option<String> = None;
        let mut pending_sig_addr: Option<usize> = None;
        let mut max_visible: usize = 0;
        let len = self.active_len();

        {
            // Disjoint field borrows: `insns`/`dissect` (shared) coexist with the
            // `scroll_to_row.take()` (mut, different field) because they are all
            // direct field paths.
            let insns: &[InstructionData] = match self.mode {
                DisasmMode::Linear => &self.linear_insns,
                DisasmMode::Function => self
                    .cache
                    .as_ref()
                    .map(|c| c.instructions.as_slice())
                    .unwrap_or(&[]),
            };
            let dissect = self.dissect.as_ref();
            let modules: &[ModuleInfoWithName] = &self.modules;
            let selected_row = self.selected_row;
            let scroll_to = self.scroll_to_row.take();

            if insns.is_empty() {
                if is_linear {
                    ui.weak("Decoding…");
                } else if self.address == 0 {
                    ui.label("Select modules in the Modules panel, or enter an address, to disassemble.");
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
                // Re-decode the patched bytes.
                match self.mode {
                    DisasmMode::Function => self.cache = None,
                    DisasmMode::Linear => {
                        let focus = self.address as u64;
                        self.linear_reset(focus);
                    }
                }
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
        if is_linear
            && self.linear_next.is_some()
            && (len == 0 || max_visible + LINEAR_EXTEND_ROWS >= len)
        {
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
