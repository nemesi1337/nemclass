//! Disassembly tab panel — shows a navigable disassembly for the currently-
//! attached process, either of a single function or (module mode) a continuous
//! linear sweep of a whole loaded module's code.
//!
//! ## Layout
//! ```text
//! ┌─ Disassembly ──────────────────────────────────────────────────────────┐
//! │  Module: [libc.so.6 (0x7fff…, 1800 KiB) ▼]  [Dissect]  1234 call targets │
//! │  [◀ Back] [▶ Forward] [Page ▲] [Page ▼]  Address: [0x…____]  [Go]        │
//! │  This is: <symbol name>                                                  │
//! │  ──────────────────────────────────────────────────────────────────  │
//! │  ┌─ Address ───────────┬─ Bytes ──────────────────┬─ Instruction ───┐ │
//! │  │  0x00007fff0000 ⟵3  │  48 89 e5               │  push rbp        │ │
//! │  │  0x00007fff0003     │  e8 f0 ff ff ff         │  call 0xffffff→  │ │
//! │  └─────────────────────┴──────────────────────────┴─────────────────┘ │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Call/Jump/CondJump instructions with a resolved target are rendered as
//! clickable links that push history and navigate to the target address. When a
//! module has been "dissected", inbound-reference badges (`⟵N`) appear in the
//! Address column with a click-through list of the referring instructions.
//!
//! On non-Linux platforms the panel shows a static notice — the underlying
//! disassembly is Linux-only.

use eframe::egui;
#[cfg(target_os = "linux")]
use eframe::egui::{Color32, RichText};
#[cfg(target_os = "linux")]
use egui_extras::{Column, TableBuilder};

use nemclass_core::Process;
#[cfg(target_os = "linux")]
use nemclass_core::{
    DissectResult, InstructionData, ModuleInfoWithName, disassemble_function, disassemble_range,
    dissect_regions, module_exec_regions,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum bytes to read for a single function disassembly.
const DEFAULT_MAX_BYTES: usize = 4096;

/// Navigation history depth cap.
const HISTORY_CAP: usize = 64;

/// Bytes decoded per frame in linear (module) mode — roughly a screenful. Only
/// this much is decoded regardless of how large the module is; paging advances
/// the window.
#[cfg(target_os = "linux")]
const LINEAR_WINDOW_BYTES: usize = 1024;

/// Heuristic step-back for Page Up in linear mode (x86 has no fixed instruction
/// length, so we cannot page back exactly; this is clamped to the module base).
#[cfg(target_os = "linux")]
const LINEAR_PAGE_BACK: usize = 256;

// ---------------------------------------------------------------------------
// Mode
// ---------------------------------------------------------------------------

/// Whether the panel is showing a single function (stops at `ret`) or a
/// continuous linear sweep of a module region.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisasmMode {
    /// Single-function view: decode from the entry point, stop at the first
    /// `ret`/`int3`. This is the "Disassemble here" behaviour.
    Function,
    /// Module view: continuous linear disassembly, paged over the module's code.
    Linear,
}

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

/// Cached result of the last successful disassembly, keyed by address.
#[cfg(target_os = "linux")]
struct DisasmCache {
    addr: usize,
    /// Decoded instructions for the current view (function body or linear window).
    instructions: Vec<InstructionData>,
    /// Resolved symbol name for the entry point (if any).
    entry_symbol: Option<String>,
}

// ---------------------------------------------------------------------------
// DisassemblyPanel
// ---------------------------------------------------------------------------

/// Navigable disassembly panel — mirrors the idioms of `ScannerPanel` /
/// `MemoryViewer`.
pub struct DisassemblyPanel {
    // ── navigation ────────────────────────────────────────────────────────
    /// Current entry-point / window-start address being disassembled.
    address: usize,
    /// Text the user is typing in the address bar.
    address_input: String,
    /// Parse-error hint shown in red next to the Go button.
    address_error: Option<String>,
    /// Back-navigation stack.
    back: Vec<usize>,
    /// Forward-navigation stack (cleared on a new navigate).
    forward: Vec<usize>,

    // ── module / linear mode ──────────────────────────────────────────────
    /// Loaded modules of the attached process (cached on attach).
    #[cfg(target_os = "linux")]
    modules: Vec<ModuleInfoWithName>,
    /// Index into `modules` of the module currently being browsed.
    #[cfg(target_os = "linux")]
    selected_module: Option<usize>,
    /// Function vs linear (module) disassembly.
    #[cfg(target_os = "linux")]
    mode: DisasmMode,
    /// `(base, end)` of the module being browsed in linear mode; clamps paging.
    #[cfg(target_os = "linux")]
    linear_bounds: Option<(usize, usize)>,

    // ── dissect (cross-references) ────────────────────────────────────────
    /// `(module_index, result)` of the last Dissect Code scan.
    #[cfg(target_os = "linux")]
    dissect: Option<(usize, DissectResult)>,
    /// Human-readable summary of the last dissect (or its error).
    #[cfg(target_os = "linux")]
    dissect_status: Option<String>,

    // ── disasm cache ──────────────────────────────────────────────────────
    #[cfg(target_os = "linux")]
    cache: Option<DisasmCache>,

    // ── settings ──────────────────────────────────────────────────────────
    max_bytes: usize,

    // ── status ────────────────────────────────────────────────────────────
    pub status_msg: Option<String>,

    // ── pending navigation triggered from inside the table ────────────────
    /// When Some, `show()` will navigate here at the end of the frame after
    /// the table is done being drawn (avoids borrow conflicts).
    pending_navigate: Option<usize>,
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
            selected_module: None,
            #[cfg(target_os = "linux")]
            mode: DisasmMode::Function,
            #[cfg(target_os = "linux")]
            linear_bounds: None,
            #[cfg(target_os = "linux")]
            dissect: None,
            #[cfg(target_os = "linux")]
            dissect_status: None,
            #[cfg(target_os = "linux")]
            cache: None,
            max_bytes: DEFAULT_MAX_BYTES,
            status_msg: None,
            pending_navigate: None,
        }
    }

    // -----------------------------------------------------------------------
    // Lifecycle (called by the app on attach / detach)
    // -----------------------------------------------------------------------

    /// Refresh the module list from the newly-attached process.
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
            self.selected_module = None;
            self.mode = DisasmMode::Function;
            self.linear_bounds = None;
            self.dissect = None;
            self.dissect_status = None;
            self.cache = None;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = process;
    }

    /// Drop all process-tied state on detach.
    pub fn on_detach(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.modules.clear();
            self.selected_module = None;
            self.mode = DisasmMode::Function;
            self.linear_bounds = None;
            self.dissect = None;
            self.dissect_status = None;
            self.cache = None;
        }
    }

    // -----------------------------------------------------------------------
    // Public navigation API (called by the parent when wiring the
    // "Disassemble here" button in MemoryViewer).
    // -----------------------------------------------------------------------

    /// Navigate to `addr` in single-function mode, pushing the current address
    /// onto the back-stack and clearing forward. Use this when jumping from
    /// another panel.
    pub fn goto(&mut self, addr: usize) {
        // Jumping to an explicit address always drops back to function mode.
        #[cfg(target_os = "linux")]
        {
            if self.mode == DisasmMode::Linear {
                self.cache = None;
            }
            self.mode = DisasmMode::Function;
            self.linear_bounds = None;
        }
        if addr == self.address && self.cache_valid(addr) {
            return;
        }
        if self.address != 0 {
            self.push_back(self.address);
        }
        self.forward.clear();
        self.set_address(addr);
    }

    // -----------------------------------------------------------------------
    // Internal navigation helpers
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

    /// Set the address and invalidate the cache if it changed.
    fn set_address(&mut self, addr: usize) {
        self.address = addr;
        self.address_input = format!("{addr:#018x}");
        self.address_error = None;
        // Invalidate cache so we re-disassemble on the next frame.
        #[cfg(target_os = "linux")]
        if self.cache.as_ref().map(|c| c.addr) != Some(addr) {
            self.cache = None;
        }
    }

    /// Navigate forward/back internally (within the panel); pushes the
    /// opposite stack, clears nothing else. Preserves the current mode.
    fn navigate(&mut self, target: usize) {
        if target == self.address {
            return;
        }
        self.push_back(self.address);
        self.forward.clear();
        self.set_address(target);
    }

    fn go_back(&mut self) {
        if let Some(prev) = self.back.pop() {
            self.push_forward(self.address);
            self.set_address(prev);
        }
    }

    fn go_forward(&mut self) {
        if let Some(next) = self.forward.pop() {
            self.push_back(self.address);
            self.set_address(next);
        }
    }

    /// Parse `address_input` as hex (0x…) or decimal and navigate there in
    /// single-function mode.
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
                // Typing a raw address reverts to function mode.
                #[cfg(target_os = "linux")]
                {
                    if self.mode == DisasmMode::Linear {
                        self.cache = None;
                    }
                    self.mode = DisasmMode::Function;
                    self.linear_bounds = None;
                }
                self.navigate(addr);
            }
            Err(e) => {
                self.address_error = Some(format!("Bad address: {e}"));
            }
        }
    }

    /// Returns true when the cache holds a result for `addr`.
    #[cfg(target_os = "linux")]
    fn cache_valid(&self, addr: usize) -> bool {
        self.cache.as_ref().map(|c| c.addr == addr).unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    fn cache_valid(&self, _addr: usize) -> bool {
        false
    }

    // -----------------------------------------------------------------------
    // Module / linear-mode helpers (Linux-only)
    // -----------------------------------------------------------------------

    /// Switch to linear (module) mode and navigate to the module's base.
    #[cfg(target_os = "linux")]
    fn enter_linear_mode(&mut self, idx: usize) {
        let Some(m) = self.modules.get(idx) else { return; };
        let base = m.base;
        let end = m.base.saturating_add(m.size);

        self.selected_module = Some(idx);
        self.mode = DisasmMode::Linear;
        self.linear_bounds = Some((base, end));

        // The dissect result is per-module; drop it when switching modules.
        if self.dissect.as_ref().map(|(mi, _)| *mi) != Some(idx) {
            self.dissect = None;
            self.dissect_status = None;
        }

        // Navigate to the base like `goto`, but keep Linear mode. Force a fresh
        // decode even when base == current address (mode may have changed).
        if self.address != 0 && self.address != base {
            self.push_back(self.address);
        }
        self.forward.clear();
        self.cache = None;
        self.set_address(base);
    }

    /// Advance the linear window past the last decoded instruction.
    #[cfg(target_os = "linux")]
    fn page_down(&mut self) {
        if self.mode != DisasmMode::Linear {
            return;
        }
        let next = self
            .cache
            .as_ref()
            .and_then(|c| c.instructions.last())
            .map(|ins| (ins.address as usize).saturating_add(ins.length));
        if let Some(next) = next
            && next > self.address
        {
            self.navigate(next);
        }
    }

    /// Step the linear window back by a heuristic amount, clamped to the base.
    #[cfg(target_os = "linux")]
    fn page_up(&mut self) {
        if self.mode != DisasmMode::Linear {
            return;
        }
        let base = self.linear_bounds.map(|(b, _)| b).unwrap_or(0);
        let target = self.address.saturating_sub(LINEAR_PAGE_BACK).max(base);
        if target != self.address {
            self.navigate(target);
        }
    }

    /// Run a Dissect Code scan over the selected module's executable regions.
    #[cfg(target_os = "linux")]
    fn do_dissect(&mut self, process: &Process) {
        let Some(idx) = self.selected_module else {
            self.dissect_status = Some("Select a module first.".to_owned());
            return;
        };
        let Some(m) = self.modules.get(idx) else { return; };
        let (base, size) = (m.base, m.size);

        let scan = module_exec_regions(process.pid(), base, size)
            .and_then(|regions| dissect_regions(process, &regions));

        match scan {
            Ok(result) => {
                self.dissect_status = Some(format!(
                    "{} call targets, {} jump targets, {} strings",
                    result.calls.len(),
                    result.jumps.len(),
                    result.strings.len(),
                ));
                self.dissect = Some((idx, result));
            }
            Err(e) => {
                self.dissect = None;
                self.dissect_status = Some(format!("Dissect failed: {e}"));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Disassemble (Linux-only)
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn ensure_disasm(&mut self, process: &Process) {
        if self.address == 0 {
            return;
        }
        if self.cache_valid(self.address) {
            return;
        }

        let decoded = match self.mode {
            DisasmMode::Function => {
                disassemble_function(process, self.address as u64, self.max_bytes)
                    .map(|d| d.instructions)
            }
            DisasmMode::Linear => {
                let len = match self.linear_bounds {
                    // Clamp the window to the module's end; a target-click that
                    // leaves the module falls back to a full window.
                    Some((_, end)) if self.address < end => {
                        LINEAR_WINDOW_BYTES.min(end - self.address)
                    }
                    _ => LINEAR_WINDOW_BYTES,
                };
                disassemble_range(process, self.address as u64, len)
            }
        };

        match decoded {
            Ok(instructions) => {
                let entry_symbol = process.resolve_symbol(self.address).unwrap_or(None);
                self.cache = Some(DisasmCache {
                    addr: self.address,
                    instructions,
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
    // Main draw entry point
    // -----------------------------------------------------------------------

    pub fn show(&mut self, ui: &mut egui::Ui, process: Option<&Process>) {
        // On non-Linux, show a static notice.
        #[cfg(not(target_os = "linux"))]
        {
            let _ = process;
            ui.centered_and_justified(|ui| {
                ui.label("Disassembly is Linux-only for now.");
            });
            return;
        }

        #[cfg(target_os = "linux")]
        self.show_linux(ui, process);
    }

    #[cfg(target_os = "linux")]
    fn show_linux(&mut self, ui: &mut egui::Ui, process: Option<&Process>) {
        let Some(process) = process else {
            ui.centered_and_justified(|ui| {
                ui.colored_label(Color32::YELLOW, "Attach to a process to disassemble.");
            });
            return;
        };

        // Ensure the cache is warm before drawing.
        self.ensure_disasm(process);

        // ── top bar (module combo + nav) ──────────────────────────────────
        self.show_top_bar(ui, process);
        ui.separator();

        // ── keyboard paging (linear mode) ─────────────────────────────────
        if self.mode == DisasmMode::Linear {
            let (pg_up, pg_dn) = ui.input(|i| {
                (
                    i.key_pressed(egui::Key::PageUp),
                    i.key_pressed(egui::Key::PageDown),
                )
            });
            if pg_dn {
                self.page_down();
            } else if pg_up {
                self.page_up();
            }
        }

        // ── instruction table ─────────────────────────────────────────────
        self.show_table(ui, process);

        // ── status line ──────────────────────────────────────────────────
        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(Color32::from_rgb(220, 160, 40), msg);
        }

        // ── deferred navigation (avoid borrow conflicts during table draw) ─
        if let Some(target) = self.pending_navigate.take() {
            self.navigate(target);
        }
    }

    // -----------------------------------------------------------------------
    // Top bar
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn show_top_bar(&mut self, ui: &mut egui::Ui, process: &Process) {
        // ── module selection row ──────────────────────────────────────────
        let mut picked_module: Option<usize> = None;
        let mut dissect_clicked = false;
        let mut page_up_clicked = false;
        let mut page_down_clicked = false;

        ui.horizontal(|ui| {
            ui.label("Module:");

            let selected_text = self
                .selected_module
                .and_then(|i| self.modules.get(i))
                .map(module_label)
                .unwrap_or_else(|| "Select module…".to_owned());

            egui::ComboBox::from_id_salt("disasm_module_combo")
                .selected_text(selected_text)
                .width(320.0)
                .show_ui(ui, |ui| {
                    if self.modules.is_empty() {
                        ui.weak("(no modules — attach to a process)");
                    }
                    for (i, m) in self.modules.iter().enumerate() {
                        let selected = self.selected_module == Some(i);
                        if ui.selectable_label(selected, module_label(m)).clicked() {
                            picked_module = Some(i);
                        }
                    }
                });

            // Dissect the selected module's executable regions.
            let can_dissect = self.mode == DisasmMode::Linear && self.selected_module.is_some();
            if ui
                .add_enabled(can_dissect, egui::Button::new("Dissect"))
                .on_hover_text("Scan the module's code for call/jump/string cross-references")
                .on_disabled_hover_text("Pick a module first")
                .clicked()
            {
                dissect_clicked = true;
            }

            if let Some(status) = &self.dissect_status {
                ui.separator();
                ui.colored_label(Color32::from_rgb(140, 180, 220), status);
            }
        });

        // ── navigation row ────────────────────────────────────────────────
        ui.horizontal(|ui| {
            // Back / Forward buttons.
            let can_back = !self.back.is_empty();
            let can_fwd = !self.forward.is_empty();
            if ui.add_enabled(can_back, egui::Button::new("◀ Back")).clicked() {
                self.go_back();
            }
            if ui.add_enabled(can_fwd, egui::Button::new("▶ Forward")).clicked() {
                self.go_forward();
            }

            // Paging buttons (linear mode only).
            if self.mode == DisasmMode::Linear {
                ui.separator();
                if ui.button("Page ▲").on_hover_text("Page up (PgUp)").clicked() {
                    page_up_clicked = true;
                }
                if ui.button("Page ▼").on_hover_text("Page down (PgDn)").clicked() {
                    page_down_clicked = true;
                }
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

            let go_clicked = ui.button("Go").clicked();
            let enter_pressed =
                resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            if go_clicked || enter_pressed {
                self.try_parse_address();
            }

            if let Some(err) = &self.address_error {
                ui.colored_label(Color32::RED, err);
            }

            // Symbol label for the current entry point.
            if let Some(sym) = self.cache.as_ref().and_then(|c| c.entry_symbol.as_deref()) {
                ui.separator();
                ui.colored_label(
                    Color32::from_rgb(100, 200, 100),
                    format!("This is: {sym}"),
                );
            }
        });

        // ── apply deferred actions (after the closures release &mut self) ──
        if let Some(i) = picked_module {
            self.enter_linear_mode(i);
        }
        if dissect_clicked {
            self.do_dissect(process);
        }
        if page_up_clicked {
            self.page_up();
        }
        if page_down_clicked {
            self.page_down();
        }
    }

    // -----------------------------------------------------------------------
    // Instruction table
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn show_table(&mut self, ui: &mut egui::Ui, process: &Process) {
        let Some(cache) = &self.cache else {
            if self.address == 0 {
                ui.label("Enter an address, or pick a module, to disassemble.");
            } else {
                ui.label("No disassembly available.");
            }
            return;
        };

        // Snapshot the instruction list so we can borrow `self` mutably for
        // navigation clicks below without a double-borrow.
        let instructions = cache.instructions.clone();

        if instructions.is_empty() {
            ui.label("No instructions decoded.");
            return;
        }

        // Snapshot per-instruction cross-reference info (if this module has been
        // dissected) into a Vec aligned with `instructions`, so the table closure
        // does not need to borrow `self.dissect`.
        let xrefs: Vec<Option<XrefInfo>> = self.collect_xrefs(&instructions);

        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = text_height + 4.0;

        // Collect pending navigation here so we can handle it after the table.
        let mut nav_target: Option<usize> = None;

        TableBuilder::new(ui)
            .id_salt("disassembly_table")
            .striped(true)
            .resizable(true)
            .column(Column::initial(200.0).at_least(120.0)) // Address (+ xref badge)
            .column(Column::initial(160.0).at_least(80.0)) // Bytes
            .column(Column::remainder().at_least(200.0)) // Instruction
            .header(row_height + 2.0, |mut header| {
                header.col(|ui| {
                    ui.strong("Address");
                });
                header.col(|ui| {
                    ui.strong("Bytes");
                });
                header.col(|ui| {
                    ui.strong("Instruction");
                });
            })
            .body(|body| {
                body.rows(row_height, instructions.len(), |mut row| {
                    let idx = row.index();
                    let Some(ins) = instructions.get(idx) else {
                        return;
                    };

                    let addr = ins.address;
                    let length = ins.length;
                    let bytes = &ins.data[..length.min(ins.data.len())];
                    let mnemonic = ins.instruction.clone();
                    let kind = ins.kind;
                    let target = ins.target;
                    let xref = xrefs.get(idx).and_then(|x| x.as_ref());

                    // ── Address column (+ inbound-reference badge) ──────
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            ui.monospace(format!("{addr:#018x}"));
                            if let Some(xref) = xref {
                                ui.menu_button(
                                    RichText::new(format!("⟵{}", xref.count))
                                        .small()
                                        .color(Color32::from_rgb(200, 160, 90)),
                                    |ui| {
                                        if let Some(preview) = &xref.string_preview {
                                            ui.label(
                                                RichText::new(format!("\"{preview}\""))
                                                    .italics()
                                                    .color(Color32::from_rgb(150, 200, 150)),
                                            );
                                            ui.separator();
                                        }
                                        ui.weak("Referenced by:");
                                        for &r in &xref.referrers {
                                            if ui.button(format!("{r:#018x}")).clicked() {
                                                nav_target = Some(r as usize);
                                                ui.close();
                                            }
                                        }
                                    },
                                )
                                .response
                                .on_hover_text("Inbound references — click to jump");
                            }
                        });
                    });

                    // ── Bytes column ───────────────────────────────────
                    row.col(|ui| {
                        let hex: String = bytes
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<Vec<_>>()
                            .join(" ");
                        ui.monospace(hex);
                    });

                    // ── Instruction column ─────────────────────────────
                    row.col(|ui| {
                        use nemclass_core::FlowKind;

                        let is_branch = matches!(
                            kind,
                            FlowKind::Call | FlowKind::Jump | FlowKind::CondJump
                        );

                        if is_branch {
                            if let Some(tgt) = target {
                                // Resolve symbol for the target (best-effort).
                                let sym = process.resolve_symbol(tgt as usize).unwrap_or(None);

                                let link_text = if let Some(ref name) = sym {
                                    format!("{mnemonic}  → {name}")
                                } else {
                                    format!("{mnemonic}  → {tgt:#x}")
                                };

                                let resp = ui.add(
                                    egui::Label::new(
                                        RichText::new(&link_text)
                                            .color(Color32::from_rgb(100, 160, 255))
                                            .monospace(),
                                    )
                                    .sense(egui::Sense::click()),
                                );
                                if resp.clicked() {
                                    nav_target = Some(tgt as usize);
                                }
                                if resp.hovered() {
                                    resp.on_hover_text(format!(
                                        "Navigate to {tgt:#x}{}",
                                        sym.as_deref()
                                            .map(|s| format!(" ({s})"))
                                            .unwrap_or_default()
                                    ));
                                }
                            } else {
                                // Indirect branch — no resolvable target.
                                ui.monospace(
                                    RichText::new(&mnemonic)
                                        .color(Color32::from_rgb(180, 180, 100)),
                                );
                            }
                        } else {
                            // Colour ret/int3 distinctly.
                            let color = match kind {
                                FlowKind::Ret => Color32::from_rgb(255, 140, 100),
                                FlowKind::Int3 => Color32::from_rgb(160, 100, 180),
                                _ => ui.visuals().text_color(),
                            };
                            ui.monospace(RichText::new(&mnemonic).color(color));
                        }
                    });
                });
            });

        // Apply any navigation click collected during the table draw.
        if let Some(tgt) = nav_target {
            self.pending_navigate = Some(tgt);
        }
    }

    /// Builds per-instruction cross-reference info from the current dissect
    /// result (if it belongs to the selected module). Returns a Vec aligned with
    /// `instructions`.
    #[cfg(target_os = "linux")]
    fn collect_xrefs(&self, instructions: &[InstructionData]) -> Vec<Option<XrefInfo>> {
        let Some((mod_idx, dissect)) = &self.dissect else {
            return vec![None; instructions.len()];
        };
        if Some(*mod_idx) != self.selected_module {
            return vec![None; instructions.len()];
        }

        instructions
            .iter()
            .map(|ins| {
                let a = ins.address;
                let mut referrers: Vec<u64> = Vec::new();
                if let Some(v) = dissect.calls.get(&a) {
                    referrers.extend(v);
                }
                if let Some(v) = dissect.jumps.get(&a) {
                    referrers.extend(v);
                }
                if let Some(v) = dissect.strings.get(&a) {
                    referrers.extend(v);
                }
                if referrers.is_empty() {
                    return None;
                }
                referrers.sort_unstable();
                referrers.dedup();
                Some(XrefInfo {
                    count: referrers.len(),
                    referrers,
                    string_preview: dissect.string_previews.get(&a).cloned(),
                })
            })
            .collect()
    }
}

/// Per-instruction cross-reference summary for the Address-column badge.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct XrefInfo {
    count: usize,
    referrers: Vec<u64>,
    string_preview: Option<String>,
}

/// Combo/label text for a module: `name (0xbase, NN KiB)`.
#[cfg(target_os = "linux")]
fn module_label(m: &ModuleInfoWithName) -> String {
    format!("{} (0x{:x}, {} KiB)", m.name, m.base, m.size / 1024)
}

impl Default for DisassemblyPanel {
    fn default() -> Self {
        Self::new()
    }
}
