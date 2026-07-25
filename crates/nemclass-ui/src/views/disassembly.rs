//! Disassembly tab panel — shows a navigable function disassembly for the
//! currently-attached process.
//!
//! ## Layout
//! ```text
//! ┌─ Disassembly ──────────────────────────────────────────────────────────┐
//! │  [◀ Back] [▶ Forward]  Address: [0x00007fff…________]  [Go]           │
//! │  This is: <symbol name>                                                 │
//! │  ──────────────────────────────────────────────────────────────────  │
//! │  ┌─ Address ───────────┬─ Bytes ──────────────────┬─ Instruction ───┐ │
//! │  │  0x00007fff0000     │  48 89 e5               │  push rbp        │ │
//! │  │  0x00007fff0003     │  e8 f0 ff ff ff         │  call 0xffffff→  │ │
//! │  └─────────────────────┴──────────────────────────┴─────────────────┘ │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Call/Jump/CondJump instructions with a resolved target are rendered as
//! clickable links that push history and navigate to the target address.
//!
//! On non-Linux platforms the panel shows a static notice — the underlying
//! `disassemble_function` is Linux-only.

use eframe::egui;
#[cfg(target_os = "linux")]
use eframe::egui::{Color32, RichText};
#[cfg(target_os = "linux")]
use egui_extras::{Column, TableBuilder};

use nemclass_core::Process;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default maximum bytes to read for a single function disassembly.
const DEFAULT_MAX_BYTES: usize = 4096;

/// Navigation history depth cap.
const HISTORY_CAP: usize = 64;

// ---------------------------------------------------------------------------
// Cache entry
// ---------------------------------------------------------------------------

/// Cached result of the last successful disassembly, keyed by address.
#[cfg(target_os = "linux")]
struct DisasmCache {
    addr: usize,
    disasm: nemclass_core::FunctionDisasm,
    /// Resolved symbol name for the function entry point (if any).
    entry_symbol: Option<String>,
}

// ---------------------------------------------------------------------------
// DisassemblyPanel
// ---------------------------------------------------------------------------

/// Navigable disassembly panel — mirrors the idioms of `ScannerPanel` /
/// `MemoryViewer`.
pub struct DisassemblyPanel {
    // ── navigation ────────────────────────────────────────────────────────
    /// Current entry-point address being disassembled.
    address: usize,
    /// Text the user is typing in the address bar.
    address_input: String,
    /// Parse-error hint shown in red next to the Go button.
    address_error: Option<String>,
    /// Back-navigation stack.
    back: Vec<usize>,
    /// Forward-navigation stack (cleared on a new navigate).
    forward: Vec<usize>,

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
            cache: None,
            max_bytes: DEFAULT_MAX_BYTES,
            status_msg: None,
            pending_navigate: None,
        }
    }

    // -----------------------------------------------------------------------
    // Public navigation API (called by the parent when wiring the
    // "Disassemble here" button in MemoryViewer).
    // -----------------------------------------------------------------------

    /// Navigate to `addr`, pushing the current address onto the back-stack and
    /// clearing forward. Use this when jumping from another panel.
    pub fn goto(&mut self, addr: usize) {
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
    /// opposite stack, clears nothing else.
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

    /// Parse `address_input` as hex (0x…) or decimal and navigate there.
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
        match nemclass_core::disassemble_function(process, self.address as u64, self.max_bytes) {
            Ok(disasm) => {
                // Attempt to resolve the entry-point symbol.
                let entry_symbol = process
                    .resolve_symbol(self.address)
                    .unwrap_or(None);
                self.cache = Some(DisasmCache {
                    addr: self.address,
                    disasm,
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

        // ── top bar ──────────────────────────────────────────────────────
        self.show_top_bar(ui);
        ui.separator();

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
    fn show_top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Back / Forward buttons.
            let can_back = !self.back.is_empty();
            let can_fwd  = !self.forward.is_empty();
            if ui.add_enabled(can_back, egui::Button::new("◀ Back")).clicked() {
                self.go_back();
            }
            if ui.add_enabled(can_fwd, egui::Button::new("▶ Forward")).clicked() {
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

            let go_clicked     = ui.button("Go").clicked();
            let enter_pressed  = resp.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter));

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
    }

    // -----------------------------------------------------------------------
    // Instruction table
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn show_table(&mut self, ui: &mut egui::Ui, process: &Process) {
        let Some(cache) = &self.cache else {
            if self.address == 0 {
                ui.label("Enter an address above to disassemble.");
            } else {
                ui.label("No disassembly available.");
            }
            return;
        };

        // Snapshot the instruction list so we can borrow `self` mutably for
        // navigation clicks below without a double-borrow.
        let instructions = cache.disasm.instructions.clone();

        if instructions.is_empty() {
            ui.label("No instructions decoded.");
            return;
        }

        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height  = text_height + 4.0;

        // Collect pending navigation here so we can handle it after the table.
        let mut nav_target: Option<usize> = None;

        TableBuilder::new(ui)
            .id_salt("disassembly_table")
            .striped(true)
            .resizable(true)
            .column(Column::initial(160.0).at_least(100.0))   // Address
            .column(Column::initial(160.0).at_least(80.0))    // Bytes
            .column(Column::remainder().at_least(200.0))      // Instruction
            .header(row_height + 2.0, |mut header| {
                header.col(|ui| { ui.strong("Address"); });
                header.col(|ui| { ui.strong("Bytes"); });
                header.col(|ui| { ui.strong("Instruction"); });
            })
            .body(|body| {
                body.rows(row_height, instructions.len(), |mut row| {
                    let idx = row.index();
                    let Some(ins) = instructions.get(idx) else { return; };

                    let addr    = ins.address;
                    let length  = ins.length;
                    let bytes   = &ins.data[..length.min(ins.data.len())];
                    let mnemonic = ins.instruction.clone();
                    let kind    = ins.kind;
                    let target  = ins.target;

                    // ── Address column ─────────────────────────────────
                    row.col(|ui| {
                        ui.monospace(format!("{addr:#018x}"));
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
                                let sym = process
                                    .resolve_symbol(tgt as usize)
                                    .unwrap_or(None);

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
                                FlowKind::Ret  => Color32::from_rgb(255, 140, 100),
                                FlowKind::Int3 => Color32::from_rgb(160, 100, 180),
                                _              => ui.visuals().text_color(),
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
}
