//! Kernel debugger panel — Linux-only.
//!
//! On non-Linux this module exposes only a `DebuggerPanel` stub that renders a
//! "Linux only" note. On Linux it wraps `nemclass_core::Debugger` (the char-
//! device controller that speaks the `nemclass_mod` kernel ABI).
//!
//! ## Layout
//! ```text
//! ┌─ Debugger (Linux / nemclass_mod) ────────────────────────────────────┐
//! │  Key (hex): [__________]   [Attach Debugger]   [Detach]             │
//! │  Status: <error or "attached to pid 1234">                           │
//! │  ── Set Breakpoint ────────────────────────────────────────────────  │
//! │  Addr (hex): [0x…]  Kind: [Execute ▼]  Len: [4]  [Set]             │
//! │  ── Active Breakpoints ────────────────────────────────────────────  │
//! │  bp#0  Execute @ 0x4011a0   [Clear]                                  │
//! │  ── Event Log ─────────────────────────────────────────────────────  │
//! │  pid=1234 tid=1234 addr=0x4011a0 kind=Execute                        │
//! │  ── Registers ─────────────────────────────────────────────────────  │
//! │  RIP: 0x…  RSP: 0x…  RAX: 0x… …                                    │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```

// ─── Linux implementation ───────────────────────────────────────────────────
#[cfg(target_os = "linux")]
mod linux {
    use std::time::{Duration, Instant};

    use eframe::egui;

    use nemclass_core::{
        Breakpoint, BreakpointId, BreakpointSpec, DebugEvent, Debugger, Registers,
        kernel::abi::HwBreakpointType,
    };

    /// Interval for non-blocking `wait_event` polls.
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// Maximum event-log entries kept in memory.
    const MAX_EVENTS: usize = 200;

    /// Breakpoint kind selected in the "set breakpoint" row.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum BpKind {
        Execute,
        HwWrite,
        HwRead,
        HwAccess,
        Uprobe,
    }

    impl BpKind {
        const ALL: &'static [Self] = &[
            Self::Execute,
            Self::HwWrite,
            Self::HwRead,
            Self::HwAccess,
            Self::Uprobe,
        ];

        fn label(self) -> &'static str {
            match self {
                Self::Execute  => "Execute",
                Self::HwWrite  => "HW-Write",
                Self::HwRead   => "HW-Read",
                Self::HwAccess => "HW-Access",
                Self::Uprobe   => "Uprobe",
            }
        }

        /// True if this kind requires a watchpoint length field.
        fn needs_len(self) -> bool {
            matches!(self, Self::HwWrite | Self::HwRead | Self::HwAccess)
        }

        fn to_spec(self, addr: u64, len: u32) -> nemclass_core::Result<BreakpointSpec> {
            match self {
                Self::Execute  => Ok(BreakpointSpec::execute(addr)),
                Self::HwWrite  => BreakpointSpec::watch_write(addr, len),
                Self::HwRead   => BreakpointSpec::watch_read(addr, len),
                Self::HwAccess => BreakpointSpec::watch_access(addr, len),
                Self::Uprobe   => Ok(BreakpointSpec::uprobe(addr)),
            }
        }
    }

    /// A single line in the event log. Either a decoded breakpoint hit or a
    /// one-line error/status string.
    enum EventEntry {
        Hit {
            pid:     i32,
            tid:     i32,
            address: u64,
            bp_id:   BreakpointId,
            kind:    String,
            regs:    Registers,
        },
        Message(String),
    }

    impl EventEntry {
        fn from_event(ev: &DebugEvent) -> Self {
            let kind = ev.spec.map(|s| {
                match s {
                    BreakpointSpec::Hardware { ty, .. } => match ty {
                        HwBreakpointType::Execute   => "Execute",
                        HwBreakpointType::Write     => "HW-Write",
                        HwBreakpointType::Read      => "HW-Read",
                        HwBreakpointType::ReadWrite => "HW-Access",
                    }.to_string(),
                    BreakpointSpec::Uprobe { .. } => "Uprobe".to_string(),
                }
            }).unwrap_or_else(|| "Unknown".to_string());

            EventEntry::Hit {
                pid:     ev.pid,
                tid:     ev.tid,
                address: ev.address,
                bp_id:   ev.breakpoint,
                kind,
                regs:    ev.registers,
            }
        }

        fn display_line(&self) -> String {
            match self {
                EventEntry::Hit { pid, tid, address, bp_id, kind, .. } => {
                    format!("{bp_id} pid={pid} tid={tid} addr=0x{address:X} kind={kind}")
                }
                EventEntry::Message(s) => s.clone(),
            }
        }

        /// Return the registers for this entry if it is a Hit.
        fn registers(&self) -> Option<&Registers> {
            match self {
                EventEntry::Hit { regs, .. } => Some(regs),
                EventEntry::Message(_) => None,
            }
        }
    }

    pub struct DebuggerPanel {
        // ── attach controls ───────────────────────────────────────────
        key_hex:    String,
        debugger:   Option<Debugger>,
        attach_err: Option<String>,

        // ── breakpoint controls ───────────────────────────────────────
        bp_addr_text: String,
        bp_kind:      BpKind,
        bp_len:       u32,
        bp_err:       Option<String>,

        // ── event log ─────────────────────────────────────────────────
        events:       Vec<EventEntry>,
        last_poll:    Option<Instant>,

        // ── latest register snapshot ──────────────────────────────────
        latest_regs:  Option<Registers>,
    }

    impl DebuggerPanel {
        pub fn new() -> Self {
            Self::with_key(String::new())
        }

        /// Like `new()` but pre-populates the auth-key field.  The field
        /// remains freely editable by the user.
        pub fn with_key(key: String) -> Self {
            Self {
                key_hex:      key,
                debugger:     None,
                attach_err:   None,
                bp_addr_text: String::new(),
                bp_kind:      BpKind::Execute,
                bp_len:       4,
                bp_err:       None,
                events:       Vec::new(),
                last_poll:    None,
                latest_regs:  None,
            }
        }

        // ── called from parent logic() ─────────────────────────────────

        /// Poll the debugger for new events on a throttle. Safe to call every
        /// frame; internally rate-limited by `POLL_INTERVAL`.
        pub fn tick_events(&mut self) {
            let Some(dbg) = &mut self.debugger else { return; };

            let should_poll = self
                .last_poll
                .map(|t| t.elapsed() >= POLL_INTERVAL)
                .unwrap_or(true);
            if !should_poll {
                return;
            }
            self.last_poll = Some(Instant::now());

            // Non-blocking poll: Duration::ZERO means "return immediately".
            match dbg.wait_event(Some(Duration::ZERO)) {
                Ok(Some(ev)) => {
                    let entry = EventEntry::from_event(&ev);
                    // Update latest register snapshot.
                    if let Some(r) = entry.registers() {
                        self.latest_regs = Some(*r);
                    }
                    self.events.push(entry);
                    if self.events.len() > MAX_EVENTS {
                        self.events.drain(..self.events.len() - MAX_EVENTS);
                    }
                }
                Ok(None) => {} // No event ready — normal for a non-blocking poll.
                Err(e)   => {
                    // Log the error but don't disconnect: a one-shot read error
                    // does not mean the session is gone.
                    self.events.push(EventEntry::Message(format!("[poll error: {e}]")));
                }
            }
        }

        /// Drop the debugger when the parent detaches from the process.
        pub fn on_detach(&mut self) {
            self.debugger = None;
            self.attach_err = None;
            self.events.clear();
            self.latest_regs = None;
        }

        // ── main UI ───────────────────────────────────────────────────

        pub fn show(&mut self, ui: &mut egui::Ui, pid: Option<libc::pid_t>) {
            self.show_attach_row(ui, pid);
            ui.separator();
            self.show_bp_controls(ui);
            ui.separator();
            self.show_event_log(ui);
            ui.separator();
            self.show_registers(ui);
        }

        // ── attach row ────────────────────────────────────────────────

        fn show_attach_row(&mut self, ui: &mut egui::Ui, pid: Option<libc::pid_t>) {
            ui.horizontal(|ui| {
                ui.label("Auth key (hex):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.key_hex)
                        .desired_width(160.0)
                        .hint_text("optional hex key"),
                );

                let attached = self.debugger.is_some();

                if !attached {
                    let can_attach = pid.is_some();
                    ui.add_enabled_ui(can_attach, |ui| {
                        if ui.button("Attach Debugger").clicked() {
                            self.do_attach(pid.unwrap_or(0));
                        }
                    });
                    if !can_attach {
                        ui.label("(attach to a process first)");
                    }
                } else if ui.button("Detach Debugger").clicked() {
                    self.on_detach();
                }

                if attached {
                    ui.colored_label(
                        egui::Color32::GREEN,
                        format!("Attached to pid {}", pid.unwrap_or(0)),
                    );
                }
            });

            if let Some(err) = &self.attach_err {
                ui.colored_label(egui::Color32::RED, err);
            }
        }

        fn do_attach(&mut self, pid: libc::pid_t) {
            let key_bytes = parse_hex_key(&self.key_hex);
            match Debugger::attach(pid, &key_bytes) {
                Ok(dbg) => {
                    self.debugger   = Some(dbg);
                    self.attach_err = None;
                    self.events.clear();
                }
                Err(e) => {
                    // Show the error without panicking — expected when the device
                    // is absent, key is wrong, or ABI mismatches.
                    self.attach_err = Some(format!("Attach failed: {e}"));
                    self.debugger   = None;
                }
            }
        }

        // ── breakpoint controls ───────────────────────────────────────

        fn show_bp_controls(&mut self, ui: &mut egui::Ui) {
            ui.heading("Set Breakpoint");

            let enabled = self.debugger.is_some();
            ui.add_enabled_ui(enabled, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Addr (hex):");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.bp_addr_text)
                            .desired_width(140.0)
                            .hint_text("0x4011a0"),
                    );

                    // Kind selector.
                    egui::ComboBox::from_id_salt("dbg_bp_kind")
                        .selected_text(self.bp_kind.label())
                        .show_ui(ui, |ui| {
                            for &kind in BpKind::ALL {
                                ui.selectable_value(&mut self.bp_kind, kind, kind.label());
                            }
                        });

                    // Length field — only for watchpoints.
                    if self.bp_kind.needs_len() {
                        ui.label("Len:");
                        let mut len = self.bp_len;
                        egui::ComboBox::from_id_salt("dbg_bp_len")
                            .selected_text(len.to_string())
                            .show_ui(ui, |ui| {
                                for &l in &[1u32, 2, 4, 8] {
                                    ui.selectable_value(&mut len, l, l.to_string());
                                }
                            });
                        self.bp_len = len;
                    }

                    if ui.button("Set").clicked() {
                        self.do_set_breakpoint();
                    }
                });

                if let Some(err) = &self.bp_err {
                    ui.colored_label(egui::Color32::RED, err);
                }
            });

            // Active breakpoint list.
            ui.add_space(4.0);
            ui.label("Active Breakpoints:");

            let bp_list: Vec<Breakpoint> = self
                .debugger
                .as_ref()
                .map(|d| d.breakpoints().to_vec())
                .unwrap_or_default();

            if bp_list.is_empty() {
                ui.label("  (none)");
            } else {
                let mut to_clear: Option<BreakpointId> = None;
                for bp in &bp_list {
                    ui.horizontal(|ui| {
                        let spec_str = match bp.spec {
                            BreakpointSpec::Hardware { addr, len, ty } => {
                                let ty_str = match ty {
                                    HwBreakpointType::Execute  => "Execute",
                                    HwBreakpointType::Write    => "HW-Write",
                                    HwBreakpointType::Read     => "HW-Read",
                                    HwBreakpointType::ReadWrite => "HW-Access",
                                };
                                format!("{ty_str} @ 0x{addr:X} (len={len})")
                            }
                            BreakpointSpec::Uprobe { addr } => {
                                format!("Uprobe @ 0x{addr:X}")
                            }
                        };
                        ui.monospace(format!("{}  {}", bp.id, spec_str));
                        if ui.small_button("Clear").clicked() {
                            to_clear = Some(bp.id);
                        }
                    });
                }
                if let Some(id) = to_clear
                    && let Some(dbg) = &mut self.debugger
                {
                    if let Err(e) = dbg.clear_breakpoint(id) {
                        self.bp_err = Some(format!("Clear {id}: {e}"));
                    } else {
                        self.bp_err = None;
                    }
                }
            }
        }

        fn do_set_breakpoint(&mut self) {
            // Shared with every other address box in the app — see
            // `crate::views::parse_address`.
            let addr = match crate::views::parse_address(&self.bp_addr_text) {
                Ok(a) => a as u64,
                Err(e) => {
                    self.bp_err = Some(e);
                    return;
                }
            };

            let spec = match self.bp_kind.to_spec(addr, self.bp_len) {
                Ok(s) => s,
                Err(e) => {
                    self.bp_err = Some(format!("Invalid spec: {e}"));
                    return;
                }
            };

            if let Some(dbg) = &mut self.debugger {
                match dbg.set_breakpoint(spec) {
                    Ok(id) => {
                        self.bp_err = None;
                        let _ = id; // id is visible in the breakpoint list
                    }
                    Err(e) => {
                        self.bp_err = Some(format!("Set breakpoint: {e}"));
                    }
                }
            }
        }

        // ── event log ─────────────────────────────────────────────────

        fn show_event_log(&mut self, ui: &mut egui::Ui) {
            ui.heading("Event Log");

            if self.events.is_empty() {
                ui.label("No events yet.");
            } else {
                egui::ScrollArea::vertical()
                    .id_salt("dbg_event_log")
                    .max_height(150.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for ev in &self.events {
                            ui.monospace(ev.display_line());
                        }
                    });
            }

            if ui.small_button("Clear log").clicked() {
                self.events.clear();
            }
        }

        // ── register view ─────────────────────────────────────────────

        fn show_registers(&mut self, ui: &mut egui::Ui) {
            ui.heading("Registers (last event)");

            let Some(r) = &self.latest_regs else {
                ui.label("No event received yet.");
                return;
            };

            egui::Grid::new("dbg_regs")
                .num_columns(4)
                .spacing([12.0, 2.0])
                .striped(true)
                .show(ui, |ui| {
                    let regs: &[(&str, u64)] = &[
                        ("RIP", r.rip), ("RSP", r.rsp), ("RFLAGS", r.rflags), ("RAX", r.rax),
                        ("RBX", r.rbx), ("RCX", r.rcx), ("RDX", r.rdx), ("RSI", r.rsi),
                        ("RDI", r.rdi), ("RBP", r.rbp), ("R8",  r.r8),  ("R9",  r.r9),
                        ("R10", r.r10), ("R11", r.r11), ("R12", r.r12), ("R13", r.r13),
                        ("R14", r.r14), ("R15", r.r15),
                    ];
                    for chunk in regs.chunks(4) {
                        for (name, val) in chunk {
                            ui.monospace(format!("{name}: 0x{val:016X}"));
                        }
                        ui.end_row();
                    }
                });
        }
    }

    impl Default for DebuggerPanel {
        fn default() -> Self { Self::new() }
    }

    /// Parses an optional hex string (e.g. `"deadbeef"` or `"DE AD BE EF"`)
    /// into raw bytes for the auth key. Empty / whitespace → empty `Vec`.
    pub(crate) fn parse_hex_key(s: &str) -> Vec<u8> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.is_empty() {
            return Vec::new();
        }
        // Pad to even length with a leading zero if needed.
        let hex = if !hex.len().is_multiple_of(2) {
            format!("0{hex}")
        } else {
            hex
        };
        (0..hex.len())
            .step_by(2)
            .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect()
    }

}

// ─── Non-Linux stub ─────────────────────────────────────────────────────────
#[cfg(not(target_os = "linux"))]
mod stub {
    use eframe::egui;

    pub struct DebuggerPanel;

    impl DebuggerPanel {
        pub fn new() -> Self { Self }
        /// Like `new()` — key is accepted for API symmetry but ignored on
        /// non-Linux targets (the panel is a stub here).
        pub fn with_key(_key: String) -> Self { Self }
        pub fn tick_events(&mut self) {}
        pub fn on_detach(&mut self) {}
        pub fn show(&mut self, ui: &mut egui::Ui, _pid: Option<i32>) {
            ui.colored_label(
                egui::Color32::GRAY,
                "Debugger panel is Linux-only (requires the nemclass_mod kernel module).",
            );
        }
    }

    impl Default for DebuggerPanel {
        fn default() -> Self { Self::new() }
    }
}

// ─── Public re-export ────────────────────────────────────────────────────────
#[cfg(target_os = "linux")]
pub use linux::DebuggerPanel;
#[cfg(target_os = "linux")]
pub(crate) use linux::parse_hex_key;

#[cfg(not(target_os = "linux"))]
pub use stub::DebuggerPanel;
