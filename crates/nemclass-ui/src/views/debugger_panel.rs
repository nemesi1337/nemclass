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
        AccessTally, Breakpoint, BreakpointId, BreakpointSpec, DebugEvent, Debugger, Registers,
        kernel::abi::HwBreakpointType,
    };

    /// Interval for non-blocking `wait_event` polls.
    const POLL_INTERVAL: Duration = Duration::from_millis(100);

    /// Maximum event-log entries kept in memory.
    const MAX_EVENTS: usize = 200;

    /// How often the thread list is re-read. Threads come and go, but not on a
    /// frame's timescale, and each refresh is one directory walk plus a read per
    /// thread.
    const THREAD_REFRESH: Duration = Duration::from_secs(2);

    /// How many events one poll folds in before handing the frame back.
    ///
    /// A watchpoint on a field written every frame produces hits faster than the
    /// poll interval; without a ceiling this loop would keep itself fed and the
    /// UI would stop repainting.
    const MAX_EVENTS_PER_POLL: usize = 4096;

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

        // ── "find what accesses this address" ─────────────────────────
        /// Address the watch is armed on, as typed.
        watch_addr_text: String,
        /// Span in bytes: 1, 2, 4 or 8.
        watch_len: u32,
        /// Whether to watch writes only or reads as well.
        watch_writes_only: bool,
        /// The armed watchpoint, if any, and what it covers.
        watch: Option<ActiveWatch>,
        /// Per-instruction tally of what has hit the watch.
        watch_tally: AccessTally,
        watch_err: Option<String>,
        /// The target's threads, refreshed on a throttle.
        threads: Vec<(i32, String)>,
        threads_at: Option<Instant>,
        /// Set when the user clicks an access site; consumed by the parent to
        /// open the disassembler there.
        pending_goto_disasm: Option<usize>,
    }

    /// The watchpoint behind the access finder.
    ///
    /// Held here rather than in a `nemclass_core::AccessWatch` because that
    /// takes ownership of the `Debugger`, and this panel's event log polls the
    /// same session — one queue cannot have two owners.
    struct ActiveWatch {
        id: BreakpointId,
        address: u64,
        length: u32,
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
                watch_addr_text: String::new(),
                watch_len: 4,
                watch_writes_only: true,
                watch: None,
                watch_tally: AccessTally::new(),
                watch_err: None,
                threads: Vec::new(),
                threads_at: None,
                pending_goto_disasm: None,
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
            // Drain the whole queue rather than one event per tick. A
            // watchpoint on a field written every frame produces hits far faster
            // than the poll interval, so taking one at a time meant the queue
            // only ever grew and the tally lagged further behind the target.
            let watch_id = self.watch.as_ref().map(|w| w.id);
            for _ in 0..MAX_EVENTS_PER_POLL {
                match dbg.wait_event(Some(Duration::ZERO)) {
                    Ok(Some(ev)) => {
                        // Watchpoint hits go to the tally, not the log: a busy
                        // field produces thousands a second and would bury every
                        // other event.
                        if Some(ev.breakpoint) == watch_id {
                            self.watch_tally.record(ev.registers, ev.tid);
                            self.latest_regs = Some(ev.registers);
                            continue;
                        }
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
                    // No event ready — normal for a non-blocking poll.
                    Ok(None) => break,
                    Err(e) => {
                        // Log the error but don't disconnect: a one-shot read
                        // error does not mean the session is gone.
                        self.events.push(EventEntry::Message(format!("[poll error: {e}]")));
                        break;
                    }
                }
            }
        }

        /// Drop the debugger when the parent detaches from the process.
        pub fn on_detach(&mut self) {
            self.debugger = None;
            self.attach_err = None;
            self.events.clear();
            self.latest_regs = None;
            // The watchpoint died with the session's fd; forgetting the id here
            // stops a later Stop from trying to clear a slot that is gone.
            self.watch = None;
            self.watch_tally.clear();
            self.watch_err = None;
        }

        /// Arm the access finder on `addr` from elsewhere in the app (the class
        /// view's "find what writes this" action).
        pub fn watch_address(&mut self, addr: usize, len: u32, writes_only: bool) {
            self.watch_addr_text = format!("{addr:#x}");
            self.watch_len = len;
            self.watch_writes_only = writes_only;
            self.start_watch();
        }

        /// The address the user asked to disassemble, if any. Consumed.
        pub fn take_goto_disasm(&mut self) -> Option<usize> {
            self.pending_goto_disasm.take()
        }

        /// Arm an execute breakpoint at `addr` from elsewhere in the app (the
        /// disassembler's "set breakpoint here").
        ///
        /// The address field is filled in either way, so a failure leaves the
        /// user one click from retrying rather than retyping.
        pub fn set_execute_breakpoint(&mut self, addr: usize) {
            self.bp_addr_text = format!("{addr:#x}");
            self.bp_kind = BpKind::Execute;
            if self.debugger.is_some() {
                self.do_set_breakpoint();
            } else {
                self.bp_err =
                    Some("Attach the debugger, then press Set to arm this breakpoint.".into());
            }
        }

        // ── main UI ───────────────────────────────────────────────────

        pub fn show(&mut self, ui: &mut egui::Ui, pid: Option<libc::pid_t>) {
            self.show_attach_row(ui, pid);
            ui.separator();
            self.show_bp_controls(ui);
            ui.separator();
            self.show_access_finder(ui);
            ui.separator();
            self.show_threads(ui, pid);
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

        // ── thread list ───────────────────────────────────────────────

        /// The target's threads.
        ///
        /// Every debugger hit reports a `tid`, and there was nothing anywhere in
        /// the app to turn that number into a thread with a name.
        fn show_threads(&mut self, ui: &mut egui::Ui, pid: Option<libc::pid_t>) {
            let Some(pid) = pid else { return };
            egui::CollapsingHeader::new("Threads")
                .id_salt("debugger_threads")
                .show(ui, |ui| {
                    let now = Instant::now();
                    let stale = self
                        .threads_at
                        .map(|t: Instant| now.duration_since(t) >= THREAD_REFRESH)
                        .unwrap_or(true);
                    if stale {
                        self.threads_at = Some(now);
                        // Read through a fresh handle rather than the debugger's:
                        // `/proc/<pid>/task` needs no session at all, and this
                        // keeps the list working before an attach.
                        self.threads = std::fs::read_dir(format!("/proc/{pid}/task"))
                            .map(|dir| {
                                let mut out: Vec<(i32, String)> = dir
                                    .flatten()
                                    .filter_map(|e| {
                                        let tid =
                                            e.file_name().to_str()?.parse::<i32>().ok()?;
                                        let name = std::fs::read_to_string(format!(
                                            "/proc/{pid}/task/{tid}/comm"
                                        ))
                                        .map(|s| s.trim().to_string())
                                        .unwrap_or_default();
                                        Some((tid, name))
                                    })
                                    .collect();
                                out.sort_by_key(|(tid, _)| *tid);
                                out
                            })
                            .unwrap_or_default();
                    }

                    if self.threads.is_empty() {
                        ui.weak("No threads listed — the process may have exited.");
                        return;
                    }
                    // Which threads the access finder has actually seen, so a
                    // hit's tid is recognisable rather than a bare number.
                    let seen: std::collections::HashSet<i32> =
                        self.watch_tally.sites().iter().map(|s| s.first_tid).collect();
                    egui::ScrollArea::vertical()
                        .id_salt("thread_list")
                        .max_height(120.0)
                        .show(ui, |ui| {
                            for (tid, name) in &self.threads {
                                ui.horizontal(|ui| {
                                    ui.monospace(format!("{tid:>7}"));
                                    ui.label(name);
                                    if seen.contains(tid) {
                                        ui.colored_label(
                                            egui::Color32::from_rgb(140, 200, 140),
                                            "• hit the watchpoint",
                                        );
                                    }
                                });
                            }
                        });
                });
        }

        // ── find what accesses this address ───────────────────────────

        /// The headline debugger workflow: arm a watchpoint on a field and see
        /// which instructions touch it, ranked by how often.
        ///
        /// Every primitive for this already existed — hardware watchpoints,
        /// register capture, an event queue — and none of it was assembled into
        /// the thing anyone actually opens a debugger for.
        fn show_access_finder(&mut self, ui: &mut egui::Ui) {
            ui.strong("Find what accesses this address");

            let attached = self.debugger.is_some();
            let watching = self.watch.is_some();

            ui.horizontal_wrapped(|ui| {
                ui.label("Address:");
                ui.add_enabled(
                    !watching,
                    egui::TextEdit::singleline(&mut self.watch_addr_text)
                        .desired_width(150.0)
                        .hint_text("0x7fff…"),
                );
                ui.label("Size:");
                ui.add_enabled_ui(!watching, |ui| {
                    egui::ComboBox::from_id_salt("access_watch_len")
                        .selected_text(self.watch_len.to_string())
                        .width(48.0)
                        .show_ui(ui, |ui| {
                            for len in [1u32, 2, 4, 8] {
                                ui.selectable_value(&mut self.watch_len, len, len.to_string());
                            }
                        });
                });
                ui.add_enabled_ui(!watching, |ui| {
                    ui.checkbox(&mut self.watch_writes_only, "Writes only")
                        .on_hover_text(
                            "x86 debug registers cannot watch reads alone, so unticking this \
                             reports reads *and* writes — a CPU limitation, not a choice here.",
                        );
                });

                if !watching {
                    if ui
                        .add_enabled(attached, egui::Button::new("Start"))
                        .on_disabled_hover_text("Attach the debugger first")
                        .clicked()
                    {
                        self.start_watch();
                    }
                } else if ui.button("Stop").clicked() {
                    self.stop_watch();
                }
                if ui.add_enabled(watching, egui::Button::new("Reset")).clicked() {
                    self.watch_tally.clear();
                }
            });

            if let Some(err) = &self.watch_err {
                ui.colored_label(egui::Color32::RED, err);
            }

            let Some(watch) = &self.watch else { return };
            let total = self.watch_tally.total_hits();
            ui.label(format!(
                "Watching {:#x} (+{} bytes) — {total} hit(s) from {} instruction(s)",
                watch.address,
                watch.length,
                self.watch_tally.site_count()
            ));
            if self.watch_tally.dropped_hits() > 0 {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 40),
                    format!(
                        "{} hit(s) from further instructions were not recorded — the site \
                         list is capped.",
                        self.watch_tally.dropped_hits()
                    ),
                );
            }

            let sites = self.watch_tally.sites();
            if sites.is_empty() {
                ui.weak("Nothing has touched it yet.");
                return;
            }

            let mut goto: Option<usize> = None;
            egui::ScrollArea::vertical()
                .id_salt("access_sites")
                .max_height(180.0)
                .show(ui, |ui| {
                    for site in sites.iter().take(64) {
                        ui.horizontal(|ui| {
                            // The captured RIP is the instruction *after* the
                            // access — a data watchpoint traps on completion —
                            // so the address to look at is the one before it.
                            let label = format!("{:#018x}", site.rip);
                            if ui
                                .add(egui::Button::new(egui::RichText::new(label).monospace())
                                    .frame(false))
                                .on_hover_text(
                                    "Open in the disassembler. This is the instruction *after* \
                                     the access: a data watchpoint traps once the access has \
                                     completed.",
                                )
                                .clicked()
                            {
                                goto = Some(site.rip as usize);
                            }
                            ui.label(format!("×{}", site.hits));
                            ui.weak(format!("tid {}", site.first_tid));
                            let r = site.last_registers;
                            ui.weak(
                                egui::RichText::new(format!(
                                    "rax={:x} rbx={:x} rcx={:x} rdx={:x}",
                                    r.rax, r.rbx, r.rcx, r.rdx
                                ))
                                .monospace(),
                            )
                            .on_hover_text(format!(
                                "rsp={:#x} rbp={:#x} rsi={:#x} rdi={:#x}\n\
                                 r8={:#x} r9={:#x} r10={:#x} r11={:#x}\n\
                                 r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
                                r.rsp, r.rbp, r.rsi, r.rdi,
                                r.r8, r.r9, r.r10, r.r11,
                                r.r12, r.r13, r.r14, r.r15,
                            ));
                        });
                    }
                });
            if let Some(addr) = goto {
                self.pending_goto_disasm = Some(addr);
            }
        }

        fn start_watch(&mut self) {
            self.watch_err = None;
            let Some(dbg) = &mut self.debugger else {
                self.watch_err = Some("Attach the debugger first.".into());
                return;
            };
            let addr = match crate::views::parse_address(&self.watch_addr_text) {
                Ok(a) => a as u64,
                Err(e) => {
                    self.watch_err = Some(e);
                    return;
                }
            };
            let kind = if self.watch_writes_only {
                HwBreakpointType::Write
            } else {
                HwBreakpointType::ReadWrite
            };
            let spec = match BreakpointSpec::hardware(addr, self.watch_len, kind) {
                Ok(s) => s,
                Err(e) => {
                    self.watch_err = Some(e.to_string());
                    return;
                }
            };
            match dbg.set_breakpoint(spec) {
                Ok(id) => {
                    self.watch_tally.clear();
                    self.watch = Some(ActiveWatch { id, address: addr, length: self.watch_len });
                }
                Err(e) => self.watch_err = Some(format!("Could not arm the watchpoint: {e}")),
            }
        }

        fn stop_watch(&mut self) {
            let Some(watch) = self.watch.take() else { return };
            let Some(dbg) = &mut self.debugger else { return };
            // Reported rather than swallowed: the breakpoint stays armed in the
            // kernel until the fd closes, and a silently occupied debug register
            // is how the next watch fails for no visible reason.
            if let Err(e) = dbg.clear_breakpoint(watch.id) {
                self.watch_err = Some(format!("Could not disarm the watchpoint: {e}"));
            }
        }

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
        pub fn watch_address(&mut self, _addr: usize, _len: u32, _writes_only: bool) {}
        pub fn take_goto_disasm(&mut self) -> Option<usize> { None }
        pub fn set_execute_breakpoint(&mut self, _addr: usize) {}
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
