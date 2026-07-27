//! Cheat-Engine-style memory scanner panel.
//!
//! ## Layout
//! ```text
//! ┌─ Scanner ────────────────────────────────────────────────────────────┐
//! │  Type: [I32 ▼]   Compare: [Exact ▼]   Value: [_________]           │
//! │  [First Scan]  [Next Scan]  [Undo]  [New Scan]                      │
//! │  Results: 42 / 100 shown  (capped at MAX_DISPLAY)                   │
//! │  ┌─ Address ──────────────┬─ Value ────┬─ Actions ──────────────┐   │
//! │  │  0x00007fff…           │  1337      │ [Freeze] [Add to class]│   │
//! │  └────────────────────────┴────────────┴────────────────────────┘   │
//! │  ── Freeze list ──────────────────────────────────────────────────  │
//! │  0x00007fff… = 1337   [Unfreeze]                                    │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The scanner is disabled (greyed out) when no process is attached.
//! A `ProcessTarget` is built from the attached `Process` when First Scan fires.
//! `FreezeSet::apply` is called each frame on a throttled timer.

use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_scan::{
    FreezeSet, Needle, ScanCompareType, ScanValueType, Scanner,
};

#[cfg(target_os = "linux")]
use nemclass_scan::ProcessTarget;

use nemclass_core::{Pid, Process};

use super::tasks::{BackgroundJob, Poll as JobPoll};

/// Result of a background scan. The outer `Err` is a fatal failure with no usable
/// scanner (e.g. the target couldn't be attached); `Ok` carries the (moved-back)
/// `Scanner` plus the inner scan result — so even a failed scan returns the
/// session handle, and a Next Scan never loses the user's result set.
#[cfg(target_os = "linux")]
type ScanOutcome =
    Result<(Scanner<ProcessTarget>, Result<Vec<(usize, Vec<u8>)>, String>), String>;

/// How many results to display at most (the full set can be millions of
/// addresses; capping keeps the table from stalling the frame).
const MAX_DISPLAY: usize = 1_000;

/// Interval between `FreezeSet::apply` calls (write-back for frozen values).
const FREEZE_INTERVAL: Duration = Duration::from_millis(200);

/// A single entry in the freeze list sub-panel.
struct FreezeEntry {
    address: usize,
    /// The captured value bytes, also the display string.
    display: String,
}

/// All mutable state owned by the scanner panel.
pub struct ScannerPanel {
    // ── scan configuration ─────────────────────────────────────────────
    value_type: ScanValueType,
    compare:    ScanCompareType,
    /// The text in the value/needle field.
    needle_text: String,
    /// Upper-bound text field, shown only when `compare == Between`.
    upper_text: String,

    // ── active scanner (Linux: Option<Scanner<ProcessTarget>>) ─────────
    /// Boxed so it can be `None` on non-Linux, or before the first scan.
    #[cfg(target_os = "linux")]
    scanner: Option<Scanner<ProcessTarget>>,
    /// In-flight First/Next scan running on the background pool. While set, the
    /// `Scanner` lives inside the worker; it is moved back when the job completes.
    #[cfg(target_os = "linux")]
    scan_job: BackgroundJob<ScanOutcome>,
    /// Mirror the result set as a snapshot for the display, so the borrow
    /// checker can let us iterate while also drawing "add to class" buttons.
    result_snapshot: Vec<(usize, Vec<u8>)>,

    // ── freeze list ────────────────────────────────────────────────────
    freeze_set:     FreezeSet,
    freeze_entries: Vec<FreezeEntry>,
    last_freeze:    Option<Instant>,

    // ── error / status ─────────────────────────────────────────────────
    pub status_msg: Option<String>,
}

impl ScannerPanel {
    pub fn new() -> Self {
        Self {
            value_type:   ScanValueType::I32,
            compare:      ScanCompareType::Exact,
            needle_text:  String::new(),
            upper_text:   String::new(),
            #[cfg(target_os = "linux")]
            scanner:      None,
            #[cfg(target_os = "linux")]
            scan_job:     BackgroundJob::default(),
            result_snapshot: Vec::new(),
            freeze_set:   FreezeSet::new(),
            freeze_entries: Vec::new(),
            last_freeze:  None,
            status_msg:   None,
        }
    }

    // ── called each frame from the parent's `logic()` ──────────────────

    /// Drive the freeze write-back on a throttled interval. Call from the
    /// parent's `logic()` hook (runs even when the tab is not visible).
    #[cfg(target_os = "linux")]
    pub fn tick_freeze(&mut self) {
        if self.freeze_set.is_empty() {
            return;
        }
        let should_apply = self
            .last_freeze
            .map(|t| t.elapsed() >= FREEZE_INTERVAL)
            .unwrap_or(true);
        if !should_apply {
            return;
        }
        if let Some(scanner) = &self.scanner {
            let _ = self.freeze_set.apply(scanner.target());
        }
        self.last_freeze = Some(Instant::now());
    }

    #[cfg(not(target_os = "linux"))]
    pub fn tick_freeze(&mut self) {}

    /// Drain a completed background scan, moving the `Scanner` and its results
    /// back onto the panel. Call each frame from the parent's `logic()` (runs even
    /// when the Scanner tab is not visible, so results land promptly).
    #[cfg(target_os = "linux")]
    pub fn poll(&mut self) {
        if let JobPoll::Done(outcome) = self.scan_job.poll() {
            match outcome {
                // Fatal: no scanner to restore (e.g. attach failed).
                Err(msg) => self.status_msg = Some(msg),
                Ok((scanner, scan_result)) => {
                    self.scanner = Some(scanner);
                    match scan_result {
                        Ok(snapshot) => {
                            self.result_snapshot = snapshot;
                            self.status_msg = None;
                        }
                        Err(msg) => self.status_msg = Some(msg),
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn poll(&mut self) {}

    /// Reset the scanner when the user detaches from the process.
    pub fn on_detach(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.scanner = None;
            // Drop any in-flight scan so its (now-stale) result is discarded.
            self.scan_job = BackgroundJob::default();
        }
        self.result_snapshot.clear();
        self.freeze_set = FreezeSet::new();
        self.freeze_entries.clear();
        self.status_msg = None;
    }

    // ── main UI draw ───────────────────────────────────────────────────

    /// Draw the full scanner panel. `process` is the currently-attached handle
    /// (or `None`); `pid` is its OS pid on Linux. `add_to_class_cb` is called
    /// when "Add to class" is clicked for a result address.
    #[allow(clippy::too_many_arguments)]
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<&Process>,
        pid: Option<Pid>,
        rt: &tokio::runtime::Handle,
        mut add_to_class_cb: impl FnMut(usize),
        mut add_to_table_cb: impl FnMut(usize, &str),
        mut ptr_scan_cb: impl FnMut(usize),
    ) {
        let attached = process.is_some();

        if !attached {
            ui.colored_label(egui::Color32::YELLOW, "Attach to a process to use the scanner.");
            ui.add_space(4.0);
        }

        ui.add_enabled_ui(attached, |ui| {
            self.show_controls(ui, pid, rt);
        });

        ui.separator();

        // Results table (always drawn, but empty when idle). Values update live
        // from the attached process each frame, like Cheat Engine.
        self.show_results(ui, process, &mut add_to_class_cb, &mut add_to_table_cb, &mut ptr_scan_cb);

        ui.separator();

        // Freeze list sub-panel.
        self.show_freeze_list(ui);

        // Status / error line.
        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(220, 160, 40), msg);
        }
    }

    // ── controls row ───────────────────────────────────────────────────

    fn show_controls(&mut self, ui: &mut egui::Ui, pid: Option<Pid>, rt: &tokio::runtime::Handle) {
        ui.horizontal(|ui| {
            // Value type selector.
            egui::ComboBox::from_id_salt("scan_vtype")
                .selected_text(value_type_label(self.value_type))
                .show_ui(ui, |ui| {
                    for &vt in ALL_VALUE_TYPES {
                        let label = value_type_label(vt);
                        ui.selectable_value(&mut self.value_type, vt, label);
                    }
                });

            // Compare type selector.
            egui::ComboBox::from_id_salt("scan_compare")
                .selected_text(compare_label(self.compare))
                .show_ui(ui, |ui| {
                    for &ct in ALL_COMPARE_TYPES {
                        ui.selectable_value(&mut self.compare, ct, compare_label(ct));
                    }
                });

            // Needle text field (hidden when compare does not need a needle).
            if self.compare.needs_needle() {
                ui.add(
                    egui::TextEdit::singleline(&mut self.needle_text)
                        .desired_width(120.0)
                        .hint_text("value"),
                );
                // Second field: upper bound, visible only for Between.
                if self.compare == ScanCompareType::Between {
                    ui.label("to");
                    ui.add(
                        egui::TextEdit::singleline(&mut self.upper_text)
                            .desired_width(120.0)
                            .hint_text("upper bound"),
                    );
                }
            }
        });

        ui.add_space(2.0);

        // A scan is running on the background pool: gate the scan buttons and show
        // a spinner so the user can't stack scans and sees progress.
        let scanning = {
            #[cfg(target_os = "linux")]
            { self.scan_job.is_running() }
            #[cfg(not(target_os = "linux"))]
            { false }
        };

        ui.horizontal(|ui| {
            // First Scan.
            #[cfg(target_os = "linux")]
            if ui.add_enabled(!scanning, egui::Button::new("First Scan")).clicked() {
                self.do_first_scan(pid, rt, ui.ctx().clone());
            }
            #[cfg(not(target_os = "linux"))]
            if ui.button("First Scan").clicked() {
                self.status_msg = Some("Scanner requires Linux.".into());
            }

            // Next Scan.
            let has_scan = {
                #[cfg(target_os = "linux")]
                { self.scanner.is_some() }
                #[cfg(not(target_os = "linux"))]
                { false }
            };
            ui.add_enabled_ui(has_scan && !scanning, |ui| {
                #[cfg(target_os = "linux")]
                if ui.button("Next Scan").clicked() {
                    self.do_next_scan(rt, ui.ctx().clone());
                }
                #[cfg(not(target_os = "linux"))]
                { ui.button("Next Scan"); }
            });

            if scanning {
                ui.spinner();
            }

            // Undo.
            let can_undo = {
                #[cfg(target_os = "linux")]
                { self.scanner.as_ref().is_some_and(|s| s.can_undo()) }
                #[cfg(not(target_os = "linux"))]
                { false }
            };
            ui.add_enabled_ui(can_undo, |ui| {
                #[cfg(target_os = "linux")]
                if ui.button("Undo").clicked() {
                    self.do_undo();
                }
                #[cfg(not(target_os = "linux"))]
                { ui.button("Undo"); }
            });

            // New Scan.
            if ui.button("New Scan").clicked() {
                self.new_scan();
            }

            // Result count label.
            let total = self.result_snapshot.len();
            ui.separator();
            if total > MAX_DISPLAY {
                ui.label(format!(
                    "Results: {} total (showing {})",
                    total, MAX_DISPLAY,
                ));
            } else {
                ui.label(format!("Results: {}", total));
            }
        });
    }

    // ── scan actions ───────────────────────────────────────────────────

    /// Launches a first scan on the background pool. Scanning the whole address
    /// space can take seconds, so it must not run on the UI thread. The
    /// `ProcessTarget` is (re)attached inside the worker; the `Scanner` and its
    /// results are moved back in [`Self::poll`].
    #[cfg(target_os = "linux")]
    fn do_first_scan(&mut self, pid: Option<Pid>, rt: &tokio::runtime::Handle, ctx: egui::Context) {
        let Some(pid) = pid else {
            self.status_msg = Some("No process attached.".into());
            return;
        };
        if self.scan_job.is_running() {
            return;
        }

        let needle = self.parse_needle();
        if self.compare.needs_needle() && needle.is_none() {
            // Error already set by parse_needle.
            return;
        }

        let compare = self.compare;
        let value_type = self.value_type;
        self.status_msg = Some("Scanning…".into());
        self.scan_job.spawn(rt, ctx, move || {
            let target =
                ProcessTarget::attach(pid).map_err(|e| format!("ProcessTarget: {e}"))?;
            let mut scanner = Scanner::new(target, value_type);
            let scan_result = scanner
                .first_scan(compare, needle)
                .map(snapshot_results)
                .map_err(|e| format!("First scan: {e}"));
            Ok((scanner, scan_result))
        });
    }

    /// Launches a next scan on the background pool. The existing `Scanner` is
    /// moved into the worker and returned in [`Self::poll`] (even on error, so the
    /// session survives a failed narrowing).
    #[cfg(target_os = "linux")]
    fn do_next_scan(&mut self, rt: &tokio::runtime::Handle, ctx: egui::Context) {
        if self.scan_job.is_running() {
            return;
        }
        let needle = self.parse_needle();
        if self.compare.needs_needle() && needle.is_none() {
            return;
        }
        let Some(mut scanner) = self.scanner.take() else {
            return;
        };

        let compare = self.compare;
        self.status_msg = Some("Scanning…".into());
        self.scan_job.spawn(rt, ctx, move || {
            let scan_result = scanner
                .next_scan(compare, needle)
                .map(snapshot_results)
                .map_err(|e| format!("Next scan: {e}"));
            Ok((scanner, scan_result))
        });
    }

    #[cfg(target_os = "linux")]
    fn do_undo(&mut self) {
        if let Some(scanner) = &mut self.scanner
            && scanner.undo()
        {
            self.result_snapshot = scanner
                .results()
                .iter()
                .map(|r| (r.address, r.previous_value_bytes.clone()))
                .collect();
            self.status_msg = None;
        }
    }

    fn new_scan(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.scanner = None;
        }
        self.result_snapshot.clear();
        self.status_msg = None;
    }

    /// Parse the needle text for the current value type, storing an error
    /// message and returning `None` on failure.
    ///
    /// When the compare type is `Between`, also parses `upper_text` and
    /// attaches it as the exclusive upper bound via [`Needle::with_upper_bound`].
    /// A missing or empty upper-bound field is treated as a parse error so the
    /// user always gets a meaningful two-sided range, never a silent `> value`.
    fn parse_needle(&mut self) -> Option<Needle> {
        if !self.compare.needs_needle() || self.needle_text.trim().is_empty() {
            return None;
        }
        let needle = match self.value_type.parse_needle(&self.needle_text) {
            Ok(n) => n,
            Err(e) => {
                self.status_msg = Some(format!("Bad value: {e}"));
                return None;
            }
        };
        if self.compare == ScanCompareType::Between {
            if self.upper_text.trim().is_empty() {
                self.status_msg = Some(
                    "Between requires an upper bound — fill in the \"to\" field.".into(),
                );
                return None;
            }
            match needle.with_upper_bound(&self.upper_text) {
                Ok(n) => Some(n),
                Err(e) => {
                    self.status_msg = Some(format!("Bad upper bound: {e}"));
                    None
                }
            }
        } else {
            Some(needle)
        }
    }

    // ── results table ──────────────────────────────────────────────────

    fn show_results(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<&Process>,
        add_to_class_cb: &mut dyn FnMut(usize),
        add_to_table_cb: &mut dyn FnMut(usize, &str),
        ptr_scan_cb: &mut dyn FnMut(usize),
    ) {
        // (address, captured-bytes) for the displayed (capped) result set.
        let visible: Vec<(usize, Vec<u8>)> = self
            .result_snapshot
            .iter()
            .take(MAX_DISPLAY)
            .map(|(addr, bytes)| (*addr, bytes.clone()))
            .collect();

        if visible.is_empty() {
            ui.label("No results.");
            return;
        }

        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height  = text_height + 4.0;

        let value_type = self.value_type;
        let freeze_set  = &mut self.freeze_set;
        let freeze_entries = &mut self.freeze_entries;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::initial(160.0).at_least(100.0))  // Address
            .column(Column::initial(100.0).at_least(60.0))   // Value (live)
            .column(Column::remainder().at_least(160.0))     // Actions
            .header(row_height + 2.0, |mut h| {
                h.col(|ui| { ui.strong("Address"); });
                h.col(|ui| { ui.strong("Value"); });
                h.col(|ui| { ui.strong("Actions"); });
            })
            .body(|body| {
                body.rows(row_height, visible.len(), |mut row| {
                    let idx = row.index();
                    let Some((addr, captured)) = visible.get(idx) else { return; };
                    let addr = *addr;

                    // Live value: re-read the address from the target each frame
                    // (only visible rows are drawn). Fall back to the captured
                    // scan-time bytes if the read fails or the type is variable.
                    let live = read_live_value(process, addr, value_type)
                        .unwrap_or_else(|| format_value_bytes(captured, value_type));

                    row.col(|ui| {
                        ui.monospace(format!("0x{addr:016X}"));
                    });
                    row.col(|ui| {
                        ui.monospace(&live);
                    });
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            if ui.small_button("Freeze").clicked() {
                                // Freeze the current live value (falling back to
                                // the captured scan-time bytes if unreadable).
                                let bytes = read_live_bytes(process, addr, value_type)
                                    .unwrap_or_else(|| captured.clone());
                                freeze_set.set(addr, bytes);
                                freeze_entries.retain(|e| e.address != addr);
                                freeze_entries.push(FreezeEntry {
                                    address: addr,
                                    display: live.clone(),
                                });
                            }
                            if ui.small_button("Add to class").clicked() {
                                add_to_class_cb(addr);
                            }
                            let tag = value_type.as_tag();
                            if ui.small_button("Add to table").clicked() {
                                add_to_table_cb(addr, tag);
                            }
                            if ui.small_button("Ptr-scan").clicked() {
                                ptr_scan_cb(addr);
                            }
                        });
                    });
                });
            });
    }

    // ── freeze list sub-panel ──────────────────────────────────────────

    fn show_freeze_list(&mut self, ui: &mut egui::Ui) {
        ui.collapsing("Freeze list", |ui| {
            if self.freeze_entries.is_empty() {
                ui.label("No frozen values.");
                return;
            }

            let mut to_remove: Option<usize> = None;
            for (i, entry) in self.freeze_entries.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.monospace(format!("0x{:016X}", entry.address));
                    ui.label("=");
                    ui.label(&entry.display);
                    if ui.small_button("Unfreeze").clicked() {
                        to_remove = Some(i);
                    }
                });
            }
            if let Some(idx) = to_remove {
                let addr = self.freeze_entries[idx].address;
                self.freeze_set.remove(addr);
                self.freeze_entries.remove(idx);
            }
        });
    }
}

impl Default for ScannerPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Collapse a scan's [`ScanResults`] into the `(address, captured-bytes)` display
/// snapshot the panel renders. Owned output, so it outlives the borrow of the
/// `Scanner` and can travel back from the worker.
#[cfg(target_os = "linux")]
fn snapshot_results(results: &nemclass_scan::ScanResults) -> Vec<(usize, Vec<u8>)> {
    results
        .iter()
        .map(|r| (r.address, r.previous_value_bytes.clone()))
        .collect()
}

/// Reads the raw bytes of a fixed-width value live from the target. Returns
/// `None` for variable-width types (Bytes/strings), on a short read, or when
/// no process is attached.
fn read_live_bytes(process: Option<&Process>, addr: usize, vt: ScanValueType) -> Option<Vec<u8>> {
    let width = vt.fixed_width()?;
    let process = process?;
    let mut buf = vec![0u8; width];
    let n = process.read_buf(addr, &mut buf).ok()?;
    (n >= width).then_some(buf)
}

/// Reads and formats a value live from the target (see [`read_live_bytes`]).
fn read_live_value(process: Option<&Process>, addr: usize, vt: ScanValueType) -> Option<String> {
    read_live_bytes(process, addr, vt).map(|b| format_value_bytes(&b, vt))
}

fn format_value_bytes(bytes: &[u8], vt: ScanValueType) -> String {
    match vt {
        ScanValueType::I8  if !bytes.is_empty()   => i8::from_le_bytes([bytes[0]]).to_string(),
        ScanValueType::I16 if bytes.len() >= 2 => i16::from_le_bytes(bytes[..2].try_into().unwrap_or_default()).to_string(),
        ScanValueType::I32 if bytes.len() >= 4 => i32::from_le_bytes(bytes[..4].try_into().unwrap_or_default()).to_string(),
        ScanValueType::I64 if bytes.len() >= 8 => i64::from_le_bytes(bytes[..8].try_into().unwrap_or_default()).to_string(),
        ScanValueType::U8  if !bytes.is_empty()   => u8::from_le_bytes([bytes[0]]).to_string(),
        ScanValueType::U16 if bytes.len() >= 2 => u16::from_le_bytes(bytes[..2].try_into().unwrap_or_default()).to_string(),
        ScanValueType::U32 if bytes.len() >= 4 => u32::from_le_bytes(bytes[..4].try_into().unwrap_or_default()).to_string(),
        ScanValueType::U64 if bytes.len() >= 8 => u64::from_le_bytes(bytes[..8].try_into().unwrap_or_default()).to_string(),
        ScanValueType::F32 if bytes.len() >= 4 => {
            let v = f32::from_le_bytes(bytes[..4].try_into().unwrap_or_default());
            format!("{v:.4}")
        }
        ScanValueType::F64 if bytes.len() >= 8 => {
            let v = f64::from_le_bytes(bytes[..8].try_into().unwrap_or_default());
            format!("{v:.6}")
        }
        ScanValueType::Bytes | ScanValueType::StringUtf8 | ScanValueType::StringUtf16 => {
            bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
        }
        _ => "<?>".to_string(),
    }
}

fn value_type_label(vt: ScanValueType) -> &'static str {
    match vt {
        ScanValueType::I8          => "Int8 (i8)",
        ScanValueType::I16         => "Int16 (i16)",
        ScanValueType::I32         => "Int32 (i32)",
        ScanValueType::I64         => "Int64 (i64)",
        ScanValueType::U8          => "UInt8 (u8)",
        ScanValueType::U16         => "UInt16 (u16)",
        ScanValueType::U32         => "UInt32 (u32)",
        ScanValueType::U64         => "UInt64 (u64)",
        ScanValueType::F32         => "Float (f32)",
        ScanValueType::F64         => "Double (f64)",
        ScanValueType::Bytes       => "Bytes (AOB)",
        ScanValueType::StringUtf8  => "String (UTF-8)",
        ScanValueType::StringUtf16 => "String (UTF-16)",
    }
}

fn compare_label(ct: ScanCompareType) -> &'static str {
    match ct {
        ScanCompareType::Exact       => "Exact (==)",
        ScanCompareType::NotEqual    => "Not Equal (!=)",
        ScanCompareType::GreaterThan => "Greater Than (>)",
        ScanCompareType::LessThan    => "Less Than (<)",
        ScanCompareType::Between     => "Between",
        ScanCompareType::Unknown     => "Unknown (all)",
        ScanCompareType::Increased   => "Increased",
        ScanCompareType::IncreasedBy => "Increased By",
        ScanCompareType::Decreased   => "Decreased",
        ScanCompareType::DecreasedBy => "Decreased By",
        ScanCompareType::Changed     => "Changed",
        ScanCompareType::Unchanged   => "Unchanged",
    }
}

const ALL_VALUE_TYPES: &[ScanValueType] = &[
    ScanValueType::I8,
    ScanValueType::I16,
    ScanValueType::I32,
    ScanValueType::I64,
    ScanValueType::U8,
    ScanValueType::U16,
    ScanValueType::U32,
    ScanValueType::U64,
    ScanValueType::F32,
    ScanValueType::F64,
    ScanValueType::Bytes,
    ScanValueType::StringUtf8,
    ScanValueType::StringUtf16,
];

const ALL_COMPARE_TYPES: &[ScanCompareType] = &[
    ScanCompareType::Exact,
    ScanCompareType::NotEqual,
    ScanCompareType::GreaterThan,
    ScanCompareType::LessThan,
    ScanCompareType::Between,
    ScanCompareType::Unknown,
    ScanCompareType::Increased,
    ScanCompareType::IncreasedBy,
    ScanCompareType::Decreased,
    ScanCompareType::DecreasedBy,
    ScanCompareType::Changed,
    ScanCompareType::Unchanged,
];

