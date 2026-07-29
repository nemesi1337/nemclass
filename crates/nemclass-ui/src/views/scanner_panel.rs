//! Cheat-Engine-style memory scanner panel.
//!
//! ## Layout
//! ```text
//! ┌─ Scanner ────────────────────────────────────────────────────────────┐
//! │  Type: [I32 ▼]  Compare: [Exact ▼]  Value: [____]  [x] Fast scan    │
//! │  [First Scan]  [Next Scan]  [Undo]  [New Scan]                      │
//! │  Results: 42 / 100 shown  (capped at MAX_DISPLAY)                   │
//! │  ┌─ Address ────────┬─ Value ──┬─ Previous ┬─ Actions ──────────┐   │
//! │  │  0x00007fff…     │  1337    │  1200     │ [Freeze] [Add…]    │   │
//! │  └──────────────────┴──────────┴───────────┴────────────────────┘   │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! The scanner is disabled (greyed out) when no process is attached.
//!
//! The panel holds the app's `Arc<Process>` rather than opening its own, so the
//! scan engine, the live Value column and the freeze write-back all go through
//! the backend the user actually attached with.
//!
//! **Value** is re-read from the target on a throttle
//! ([`ScannerPanel::set_live_interval`]) for the rows the table actually drew,
//! and is tinted when it differs from what the scan matched. An address that
//! cannot be read shows `??` — never the stale scan-time bytes, which would be
//! indistinguishable from a value that simply is not moving. **Previous** is the
//! value as of the scan generation before the current one.
//!
//! Freezing is delegated to the address-list (cheat-table) panel rather than
//! kept here: that panel re-derives its write-back from the model every tick, so
//! there is one freeze loop instead of two that can disagree.

use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_scan::{
    FilterState, FloatRound, Needle, Region, RegionFilter, ScanCompareType, ScanValueType,
    Scanner, SectionFilter,
};

#[cfg(target_os = "linux")]
use nemclass_scan::ProcessTarget;

use nemclass_core::{ModuleInfoWithName, Process};

use super::tasks::{BackgroundJob, JobHandle, Poll as JobPoll};

/// Result of a background scan. The outer `Err` is a fatal failure with no usable
/// scanner (e.g. the target couldn't be attached); `Ok` carries the (moved-back)
/// `Scanner` plus the inner scan result — so even a failed scan returns the
/// session handle, and a Next Scan never loses the user's result set.
#[cfg(target_os = "linux")]
type ScanOutcome = Result<(Scanner<ProcessTarget>, Result<Vec<ResultRow>, String>), String>;

/// How many results to display at most (the full set can be millions of
/// addresses; capping keeps the table from stalling the frame).
const MAX_DISPLAY: usize = 1_000;

/// Fallback live-refresh cadence, used until the app supplies
/// `settings.live_interval_ms`.
const DEFAULT_LIVE_INTERVAL: Duration = Duration::from_millis(100);

/// How many rows to read on the first refresh after a scan, before the table has
/// reported which rows the viewport actually drew. A generous screenful.
pub(super) const LIVE_SEED_ROWS: usize = 64;

/// Live value differing from the scan-time value (Cheat Engine's red).
pub(super) const CHANGED_COLOR: egui::Color32 = egui::Color32::from_rgb(220, 110, 90);

/// An address that could not be read back.
pub(super) const UNREADABLE_COLOR: egui::Color32 = egui::Color32::from_rgb(200, 80, 80);

/// What the live column knows about one address this frame.
pub(super) enum LiveValue<'a> {
    /// Read succeeded this refresh.
    Read(&'a [u8]),
    /// Read was attempted and failed — the address is gone.
    Failed,
    /// Not read yet (off-screen last frame, or no process attached).
    Pending,
}

/// One row of the results table, as captured when the scan completed.
///
/// `current` is the value the scan matched on; `previous` is what the same
/// address held in the generation before, which is Cheat Engine's "Previous"
/// column. On a first scan the two are equal.
pub(crate) struct ResultRow {
    address: usize,
    current: Vec<u8>,
    previous: Vec<u8>,
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
    /// Cheat Engine's "Fast Scan": only test addresses aligned to the value's
    /// width. On by default — compilers align scalars, so the misses are rare
    /// and it cuts both scan time and result count by the type width.
    fast_scan: bool,
    /// The alignment Fast Scan uses, when the user has overridden it. Cheat
    /// Engine lets you type this — a value laid out on a 16-byte lattice is a
    /// quarter of the candidates of a 4-byte one. Empty means the type's width.
    alignment_text: String,
    /// How float equality is decided (Cheat Engine's rounding setting).
    round_mode: FloatRound,
    /// Match strings ignoring ASCII case.
    case_insensitive: bool,
    /// Show result values as hex rather than decimal.
    show_hex: bool,

    // ── scan scope (first scan only) ───────────────────────────────────
    /// Master toggle for the whole "Scan range" section.
    scan_range_enabled: bool,
    /// Manual window start (hex, inclusive). Empty = no lower bound.
    range_start_text: String,
    /// Manual window end (hex, **exclusive**, as in `/proc/<pid>/maps`).
    /// Empty = no upper bound.
    range_end_text: String,
    /// Modules whose image spans restrict the scan, held by *name* so the
    /// selection survives the per-frame module re-enumeration.
    selected_modules: std::collections::BTreeSet<String>,
    /// Filter text for the module checkbox list.
    module_filter: String,
    /// Protection and memory-type filters (ReClass.NET's `ScanSettings`).
    writable: FilterState,
    executable: FilterState,
    copy_on_write: FilterState,
    scan_private: bool,
    scan_image: bool,
    scan_mapped: bool,

    // ── active scanner (Linux: Option<Scanner<ProcessTarget>>) ─────────
    /// Boxed so it can be `None` on non-Linux, or before the first scan.
    #[cfg(target_os = "linux")]
    scanner: Option<Scanner<ProcessTarget>>,
    /// In-flight First/Next scan running on the background pool. While set, the
    /// `Scanner` lives inside the worker; it is moved back when the job completes.
    #[cfg(target_os = "linux")]
    scan_job: BackgroundJob<ScanOutcome>,
    /// Whether the in-flight job is a *first* scan, so [`Self::poll`] knows
    /// `scanned_region_count()` reflects it.
    #[cfg(target_os = "linux")]
    last_job_was_first_scan: bool,
    /// Mirror the result set as a snapshot for the display, so the borrow
    /// checker can let us iterate while also drawing "add to class" buttons.
    result_snapshot: Vec<ResultRow>,

    /// The attached process, refreshed each frame by [`Self::show`].
    ///
    /// Held rather than only passed in so the per-frame `logic()` hooks
    /// (freeze write-back) keep working when the Scanner tab is not the one
    /// being drawn, and while a scan job has moved the `Scanner` off-panel.
    process: Option<std::sync::Arc<Process>>,

    // ── live value column ──────────────────────────────────────────────
    /// Last read of each on-screen address. `None` means the read was *tried*
    /// and failed, which the table renders as `??` — distinct from an address
    /// simply not refreshed yet.
    live_cache: std::collections::HashMap<usize, Option<Vec<u8>>>,
    /// When [`Self::refresh_live_values`] last ran.
    last_live_refresh: Option<Instant>,
    /// Row range the table drew last frame, so the refresh only reads what is
    /// actually on screen.
    visible_rows: std::ops::Range<usize>,
    /// Live-refresh cadence, mirroring the class view's snapshot interval.
    live_interval: Duration,

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
            fast_scan:    true,
            alignment_text: String::new(),
            round_mode: FloatRound::Normal,
            case_insensitive: false,
            show_hex: false,
            scan_range_enabled: false,
            range_start_text: String::new(),
            range_end_text:   String::new(),
            selected_modules: std::collections::BTreeSet::new(),
            module_filter:    String::new(),
            // Mirrors `SectionFilter::default()` — writable-only, which is what
            // the scanner did before the scope controls existed.
            writable:      FilterState::Yes,
            executable:    FilterState::Any,
            copy_on_write: FilterState::No,
            scan_private: true,
            scan_image:   true,
            scan_mapped:  false,
            #[cfg(target_os = "linux")]
            scanner:      None,
            #[cfg(target_os = "linux")]
            scan_job:     BackgroundJob::default(),
            #[cfg(target_os = "linux")]
            last_job_was_first_scan: false,
            result_snapshot: Vec::new(),
            process:      None,
            live_cache:   std::collections::HashMap::new(),
            last_live_refresh: None,
            visible_rows: 0..0,
            live_interval: DEFAULT_LIVE_INTERVAL,
            status_msg:   None,
        }
    }

    /// Sets the live-value refresh cadence, so the scanner follows the same
    /// `live_interval_ms` setting as the class view.
    pub fn set_live_interval(&mut self, interval: Duration) {
        self.live_interval = interval;
    }

    /// Drops every cached live read, so the next refresh re-reads from scratch.
    /// Called whenever the addresses on screen stop meaning what they did.
    fn invalidate_live_cache(&mut self) {
        self.live_cache.clear();
        self.last_live_refresh = None;
        self.visible_rows = 0..0;
    }

    // ── called each frame from the parent's `logic()` ──────────────────

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
                    // A session is now active, so the compare list has switched
                    // to the next-scan vocabulary. Snap the selection into it
                    // here rather than in the draw code, so the combo never shows
                    // a value absent from its own list.
                    self.compare = snap_compare(self.compare, true);
                    match scan_result {
                        Ok(snapshot) => {
                            self.result_snapshot = snapshot;
                            self.invalidate_live_cache();
                            // A scope that excluded every region yields an empty
                            // result set indistinguishable from "value not
                            // found". Say so explicitly rather than let the user
                            // conclude their value isn't there. Reported here
                            // rather than as an `Err` because the error branch
                            // leaves the *previous* results on screen.
                            let scope_matched_nothing = self.last_job_was_first_scan
                                && self
                                    .scanner
                                    .as_ref()
                                    .is_some_and(|s| s.scanned_region_count() == 0);
                            // A next scan silently drops results whose address is
                            // no longer mapped. Say how many, so a result count
                            // that fell further than expected is explained.
                            let dropped = if self.last_job_was_first_scan {
                                0
                            } else {
                                self.scanner
                                    .as_ref()
                                    .map_or(0, |s| s.last_scan_stats().unreadable)
                            };
                            // The cap exists so an `Unknown` baseline over a live
                            // working set cannot OOM the process. Say the set is
                            // a prefix — otherwise a later narrowing that never
                            // finds the value looks inexplicable.
                            let truncated = self.last_job_was_first_scan
                                && self
                                    .scanner
                                    .as_ref()
                                    .is_some_and(|s| s.results_truncated());
                            self.status_msg = if truncated {
                                Some(format!(
                                    "Stopped at {} results — this is only part of the matches. \
                                     Narrow the scan range or scan for a known value.",
                                    self.result_snapshot.len()
                                ))
                            } else if scope_matched_nothing {
                                Some(
                                    "Scan range matched no memory — the address window, selected \
                                     modules and memory-type filters don't overlap any region. \
                                     Widen the range or untick \"Restrict scan range\"."
                                        .to_string(),
                                )
                            } else if dropped > 0 {
                                Some(format!(
                                    "{dropped} address(es) are no longer readable and were dropped."
                                ))
                            } else {
                                None
                            };
                        }
                        Err(msg) => {
                            self.status_msg = Some(msg);
                            // A first scan builds a fresh `Scanner`, so one that
                            // failed or was stopped leaves a session that has
                            // never scanned — Next Scan would be enabled but
                            // could only error. Drop it back to "no session".
                            if self.scanner.as_ref().is_some_and(|s| !s.has_scanned()) {
                                self.scanner = None;
                                self.result_snapshot.clear();
                                self.compare = snap_compare(self.compare, false);
                                self.invalidate_live_cache();
                            }
                        }
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
            self.last_job_was_first_scan = false;
        }
        // Module names belong to the process we just left. The address window
        // and filter toggles are user preferences and deliberately persist.
        self.process = None;
        self.selected_modules.clear();
        self.result_snapshot.clear();
        self.invalidate_live_cache();
        self.status_msg = None;
    }

    // ── main UI draw ───────────────────────────────────────────────────

    /// Draw the full scanner panel. `process` is the currently-attached handle
    /// (or `None`). `add_to_class_cb` is called when "Add to class" is clicked
    /// for a result address.
    ///
    /// The handle is shared rather than borrowed so the scan engine, the live
    /// value column and the freeze write-back all read through the same backend
    /// the user attached with.
    #[allow(clippy::too_many_arguments)]
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<&std::sync::Arc<Process>>,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
        mut add_to_class_cb: impl FnMut(usize),
        mut add_to_table_cb: impl FnMut(usize, &str),
        mut ptr_scan_cb: impl FnMut(usize),
        mut freeze_cb: impl FnMut(usize, &str, String),
    ) {
        self.process = process.cloned();
        let attached = process.is_some();

        if !attached {
            ui.colored_label(egui::Color32::YELLOW, "Attach to a process to use the scanner.");
            ui.add_space(4.0);
        }

        ui.add_enabled_ui(attached, |ui| {
            self.show_controls(ui, modules, rt);
        });

        ui.separator();

        // Results table (always drawn, but empty when idle). Values update live
        // from the attached process each frame, like Cheat Engine.
        self.show_results(
            ui,
            &mut add_to_class_cb,
            &mut add_to_table_cb,
            &mut ptr_scan_cb,
            &mut freeze_cb,
        );

        ui.separator();

        // Status / error line.
        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(220, 160, 40), msg);
        }
    }

    // ── controls row ───────────────────────────────────────────────────

    fn show_controls(
        &mut self,
        ui: &mut egui::Ui,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
    ) {
        // A scan session is active: the results hold spans of the session's value
        // type, so the type is locked and the compare list switches to the
        // next-scan vocabulary.
        let has_scan = {
            #[cfg(target_os = "linux")]
            { self.scanner.is_some() }
            #[cfg(not(target_os = "linux"))]
            { false }
        };

        ui.horizontal(|ui| {
            // Value type selector. Locked while a session is active: the stored
            // previous values are this type's width, so switching would compare
            // truncated or over-long spans.
            ui.add_enabled_ui(!has_scan, |ui| {
                egui::ComboBox::from_id_salt("scan_vtype")
                    .selected_text(value_type_label(self.value_type))
                    .show_ui(ui, |ui| {
                        for &vt in ALL_VALUE_TYPES {
                            let label = value_type_label(vt);
                            ui.selectable_value(&mut self.value_type, vt, label);
                        }
                    })
                    .response
                    .on_disabled_hover_text(
                        "Value type is fixed for this scan session — press New Scan to change it.",
                    );
            });

            // Compare type selector.
            egui::ComboBox::from_id_salt("scan_compare")
                .selected_text(compare_label(self.compare))
                .show_ui(ui, |ui| {
                    for &ct in available_compares(has_scan) {
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

            // Applies to a first scan only, so it follows the same lock as the
            // value type: the existing results are already on one lattice.
            ui.add_enabled_ui(!has_scan, |ui| {
                ui.checkbox(&mut self.fast_scan, "Fast scan")
                    .on_hover_text(
                        "Only test addresses aligned to the value's width. Much faster and \
                         far fewer results; untick to find deliberately misaligned values.",
                    );
                if self.fast_scan {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.alignment_text)
                            .desired_width(40.0)
                            .hint_text("auto"),
                    )
                    .on_hover_text(
                        "Alignment in bytes. Blank uses the value's own width; a larger \
                         value (16, 32) is much faster when you know the layout.",
                    );
                }
            });
        });

        ui.horizontal_wrapped(|ui| {
            if matches!(self.value_type, ScanValueType::F32 | ScanValueType::F64) {
                ui.label("Rounding:");
                egui::ComboBox::from_id_salt("scan-round-mode")
                    .selected_text(match self.round_mode {
                        FloatRound::Normal => "Normal",
                        FloatRound::Strict => "Exact",
                        FloatRound::Truncate => "Truncated",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.round_mode, FloatRound::Normal, "Normal")
                            .on_hover_text("Within a small tolerance of the typed value");
                        ui.selectable_value(&mut self.round_mode, FloatRound::Truncate, "Truncated")
                            .on_hover_text(
                                "Ignore the fractional part — finds 100.63 when the game \
                                 shows 100",
                            );
                        ui.selectable_value(&mut self.round_mode, FloatRound::Strict, "Exact")
                            .on_hover_text("Bit-for-bit equality");
                    });
                ui.separator();
            }
            if self.value_type.is_string() {
                ui.checkbox(&mut self.case_insensitive, "Ignore case");
                ui.separator();
            }
            ui.checkbox(&mut self.show_hex, "Hex values")
                .on_hover_text("Show the Value and Previous columns in hexadecimal");
        });

        ui.add_space(2.0);

        self.show_scan_range(ui, modules);

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
                self.do_first_scan(modules, rt, ui.ctx().clone());
            }
            #[cfg(not(target_os = "linux"))]
            if ui.button("First Scan").clicked() {
                self.status_msg = Some("Scanner requires Linux.".into());
            }

            // Next Scan.
            ui.add_enabled_ui(has_scan && !scanning, |ui| {
                #[cfg(target_os = "linux")]
                if ui.button("Next Scan").clicked() {
                    self.do_next_scan(rt, ui.ctx().clone());
                }
                #[cfg(not(target_os = "linux"))]
                { ui.button("Next Scan"); }
            });

            // A whole-address-space scan takes seconds; without a bar it is
            // indistinguishable from a hang, and without a Stop the only way out
            // used to be waiting it out.
            #[cfg(target_os = "linux")]
            if scanning {
                match self.scan_job.handle().and_then(|h| h.fraction()) {
                    Some(f) => {
                        ui.add(
                            egui::ProgressBar::new(f)
                                .desired_width(140.0)
                                .show_percentage(),
                        );
                    }
                    // No total yet (still enumerating regions), or a next scan
                    // over an empty set.
                    None => {
                        ui.spinner();
                    }
                }
                if ui.button("Stop").clicked() {
                    self.scan_job.cancel();
                }
            }
            #[cfg(not(target_os = "linux"))]
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
            // With a scope active, show how much memory it actually covered so
            // the restriction is visibly taking effect.
            #[cfg(target_os = "linux")]
            if self.scan_range_enabled
                && self.last_job_was_first_scan
                && let Some(n) = self.scanner.as_ref().map(|s| s.scanned_region_count())
                && n > 0
            {
                ui.weak(format!("({n} region(s) scanned)"));
            }
        });
    }

    // ── scan scope ─────────────────────────────────────────────────────

    /// The collapsible "Scan range" section: a manual address window, the
    /// memory-type and protection filters, and a module multiselect.
    ///
    /// Applies to First Scan only — a next scan re-reads the addresses the first
    /// scan found and never consults the region list.
    fn show_scan_range(&mut self, ui: &mut egui::Ui, modules: &[ModuleInfoWithName]) {
        // Built before `.show()` so this `&self` borrow ends before the closure
        // below takes `&mut self`.
        let header = self.range_summary(modules);
        egui::CollapsingHeader::new(header)
            .id_salt("scan_range")
            .default_open(false)
            .show(ui, |ui| {
                ui.checkbox(&mut self.scan_range_enabled, "Restrict scan range")
                    .on_hover_text(
                        "Applies to First Scan only — Next Scan re-reads the existing \
                         results, which are already inside the range.",
                    );
                let enabled = self.scan_range_enabled;

                ui.add_enabled_ui(enabled, |ui| {
                    // ── manual address window ─────────────────────────────
                    ui.horizontal(|ui| {
                        ui.label("Start:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.range_start_text)
                                .desired_width(150.0)
                                .hint_text("0x0"),
                        )
                        .on_hover_text("Hex, inclusive. Empty = no lower bound.");
                        ui.label("End:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.range_end_text)
                                .desired_width(150.0)
                                .hint_text("end (exclusive)"),
                        )
                        .on_hover_text(
                            "Hex, exclusive — the same convention as /proc/<pid>/maps, \
                             so a range pasted from there scans exactly that mapping. \
                             Empty = no upper bound.",
                        );
                        if ui.small_button("Clear").clicked() {
                            self.range_start_text.clear();
                            self.range_end_text.clear();
                        }
                    });

                    // ── memory type ───────────────────────────────────────
                    ui.horizontal(|ui| {
                        ui.label("Memory type:");
                        ui.checkbox(&mut self.scan_private, "Private")
                            .on_hover_text("The heap, thread stacks, anonymous memory.");
                        ui.checkbox(&mut self.scan_image, "Image")
                            .on_hover_text("Mappings belonging to a loaded module.");
                        ui.checkbox(&mut self.scan_mapped, "Mapped")
                            .on_hover_text("Shared memory visible to other processes.");
                    });

                    // ── protection tri-states ─────────────────────────────
                    ui.horizontal(|ui| {
                        ui.label("Protection:");
                        tri_state_combo(ui, "scan_prot_w", "Writable", &mut self.writable);
                        tri_state_combo(ui, "scan_prot_x", "Executable", &mut self.executable);
                        tri_state_combo(ui, "scan_prot_c", "Copy-on-write", &mut self.copy_on_write);
                    });

                    // An explicit address window supersedes the module picker,
                    // so grey the list out rather than let it look effective.
                    let range_set = !self.range_start_text.trim().is_empty()
                        || !self.range_end_text.trim().is_empty();
                    ui.add_enabled_ui(!range_set, |ui| {
                        self.show_module_picker(ui, modules, range_set);
                    });
                });
            });
    }

    /// The filterable module checkbox list. `range_set` only affects the hint
    /// text — the caller has already disabled the surrounding `Ui`.
    fn show_module_picker(
        &mut self,
        ui: &mut egui::Ui,
        modules: &[ModuleInfoWithName],
        range_set: bool,
    ) {
        ui.horizontal(|ui| {
            ui.label("Modules:");
            ui.add(
                egui::TextEdit::singleline(&mut self.module_filter)
                    .desired_width(140.0)
                    .hint_text("name…"),
            );
            if !self.module_filter.is_empty() && ui.small_button("✕").clicked() {
                self.module_filter.clear();
            }
            // Bulk actions respect the active filter, so "All" over a filtered
            // list selects what the user can actually see.
            let needle = self.module_filter.to_ascii_lowercase();
            if ui.small_button("All").clicked() {
                for m in modules {
                    if needle.is_empty() || m.name.to_ascii_lowercase().contains(&needle) {
                        self.selected_modules.insert(m.name.clone());
                    }
                }
            }
            if ui.small_button("None").clicked() {
                self.selected_modules.clear();
            }
            if range_set {
                ui.weak("(overridden by the address range)");
            } else if self.selected_modules.is_empty() {
                ui.weak("all memory");
            } else {
                ui.weak(format!("{} selected", self.selected_modules.len()));
            }
        });

        let needle = self.module_filter.to_ascii_lowercase();
        let mut shown = 0usize;
        egui::ScrollArea::vertical()
            .id_salt("scan_range_modules")
            .max_height(160.0)
            .show(ui, |ui| {
                for m in modules {
                    if !needle.is_empty() && !m.name.to_ascii_lowercase().contains(&needle) {
                        continue;
                    }
                    shown += 1;
                    let mut checked = self.selected_modules.contains(&m.name);
                    let label = format!(
                        "{}   0x{:X}–0x{:X}",
                        m.name,
                        m.base,
                        m.base.saturating_add(m.size)
                    );
                    if ui.checkbox(&mut checked, label).changed() {
                        if checked {
                            self.selected_modules.insert(m.name.clone());
                        } else {
                            self.selected_modules.remove(&m.name);
                        }
                    }
                }
            });
        if modules.is_empty() {
            ui.weak("(no modules enumerated for this process)");
        } else if shown == 0 {
            ui.weak("(no modules match the filter)");
        }
    }

    /// One-line summary for the collapsed header, so the active scope is
    /// visible without expanding the section.
    fn range_summary(&self, modules: &[ModuleInfoWithName]) -> String {
        if !self.scan_range_enabled {
            return "Scan range: all writable memory".to_string();
        }
        let start = self.range_start_text.trim();
        let end = self.range_end_text.trim();
        if !start.is_empty() || !end.is_empty() {
            let lo = if start.is_empty() { "…" } else { start };
            let hi = if end.is_empty() { "…" } else { end };
            return format!("Scan range: {lo}–{hi}");
        }
        // Count only the selections that resolve, so a stale name from a
        // previous target doesn't inflate the number.
        let picked = modules
            .iter()
            .filter(|m| self.selected_modules.contains(&m.name))
            .count();
        match picked {
            0 => "Scan range: all memory (filtered)".to_string(),
            1 => "Scan range: 1 module".to_string(),
            n => format!("Scan range: {n} modules"),
        }
    }

    /// Build the scan scope from the range fields, mirroring
    /// [`Self::parse_needle`]: on invalid input it stores a `status_msg` and
    /// returns `None`, so the caller aborts before spawning any work.
    ///
    /// `Some(defaults)` means "explicitly unrestricted" and is distinct from the
    /// `None` error case.
    #[cfg(target_os = "linux")]
    fn build_filters(
        &mut self,
        modules: &[ModuleInfoWithName],
    ) -> Option<(RegionFilter, SectionFilter)> {
        if !self.scan_range_enabled {
            return Some((RegionFilter::default(), SectionFilter::default()));
        }

        let start = match parse_opt_hex(&self.range_start_text) {
            Ok(v) => v.unwrap_or(0),
            Err(()) => {
                self.status_msg =
                    Some("Bad start address — expected hex, e.g. 0x7f0000000000.".into());
                return None;
            }
        };
        let stop = match parse_opt_hex(&self.range_end_text) {
            Ok(v) => v.unwrap_or(usize::MAX),
            Err(()) => {
                self.status_msg =
                    Some("Bad end address — expected hex, e.g. 0x7f0100000000.".into());
                return None;
            }
        };
        if stop <= start {
            self.status_msg = Some(format!(
                "End address (0x{stop:X}) must be greater than start (0x{start:X})."
            ));
            return None;
        }

        if !self.scan_private && !self.scan_image && !self.scan_mapped {
            self.status_msg =
                Some("Tick at least one memory type (Private, Image or Mapped).".into());
            return None;
        }

        // An explicit window overrides the module selection entirely.
        let range_set = !self.range_start_text.trim().is_empty()
            || !self.range_end_text.trim().is_empty();
        let include: Vec<Region> = if range_set {
            Vec::new()
        } else {
            modules
                .iter()
                .filter(|m| self.selected_modules.contains(&m.name))
                .map(|m| Region::new(m.base, m.size))
                .collect()
        };
        if !range_set && !self.selected_modules.is_empty() && include.is_empty() {
            self.status_msg = Some(
                "None of the selected modules are loaded in this process — \
                 clear the selection or re-attach."
                    .into(),
            );
            return None;
        }

        let region = RegionFilter { start, stop, include };
        let section = SectionFilter {
            writable: self.writable,
            executable: self.executable,
            copy_on_write: self.copy_on_write,
            scan_private: self.scan_private,
            scan_image: self.scan_image,
            scan_mapped: self.scan_mapped,
        };
        Some((region, section))
    }

    // ── scan actions ───────────────────────────────────────────────────

    /// Launches a first scan on the background pool. Scanning the whole address
    /// space can take seconds, so it must not run on the UI thread. The `Scanner`
    /// and its results are moved back in [`Self::poll`].
    #[cfg(target_os = "linux")]
    fn do_first_scan(
        &mut self,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
        ctx: egui::Context,
    ) {
        let Some(process) = self.process.clone() else {
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
        // Resolved here, on the UI thread: the worker can't see the module list.
        // Both filters are owned, so they move into the closure cleanly.
        let Some((region_filter, section_filter)) = self.build_filters(modules) else {
            // Error already set by build_filters.
            return;
        };

        let compare = self.compare;
        let value_type = self.value_type;
        let alignment = self.scan_alignment();
        self.last_job_was_first_scan = true;
        self.status_msg = Some("Scanning…".into());
        self.scan_job.spawn_cancellable(rt, ctx, move |job| {
            // Shares the app's handle rather than opening a second one, so the
            // scan reads through whichever backend the user attached with — the
            // same one the live value column reads through.
            let target =
                ProcessTarget::from_shared(process).with_section_filter(section_filter);
            let mut scanner = Scanner::new(target, value_type)
                .with_region_filter(region_filter)
                .with_alignment(alignment);
            let scan_result = scanner
                .first_scan_with(compare, needle, &mut observer_for(job))
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
        self.last_job_was_first_scan = false;
        self.status_msg = Some("Scanning…".into());
        self.scan_job.spawn_cancellable(rt, ctx, move |job| {
            let scan_result = scanner
                .next_scan_with(compare, needle, &mut observer_for(job))
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
            self.result_snapshot = snapshot_results(scanner.results());
            self.invalidate_live_cache();
            self.status_msg = None;
        }
    }

    fn new_scan(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.scanner = None;
        }
        self.result_snapshot.clear();
        self.invalidate_live_cache();
        // Back to a first-scan session: a change-relative compare has nothing to
        // compare against any more.
        self.compare = snap_compare(self.compare, false);
        self.status_msg = None;
    }

    /// Parse the needle text for the current value type, storing an error
    /// message and returning `None` on failure.
    ///
    /// When the compare type is `Between`, also parses `upper_text` and
    /// attaches it as the exclusive upper bound via [`Needle::with_upper_bound`].
    /// A missing or empty upper-bound field is treated as a parse error so the
    /// user always gets a meaningful two-sided range, never a silent `> value`.
    /// The first-scan candidate step: 0 asks the scanner for the value's own
    /// width, 1 tests every byte, and anything else is the user's override.
    ///
    /// A non-numeric or zero override falls back to the type width rather than
    /// erroring: the field is a hint, and refusing to scan over a typo in an
    /// optional box is worse than ignoring it.
    fn scan_alignment(&self) -> usize {
        if !self.fast_scan {
            return 1;
        }
        self.alignment_text.trim().parse::<usize>().unwrap_or(0)
    }

    fn parse_needle(&mut self) -> Option<Needle> {
        // Two very different situations used to collapse into a silent `None`:
        // a compare that legitimately takes no needle, and a compare that needs
        // one from an empty field. The second must say so — otherwise the scan
        // button simply does nothing.
        if !self.compare.needs_needle() {
            return None;
        }
        if self.needle_text.trim().is_empty() {
            self.status_msg = Some(format!(
                "{} needs a value — the field is empty.",
                compare_label(self.compare)
            ));
            return None;
        }
        let needle = match self.value_type.parse_needle(&self.needle_text) {
            Ok(n) => n
                .with_round_mode(self.round_mode)
                .with_case_insensitive(self.case_insensitive),
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
        add_to_class_cb: &mut dyn FnMut(usize),
        add_to_table_cb: &mut dyn FnMut(usize, &str),
        ptr_scan_cb: &mut dyn FnMut(usize),
        freeze_cb: &mut dyn FnMut(usize, &str, String),
    ) {
        let row_count = self.result_snapshot.len().min(MAX_DISPLAY);
        if row_count == 0 {
            ui.label("No results.");
            return;
        }

        self.refresh_live_values();

        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height  = text_height + 4.0;

        let value_type = self.value_type;
        let show_hex = self.show_hex;
        // Disjoint field borrows: the table body needs `&self.result_snapshot`
        // and `&self.live_cache` while mutating the freeze state, so split them
        // here rather than cloning a thousand rows every frame to dodge it.
        let snapshot = &self.result_snapshot;
        let live_cache = &self.live_cache;
        let mut drawn: Option<(usize, usize)> = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::initial(160.0).at_least(100.0))  // Address
            .column(Column::initial(100.0).at_least(60.0))   // Value (live)
            .column(Column::initial(100.0).at_least(60.0))   // Previous
            .column(Column::remainder().at_least(160.0))     // Actions
            .header(row_height + 2.0, |mut h| {
                h.col(|ui| { ui.strong("Address"); });
                h.col(|ui| { ui.strong("Value"); });
                h.col(|ui| { ui.strong("Previous"); });
                h.col(|ui| { ui.strong("Actions"); });
            })
            .body(|body| {
                body.rows(row_height, row_count, |mut row| {
                    let idx = row.index();
                    let Some(entry) = snapshot.get(idx) else { return; };
                    let addr = entry.address;
                    // Track what the viewport actually drew, so the next refresh
                    // reads only these addresses instead of all 1000.
                    drawn = Some(match drawn {
                        Some((lo, hi)) => (lo.min(idx), hi.max(idx)),
                        None => (idx, idx),
                    });

                    // Three distinct states, deliberately not collapsed: a fresh
                    // read, a read that *failed*, and no read yet. Falling back
                    // to the scan-time bytes on failure (as this used to) makes a
                    // freed address look like a live value that simply isn't
                    // moving — the exact confusion this column exists to avoid.
                    let live = match live_cache.get(&addr) {
                        Some(Some(bytes)) => LiveValue::Read(bytes),
                        Some(None) => LiveValue::Failed,
                        None => LiveValue::Pending,
                    };

                    row.col(|ui| {
                        // Double-click sends the hit to the address list, as in
                        // Cheat Engine. The buttons stay for discoverability.
                        let r = ui.add(
                            egui::Label::new(egui::RichText::new(format!("0x{addr:016X}")).monospace())
                                .sense(egui::Sense::click()),
                        );
                        if r.double_clicked() {
                            add_to_table_cb(addr, value_type.as_tag());
                        }
                        r.on_hover_text("Double-click to add to the address list")
                            .context_menu(|ui| {
                                if ui.button("Add to address list").clicked() {
                                    add_to_table_cb(addr, value_type.as_tag());
                                    ui.close();
                                }
                                if ui.button("Add to class").clicked() {
                                    add_to_class_cb(addr);
                                    ui.close();
                                }
                                if ui.button("Pointer-scan this address").clicked() {
                                    ptr_scan_cb(addr);
                                    ui.close();
                                }
                            });
                    });
                    row.col(|ui| {
                        match live {
                            LiveValue::Read(bytes) => {
                                let text = format_value_bytes_radix(bytes, value_type, show_hex);
                                // Tint when the live value has moved away from
                                // what the scan matched: the clearest possible
                                // signal that this column really is live.
                                if bytes == entry.current.as_slice() {
                                    ui.monospace(text);
                                } else {
                                    ui.monospace(
                                        egui::RichText::new(text).color(CHANGED_COLOR),
                                    );
                                }
                            }
                            LiveValue::Failed => {
                                ui.monospace(
                                    egui::RichText::new("??").color(UNREADABLE_COLOR),
                                )
                                .on_hover_text(
                                    "This address could not be read — it may have been freed.",
                                );
                            }
                            LiveValue::Pending => {
                                ui.weak("…");
                            }
                        };
                    });
                    row.col(|ui| {
                        ui.monospace(
                            egui::RichText::new(format_value_bytes_radix(
                                &entry.previous,
                                value_type,
                                show_hex,
                            ))
                                .weak(),
                        );
                    });
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            // Freezing means "add to the address list, frozen":
                            // the address list owns freezing, and it re-derives
                            // its write-back from the model every tick, so an
                            // edit there can never be reverted by a stale cache
                            // the scanner kept on the side.
                            if ui.small_button("Freeze").clicked() {
                                // Pin what is actually there now, falling back to
                                // the scan-time bytes when there is no live read.
                                let bytes = match live {
                                    LiveValue::Read(b) => b,
                                    _ => entry.current.as_slice(),
                                };
                                freeze_cb(
                                    addr,
                                    value_type.as_tag(),
                                    format_value_bytes_radix(bytes, value_type, show_hex),
                                );
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

        self.visible_rows = drawn.map_or(0..0, |(lo, hi)| lo..hi + 1);
    }

    /// Re-read the addresses the table drew last frame, on a throttle.
    ///
    /// Reading every drawn row every frame is one syscall per row per frame for
    /// no visible benefit; the class view already settles for
    /// `settings.live_interval_ms` (100 ms by default) and one frame of lag at
    /// that cadence is imperceptible. Only the rows the viewport actually
    /// scrolled to are read, so the cost is bounded by screen height rather than
    /// by `MAX_DISPLAY`.
    fn refresh_live_values(&mut self) {
        let due = self
            .last_live_refresh
            .is_none_or(|t| t.elapsed() >= self.live_interval);
        if !due {
            return;
        }
        self.last_live_refresh = Some(Instant::now());
        self.live_cache.clear();

        let Some(process) = self.process.clone() else { return };
        let range = self.visible_rows.clone();
        // First paint after a scan has no viewport yet; seed with a screenful so
        // the column is populated immediately rather than a beat later.
        let range = if range.is_empty() {
            0..LIVE_SEED_ROWS.min(self.result_snapshot.len())
        } else {
            range.start..range.end.min(self.result_snapshot.len())
        };

        for entry in &self.result_snapshot[range] {
            self.live_cache.insert(
                entry.address,
                read_live_bytes(Some(&process), entry.address, self.value_type),
            );
        }
    }
}

impl Default for ScannerPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// A labelled Yes/No/Any combo for one [`FilterState`]. egui has no tri-state
/// checkbox, and a three-item combo is unambiguous where a cycling checkbox
/// would not be.
fn tri_state_combo(ui: &mut egui::Ui, id: &str, label: &str, state: &mut FilterState) {
    ui.label(label);
    egui::ComboBox::from_id_salt(id)
        .selected_text(filter_state_label(*state))
        .width(60.0)
        .show_ui(ui, |ui| {
            for s in [FilterState::Yes, FilterState::No, FilterState::Any] {
                ui.selectable_value(state, s, filter_state_label(s));
            }
        });
}

fn filter_state_label(state: FilterState) -> &'static str {
    match state {
        FilterState::Yes => "Yes",
        FilterState::No => "No",
        FilterState::Any => "Any",
    }
}

/// Parses an optional hex address field: `Ok(None)` for an empty field,
/// `Ok(Some(addr))` for a valid one, `Err(())` for garbage — so "unset" and
/// "invalid" stay distinguishable and a blank field is never an error.
#[cfg(target_os = "linux")]
fn parse_opt_hex(text: &str) -> Result<Option<usize>, ()> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    super::parse_hex_addr(text).map(Some).ok_or(())
}

/// Bridges the scan engine's observer to the job handle: publishes progress and
/// aborts as soon as the UI's Stop button sets the cancel flag.
#[cfg(target_os = "linux")]
pub(super) fn observer_for(job: &JobHandle) -> impl nemclass_scan::ScanObserver + '_ {
    move |p: nemclass_scan::ScanProgress| {
        job.set_progress(p.done as u64, p.total as u64);
        !job.is_cancelled()
    }
}

/// Collapse a scan's [`ScanResults`] into the display snapshot the panel renders.
/// Owned output, so it outlives the borrow of the `Scanner` and can travel back
/// from the worker.
#[cfg(target_os = "linux")]
fn snapshot_results(results: &nemclass_scan::ScanResults) -> Vec<ResultRow> {
    results
        .iter()
        .map(|r| ResultRow {
            address: r.address,
            current: r.current.to_vec(),
            previous: r.previous.to_vec(),
        })
        .collect()
}

/// Reads the raw bytes of a fixed-width value live from the target. Returns
/// `None` for variable-width types (Bytes/strings), on a short read, or when
/// no process is attached.
pub(super) fn read_live_bytes(process: Option<&Process>, addr: usize, vt: ScanValueType) -> Option<Vec<u8>> {
    let width = vt.fixed_width()?;
    let process = process?;
    let mut buf = vec![0u8; width];
    let n = process.read_buf(addr, &mut buf).ok()?;
    (n >= width).then_some(buf)
}

/// [`format_value_bytes`], optionally in hexadecimal.
///
/// Cheat Engine's "hexadecimal" checkbox. Integers are shown as their raw
/// little-endian bytes widened to the type; floats and the variable-width types
/// have no useful hex form and are left as they are.
pub(super) fn format_value_bytes_radix(
    bytes: &[u8],
    vt: ScanValueType,
    hex: bool,
) -> String {
    if !hex {
        return format_value_bytes(bytes, vt);
    }
    let Some(width) = vt.fixed_width() else {
        return format_value_bytes(bytes, vt);
    };
    if matches!(vt, ScanValueType::F32 | ScanValueType::F64) || bytes.len() < width {
        return format_value_bytes(bytes, vt);
    }
    let mut raw = 0u64;
    for (i, &b) in bytes[..width].iter().enumerate() {
        raw |= (b as u64) << (i * 8);
    }
    format!("0x{raw:0width$X}", width = width * 2)
}

pub(super) fn format_value_bytes(bytes: &[u8], vt: ScanValueType) -> String {
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

pub(super) fn value_type_label(vt: ScanValueType) -> &'static str {
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
        ScanValueType::StringUtf32 => "String (UTF-32)",
    }
}

pub(super) fn compare_label(ct: ScanCompareType) -> &'static str {
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
        ScanCompareType::IncreasedByPercent => "Increased By % ",
        ScanCompareType::DecreasedByPercent => "Decreased By %",
        ScanCompareType::UnchangedFromFirst => "Same As First Scan",
        ScanCompareType::ChangedFromFirst   => "Different From First Scan",
    }
}

pub(super) const ALL_VALUE_TYPES: &[ScanValueType] = &[
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
    ScanValueType::StringUtf32,
];

/// Compares offered before any scan: the absolute kinds plus the "unknown
/// initial value" baseline. The change-relative kinds are absent because there
/// is nothing to compare against yet.
const FIRST_SCAN_COMPARES: &[ScanCompareType] = &[
    ScanCompareType::Exact,
    ScanCompareType::NotEqual,
    ScanCompareType::GreaterThan,
    ScanCompareType::LessThan,
    ScanCompareType::Between,
    ScanCompareType::Unknown,
];

/// Compares offered once a session is under way: the absolute kinds stay
/// available (re-narrowing by value is normal), the change-relative kinds
/// appear, and `Unknown` disappears — it accepts everything, so on a next scan
/// it is either a no-op or a wipe. Cheat Engine hides it the same way.
pub(super) const NEXT_SCAN_COMPARES: &[ScanCompareType] = &[
    ScanCompareType::Exact,
    ScanCompareType::NotEqual,
    ScanCompareType::GreaterThan,
    ScanCompareType::LessThan,
    ScanCompareType::Between,
    ScanCompareType::Increased,
    ScanCompareType::IncreasedBy,
    ScanCompareType::Decreased,
    ScanCompareType::DecreasedBy,
    ScanCompareType::Changed,
    ScanCompareType::Unchanged,
    ScanCompareType::IncreasedByPercent,
    ScanCompareType::DecreasedByPercent,
    ScanCompareType::UnchangedFromFirst,
    ScanCompareType::ChangedFromFirst,
];

/// The compares the combo offers, given whether a scan session is active.
///
/// Split out of the draw code so the invariant that matters — the selected
/// compare is always present in the list being drawn — is unit-testable without
/// an `egui::Ui`.
fn available_compares(has_scan: bool) -> &'static [ScanCompareType] {
    if has_scan {
        NEXT_SCAN_COMPARES
    } else {
        FIRST_SCAN_COMPARES
    }
}

/// Keeps `compare` inside [`available_compares`] when a session starts or ends.
///
/// Without this the combo can display a value absent from its own list: after a
/// first scan `Unknown` has no next-scan meaning (Cheat Engine's own post-unknown
/// default is `Changed`), and after `New Scan` a change-relative kind has nothing
/// to compare against.
fn snap_compare(compare: ScanCompareType, has_scan: bool) -> ScanCompareType {
    if available_compares(has_scan).contains(&compare) {
        return compare;
    }
    if has_scan {
        ScanCompareType::Changed
    } else {
        ScanCompareType::Exact
    }
}


#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn module(name: &str, base: usize, size: usize) -> ModuleInfoWithName {
        ModuleInfoWithName { base, size, name: name.to_string() }
    }

    /// Two loaded modules to resolve a selection against.
    fn modules() -> Vec<ModuleInfoWithName> {
        vec![module("game.exe", 0x1000, 0x1000), module("libc.so.6", 0x8000, 0x2000)]
    }

    /// A panel with the scope section switched on, as a user would.
    fn scoped_panel() -> ScannerPanel {
        let mut p = ScannerPanel::new();
        p.scan_range_enabled = true;
        p
    }

    #[test]
    fn disabled_scope_yields_unrestricted_defaults() {
        let mut p = ScannerPanel::new();
        let (region, section) = p.build_filters(&modules()).expect("no error");
        assert!(region.is_unrestricted());
        assert_eq!(section, SectionFilter::default());
        assert!(p.status_msg.is_none());
    }

    #[test]
    fn blank_range_fields_mean_unbounded_not_invalid() {
        let mut p = scoped_panel();
        let (region, _) = p.build_filters(&modules()).expect("blank fields are not an error");
        assert_eq!(region.start, 0);
        assert_eq!(region.stop, usize::MAX);
        assert!(region.include.is_empty());
    }

    #[test]
    fn manual_range_is_parsed_with_optional_prefix_and_separators() {
        let mut p = scoped_panel();
        p.range_start_text = "0x1_000".into();
        p.range_end_text = "2000".into();
        let (region, _) = p.build_filters(&modules()).expect("valid hex");
        assert_eq!((region.start, region.stop), (0x1000, 0x2000));
    }

    #[test]
    fn manual_range_overrides_module_selection() {
        let mut p = scoped_panel();
        p.selected_modules.insert("game.exe".into());
        p.range_start_text = "0x1000".into();
        let (region, _) = p.build_filters(&modules()).expect("valid");
        assert_eq!(region.start, 0x1000);
        assert!(
            region.include.is_empty(),
            "an explicit window supersedes the module picker",
        );
    }

    #[test]
    fn selected_modules_become_include_spans() {
        let mut p = scoped_panel();
        p.selected_modules.insert("game.exe".into());
        p.selected_modules.insert("libc.so.6".into());
        let (region, _) = p.build_filters(&modules()).expect("valid");
        assert_eq!(
            region.include,
            vec![Region::new(0x1000, 0x1000), Region::new(0x8000, 0x2000)],
        );
    }

    #[test]
    fn a_module_no_longer_loaded_is_skipped() {
        let mut p = scoped_panel();
        p.selected_modules.insert("game.exe".into());
        p.selected_modules.insert("unloaded.so".into());
        let (region, _) = p.build_filters(&modules()).expect("one still resolves");
        assert_eq!(region.include, vec![Region::new(0x1000, 0x1000)]);
        assert!(p.status_msg.is_none());
    }

    #[test]
    fn selection_that_resolves_to_nothing_is_an_error() {
        let mut p = scoped_panel();
        p.selected_modules.insert("unloaded.so".into());
        assert!(p.build_filters(&modules()).is_none());
        assert!(p.status_msg.as_deref().unwrap().contains("None of the selected modules"));
    }

    #[test]
    fn bad_hex_in_either_field_is_reported() {
        let mut p = scoped_panel();
        p.range_start_text = "not-hex".into();
        assert!(p.build_filters(&modules()).is_none());
        assert!(p.status_msg.as_deref().unwrap().contains("start address"));

        let mut p = scoped_panel();
        p.range_end_text = "zzz".into();
        assert!(p.build_filters(&modules()).is_none());
        assert!(p.status_msg.as_deref().unwrap().contains("end address"));
    }

    #[test]
    fn inverted_or_empty_window_is_rejected_before_scanning() {
        let mut p = scoped_panel();
        p.range_start_text = "0x2000".into();
        p.range_end_text = "0x1000".into();
        assert!(p.build_filters(&modules()).is_none());
        assert!(p.status_msg.as_deref().unwrap().contains("must be greater than"));

        // Equal bounds are an empty half-open range, not "everything".
        let mut p = scoped_panel();
        p.range_start_text = "0x1000".into();
        p.range_end_text = "0x1000".into();
        assert!(p.build_filters(&modules()).is_none());
    }

    #[test]
    fn every_memory_type_unticked_is_rejected() {
        let mut p = scoped_panel();
        p.scan_private = false;
        p.scan_image = false;
        p.scan_mapped = false;
        assert!(p.build_filters(&modules()).is_none());
        assert!(p.status_msg.as_deref().unwrap().contains("at least one memory type"));
    }

    #[test]
    fn protection_tri_states_reach_the_section_filter() {
        let mut p = scoped_panel();
        p.writable = FilterState::Any;
        p.executable = FilterState::Yes;
        p.copy_on_write = FilterState::Any;
        p.scan_mapped = true;
        let (_, section) = p.build_filters(&modules()).expect("valid");
        assert_eq!(section.writable, FilterState::Any);
        assert_eq!(section.executable, FilterState::Yes);
        assert_eq!(section.copy_on_write, FilterState::Any);
        assert!(section.scan_mapped);
    }

    #[test]
    fn range_summary_describes_the_active_scope() {
        let mods = modules();

        // Off: the pre-existing behaviour, stated plainly.
        let p = ScannerPanel::new();
        assert_eq!(p.range_summary(&mods), "Scan range: all writable memory");

        // A window wins over a selection, matching build_filters' precedence.
        let mut p = scoped_panel();
        p.range_start_text = "0x1000".into();
        p.selected_modules.insert("game.exe".into());
        assert_eq!(p.range_summary(&mods), "Scan range: 0x1000–…");

        // Modules are counted only when they actually resolve, so a stale name
        // from a previous target can't inflate the number.
        let mut p = scoped_panel();
        p.selected_modules.insert("game.exe".into());
        p.selected_modules.insert("unloaded.so".into());
        assert_eq!(p.range_summary(&mods), "Scan range: 1 module");
    }

    #[test]
    fn on_detach_clears_the_module_selection_but_keeps_preferences() {
        let mut p = scoped_panel();
        p.selected_modules.insert("game.exe".into());
        p.range_start_text = "0x1000".into();
        p.scan_mapped = true;

        p.on_detach();

        // Names belong to the process we left.
        assert!(p.selected_modules.is_empty());
        // The window and filter toggles are user preferences.
        assert_eq!(p.range_start_text, "0x1000");
        assert!(p.scan_mapped);
        assert!(p.scan_range_enabled);
    }

    #[test]
    fn parse_opt_hex_separates_unset_from_invalid() {
        assert_eq!(parse_opt_hex(""), Ok(None));
        assert_eq!(parse_opt_hex("   "), Ok(None));
        assert_eq!(parse_opt_hex("0x20"), Ok(Some(0x20)));
        assert_eq!(parse_opt_hex("20"), Ok(Some(0x20)));
        assert_eq!(parse_opt_hex("nope"), Err(()));
    }
}

#[cfg(test)]
mod compare_tests {
    use super::*;

    #[test]
    fn unknown_is_first_scan_only() {
        assert!(available_compares(false).contains(&ScanCompareType::Unknown));
        assert!(
            !available_compares(true).contains(&ScanCompareType::Unknown),
            "Unknown on a next scan accepts everything — it must not be offered"
        );
    }

    #[test]
    fn change_relative_compares_need_a_session() {
        for ct in [
            ScanCompareType::Increased,
            ScanCompareType::Decreased,
            ScanCompareType::Changed,
            ScanCompareType::Unchanged,
            ScanCompareType::IncreasedBy,
            ScanCompareType::DecreasedBy,
        ] {
            assert!(!available_compares(false).contains(&ct), "{ct:?}");
            assert!(available_compares(true).contains(&ct), "{ct:?}");
        }
    }

    #[test]
    fn every_offered_compare_is_selectable_in_its_own_list() {
        // The invariant the combo depends on: whatever `snap_compare` returns is
        // present in the list drawn for that session state.
        for &has_scan in &[false, true] {
            for &ct in ALL_COMPARE_TYPES_FOR_TEST {
                let snapped = snap_compare(ct, has_scan);
                assert!(
                    available_compares(has_scan).contains(&snapped),
                    "{ct:?} snapped to {snapped:?}, absent from the has_scan={has_scan} list"
                );
            }
        }
    }

    #[test]
    fn snapping_leaves_a_valid_compare_alone() {
        assert_eq!(
            snap_compare(ScanCompareType::Exact, true),
            ScanCompareType::Exact
        );
        assert_eq!(
            snap_compare(ScanCompareType::Between, false),
            ScanCompareType::Between
        );
    }

    #[test]
    fn unknown_snaps_to_changed_after_a_first_scan() {
        assert_eq!(
            snap_compare(ScanCompareType::Unknown, true),
            ScanCompareType::Changed
        );
    }

    #[test]
    fn change_relative_snaps_back_to_exact_on_new_scan() {
        assert_eq!(
            snap_compare(ScanCompareType::Increased, false),
            ScanCompareType::Exact
        );
    }

    const ALL_COMPARE_TYPES_FOR_TEST: &[ScanCompareType] = &[
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
}

/// Live-value column behaviour, driven through a mock memory backend so it runs
/// without a live target.
#[cfg(test)]
mod live_value_tests {
    use super::*;
    use nemclass_core::MockMemoryBackend;
    use std::sync::Arc;

    const BASE: usize = 0x1000;

    /// A process serving 256 bytes at [`BASE`], with an `i32` at `BASE + 0`.
    fn mock_process(value: i32) -> Arc<Process> {
        let mut bytes = vec![0u8; 256];
        bytes[0..4].copy_from_slice(&value.to_le_bytes());
        Arc::new(Process::from_backend_for_test(
            1,
            Box::new(MockMemoryBackend::new(BASE, bytes)),
        ))
    }

    fn row(address: usize, current: i32) -> ResultRow {
        ResultRow {
            address,
            current: current.to_le_bytes().to_vec(),
            previous: current.to_le_bytes().to_vec(),
        }
    }

    #[test]
    fn a_failed_read_is_recorded_as_unknown_not_as_stale_bytes() {
        let mut panel = ScannerPanel::new();
        panel.process = Some(mock_process(1337));
        // One readable address, one well outside the mapped range.
        panel.result_snapshot = vec![row(BASE, 1337), row(0xDEAD_0000, 1337)];

        panel.refresh_live_values();

        assert_eq!(
            panel.live_cache.get(&BASE),
            Some(&Some(1337i32.to_le_bytes().to_vec()))
        );
        assert_eq!(
            panel.live_cache.get(&0xDEAD_0000),
            Some(&None),
            "an unreadable address must be recorded as a failure, so the table can \
             show ?? instead of the stale scan-time value"
        );
    }

    #[test]
    fn refresh_only_reads_the_rows_the_table_drew() {
        let mut panel = ScannerPanel::new();
        panel.process = Some(mock_process(1));
        panel.result_snapshot = (0..5000).map(|i| row(BASE + i * 4, 1)).collect();
        panel.visible_rows = 10..40;

        panel.refresh_live_values();

        assert_eq!(panel.live_cache.len(), 30);
        assert!(panel.live_cache.contains_key(&(BASE + 10 * 4)));
        assert!(!panel.live_cache.contains_key(&BASE));
    }

    #[test]
    fn the_first_refresh_after_a_scan_seeds_a_screenful() {
        // No viewport reported yet, so the column would otherwise stay blank for
        // a frame.
        let mut panel = ScannerPanel::new();
        panel.process = Some(mock_process(1));
        panel.result_snapshot = (0..10).map(|i| row(BASE + i * 4, 1)).collect();
        panel.visible_rows = 0..0;

        panel.refresh_live_values();
        assert_eq!(panel.live_cache.len(), 10);
    }

    #[test]
    fn the_refresh_is_throttled() {
        let mut panel = ScannerPanel::new();
        panel.process = Some(mock_process(1));
        panel.result_snapshot = vec![row(BASE, 1)];

        panel.refresh_live_values();
        let first = panel.last_live_refresh;
        panel.refresh_live_values();
        assert_eq!(
            panel.last_live_refresh, first,
            "a second call inside the interval must not re-read"
        );
    }

    #[test]
    fn the_cache_is_dropped_when_the_results_change() {
        let mut panel = ScannerPanel::new();
        panel.process = Some(mock_process(1));
        panel.result_snapshot = vec![row(BASE, 1)];
        panel.refresh_live_values();
        assert!(!panel.live_cache.is_empty());

        panel.new_scan();
        assert!(panel.live_cache.is_empty());
        assert!(panel.last_live_refresh.is_none());
    }

    #[test]
    fn detaching_drops_the_shared_handle_and_the_cache() {
        let mut panel = ScannerPanel::new();
        panel.process = Some(mock_process(1));
        panel.result_snapshot = vec![row(BASE, 1)];
        panel.refresh_live_values();

        panel.on_detach();
        assert!(panel.process.is_none());
        assert!(panel.live_cache.is_empty());
    }

    #[test]
    fn with_no_process_every_row_stays_pending() {
        let mut panel = ScannerPanel::new();
        panel.result_snapshot = vec![row(BASE, 1)];
        panel.refresh_live_values();
        assert!(
            panel.live_cache.is_empty(),
            "no attached process is Pending, not a failed read"
        );
    }
}
