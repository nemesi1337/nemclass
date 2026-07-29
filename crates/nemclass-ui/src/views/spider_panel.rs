//! Structure-spider panel — search *inside* a known object for a value.
//!
//! The scanner sweeps all of memory for a value and knows nothing about
//! structure; the pointer scanner works backwards from an address to a module
//! anchor. This panel is the combination of the two, and answers the question
//! you actually have while reversing a struct: *"I have a pointer to the player
//! object — where inside it, through however many nested pointers, does health
//! live?"*
//!
//! Each hit is an offset path such as `[[0x7f2a10 + 0x18] + 0x40] + 0x14`, which
//! is a valid nemclass address formula, so it can become a live address-list
//! entry or a `ClassNode.address_formula` directly.
//!
//! ## Layout
//! ```text
//! ┌─ Spider ─────────────────────────────────────────────────────────────────┐
//! │ Base:[0x7f2a10] Value:[100] Type:[Int32▾] Size:[0x1000] Align:[4] Depth:[3]│
//! │ [Search] ████████░░ 62% [Stop]   [New search]                             │
//! │ 42 path(s)  (8,213 structs visited)                                       │
//! │ ┌ Path ─────────────────────────┬ Value ┬ Previous ┬ Actions ──────────┐ │
//! │ │ [0x7f2a10 + 0x10] + 0x8       │  100  │   100    │ [+][Class][Goto]  │ │
//! │ │ [[0x7f2a10 + 0x18] + 0x40]+0x4│  100  │    97    │ [+][Class][Goto]  │ │
//! │ └───────────────────────────────┴───────┴──────────┴───────────────────┘ │
//! │ Refine: [Changed ▾] [____] [Refine]                                       │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Why the live column is throttled and viewport-bounded
//! Resolving one row costs *depth* sequential reads — a spider row is a pointer
//! chain, not a fixed address. Re-resolving every row every frame is therefore
//! far more expensive than in the scanner, so this reuses the scanner's
//! throttled, only-what-was-drawn refresh rather than reading the whole set.

use std::collections::HashMap;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_core::{ModuleInfoWithName, Process};
use nemclass_scan::{
    PathKind, PtrMapEntry, PtrMapFile, ResolvedPath, ScanCompareType, ScanValueType, SpiderHit,
};

#[cfg(target_os = "linux")]
use nemclass_scan::{spider_refine_with, spider_scan_with, SpiderConfig};

use super::ptrmap_io::{self, RebaseDialog};

use super::scanner_panel::{
    compare_label, format_value_bytes, value_type_label, ALL_VALUE_TYPES, CHANGED_COLOR,
    LIVE_SEED_ROWS, NEXT_SCAN_COMPARES, UNREADABLE_COLOR,
};

#[cfg(target_os = "linux")]
use super::scanner_panel::observer_for;
#[cfg(target_os = "linux")]
use super::tasks::{BackgroundJob, Poll as JobPoll};

/// Cap on rendered rows; a wide search can return six figures of hits.
const MAX_DISPLAY: usize = 1_000;

/// Fallback live-refresh cadence, until the app supplies `live_interval_ms`.
const DEFAULT_LIVE_INTERVAL: Duration = Duration::from_millis(100);

/// Compares offered for the initial search.
///
/// Deliberately not the scanner's first-scan list: `Unknown` is absent because
/// it accepts every slot, and a spider that accepts every slot returns the whole
/// reachable object graph rather than an answer. The change-relative kinds are
/// absent for the usual reason — there is no previous pass to compare against.
const SEARCH_COMPARES: &[ScanCompareType] = &[
    ScanCompareType::Exact,
    ScanCompareType::NotEqual,
    ScanCompareType::GreaterThan,
    ScanCompareType::LessThan,
    ScanCompareType::Between,
];

/// What the panel asks the parent app to do after a click. Every route needs
/// `&mut NemclassApp`, so they are returned and applied once the dock draw has
/// released its borrows (see `NemclassApp::apply_spider_action`).
pub enum SpiderAction {
    /// Nothing this frame.
    None,
    /// Add the path to the address list as a live, self-resolving entry.
    AddToTable {
        /// The address formula — stored verbatim so the chain re-resolves.
        formula: String,
        /// The scan value type's stable tag.
        tag: &'static str,
    },
    /// Create a class whose `address_formula` is this path.
    CreateClass {
        /// Suggested class name (empty to let the app pick one).
        name: String,
        /// The path as an address formula.
        formula: String,
    },
    /// Navigate the hex viewer to an already-resolved address.
    Goto(usize),
    /// Pin this path's value, via the address list's freeze set.
    Freeze {
        /// The address formula to freeze.
        formula: String,
        /// The scan value type's stable tag.
        tag: &'static str,
        /// The value to hold, formatted for the model.
        value: String,
    },
}

/// What a completed search hands back: the prepared rows, whether a cap was hit,
/// and how many structs were examined. `Err` carries a message for the status
/// line — there is no session state to restore, unlike the value scanner.
#[cfg(target_os = "linux")]
type SearchOutcome = Result<(Vec<HitRow>, bool, usize), String>;

/// What a completed refine hands back: the surviving rows and the count before
/// the pass, so the status line can say "kept 12/40".
#[cfg(target_os = "linux")]
type RefineOutcome = Result<(Vec<HitRow>, usize), String>;

/// One hit prepared for display. The formula is derived from the path and the
/// module list, so it is rebuilt whenever the hit set changes rather than stored
/// alongside and risking drift.
struct HitRow {
    hit: SpiderHit,
    formula: String,
    /// The module the root sits in, as `(name, base)`.
    ///
    /// Kept rather than recomputed when exporting: a path imported while its
    /// module was not loaded would otherwise be saved as a bare address, which
    /// will not survive the next restart.
    module: Option<(String, usize)>,
}

/// What a completed seed pass hands back: the rows that still resolve, with
/// their values read, and the count before the pass.
#[cfg(target_os = "linux")]
type SeedOutcome = (Vec<HitRow>, usize);

/// All state owned by the spider panel.
pub struct SpiderPanel {
    /// Search root address (hex).
    root_text: String,
    /// The value to search for.
    needle_text: String,
    /// Upper bound, for `Between`.
    upper_text: String,
    /// Struct window size (hex).
    size_text: String,
    /// Slot alignment.
    align_text: String,
    /// Maximum dereference hops.
    depth_text: String,
    /// Type of the value being searched for.
    value_type: ScanValueType,
    /// Comparison for the initial search.
    compare: ScanCompareType,
    /// Comparison for the refine pass.
    refine_compare: ScanCompareType,
    /// Value for the refine pass (unused by `Changed`/`Unchanged`).
    refine_text: String,
    /// Prepared result rows.
    rows: Vec<HitRow>,
    /// True if the last search hit a result or node cap.
    truncated: bool,
    /// Distinct structs examined by the last search.
    nodes_visited: usize,
    /// Module list captured when the search started, for module-anchored
    /// formulas. Owned so the worker can build formulas off the UI thread.
    modules_snapshot: Vec<ModuleInfoWithName>,
    /// The attached process, shared with the scan workers.
    process: Option<Arc<Process>>,
    /// In-flight search. Payload: rows, truncation flag, structs visited.
    #[cfg(target_os = "linux")]
    scan_job: BackgroundJob<SearchOutcome>,
    /// In-flight refine. Payload: surviving rows and the pre-refine count.
    #[cfg(target_os = "linux")]
    refine_job: BackgroundJob<RefineOutcome>,
    /// In-flight seed pass after an import, reading each path's current value.
    #[cfg(target_os = "linux")]
    seed_job: BackgroundJob<SeedOutcome>,
    /// True while the rows carry no value readings — the state an import leaves
    /// them in until the seed pass fills them.
    ///
    /// A refine compares against `hit.current`, and `compare_change` returns
    /// `false` whenever the previous reading is shorter than the value width.
    /// Refining unseeded rows would therefore discard every one of them and
    /// report it as "nothing survived", so the button stays disabled instead.
    unseeded: bool,
    /// Import prompt for a `.ptrmap`, shown after a file is picked.
    rebase_dialog: RebaseDialog,
    /// Live readings for the rows the viewport drew, keyed by row index (a
    /// spider row has no fixed address — the chain has to be walked).
    live_cache: HashMap<usize, Option<(usize, Vec<u8>)>>,
    /// When the live cache was last refilled.
    last_live_refresh: Option<Instant>,
    /// Rows the table actually drew last frame.
    visible_rows: Range<usize>,
    /// How often to re-resolve the visible rows.
    live_interval: Duration,
    /// Status / error line.
    pub status_msg: Option<String>,
}

impl Default for SpiderPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl SpiderPanel {
    pub fn new() -> Self {
        Self {
            root_text: String::new(),
            needle_text: String::new(),
            upper_text: String::new(),
            size_text: "0x1000".to_string(),
            align_text: "4".to_string(),
            depth_text: "3".to_string(),
            value_type: ScanValueType::I32,
            compare: ScanCompareType::Exact,
            refine_compare: ScanCompareType::Changed,
            refine_text: String::new(),
            rows: Vec::new(),
            truncated: false,
            nodes_visited: 0,
            modules_snapshot: Vec::new(),
            process: None,
            #[cfg(target_os = "linux")]
            scan_job: BackgroundJob::default(),
            #[cfg(target_os = "linux")]
            refine_job: BackgroundJob::default(),
            #[cfg(target_os = "linux")]
            seed_job: BackgroundJob::default(),
            unseeded: false,
            rebase_dialog: RebaseDialog::default(),
            live_cache: HashMap::new(),
            last_live_refresh: None,
            visible_rows: 0..0,
            live_interval: DEFAULT_LIVE_INTERVAL,
            status_msg: None,
        }
    }

    /// Match the app's configured live-refresh cadence.
    pub fn set_live_interval(&mut self, interval: Duration) {
        self.live_interval = interval;
    }

    /// Seed the base address, e.g. from a scanner hit or the selected class.
    pub fn set_root(&mut self, addr: usize) {
        self.root_text = format!("0x{addr:X}");
    }

    // -----------------------------------------------------------------------
    // Saving and loading the hit set
    //
    // A wide search returns six figures of hits and the table draws a thousand.
    // These carry the rest of them out of the tool and back in.
    // -----------------------------------------------------------------------

    /// Package the current rows as a `.ptrmap`.
    ///
    /// The value readings are deliberately not saved: a byte read from the last
    /// session says nothing about this one, and writing it would let a refine
    /// compare against a fabricated baseline. [`Self::seed`] re-reads them.
    ///
    /// `goal` carries the **search root**. That is load-bearing, not a label:
    /// [`Self::compare`] uses it to line a saved run's heap roots up with the
    /// object being searched now.
    fn to_file(&self) -> PtrMapFile {
        let mut file = PtrMapFile {
            goal: super::parse_hex_addr(&self.root_text).unwrap_or(0),
            modules: Vec::new(),
            entries: Vec::with_capacity(self.rows.len()),
            truncated: self.truncated,
        };
        for row in &self.rows {
            let owner = row.module.as_ref().map(|(n, b)| (n.as_str(), *b));
            let anchor = ptrmap_io::anchor_for(&mut file, row.hit.path.root, owner);
            file.entries
                .push(PtrMapEntry::from_spider_path(&row.hit.path, anchor));
        }
        file
    }

    /// Rebuild display rows from paths resolved against the current process.
    ///
    /// The reconstructed hits carry empty value buffers, which is what
    /// [`Self::unseeded`] exists to guard.
    fn rows_from(paths: &[ResolvedPath]) -> Vec<HitRow> {
        paths
            .iter()
            .filter_map(|p| {
                let path = p.to_spider_path().ok()?;
                Some(HitRow {
                    formula: p.to_formula(),
                    hit: SpiderHit { path, current: Vec::new(), previous: Vec::new() },
                    module: p.module.as_ref().map(|m| (m.name.clone(), m.base)),
                })
            })
            .collect()
    }

    /// Pick a `.ptrmap` and stage it in the rebase prompt.
    fn import(&mut self, modules: &[ModuleInfoWithName], start_dir: &Path) {
        match ptrmap_io::pick(start_dir) {
            Ok(Some((file, name))) => {
                if let Err(e) = self.rebase_dialog.open(file, name, PathKind::Spider, modules) {
                    self.status_msg = Some(e);
                }
            }
            Ok(None) => {}
            Err(e) => self.status_msg = Some(e),
        }
    }

    /// Narrow the current hits to the paths a saved run also found.
    ///
    /// A spider root is a heap address, and the object sits somewhere else every
    /// run — so comparing raw roots would match nothing at all and report it as
    /// "no paths in common". The saved file records the root it was searched
    /// from, so the two runs are lined up on that before intersecting, and what
    /// is really being compared is the offset chain *within* the object. Module-
    /// anchored paths need no such help; they already compare by name and offset.
    fn compare(&mut self, start_dir: &Path) {
        let picked = match ptrmap_io::pick(start_dir) {
            Ok(Some(picked)) => picked,
            Ok(None) => return,
            Err(e) => {
                self.status_msg = Some(e);
                return;
            }
        };
        let (loaded, name) = picked;
        if let Some(&got) = loaded.kinds().iter().find(|&&k| k != PathKind::Spider) {
            self.status_msg =
                Some(format!("{name} holds {} paths, not spider ones.", got.label()));
            return;
        }

        let before = self.rows.len();
        let current = self.to_file();
        let aligned = align_roots(&loaded, current.goal);
        // Retained in place by index, so the surviving rows keep the value
        // readings that rebuilding them from the file would throw away — and
        // that a refine needs as its baseline.
        let kept: std::collections::HashSet<usize> =
            current.intersect_indices(&aligned).into_iter().collect();
        let mut i = 0;
        self.rows.retain(|_| {
            let keep = kept.contains(&i);
            i += 1;
            keep
        });
        self.live_cache.clear();
        self.truncated |= loaded.truncated;
        self.status_msg = Some(format!(
            "Compare: {} of {before} path(s) also in {name} ({} there).",
            self.rows.len(),
            loaded.entries.len()
        ));
    }

    /// Drop everything tied to the old target when the user detaches.
    pub fn on_detach(&mut self) {
        self.clear_results();
        self.process = None;
        self.modules_snapshot.clear();
        #[cfg(target_os = "linux")]
        {
            // Discard in-flight work so stale results never land on a new target.
            self.scan_job = BackgroundJob::default();
            self.refine_job = BackgroundJob::default();
            self.seed_job = BackgroundJob::default();
        }
        self.status_msg = None;
    }

    fn clear_results(&mut self) {
        self.rows.clear();
        self.truncated = false;
        self.nodes_visited = 0;
        self.unseeded = false;
        self.live_cache.clear();
        self.last_live_refresh = None;
        self.visible_rows = 0..0;
    }

    /// Drain completed search / refine jobs. Call each frame from `logic()`.
    #[cfg(target_os = "linux")]
    pub fn poll(&mut self) {
        if let JobPoll::Done(outcome) = self.scan_job.poll() {
            match outcome {
                Ok((rows, truncated, nodes)) => {
                    self.rows = rows;
                    self.truncated = truncated;
                    self.nodes_visited = nodes;
                    self.live_cache.clear();
                    self.last_live_refresh = None;
                    self.status_msg = if self.rows.is_empty() {
                        Some(format!(
                            "No hits in {nodes} struct(s). Try a larger size or depth, \
                             or check the base address."
                        ))
                    } else {
                        None
                    };
                }
                Err(e) => self.status_msg = Some(e),
            }
        }
        if let JobPoll::Done(outcome) = self.refine_job.poll() {
            match outcome {
                Ok((rows, before)) => {
                    let kept = rows.len();
                    self.rows = rows;
                    self.live_cache.clear();
                    self.last_live_refresh = None;
                    self.status_msg = Some(format!("Refine: {kept}/{before} path(s) kept."));
                }
                Err(e) => self.status_msg = Some(e),
            }
        }
        if let JobPoll::Done((rows, before)) = self.seed_job.poll() {
            let kept = rows.len();
            self.rows = rows;
            self.unseeded = false;
            self.live_cache.clear();
            self.last_live_refresh = None;
            self.status_msg = Some(format!(
                "Imported {before} path(s); {kept} still resolve in this process.",
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn poll(&mut self) {}

    /// Draw the panel. `modules` are the attached process's module images, used
    /// to anchor a formula in a module so it survives ASLR.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<&Arc<Process>>,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
        start_dir: &Path,
    ) -> SpiderAction {
        self.process = process.cloned();
        let attached = process.is_some();
        if !attached {
            ui.colored_label(egui::Color32::YELLOW, "Attach to a process to run a spider.");
            ui.add_space(4.0);
        }

        self.show_config(ui, attached, modules, rt);
        self.show_file_row(ui, modules, start_dir);
        ui.separator();
        self.show_summary(ui);

        // The import prompt, once a file has been picked.
        if let Some(outcome) = self.rebase_dialog.show(ui.ctx()) {
            self.clear_results();
            self.rows = Self::rows_from(&outcome.paths);
            self.truncated = outcome.truncated;
            self.unseeded = true;
            #[cfg(target_os = "linux")]
            self.seed(rt, ui.ctx().clone());
            #[cfg(not(target_os = "linux"))]
            {
                self.status_msg = Some(format!("Imported {} path(s).", self.rows.len()));
            }
        }

        let action = self.show_results(ui);
        self.show_refine(ui, rt);

        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(220, 160, 40), msg);
        }

        action
    }

    /// The search parameters, plus Search/Stop/New search.
    fn show_config(
        &mut self,
        ui: &mut egui::Ui,
        attached: bool,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
    ) {
        let busy = self.is_busy();
        // Reconfiguring mid-session would silently invalidate the hit set the
        // refine pass is narrowing, so the knobs lock until "New search".
        let locked = busy || !self.rows.is_empty();

        ui.add_enabled_ui(attached && !locked, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label("Base:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.root_text)
                        .desired_width(140.0)
                        .hint_text("0x7fff…"),
                )
                .on_hover_text("The object's address — the search starts here");

                ui.label("Value:");
                ui.add(egui::TextEdit::singleline(&mut self.needle_text).desired_width(90.0));
                if self.compare == ScanCompareType::Between {
                    ui.label("to");
                    ui.add(egui::TextEdit::singleline(&mut self.upper_text).desired_width(90.0));
                }

                egui::ComboBox::from_id_salt("spider_compare")
                    .selected_text(compare_label(self.compare))
                    .width(130.0)
                    .show_ui(ui, |ui| {
                        for &c in SEARCH_COMPARES {
                            ui.selectable_value(&mut self.compare, c, compare_label(c));
                        }
                    });

                egui::ComboBox::from_id_salt("spider_value_type")
                    .selected_text(value_type_label(self.value_type))
                    .width(130.0)
                    .show_ui(ui, |ui| {
                        for &vt in ALL_VALUE_TYPES {
                            if ui
                                .selectable_value(&mut self.value_type, vt, value_type_label(vt))
                                .clicked()
                            {
                                // Match the type's own width, as yclass does: a
                                // 4-byte value on a 1-byte lattice quadruples the
                                // work to find the same fields.
                                if let Some(w) = vt.fixed_width() {
                                    self.align_text = w.to_string();
                                }
                            }
                        }
                    });
            });

            ui.horizontal_wrapped(|ui| {
                ui.label("Struct size:");
                ui.add(egui::TextEdit::singleline(&mut self.size_text).desired_width(70.0))
                    .on_hover_text("How many bytes of each object to examine");
                ui.label("Align:");
                ui.add(egui::TextEdit::singleline(&mut self.align_text).desired_width(36.0));
                ui.label("Depth:");
                ui.add(egui::TextEdit::singleline(&mut self.depth_text).desired_width(36.0))
                    .on_hover_text("Maximum number of pointer dereferences to follow");
            });
        });

        ui.horizontal(|ui| {
            #[cfg(target_os = "linux")]
            {
                if ui
                    .add_enabled(attached && !locked, egui::Button::new("Search"))
                    .clicked()
                {
                    self.run_search(modules, rt, ui.ctx().clone());
                }
                if busy {
                    match self.progress_fraction() {
                        Some(f) => {
                            ui.add(
                                egui::ProgressBar::new(f)
                                    .show_percentage()
                                    .desired_width(140.0),
                            );
                        }
                        None => {
                            ui.spinner();
                        }
                    }
                    if ui.button("Stop").clicked() {
                        self.cancel();
                        self.status_msg = Some("Stopping…".into());
                    }
                }
                if ui
                    .add_enabled(!busy && !self.rows.is_empty(), egui::Button::new("New search"))
                    .on_hover_text("Clear the results and unlock the search parameters")
                    .clicked()
                {
                    self.clear_results();
                    self.status_msg = None;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (modules, rt, locked);
                ui.add_enabled(false, egui::Button::new("Search"));
            }
        });
    }

    /// Export / import / compare. A wide search returns far more hits than the
    /// table draws, so these are the only way to reach the rest of them.
    fn show_file_row(
        &mut self,
        ui: &mut egui::Ui,
        modules: &[ModuleInfoWithName],
        start_dir: &Path,
    ) {
        ui.horizontal(|ui| {
            let has_rows = !self.rows.is_empty();
            let busy = self.is_busy();
            if ui
                .add_enabled(has_rows && !busy, egui::Button::new("Export…"))
                .on_hover_text("Save every path — not just the ones shown — to a .ptrmap")
                .clicked()
            {
                let file = self.to_file();
                self.status_msg = Some(ptrmap_io::export(&file, "spider", start_dir));
            }
            if ui
                .add_enabled(has_rows && !busy, egui::Button::new("Export text…"))
                .on_hover_text("Save every path as a plain list of formulas, one per line")
                .clicked()
            {
                let file = self.to_file();
                self.status_msg = Some(ptrmap_io::export_text(&file, "spider", start_dir));
            }
            // Disabled while a prompt is already up: a second pick would replace
            // the staged file and the open dialog would apply the wrong one.
            if ui
                .add_enabled(
                    !busy && !self.rebase_dialog.is_open(),
                    egui::Button::new("Import…"),
                )
                .on_hover_text(
                    "Load a saved .ptrmap. The root is usually a heap address, so the \
                     prompt lets you type where the object lives now.",
                )
                .clicked()
            {
                self.import(modules, start_dir);
            }
            if ui
                .add_enabled(has_rows && !busy, egui::Button::new("Compare…"))
                .on_hover_text(
                    "Keep only the paths a saved run also found — the offsets that are \
                     really part of the structure rather than of one heap layout.",
                )
                .clicked()
            {
                self.compare(start_dir);
            }
        });
    }

    fn show_summary(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(format!("{} path(s)", self.rows.len()));
            if self.nodes_visited > 0 {
                ui.weak(format!("({} structs visited)", self.nodes_visited));
            }
            if self.rows.len() > MAX_DISPLAY {
                ui.weak(format!("showing first {MAX_DISPLAY}"));
            }
            if self.truncated {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 40),
                    "capped — narrow the size or depth",
                );
            }
        });
    }

    /// The results table. Virtualized, and only the drawn rows get re-resolved.
    fn show_results(&mut self, ui: &mut egui::Ui) -> SpiderAction {
        if self.rows.is_empty() {
            ui.label("No results.");
            return SpiderAction::None;
        }

        self.refresh_live_values();

        let row_count = self.rows.len().min(MAX_DISPLAY);
        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = text_height + 4.0;

        let value_type = self.value_type;
        let tag = value_type.as_tag();
        // Disjoint borrows so the body can read rows and the live cache at once.
        let rows = &self.rows;
        let live_cache = &self.live_cache;
        let mut action = SpiderAction::None;
        let mut drawn: Option<(usize, usize)> = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::initial(280.0).at_least(160.0)) // Path
            .column(Column::initial(90.0).at_least(60.0)) // Value (live)
            .column(Column::initial(90.0).at_least(60.0)) // Previous
            .column(Column::auto().at_least(40.0)) // Depth
            .column(Column::remainder().at_least(150.0)) // Actions
            .header(row_height + 2.0, |mut h| {
                h.col(|ui| {
                    ui.strong("Path");
                });
                h.col(|ui| {
                    ui.strong("Value");
                });
                h.col(|ui| {
                    ui.strong("Previous");
                });
                h.col(|ui| {
                    ui.strong("Depth");
                });
                h.col(|ui| {
                    ui.strong("Actions");
                });
            })
            .body(|body| {
                body.rows(row_height, row_count, |mut row| {
                    let idx = row.index();
                    let Some(entry) = rows.get(idx) else { return };
                    drawn = Some(match drawn {
                        Some((lo, hi)) => (lo.min(idx), hi.max(idx)),
                        None => (idx, idx),
                    });

                    // Three states, kept distinct: resolved and read, resolution
                    // or read failed, and not walked yet. Falling back to the
                    // search-time bytes on failure would make a dangling chain
                    // look like a value that simply is not moving.
                    let live = live_cache.get(&idx);

                    row.col(|ui| {
                        let r = ui.add(
                            egui::Label::new(
                                egui::RichText::new(&entry.formula).monospace(),
                            )
                            .truncate()
                            .sense(egui::Sense::click()),
                        );
                        if r.double_clicked() {
                            action = SpiderAction::AddToTable {
                                formula: entry.formula.clone(),
                                tag,
                            };
                        }
                        r.on_hover_text(format!(
                            "{}\nDouble-click to add to the address list",
                            entry.formula
                        ))
                        .context_menu(|ui| {
                            if ui.button("Add to address list").clicked() {
                                action = SpiderAction::AddToTable {
                                    formula: entry.formula.clone(),
                                    tag,
                                };
                                ui.close();
                            }
                            if ui.button("Create class from path").clicked() {
                                action = SpiderAction::CreateClass {
                                    name: String::new(),
                                    formula: entry.formula.clone(),
                                };
                                ui.close();
                            }
                            if let Some(Some((addr, _))) = live
                                && ui.button("Goto in memory view").clicked()
                            {
                                action = SpiderAction::Goto(*addr);
                                ui.close();
                            }
                        });
                    });
                    row.col(|ui| match live {
                        Some(Some((_, bytes))) => {
                            let text = format_value_bytes(bytes, value_type);
                            if bytes == &entry.hit.current {
                                ui.monospace(text);
                            } else {
                                ui.monospace(egui::RichText::new(text).color(CHANGED_COLOR));
                            }
                        }
                        Some(None) => {
                            ui.monospace(egui::RichText::new("??").color(UNREADABLE_COLOR))
                                .on_hover_text(
                                    "This chain no longer resolves — an intermediate \
                                     pointer is null or unmapped.",
                                );
                        }
                        None => {
                            ui.weak("…");
                        }
                    });
                    row.col(|ui| {
                        ui.monospace(
                            egui::RichText::new(format_value_bytes(
                                &entry.hit.previous,
                                value_type,
                            ))
                            .weak(),
                        );
                    });
                    row.col(|ui| {
                        ui.monospace(entry.hit.path.depth().to_string());
                    });
                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            if ui
                                .small_button("+")
                                .on_hover_text("Add to the address list")
                                .clicked()
                            {
                                action = SpiderAction::AddToTable {
                                    formula: entry.formula.clone(),
                                    tag,
                                };
                            }
                            if ui.small_button("Class").clicked() {
                                action = SpiderAction::CreateClass {
                                    name: String::new(),
                                    formula: entry.formula.clone(),
                                };
                            }
                            let resolved = match live {
                                Some(Some((addr, bytes))) => Some((*addr, bytes.as_slice())),
                                _ => None,
                            };
                            if ui
                                .add_enabled(resolved.is_some(), egui::Button::new("Goto").small())
                                .clicked()
                                && let Some((addr, _)) = resolved
                            {
                                action = SpiderAction::Goto(addr);
                            }
                            if ui
                                .small_button("Freeze")
                                .on_hover_text("Pin this value via the address list")
                                .clicked()
                            {
                                // Pin what is there now, falling back to the
                                // search-time bytes when the chain is not resolved.
                                let bytes =
                                    resolved.map_or(entry.hit.current.as_slice(), |(_, b)| b);
                                action = SpiderAction::Freeze {
                                    formula: entry.formula.clone(),
                                    tag,
                                    value: format_value_bytes(bytes, value_type),
                                };
                            }
                        });
                    });
                });
            });

        self.visible_rows = drawn.map_or(0..0, |(lo, hi)| lo..hi + 1);
        action
    }

    /// The Cheat-Engine-style narrowing row: search `100`, take damage, refine
    /// `Changed`.
    fn show_refine(&mut self, ui: &mut egui::Ui, rt: &tokio::runtime::Handle) {
        if self.rows.is_empty() {
            return;
        }
        ui.separator();
        ui.horizontal(|ui| {
            ui.label("Refine:");
            egui::ComboBox::from_id_salt("spider_refine_compare")
                .selected_text(compare_label(self.refine_compare))
                .width(140.0)
                .show_ui(ui, |ui| {
                    for &c in NEXT_SCAN_COMPARES {
                        ui.selectable_value(&mut self.refine_compare, c, compare_label(c));
                    }
                });
            // Changed/Unchanged/Increased/Decreased compare against the previous
            // reading, so there is nothing for the user to type.
            if self.refine_compare.needs_needle() {
                ui.add(egui::TextEdit::singleline(&mut self.refine_text).desired_width(90.0));
            }
            #[cfg(target_os = "linux")]
            {
                let busy = self.is_busy();
                // Unseeded rows have no baseline reading, and a refine against
                // an empty one rejects every row — a total wipe reported as
                // "nothing survived". Blocked rather than run.
                let response = ui
                    .add_enabled(!busy && !self.unseeded, egui::Button::new("Refine"));
                if self.unseeded {
                    response.on_hover_text(
                        "Imported paths have no value reading to compare against yet. \
                         Attach to a process and re-import to read them.",
                    );
                } else if response
                    .on_hover_text("Re-walk every chain and keep only the matching values")
                    .clicked()
                {
                    self.run_refine(rt, ui.ctx().clone());
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = rt;
            }
        });
    }

    /// Read each imported path's current value, dropping the ones whose chain no
    /// longer resolves.
    ///
    /// An imported hit arrives with empty value buffers, and a refine compares
    /// against them — `compare_change` rejects any reading shorter than the
    /// value width, so refining unseeded rows would discard all of them. This
    /// gives every surviving row the equal `current`/`previous` pair a fresh
    /// search would have produced.
    #[cfg(target_os = "linux")]
    fn seed(&mut self, rt: &tokio::runtime::Handle, ctx: egui::Context) {
        let Some(process) = self.process.clone() else {
            self.status_msg = Some(format!(
                "Imported {} path(s). Attach to a process to read their values.",
                self.rows.len()
            ));
            return;
        };
        let stride = self.value_type.fixed_width().unwrap_or(8);
        let rows = std::mem::take(&mut self.rows);
        let before = rows.len();
        self.status_msg = Some("Resolving imported paths…".into());

        self.seed_job.spawn_cancellable(rt, ctx, move |job| {
            let total = rows.len() as u64;
            let mut kept: Vec<HitRow> = Vec::new();
            let mut buf = vec![0u8; stride];
            for (i, mut row) in rows.into_iter().enumerate() {
                if i.is_multiple_of(128) {
                    job.set_progress(i as u64, total);
                    if job.is_cancelled() {
                        // Hand back what resolved so far rather than an empty
                        // list, matching the pointer scanner's rescan.
                        break;
                    }
                }
                let Some(addr) = resolve_live(&process, &row.hit) else { continue };
                if process.read_buf(addr, &mut buf).is_err() {
                    continue;
                }
                row.hit.current = buf.clone();
                row.hit.previous = buf.clone();
                kept.push(row);
            }
            (kept, before)
        });
    }

    #[cfg(target_os = "linux")]
    fn is_busy(&self) -> bool {
        self.scan_job.is_running()
            || self.refine_job.is_running()
            || self.seed_job.is_running()
    }

    #[cfg(not(target_os = "linux"))]
    fn is_busy(&self) -> bool {
        false
    }

    #[cfg(target_os = "linux")]
    fn progress_fraction(&self) -> Option<f32> {
        self.scan_job
            .handle()
            .or_else(|| self.refine_job.handle())
            .or_else(|| self.seed_job.handle())
            .and_then(|h| h.fraction())
    }

    #[cfg(target_os = "linux")]
    fn cancel(&mut self) {
        self.scan_job.cancel();
        self.refine_job.cancel();
        self.seed_job.cancel();
    }

    /// Parse the config fields into an engine config plus a needle.
    #[cfg(target_os = "linux")]
    fn build_search(&self) -> Result<(usize, SpiderConfig, nemclass_scan::Needle), String> {
        let root = super::parse_hex_addr(&self.root_text)
            .ok_or_else(|| "Enter a valid base address (hex).".to_string())?;

        let mut needle = self
            .value_type
            .parse_needle(self.needle_text.trim())
            .map_err(|e| format!("Value: {e}"))?;
        if self.compare == ScanCompareType::Between {
            needle = needle
                .with_upper_bound(self.upper_text.trim())
                .map_err(|e| format!("Upper bound: {e}"))?;
        }

        let cfg = SpiderConfig {
            struct_size: super::parse_hex_addr(&self.size_text).unwrap_or(0x1000),
            alignment: self.align_text.trim().parse().unwrap_or(4),
            max_depth: self.depth_text.trim().parse().unwrap_or(3),
            ..SpiderConfig::default()
        };
        Ok((root, cfg, needle))
    }

    /// Launch the search on the background pool. A wide search walks thousands
    /// of structs, so it must not block the UI thread; progress and Stop are
    /// bridged through the job handle into the engine's `ScanObserver`.
    #[cfg(target_os = "linux")]
    fn run_search(
        &mut self,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
        ctx: egui::Context,
    ) {
        if self.is_busy() {
            return;
        }
        let Some(process) = self.process.clone() else {
            self.status_msg = Some("No process attached.".into());
            return;
        };
        let (root, cfg, needle) = match self.build_search() {
            Ok(v) => v,
            Err(e) => {
                self.status_msg = Some(e);
                return;
            }
        };

        self.clear_results();
        self.modules_snapshot = modules.to_vec();
        let modules = self.modules_snapshot.clone();
        let value_type = self.value_type;
        let compare = self.compare;

        self.status_msg = Some("Searching…".into());
        self.scan_job.spawn_cancellable(rt, ctx, move |job| {
            use nemclass_scan::ProcessTarget;
            // The shared handle, not a fresh attach: one backend, one set of
            // permissions, and no second /proc open per scan.
            let target = ProcessTarget::from_shared(process);
            let out = spider_scan_with(
                &target,
                root,
                &cfg,
                value_type,
                compare,
                Some(needle),
                &mut observer_for(job),
            )
            .map_err(|e| format!("Spider: {e}"))?;
            let rows = out
                .hits
                .into_iter()
                .map(|hit| hit_row(hit, &modules))
                .collect();
            Ok((rows, out.truncated, out.nodes_visited))
        });
    }

    /// Re-walk every chain and keep only the values matching the refine compare.
    /// The rows travel into the worker and back, so a cancelled refine leaves the
    /// result set exactly as it was.
    #[cfg(target_os = "linux")]
    fn run_refine(&mut self, rt: &tokio::runtime::Handle, ctx: egui::Context) {
        if self.is_busy() {
            return;
        }
        let Some(process) = self.process.clone() else {
            self.status_msg = Some("No process attached.".into());
            return;
        };

        let compare = self.refine_compare;
        let value_type = self.value_type;
        let needle = if compare.needs_needle() {
            match value_type.parse_needle(self.refine_text.trim()) {
                Ok(n) => Some(n),
                Err(e) => {
                    self.status_msg = Some(format!("Refine value: {e}"));
                    return;
                }
            }
        } else {
            None
        };

        let cfg = SpiderConfig::default();
        let modules = self.modules_snapshot.clone();
        let rows = std::mem::take(&mut self.rows);
        let before = rows.len();

        self.status_msg = Some("Refining…".into());
        self.refine_job.spawn_cancellable(rt, ctx, move |job| {
            use nemclass_scan::ProcessTarget;
            let target = ProcessTarget::from_shared(process);
            let mut hits: Vec<SpiderHit> = rows.into_iter().map(|r| r.hit).collect();
            spider_refine_with(
                &target,
                &mut hits,
                &cfg,
                value_type,
                compare,
                needle,
                &mut observer_for(job),
            )
            .map_err(|e| format!("Refine: {e}"))?;
            // Formulas are a pure function of the path, so rebuilding them from
            // the survivors cannot drift out of step with the hit list.
            let kept = hits
                .into_iter()
                .map(|hit| hit_row(hit, &modules))
                .collect();
            Ok((kept, before))
        });
    }

    /// Re-walk the chains the table drew last frame, on a throttle.
    ///
    /// A spider row costs `depth` sequential reads to resolve, so this is
    /// deliberately bounded to the viewport rather than the whole result set.
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
        let Some(width) = self.value_type.fixed_width() else { return };

        let range = self.visible_rows.clone();
        // The first paint after a search has no viewport yet; seed a screenful
        // so the column is populated immediately rather than a beat later.
        let range = if range.is_empty() {
            0..LIVE_SEED_ROWS.min(self.rows.len())
        } else {
            range.start..range.end.min(self.rows.len())
        };

        for idx in range {
            let Some(row) = self.rows.get(idx) else { continue };
            self.live_cache
                .insert(idx, resolve_and_read(&process, &row.hit, width));
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

/// Walk a hit's chain against live memory and read the value it lands on.
/// `None` if any hop is null or unmapped, or the final read comes up short.
fn resolve_and_read(process: &Process, hit: &SpiderHit, width: usize) -> Option<(usize, Vec<u8>)> {
    let addr = resolve_live(process, hit)?;
    let mut buf = vec![0u8; width];
    let n = process.read_buf(addr, &mut buf).ok()?;
    (n >= width).then_some((addr, buf))
}

/// Walk the pointer chain itself. Every hop is a live pointer-sized read, and a
/// null or unreadable hop aborts rather than being followed into nonsense.
fn resolve_live(process: &Process, hit: &SpiderHit) -> Option<usize> {
    hit.path
        .resolve(|addr| process.read::<u64>(addr).ok().map(|v| v as usize))
}

/// Prepare a hit for display, anchoring its formula in the owning module when
/// the root falls inside one so the path survives a restart.
/// Shift a saved run's heap-rooted paths so they start at `root`.
///
/// The object a spider searched is at a different address every run, so two runs
/// of the same search produce the same offset chains under two different roots.
/// Moving the saved run onto the current root is what makes the offsets — the
/// part that is actually a property of the structure — comparable. Module-
/// anchored paths are left alone: their anchors are already relocation-proof.
fn align_roots(file: &PtrMapFile, root: usize) -> PtrMapFile {
    let delta = (root as isize).wrapping_sub(file.goal as isize);
    PtrMapFile {
        goal: root,
        modules: file.modules.clone(),
        entries: file
            .entries
            .iter()
            .map(|e| PtrMapEntry {
                anchor: match e.anchor {
                    nemclass_scan::Anchor::Absolute(a) => {
                        nemclass_scan::Anchor::Absolute(a.wrapping_add_signed(delta))
                    }
                    module => module,
                },
                ..e.clone()
            })
            .collect(),
        truncated: file.truncated,
    }
}

fn hit_row(hit: SpiderHit, modules: &[ModuleInfoWithName]) -> HitRow {
    let module = ptrmap_io::module_at(hit.path.root, modules);
    let formula = match &module {
        Some((name, base)) => hit.path.to_formula_at_module(name, *base),
        None => hit.path.to_formula_raw(),
    };
    HitRow { hit, formula, module }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nemclass_scan::SpiderPath;

    fn row(
        root: usize,
        module: Option<(&str, usize)>,
        parents: &[usize],
        offset: usize,
        value: i32,
    ) -> HitRow {
        let path = SpiderPath {
            root,
            parent_offsets: Arc::from(parents),
            offset,
        };
        let formula = match module {
            Some((name, base)) => path.to_formula_at_module(name, base),
            None => path.to_formula_raw(),
        };
        HitRow {
            hit: SpiderHit {
                path,
                current: value.to_le_bytes().to_vec(),
                previous: (value - 1).to_le_bytes().to_vec(),
            },
            formula,
            module: module.map(|(n, b)| (n.to_string(), b)),
        }
    }

    fn panel_with(rows: Vec<HitRow>) -> SpiderPanel {
        let mut panel = SpiderPanel::new();
        panel.root_text = "0x55550000".to_string();
        panel.rows = rows;
        panel
    }

    fn sample_rows() -> Vec<HitRow> {
        vec![
            row(0x5555_0000, None, &[0x18, 0x40], 0x14, 100),
            row(0x5555_0000, None, &[], 0x8, 200),
            row(0x40_1000, Some(("game.exe", 0x40_0000)), &[0x10], 0x4, 300),
        ]
    }

    #[test]
    fn every_row_reaches_the_file_including_the_ones_past_the_display_cap() {
        let rows: Vec<HitRow> = (0..MAX_DISPLAY + 42)
            .map(|i| row(0x5555_0000, None, &[0x18], i * 4, i as i32))
            .collect();
        let file = panel_with(rows).to_file();
        assert_eq!(file.entries.len(), MAX_DISPLAY + 42);
        assert!(file.entries.iter().all(|e| e.kind == PathKind::Spider));
    }

    #[test]
    fn paths_survive_a_trip_through_the_file_unchanged() {
        let original = sample_rows();
        let file = panel_with(original.clone_paths()).to_file();
        let back = PtrMapFile::from_bytes(&file.to_bytes()).expect("round trip");
        let rows = SpiderPanel::rows_from(&back.rebase(&|_| None, 0));

        assert_eq!(rows.len(), original.len());
        for (got, want) in rows.iter().zip(&original) {
            assert_eq!(got.formula, want.formula);
            assert_eq!(got.hit.path, want.hit.path);
            assert_eq!(got.module, want.module);
        }
    }

    #[test]
    fn an_imported_row_arrives_unseeded() {
        // The state `unseeded` exists to guard: a refine compares against
        // `current`, and an empty reading makes `compare_change` reject the row.
        let file = panel_with(sample_rows()).to_file();
        let back = PtrMapFile::from_bytes(&file.to_bytes()).unwrap();
        let rows = SpiderPanel::rows_from(&back.rebase(&|_| None, 0));
        assert!(rows.iter().all(|r| r.hit.current.is_empty()));
        assert!(rows.iter().all(|r| r.hit.previous.is_empty()));
    }

    #[test]
    fn an_unanchored_root_follows_the_manual_delta() {
        // The common spider case: the object moved, and the user types where it
        // lives now. Only the heap-rooted paths shift.
        let file = panel_with(sample_rows()).to_file();
        let back = PtrMapFile::from_bytes(&file.to_bytes()).unwrap();
        let rows = SpiderPanel::rows_from(&back.rebase(&|_| None, 0x1_0000));

        assert_eq!(rows[0].hit.path.root, 0x5556_0000);
        assert_eq!(rows[1].hit.path.root, 0x5556_0000);
        assert_eq!(rows[2].hit.path.root, 0x40_1000, "a module anchor ignores the delta");
        assert_eq!(rows[0].formula, "[[0x55560000 + 0x18] + 0x40] + 0x14");
    }

    #[test]
    fn comparing_keeps_the_value_readings_of_the_surviving_rows() {
        // The reason compare retains in place instead of rebuilding from the
        // file: rebuilt rows would be unseeded, and the next refine would then
        // discard every one of them.
        let mut panel = panel_with(sample_rows());
        let current = panel.to_file();

        // A second run of a restarted target: the object is now at 0x8888_0000
        // and the modules moved too. It found the first and third paths again
        // and never saw the second.
        let mut other = PtrMapFile {
            goal: 0x8888_0000,
            modules: Vec::new(),
            entries: Vec::new(),
            truncated: false,
        };
        for (root, module, parents, offset) in [
            (0x8888_0000usize, None, vec![0x18usize, 0x40], 0x14usize),
            (0x9000_1000, Some(("game.exe", 0x9000_0000usize)), vec![0x10], 0x4),
        ] {
            let path = SpiderPath { root, parent_offsets: Arc::from(parents.as_slice()), offset };
            let anchor = ptrmap_io::anchor_for(&mut other, root, module);
            other.entries.push(PtrMapEntry::from_spider_path(&path, anchor));
        }

        let aligned = align_roots(&other, current.goal);
        let kept: std::collections::HashSet<usize> =
            current.intersect_indices(&aligned).into_iter().collect();
        assert_eq!(kept.len(), 2);
        let mut i = 0;
        panel.rows.retain(|_| {
            let keep = kept.contains(&i);
            i += 1;
            keep
        });

        assert_eq!(panel.rows.len(), 2);
        // The values came through intact, so a refine still has its baseline.
        assert_eq!(panel.rows[0].hit.current, 100i32.to_le_bytes().to_vec());
        assert_eq!(panel.rows[0].hit.previous, 99i32.to_le_bytes().to_vec());
        assert_eq!(panel.rows[1].hit.current, 300i32.to_le_bytes().to_vec());
    }

    #[test]
    fn aligning_roots_is_what_makes_a_heap_rooted_compare_work_at_all() {
        // Without it, a saved run's roots never coincide with this run's and the
        // comparison silently returns nothing.
        let a = panel_with(vec![row(0x5555_0000, None, &[0x18], 0x8, 1)]).to_file();
        let mut b = panel_with(vec![row(0x6666_0000, None, &[0x18], 0x8, 1)]).to_file();
        b.goal = 0x6666_0000;

        assert!(
            a.intersect_indices(&b).is_empty(),
            "raw roots from two runs do not coincide"
        );
        assert_eq!(a.intersect_indices(&align_roots(&b, a.goal)), vec![0]);
    }

    #[test]
    fn aligning_roots_leaves_module_anchored_paths_alone() {
        // Their anchors are already relocation-proof; shifting them would break
        // the match instead of enabling it.
        let a = panel_with(vec![row(
            0x40_1000,
            Some(("game.exe", 0x40_0000)),
            &[0x10],
            0x4,
            1,
        )])
        .to_file();
        let mut b = panel_with(vec![row(
            0x9000_1000,
            Some(("game.exe", 0x9000_0000)),
            &[0x10],
            0x4,
            1,
        )])
        .to_file();
        b.goal = 0x8888_0000;

        assert_eq!(a.intersect_indices(&align_roots(&b, a.goal)), vec![0]);
    }

    #[test]
    fn aligning_roots_does_not_make_different_offset_chains_match() {
        // The alignment must not be so aggressive that it collapses distinct
        // paths — the offsets still have to agree.
        let a = panel_with(vec![row(0x5555_0000, None, &[0x18], 0x8, 1)]).to_file();
        let mut b = panel_with(vec![row(0x6666_0000, None, &[0x20], 0x8, 1)]).to_file();
        b.goal = 0x6666_0000;
        assert!(a.intersect_indices(&align_roots(&b, a.goal)).is_empty());
    }

    /// `HitRow` is not `Clone` (a `SpiderHit` carries value buffers); the tests
    /// only need the paths duplicated.
    trait ClonePaths {
        fn clone_paths(&self) -> Vec<HitRow>;
    }

    impl ClonePaths for Vec<HitRow> {
        fn clone_paths(&self) -> Vec<HitRow> {
            self.iter()
                .map(|r| HitRow {
                    hit: SpiderHit {
                        path: r.hit.path.clone(),
                        current: r.hit.current.clone(),
                        previous: r.hit.previous.clone(),
                    },
                    formula: r.formula.clone(),
                    module: r.module.clone(),
                })
                .collect()
        }
    }
}
