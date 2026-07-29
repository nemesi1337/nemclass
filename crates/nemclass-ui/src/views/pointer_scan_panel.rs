//! Pointer-scan panel — the Cheat Engine / PINCE "Pointer scan" feature.
//!
//! Given a *goal* address (the address whose value you want a stable path to),
//! this finds pointer chains `<module>+off → [+o₀] → … → goal` anchored in a
//! module image, so the path survives ASLR. Each hit can be turned directly into
//! a class whose `address_formula` is the chain (via
//! [`PointerPath::to_formula`]), wiring pointer-scan results into the ReClass
//! side of the tool.
//!
//! ## Layout
//! ```text
//! ┌─ Pointer scan ───────────────────────────────────────────────────────┐
//! │  Goal: [0x________]  Depth: [5]  Max offset: [0x1000]   [Scan]        │
//! │  42 path(s)  (map: 1,234,567 ptrs)                                    │
//! │  ┌─ Formula ───────────────────────────┬─ Depth ┬─ Actions ───────┐  │
//! │  │ [[<game.exe>+0x1000]+0x40]+0x14     │   2    │ [Class] [Goto]  │  │
//! │  └─────────────────────────────────────┴────────┴─────────────────┘  │
//! └──────────────────────────────────────────────────────────────────────┘
//! ```
//! Disabled (greyed) when no process is attached. A `ProcessTarget` is built
//! from the attached process when Scan fires.

use std::path::Path;
use std::sync::Arc;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_core::{ModuleInfoWithName, Pid, Process};
use nemclass_scan::{
    PathKind, PointerScanConfig, PtrMapEntry, PtrMapFile, Region, ResolvedPath,
};

#[cfg(target_os = "linux")]
use nemclass_scan::{PointerMap, PointerPath};

use super::ptrmap_io::{self, RebaseDialog};

#[cfg(target_os = "linux")]
use super::tasks::{BackgroundJob, Poll as JobPoll};

/// Cap on rendered rows (a scan can return thousands of paths).
const MAX_DISPLAY: usize = 500;

/// What a finished scan hands back: the prepared rows, whether a cap was hit,
/// and the pointer map it built, returned so the panel can reuse or save it.
#[cfg(target_os = "linux")]
type ScanOutcome = (Vec<PathRow>, bool, Arc<PointerMap>);

/// What the panel asks the parent app to do after a click.
pub enum PointerScanAction {
    /// Nothing this frame.
    None,
    /// Create a class with `name` and the given pointer-chain `formula`.
    CreateClass { name: String, formula: String },
    /// Navigate the memory view to `addr` (a chain's static anchor).
    Goto(usize),
}

/// One discovered path, prepared for display.
#[derive(Clone)]
struct PathRow {
    /// Address formula (`[[<mod>+x]+y]+z`) — also the class `address_formula`.
    formula: String,
    /// Number of offsets in the chain.
    depth: usize,
    /// Static anchor address (for "Goto").
    base: usize,
    /// The module the anchor sits in, as `(name, base)`.
    ///
    /// Kept rather than recomputed at export time: a path imported while its
    /// module was not loaded would otherwise be re-exported as a bare address,
    /// throwing away the one property that makes it worth saving.
    module: Option<(String, usize)>,
    /// The chain's offsets, kept so a "Rescan" can re-resolve the path against
    /// the live process (Cheat-Engine-style filtering after a relocation).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    offsets: Vec<isize>,
}

/// All state owned by the pointer-scan panel.
pub struct PointerScanPanel {
    /// Goal address text (hex, `0x…` optional).
    goal_text: String,
    /// Max chain depth text.
    depth_text: String,
    /// Max per-hop struct offset text (hex).
    max_offset_text: String,
    /// Maximum backwards offset; 0 (the default) means forwards only.
    max_negative_text: String,
    /// Only accept offsets that are a multiple of this.
    offset_align_text: String,
    /// Report chains that ran out of depth without reaching a module.
    include_unanchored: bool,
    /// Prepared result rows.
    rows: Vec<PathRow>,
    /// The harvested pointer map from the last scan, kept so a second goal can
    /// be searched without walking the target's memory again — which is most of
    /// the cost of a scan. Also what `Export map` writes.
    #[cfg(target_os = "linux")]
    map: Option<Arc<PointerMap>>,
    /// Whether the next scan should reuse [`Self::map`] instead of rebuilding.
    reuse_map: bool,
    /// Number of harvested pointer-map entries from the last scan.
    map_entries: usize,
    /// True if the last scan hit a result/entry cap.
    truncated: bool,
    /// Import prompt for a `.ptrmap`, shown after a file is picked.
    rebase_dialog: RebaseDialog,
    /// In-flight pointer scan (can take tens of seconds — must be off the UI
    /// thread). Payload: the prepared rows, the truncation flag and the pointer
    /// map that produced them, or an error.
    #[cfg(target_os = "linux")]
    scan_job: BackgroundJob<Result<ScanOutcome, String>>,
    /// In-flight rescan (re-reads the live process for every path). Payload: the
    /// retained rows plus the pre-rescan count for the status line.
    #[cfg(target_os = "linux")]
    rescan_job: BackgroundJob<(Vec<PathRow>, usize)>,
    /// Status / error line.
    pub status_msg: Option<String>,
}

impl Default for PointerScanPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl PointerScanPanel {
    pub fn new() -> Self {
        Self {
            goal_text: String::new(),
            depth_text: "5".to_string(),
            max_offset_text: "0x1000".to_string(),
            max_negative_text: "0".to_string(),
            offset_align_text: "1".to_string(),
            include_unanchored: false,
            rows: Vec::new(),
            #[cfg(target_os = "linux")]
            map: None,
            reuse_map: true,
            map_entries: 0,
            truncated: false,
            rebase_dialog: RebaseDialog::default(),
            #[cfg(target_os = "linux")]
            scan_job: BackgroundJob::default(),
            #[cfg(target_os = "linux")]
            rescan_job: BackgroundJob::default(),
            status_msg: None,
        }
    }

    /// Clear results when the user detaches.
    pub fn on_detach(&mut self) {
        self.rows.clear();
        self.map_entries = 0;
        self.truncated = false;
        #[cfg(target_os = "linux")]
        {
            // The map describes the process that just went away; keeping it
            // would let a later scan search a dead address space.
            self.map = None;
            // Discard any in-flight scan/rescan so stale results don't land.
            self.scan_job = BackgroundJob::default();
            self.rescan_job = BackgroundJob::default();
        }
        self.status_msg = None;
    }

    /// Drain completed pointer scan / rescan jobs. Call each frame from the
    /// parent's `logic()`.
    #[cfg(target_os = "linux")]
    pub fn poll(&mut self) {
        if let JobPoll::Done(outcome) = self.scan_job.poll() {
            match outcome {
                Ok((rows, truncated, map)) => {
                    self.rows = rows;
                    self.truncated = truncated;
                    self.map_entries = map.len();
                    self.map = Some(map);
                    self.status_msg = if self.rows.is_empty() {
                        Some("No paths found. Try a larger depth or max offset.".into())
                    } else {
                        None
                    };
                }
                Err(e) => self.status_msg = Some(e),
            }
        }
        if let JobPoll::Done((kept, before)) = self.rescan_job.poll() {
            let kept_len = kept.len();
            self.rows = kept;
            self.status_msg = Some(format!(
                "Rescan: {kept_len}/{before} paths still resolve to the goal.",
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn poll(&mut self) {}

    /// Seed the goal field (e.g. from a scanner "pointer-scan this address").
    pub fn set_goal(&mut self, addr: usize) {
        self.goal_text = format!("0x{addr:X}");
    }

    // -----------------------------------------------------------------------
    // Saving and loading the result set
    //
    // The display cap is 500 rows and a scan routinely returns tens of
    // thousands. Everything past the cap used to be unreachable and was thrown
    // away when the target restarted; these are the way out.
    // -----------------------------------------------------------------------

    /// Package the current rows as a `.ptrmap`, anchoring each path in the
    /// module it was found in.
    fn to_file(&self) -> PtrMapFile {
        let mut file = PtrMapFile {
            goal: super::parse_hex_addr(&self.goal_text).unwrap_or(0),
            modules: Vec::new(),
            entries: Vec::with_capacity(self.rows.len()),
            truncated: self.truncated,
        };
        for row in &self.rows {
            let owner = row.module.as_ref().map(|(n, b)| (n.as_str(), *b));
            let anchor = ptrmap_io::anchor_for(&mut file, row.base, owner);
            file.entries.push(PtrMapEntry {
                kind: PathKind::Pointer,
                anchor,
                offsets: row.offsets.iter().map(|&o| o as i64).collect(),
            });
        }
        file
    }

    /// Rebuild the display rows from paths resolved against the current process.
    fn rows_from(paths: &[ResolvedPath]) -> Vec<PathRow> {
        paths
            .iter()
            .filter_map(|p| {
                let path = p.to_pointer_path().ok()?;
                Some(PathRow {
                    formula: p.to_formula(),
                    depth: p.depth(),
                    base: p.anchor,
                    module: p.module.as_ref().map(|m| (m.name.clone(), m.base)),
                    offsets: path.offsets,
                })
            })
            .collect()
    }

    /// Pick a `.ptrmap` and stage it in the rebase prompt.
    fn import(&mut self, modules: &[ModuleInfoWithName], start_dir: &Path) {
        match ptrmap_io::pick(start_dir) {
            Ok(Some((file, name))) => {
                if let Err(e) =
                    self.rebase_dialog
                        .open(file, name, PathKind::Pointer, modules)
                {
                    self.status_msg = Some(e);
                }
            }
            Ok(None) => {}
            Err(e) => self.status_msg = Some(e),
        }
    }

    /// Narrow the current results to the paths a saved run also found.
    ///
    /// Cheat Engine's compare: the chains present in two runs of the target are
    /// the real structure relationships, and everything else was a coincidence
    /// of one heap layout. Matching ignores absolute bases, so it works across
    /// the restart that makes the comparison meaningful.
    fn compare(&mut self, start_dir: &Path) {
        let loaded = match ptrmap_io::pick(start_dir) {
            Ok(Some(picked)) => picked,
            Ok(None) => return,
            Err(e) => {
                self.status_msg = Some(e);
                return;
            }
        };
        let (loaded, name) = loaded;
        if let Some(&got) = loaded.kinds().iter().find(|&&k| k != PathKind::Pointer) {
            self.status_msg =
                Some(format!("{name} holds {} paths, not pointer ones.", got.label()));
            return;
        }

        let before = self.rows.len();
        let current = self.to_file();
        let kept = current.intersect(&loaded);
        let kept_len = kept.len();

        // Rebuild the rows from the surviving entries. The bases recorded in
        // `current` are the live ones — it was just built from them — so this
        // resolves with no rebasing.
        let filtered = PtrMapFile { entries: kept, ..current };
        self.rows = Self::rows_from(&filtered.rebase(&|_| None, 0));
        // The comparison is only as complete as its inputs; say so rather than
        // letting a capped run read as a clean result.
        self.truncated |= loaded.truncated;
        self.status_msg = Some(format!(
            "Compare: {kept_len} of {before} path(s) also in {name} ({} there).",
            loaded.entries.len()
        ));
    }

    /// Draw the panel. `modules` are the attached process's module images, used
    /// as the static anchor ranges.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<Arc<Process>>,
        pid: Option<Pid>,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
        start_dir: &Path,
    ) -> PointerScanAction {
        let attached = process.is_some();
        if !attached {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Attach to a process to run a pointer scan.",
            );
            ui.add_space(4.0);
        }

        let mut action = PointerScanAction::None;

        ui.add_enabled_ui(attached, |ui| {
            ui.horizontal(|ui| {
                ui.label("Goal:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.goal_text)
                        .desired_width(140.0)
                        .hint_text("0x7fff…"),
                );
                ui.label("Depth:");
                ui.add(egui::TextEdit::singleline(&mut self.depth_text).desired_width(36.0));
                ui.label("Max offset:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.max_offset_text).desired_width(72.0),
                );
                ui.label("Max −offset:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.max_negative_text).desired_width(60.0),
                )
                .on_hover_text(
                    "How far backwards a hop may reach. 0 is forwards-only; raise it to find \
                     a field addressed from a pointer stored after it.",
                );
                ui.label("Align:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.offset_align_text).desired_width(36.0),
                )
                .on_hover_text(
                    "Only accept offsets that are a multiple of this. Set it to the pointer \
                     size when the target's fields are aligned — it cuts the search by that \
                     factor.",
                );
                ui.checkbox(&mut self.include_unanchored, "Unanchored")
                    .on_hover_text(
                        "Also report chains that never reach a module. They will not survive \
                         a restart, but they show how the structure is reached.",
                    );

                #[cfg(target_os = "linux")]
                {
                    let busy = self.scan_job.is_running() || self.rescan_job.is_running();
                    if ui
                        .add_enabled(!busy, egui::Button::new("Scan"))
                        .clicked()
                    {
                        self.run_scan(pid, modules, rt, ui.ctx().clone());
                    }
                    // Rescan verifies existing results against current memory —
                    // enabled only once a scan has produced rows.
                    if ui
                        .add_enabled(!busy && !self.rows.is_empty(), egui::Button::new("Rescan"))
                        .on_hover_text("Keep only chains that still resolve to the goal (after a restart / relocation)")
                        .clicked()
                    {
                        self.rescan(process.clone(), rt, ui.ctx().clone());
                    }
                    if busy {
                        ui.spinner();
                    }
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let _ = (pid, modules, &process, rt);
                    ui.add_enabled(false, egui::Button::new("Scan"));
                }
            });
        });

        // File row. A scan returns far more paths than the table shows, so
        // these are the only way to see, keep, or narrow the rest of them.
        ui.horizontal(|ui| {
            let has_rows = !self.rows.is_empty();
            if ui
                .add_enabled(has_rows, egui::Button::new("Export…"))
                .on_hover_text("Save every path — not just the ones shown — to a .ptrmap")
                .clicked()
            {
                let file = self.to_file();
                self.status_msg = Some(ptrmap_io::export(&file, "pointer-scan", start_dir));
            }
            if ui
                .add_enabled(has_rows, egui::Button::new("Export text…"))
                .on_hover_text("Save every path as a plain list of formulas, one per line")
                .clicked()
            {
                let file = self.to_file();
                self.status_msg =
                    Some(ptrmap_io::export_text(&file, "pointer-scan", start_dir));
            }
            // Disabled while a prompt is already up: a second pick would replace
            // the staged file and the open dialog would apply the wrong one.
            if ui
                .add_enabled(
                    !self.rebase_dialog.is_open(),
                    egui::Button::new("Import…"),
                )
                .on_hover_text("Load a saved .ptrmap, rebased onto the attached process")
                .clicked()
            {
                self.import(modules, start_dir);
            }
            if ui
                .add_enabled(has_rows, egui::Button::new("Compare…"))
                .on_hover_text(
                    "Keep only the paths a saved run also found. Scan, restart the target, \
                     scan again, then compare — what survives is what is actually stable.",
                )
                .clicked()
            {
                self.compare(start_dir);
            }

            #[cfg(target_os = "linux")]
            {
                ui.separator();
                self.show_map_controls(ui, start_dir);
            }
            #[cfg(not(target_os = "linux"))]
            let _ = start_dir;
        });

        // Result summary.
        ui.horizontal(|ui| {
            let shown = self.rows.len().min(MAX_DISPLAY);
            if self.rows.len() > shown {
                // Without this the table just stops, and the missing thousands
                // read as "the scan found 500 paths".
                ui.label(format!(
                    "{} path(s) total (showing {shown})",
                    self.rows.len()
                ))
                .on_hover_text("Export to see them all, or compare against another run to narrow them down.");
            } else {
                ui.label(format!("{} path(s)", self.rows.len()));
            }
            if self.map_entries > 0 {
                ui.label(format!("(map: {} ptrs)", self.map_entries));
            }
            if self.truncated {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 40),
                    "results capped — narrow depth/offset",
                );
            }
        });

        // The import prompt, once a file has been picked.
        if let Some(outcome) = self.rebase_dialog.show(ui.ctx()) {
            self.rows = Self::rows_from(&outcome.paths);
            self.truncated = outcome.truncated;
            self.status_msg = Some(format!(
                "Imported {} path(s) from {}.",
                self.rows.len(),
                outcome.source
            ));
        }

        ui.separator();
        action = self.show_results(ui).unwrap_or(action);

        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(220, 160, 40), msg);
        }

        action
    }

    /// Controls for the harvested pointer map.
    ///
    /// Building the map is most of the cost of a pointer scan, and it used to be
    /// rebuilt from scratch for every goal — including for a second goal seconds
    /// later against the same unchanged process. Keeping it makes the second
    /// scan near-instant, and saving it carries that across sessions.
    #[cfg(target_os = "linux")]
    fn show_map_controls(&mut self, ui: &mut egui::Ui, start_dir: &Path) {
        let entries = self.map.as_ref().map(|m| m.len());

        // Serialize before touching `status_msg`, so the borrow of `self.map`
        // ends first.
        let snapshot = ui
            .add_enabled(entries.is_some(), egui::Button::new("Export map…"))
            .on_hover_text("Save the harvested pointer map so a later session can skip the memory walk")
            .clicked()
            .then(|| self.map.as_ref().map(|m| (m.to_bytes(), m.len())))
            .flatten();
        if let Some((bytes, len)) = snapshot {
            self.status_msg = Some(ptrmap_io::export_snapshot(&bytes, len, start_dir));
        }

        if ui
            .button("Import map…")
            .on_hover_text("Load a saved pointer map and scan it without re-reading the target")
            .clicked()
        {
            self.import_map(start_dir);
        }

        if let Some(n) = entries {
            ui.checkbox(&mut self.reuse_map, "Reuse")
                .on_hover_text(
                    "Search the map already in memory instead of rebuilding it. Uncheck \
                     after the target has allocated or freed anything you care about.",
                );
            // A capped map is 8M entries of 16 bytes; the user should be able to
            // see that cost and drop it.
            let mib = (n * 16) / (1024 * 1024);
            if ui
                .small_button("Free")
                .on_hover_text(format!("Release the pointer map (~{mib} MiB)"))
                .clicked()
            {
                self.map = None;
                self.map_entries = 0;
            }
        }
    }

    /// Load a saved pointer-map snapshot and arm it for the next scan.
    #[cfg(target_os = "linux")]
    fn import_map(&mut self, start_dir: &Path) {
        let picked = match ptrmap_io::pick_snapshot(start_dir) {
            Ok(Some(picked)) => picked,
            Ok(None) => return,
            Err(e) => {
                self.status_msg = Some(e);
                return;
            }
        };
        let (bytes, name) = picked;
        match PointerMap::from_bytes(&bytes) {
            Ok(map) => {
                let capped = map.truncated();
                self.map_entries = map.len();
                self.map = Some(Arc::new(map));
                self.reuse_map = true;
                self.status_msg = Some(format!(
                    "Loaded {} pointer(s) from {name}{}. The next scan will reuse it.",
                    self.map_entries,
                    if capped { " (capped)" } else { "" }
                ));
            }
            Err(e) => self.status_msg = Some(format!("{name}: {e}")),
        }
    }

    /// Draw the results table; returns an action if a row button was clicked.
    fn show_results(&mut self, ui: &mut egui::Ui) -> Option<PointerScanAction> {
        let mut action: Option<PointerScanAction> = None;
        let show_n = self.rows.len().min(MAX_DISPLAY);

        TableBuilder::new(ui)
            .striped(true)
            .column(Column::remainder().at_least(220.0)) // formula
            .column(Column::auto().at_least(44.0)) // depth
            .column(Column::auto().at_least(140.0)) // actions
            .header(18.0, |mut header| {
                header.col(|ui| { ui.strong("Formula"); });
                header.col(|ui| { ui.strong("Depth"); });
                header.col(|ui| { ui.strong("Actions"); });
            })
            .body(|mut body| {
                for row in self.rows.iter().take(show_n) {
                    body.row(18.0, |mut r| {
                        r.col(|ui| {
                            ui.add(
                                egui::Label::new(egui::RichText::new(&row.formula).monospace())
                                    .truncate(),
                            )
                            .on_hover_text(&row.formula);
                        });
                        r.col(|ui| { ui.monospace(row.depth.to_string()); });
                        r.col(|ui| {
                            ui.horizontal(|ui| {
                                if ui.small_button("Class").clicked() {
                                    action = Some(PointerScanAction::CreateClass {
                                        name: String::new(),
                                        formula: row.formula.clone(),
                                    });
                                }
                                if ui.small_button("Goto").clicked() {
                                    action = Some(PointerScanAction::Goto(row.base));
                                }
                            });
                        });
                    });
                }
            });

        action
    }

    /// Launch a pointer scan on the background pool. Building the pointer map and
    /// walking it can take tens of seconds, so it must not block the UI thread.
    /// The `ProcessTarget` is (re)attached inside the worker; the prepared rows
    /// land via [`Self::poll`].
    #[cfg(target_os = "linux")]
    fn run_scan(
        &mut self,
        pid: Option<Pid>,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
        ctx: egui::Context,
    ) {
        if self.scan_job.is_running() {
            return;
        }
        self.rows.clear();
        self.truncated = false;
        // Reusing the map skips the memory walk entirely, which is most of the
        // scan; rebuilding drops the old one only once the new one lands.
        let reuse = self.reuse_map.then(|| self.map.clone()).flatten();
        if reuse.is_none() {
            self.map_entries = 0;
        }

        let Some(pid) = pid else {
            self.status_msg = Some("No process attached.".into());
            return;
        };
        let Some(goal) = super::parse_hex_addr(&self.goal_text) else {
            self.status_msg = Some("Enter a valid goal address (hex).".into());
            return;
        };
        let max_depth: usize = self.depth_text.trim().parse().unwrap_or(5).clamp(1, 12);
        let max_offset = super::parse_hex_addr(&self.max_offset_text).unwrap_or(0x1000);
        let max_negative_offset = super::parse_hex_addr(&self.max_negative_text).unwrap_or(0);
        let offset_alignment =
            self.offset_align_text.trim().parse::<usize>().unwrap_or(1).max(1);
        let must_end_in_static = !self.include_unanchored;

        // Static anchors = module images. Snapshot them (owned) for the worker.
        let static_ranges: Vec<Region> =
            modules.iter().map(|m| Region::new(m.base, m.size)).collect();
        if static_ranges.is_empty() {
            self.status_msg = Some("No modules enumerated to anchor a chain.".into());
            return;
        }
        let modules: Vec<ModuleInfoWithName> = modules.to_vec();

        self.status_msg = Some(if reuse.is_some() {
            "Scanning the map already in memory…".into()
        } else {
            "Scanning…".to_string()
        });
        // Cancellable: this is the longest operation in the application, and it
        // used to show a spinner with no progress and no way to stop it.
        self.scan_job.spawn_cancellable(rt, ctx, move |job| {
            use nemclass_scan::ProcessTarget;
            let cfg = PointerScanConfig {
                max_depth,
                max_offset,
                max_negative_offset,
                offset_alignment,
                must_end_in_static,
                static_ranges,
                ..Default::default()
            };
            let mut observer = |p: nemclass_scan::PointerScanProgress| {
                job.set_progress(p.done as u64, p.total as u64);
                !job.is_cancelled()
            };

            // Harvesting the pointers is the expensive half. Skip it when the
            // caller already has a map — the whole point of keeping one.
            let map = match reuse {
                Some(map) => map,
                None => {
                    let target = ProcessTarget::attach(pid)
                        .map_err(|e| format!("ProcessTarget: {e}"))?;
                    Arc::new(
                        PointerMap::build_with(&target, &cfg, &mut observer)
                            .map_err(|e| format!("Pointer scan: {e}"))?,
                    )
                }
            };

            let mut result = map.find_paths_with(goal, &cfg, &mut observer);
            result.truncated |= map.truncated();
            // Turn each path into a module-relative formula.
            let rows: Vec<PathRow> =
                result.paths.iter().map(|p| path_row(p, &modules)).collect();
            Ok((rows, result.truncated, map))
        });
    }

    /// Re-resolve every discovered path against the live process and keep only
    /// those that still point at the goal. This is Cheat Engine's pointer-scan
    /// "rescan": run once, restart/relocate the target, rescan to drop the
    /// chains that were coincidental. Runs on the background pool (one live read
    /// per path); the retained rows land via [`Self::poll`].
    #[cfg(target_os = "linux")]
    fn rescan(
        &mut self,
        process: Option<Arc<Process>>,
        rt: &tokio::runtime::Handle,
        ctx: egui::Context,
    ) {
        if self.rescan_job.is_running() {
            return;
        }
        let Some(proc) = process else {
            self.status_msg = Some("No process attached.".into());
            return;
        };
        let Some(goal) = super::parse_hex_addr(&self.goal_text) else {
            self.status_msg = Some("Enter a valid goal address (hex).".into());
            return;
        };
        // Move the rows into the worker; they return filtered (or intact on error).
        let rows = std::mem::take(&mut self.rows);
        let before = rows.len();
        self.status_msg = Some("Rescanning…".into());
        // Cancellable, and it publishes progress: a rescan does one live read
        // per path, which over ten thousand results is not instant.
        self.rescan_job.spawn_cancellable(rt, ctx, move |job| {
            let read_ptr = |addr: usize| -> Option<usize> {
                proc.read::<u64>(addr).ok().map(|v| v as usize)
            };
            let total = rows.len() as u64;
            let mut kept: Vec<PathRow> = Vec::new();
            for (i, row) in rows.into_iter().enumerate() {
                if i % 128 == 0 {
                    job.set_progress(i as u64, total);
                    if job.is_cancelled() {
                        // Hand back what survived so far rather than an empty
                        // list: a stopped rescan should not look like "every
                        // chain is dead".
                        break;
                    }
                }
                let path = PointerPath { base: row.base, offsets: row.offsets.clone() };
                if path.resolve(read_ptr) == Some(goal) {
                    kept.push(row);
                }
            }
            (kept, before)
        });
    }
}

/// Map a path's static base to its owning module and render the formula.
#[cfg(target_os = "linux")]
fn path_row(p: &PointerPath, modules: &[ModuleInfoWithName]) -> PathRow {
    let module = ptrmap_io::module_at(p.base, modules);
    let formula = match &module {
        Some((name, base)) => p.to_formula(name, *base),
        // An unanchored chain, which the "Unanchored" checkbox asks for. It gets
        // a bare hex anchor rather than a `<unknown>` module that does not exist
        // and would not resolve if the formula were saved to a class.
        None => p.to_formula_raw(),
    };
    PathRow {
        formula,
        depth: p.offsets.len(),
        base: p.base,
        module,
        offsets: p.offsets.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panel_with(rows: Vec<PathRow>) -> PointerScanPanel {
        let mut panel = PointerScanPanel::new();
        panel.goal_text = "0x7F2C4A18".to_string();
        panel.rows = rows;
        panel
    }

    fn row(base: usize, module: Option<(&str, usize)>, offsets: Vec<isize>) -> PathRow {
        let path = PointerPath { base, offsets: offsets.clone() };
        let formula = match module {
            Some((name, mod_base)) => path.to_formula(name, mod_base),
            None => path.to_formula_raw(),
        };
        PathRow {
            formula,
            depth: offsets.len(),
            base,
            module: module.map(|(n, b)| (n.to_string(), b)),
            offsets,
        }
    }

    fn sample_rows() -> Vec<PathRow> {
        vec![
            row(0x40_1230, Some(("game.exe", 0x40_0000)), vec![0x18, 0x40, 0x8]),
            row(0x40_2000, Some(("game.exe", 0x40_0000)), vec![-0x20, 0x8]),
            row(0x7F00_2210, Some(("libfoo.so", 0x7F00_0000)), vec![0x0]),
            row(0x5555_0000, None, vec![0x10]),
        ]
    }

    #[test]
    fn every_row_reaches_the_file_including_the_ones_past_the_display_cap() {
        // The whole point: the export is not bounded by MAX_DISPLAY.
        let rows: Vec<PathRow> = (0..MAX_DISPLAY + 137)
            .map(|i| row(0x40_0000 + i * 8, Some(("game.exe", 0x40_0000)), vec![0x8]))
            .collect();
        let file = panel_with(rows).to_file();
        assert_eq!(file.entries.len(), MAX_DISPLAY + 137);
        assert_eq!(file.to_text().lines().filter(|l| !l.starts_with('#')).count(), MAX_DISPLAY + 137);
    }

    #[test]
    fn rows_survive_a_trip_through_the_file_unchanged() {
        let original = sample_rows();
        let file = panel_with(original.clone()).to_file();

        // The goal is carried, and each module is interned once.
        assert_eq!(file.goal, 0x7F2C_4A18);
        assert_eq!(file.modules.len(), 2);

        let bytes = file.to_bytes();
        let back = PtrMapFile::from_bytes(&bytes).expect("round trip");
        let rows = PointerScanPanel::rows_from(&back.rebase(&|_| None, 0));

        assert_eq!(rows.len(), original.len());
        for (got, want) in rows.iter().zip(&original) {
            assert_eq!(got.formula, want.formula);
            assert_eq!(got.base, want.base);
            assert_eq!(got.offsets, want.offsets);
            assert_eq!(got.module, want.module);
            assert_eq!(got.depth, want.depth);
        }
    }

    #[test]
    fn an_imported_row_follows_its_module_to_a_new_base() {
        let file = panel_with(sample_rows()).to_file();
        let back = PtrMapFile::from_bytes(&file.to_bytes()).unwrap();

        let rows = PointerScanPanel::rows_from(
            &back.rebase(&|name| (name == "game.exe").then_some(0x7FFF_0000), 0),
        );

        // The two game.exe paths moved; the libfoo.so one did not.
        assert_eq!(rows[0].base, 0x7FFF_1230);
        assert_eq!(rows[1].base, 0x7FFF_2000);
        assert_eq!(rows[2].base, 0x7F00_2210);
        // The formula is still module-anchored, so it survives the next restart.
        assert_eq!(rows[0].formula, "[[[<game.exe> + 0x1230] + 0x18] + 0x40] + 0x8");
        // And the negative offset kept its sign through the file.
        assert_eq!(rows[1].offsets, vec![-0x20, 0x8]);
        assert!(rows[1].formula.contains("- 0x20"), "{}", rows[1].formula);
    }

    #[test]
    fn an_unanchored_row_keeps_a_bare_hex_formula() {
        // Not `<unknown> + …`, which names a module that does not exist and
        // would not resolve if the formula were saved to a class.
        let rows = sample_rows();
        assert_eq!(rows[3].formula, "[0x55550000] + 0x10");
        assert!(rows[3].module.is_none());

        let file = panel_with(rows).to_file();
        let back = PtrMapFile::from_bytes(&file.to_bytes()).unwrap();
        let out = PointerScanPanel::rows_from(&back.rebase(&|_| None, 0));
        assert_eq!(out[3].formula, "[0x55550000] + 0x10");
    }

    #[test]
    fn comparing_two_runs_keeps_only_the_paths_in_both() {
        let mut panel = panel_with(sample_rows());
        let current = panel.to_file();

        // A second run of a relocated target that found the first and third
        // paths again, plus one the first run never saw.
        let mut other = PtrMapFile {
            goal: 0x1111,
            modules: Vec::new(),
            entries: Vec::new(),
            truncated: false,
        };
        for (base, module, offsets) in [
            (0x9000_1230usize, Some(("game.exe", 0x9000_0000usize)), vec![0x18i64, 0x40, 0x8]),
            (0xA000_2210, Some(("libfoo.so", 0xA000_0000)), vec![0x0]),
            (0x9000_9999, Some(("game.exe", 0x9000_0000)), vec![0x8]),
        ] {
            let anchor = ptrmap_io::anchor_for(&mut other, base, module);
            other.entries.push(PtrMapEntry { kind: PathKind::Pointer, anchor, offsets });
        }

        let kept = current.intersect(&other);
        assert_eq!(kept.len(), 2, "only the two paths present in both runs survive");

        let filtered = PtrMapFile { entries: kept, ..current };
        panel.rows = PointerScanPanel::rows_from(&filtered.rebase(&|_| None, 0));

        let formulas: Vec<&str> = panel.rows.iter().map(|r| r.formula.as_str()).collect();
        assert_eq!(
            formulas,
            vec![
                "[[[<game.exe> + 0x1230] + 0x18] + 0x40] + 0x8",
                "[<libfoo.so> + 0x2210] + 0x0",
            ]
        );
    }

    #[test]
    fn a_comparison_that_shares_nothing_empties_the_results() {
        let panel = panel_with(sample_rows());
        let current = panel.to_file();
        let other = PtrMapFile {
            goal: 0,
            modules: vec![nemclass_scan::ModuleRef {
                name: "game.exe".into(),
                base: 0x9000_0000,
            }],
            entries: vec![PtrMapEntry {
                kind: PathKind::Pointer,
                // Same module, different offset — a different path.
                anchor: nemclass_scan::Anchor::Module { module: 0, offset: 0x1231 },
                offsets: vec![0x18, 0x40, 0x8],
            }],
            truncated: false,
        };
        assert!(current.intersect(&other).is_empty());
    }
}
