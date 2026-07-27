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

use std::sync::Arc;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_core::{ModuleInfoWithName, Pid, Process};
use nemclass_scan::{PointerScanConfig, Region};

#[cfg(target_os = "linux")]
use nemclass_scan::{pointer_scan, PointerPath};

#[cfg(target_os = "linux")]
use super::tasks::{BackgroundJob, Poll as JobPoll};

/// Cap on rendered rows (a scan can return thousands of paths).
const MAX_DISPLAY: usize = 500;

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
struct PathRow {
    /// Address formula (`[[<mod>+x]+y]+z`) — also the class `address_formula`.
    formula: String,
    /// Number of offsets in the chain.
    depth: usize,
    /// Static anchor address (for "Goto").
    base: usize,
    /// The chain's offsets, kept so a "Rescan" can re-resolve the path against
    /// the live process (Cheat-Engine-style filtering after a relocation).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    offsets: Vec<usize>,
}

/// All state owned by the pointer-scan panel.
pub struct PointerScanPanel {
    /// Goal address text (hex, `0x…` optional).
    goal_text: String,
    /// Max chain depth text.
    depth_text: String,
    /// Max per-hop struct offset text (hex).
    max_offset_text: String,
    /// Prepared result rows.
    rows: Vec<PathRow>,
    /// Number of harvested pointer-map entries from the last scan.
    map_entries: usize,
    /// True if the last scan hit a result/entry cap.
    truncated: bool,
    /// In-flight pointer scan (can take tens of seconds — must be off the UI
    /// thread). Payload: the prepared rows plus the truncation flag, or an error.
    #[cfg(target_os = "linux")]
    scan_job: BackgroundJob<Result<(Vec<PathRow>, bool), String>>,
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
            rows: Vec::new(),
            map_entries: 0,
            truncated: false,
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
                Ok((rows, truncated)) => {
                    self.rows = rows;
                    self.truncated = truncated;
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

    /// Draw the panel. `modules` are the attached process's module images, used
    /// as the static anchor ranges.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<Arc<Process>>,
        pid: Option<Pid>,
        modules: &[ModuleInfoWithName],
        rt: &tokio::runtime::Handle,
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

        // Result summary.
        ui.horizontal(|ui| {
            ui.label(format!("{} path(s)", self.rows.len()));
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

        ui.separator();
        action = self.show_results(ui).unwrap_or(action);

        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(220, 160, 40), msg);
        }

        action
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

    /// Parse `0x…`/decimal into a usize address.
    fn parse_addr(&self, text: &str) -> Option<usize> {
        let t = text.trim();
        let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
        usize::from_str_radix(t, 16).ok()
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
        self.map_entries = 0;

        let Some(pid) = pid else {
            self.status_msg = Some("No process attached.".into());
            return;
        };
        let Some(goal) = self.parse_addr(&self.goal_text) else {
            self.status_msg = Some("Enter a valid goal address (hex).".into());
            return;
        };
        let max_depth: usize = self.depth_text.trim().parse().unwrap_or(5).clamp(1, 12);
        let max_offset = self.parse_addr(&self.max_offset_text).unwrap_or(0x1000);

        // Static anchors = module images. Snapshot them (owned) for the worker.
        let static_ranges: Vec<Region> =
            modules.iter().map(|m| Region::new(m.base, m.size)).collect();
        if static_ranges.is_empty() {
            self.status_msg = Some("No modules enumerated to anchor a chain.".into());
            return;
        }
        let modules: Vec<ModuleInfoWithName> = modules.to_vec();

        self.status_msg = Some("Scanning…".into());
        self.scan_job.spawn(rt, ctx, move || {
            use nemclass_scan::ProcessTarget;
            let target =
                ProcessTarget::attach(pid).map_err(|e| format!("ProcessTarget: {e}"))?;
            let cfg = PointerScanConfig {
                max_depth,
                max_offset,
                static_ranges,
                ..Default::default()
            };
            let result =
                pointer_scan(&target, goal, &cfg).map_err(|e| format!("Pointer scan: {e}"))?;
            // Turn each path into a module-relative formula.
            let rows: Vec<PathRow> =
                result.paths.iter().map(|p| path_row(p, &modules)).collect();
            Ok((rows, result.truncated))
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
        let Some(goal) = self.parse_addr(&self.goal_text) else {
            self.status_msg = Some("Enter a valid goal address (hex).".into());
            return;
        };
        // Move the rows into the worker; they return filtered (or intact on error).
        let rows = std::mem::take(&mut self.rows);
        let before = rows.len();
        self.status_msg = Some("Rescanning…".into());
        self.rescan_job.spawn(rt, ctx, move || {
            let read_ptr = |addr: usize| -> Option<usize> {
                proc.read::<u64>(addr).ok().map(|v| v as usize)
            };
            let kept: Vec<PathRow> = rows
                .into_iter()
                .filter(|row| {
                    let path = PointerPath { base: row.base, offsets: row.offsets.clone() };
                    path.resolve(read_ptr) == Some(goal)
                })
                .collect();
            (kept, before)
        });
    }
}

/// Map a path's static base to its owning module and render the formula.
#[cfg(target_os = "linux")]
fn path_row(p: &PointerPath, modules: &[ModuleInfoWithName]) -> PathRow {
    let module = modules
        .iter()
        .find(|m| p.base >= m.base && p.base < m.base.saturating_add(m.size));
    let formula = match module {
        Some(m) => p.to_formula(&m.name, m.base),
        // Fallback: no owning module (shouldn't happen) → absolute anchor.
        None => p.to_formula("unknown", 0),
    };
    PathRow { formula, depth: p.offsets.len(), base: p.base, offsets: p.offsets.clone() }
}
