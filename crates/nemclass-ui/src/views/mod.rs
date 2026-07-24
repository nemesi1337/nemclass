//! Top-level `NemclassApp` — the `eframe::App` implementation.
//!
//! ## Layout
//! ```text
//! ┌─ menu bar (New / Open / Save) ───────────────────────────────────┐
//! ├─ top bar (address_bar) ──────────────────────────────────────────┤
//! │ Class: PlayerObject   Base: 0x7fff…   Formula: [_____]           │
//! ├─ left panel ────┬─ central panel ──────────────────────────────── ┤
//! │ Backend: [combo]│ [Memory View] [Scanner] [Debugger]             │
//! │ [Refresh][Attach│────────────────────────────────────────────────│
//! │  pid list ]     │  active tab content …                          │
//! │─────────────────│                                                │
//! │ Classes:        │                                                │
//! │  ▶ PlayerObject │                                                │
//! └─────────────────┴──────────────────────────────────────────────── ┘
//! ```

mod scanner_panel;
mod debugger_panel;

pub use scanner_panel::ScannerPanel;
pub use debugger_panel::DebuggerPanel;

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_core::{ModuleInfoWithName, Process, ProcessEntry, ProviderRegistry};
use nemclass_model::{ClassNode, ModelError, Node, NodeRegistry, Project, RenderedValue, resolve_formula};
use nemclass_script::{Event, EventBus};
use uuid::Uuid;

use crate::process_reader::ProcessReader;
use crate::project_io::{create_project_at, load_project_from, save_project_to};

// ---------------------------------------------------------------------------
// Central-panel tab selector
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CentralTab {
    MemoryView,
    Scanner,
    Debugger,
}

// ---------------------------------------------------------------------------
// Flat snapshot of a node tree row
// ---------------------------------------------------------------------------

struct NodeSnapshot {
    /// Absolute address in target address space.
    address: usize,
    /// Byte offset from the class base.
    offset: usize,
    /// Tree depth (0 = direct child of the class, 1 = grandchild, …).
    depth: usize,
    /// Dot-separated index path: "0", "0.2", "0.2.1" — used as the egui id
    /// and the collapse-set key.
    id_path: String,
    /// Pre-rendered value string from the last snapshot.
    rendered: RenderedValue,
    /// True if this node has children (is a container).
    has_children: bool,
    type_tag: &'static str,
    name: String,
    comment: String,
    _memory_size: usize,
}

// ---------------------------------------------------------------------------
// Active cell edit
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct EditState {
    node_id: String,
    text: String,
}

// ---------------------------------------------------------------------------
// File dialog state
// ---------------------------------------------------------------------------

/// Which file operation is pending.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FileOp {
    /// Creating a new project — `path_buf` is the target directory.
    New,
    /// Opening an existing project file or directory.
    Open,
    /// Saving to a new directory (Save As / first save).
    SaveAs,
}

/// State for the in-app path-input dialog.
struct FileDialog {
    op: FileOp,
    /// The text the user is typing into the path field.
    path_text: String,
    /// Error message to show inside the dialog (e.g. parse/IO failure).
    error: Option<String>,
}

impl FileDialog {
    fn new(op: FileOp, initial: &str) -> Self {
        Self { op, path_text: initial.to_owned(), error: None }
    }
}

// ---------------------------------------------------------------------------
// NemclassApp
// ---------------------------------------------------------------------------

pub struct NemclassApp {
    // Backend / process
    registry: ProviderRegistry,
    backend_names: Vec<String>,
    selected_backend: String,
    process_list: Vec<ProcessEntry>,
    process_list_status: String,
    selected_process_idx: Option<usize>,
    process: Option<Process>,
    attached_name: Option<String>,
    last_error: Option<String>,

    // Project
    project: Project,
    /// The shared node-type registry (built once with `with_builtins()`).
    node_registry: NodeRegistry,
    /// Directory that contains `project.nemclass`, or `None` if unsaved.
    project_dir: Option<PathBuf>,
    selected_class: Option<Uuid>,

    // Memory view
    node_snapshots: Vec<NodeSnapshot>,
    class_base: Option<usize>,
    mem_buf: Vec<u8>,
    last_snapshot: Option<Instant>,
    snapshot_interval: Duration,
    collapsed: HashSet<String>,
    edit_state: Option<EditState>,

    // Scripting seam
    event_bus: EventBus,

    // In-app file dialog
    file_dialog: Option<FileDialog>,
    /// Non-modal status message shown below the menu bar (e.g. last save path).
    status_msg: Option<String>,

    // Central panel tab
    central_tab: CentralTab,

    // Scanner panel
    scanner_panel: ScannerPanel,

    // Debugger panel
    debugger_panel: DebuggerPanel,
}

impl NemclassApp {
    pub fn new() -> Self {
        let registry = ProviderRegistry::default();
        let mut backend_names: Vec<String> = registry.names().map(str::to_owned).collect();
        backend_names.sort();
        let selected_backend = backend_names.first().cloned().unwrap_or_default();

        let node_registry = NodeRegistry::new().with_builtins();
        let project = demo_project();

        // Pre-select the first (demo) class.
        let selected_class = project.classes_in_order().next().map(|c| c.uuid);

        Self {
            registry,
            backend_names,
            selected_backend,
            process_list: Vec::new(),
            process_list_status: "Press Refresh to enumerate processes.".into(),
            selected_process_idx: None,
            process: None,
            attached_name: None,
            last_error: None,
            project,
            node_registry,
            project_dir: None,
            selected_class,
            node_snapshots: Vec::new(),
            class_base: None,
            mem_buf: Vec::new(),
            last_snapshot: None,
            snapshot_interval: Duration::from_millis(100),
            collapsed: HashSet::new(),
            edit_state: None,
            event_bus: EventBus::new(),
            file_dialog: None,
            status_msg: Some("Demo project loaded. Use File > New or Open to load a project.".into()),
            central_tab: CentralTab::MemoryView,
            scanner_panel: ScannerPanel::new(),
            debugger_panel: DebuggerPanel::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Process actions
    // -----------------------------------------------------------------------

    fn do_refresh(&mut self) {
        let Some(provider) = self.registry.get(&self.selected_backend) else {
            self.process_list_status = format!("Backend '{}' not found.", self.selected_backend);
            return;
        };
        match provider.enumerate_processes() {
            Ok(list) => {
                self.process_list_status = format!("{} processes", list.len());
                self.process_list = list;
                self.selected_process_idx = None;
            }
            Err(e) => {
                self.process_list_status = format!("Error: {e}");
                self.process_list.clear();
            }
        }
    }

    fn do_attach(&mut self) {
        let Some(idx) = self.selected_process_idx else {
            self.last_error = Some("No process selected.".into());
            return;
        };
        let Some(entry) = self.process_list.get(idx) else {
            self.last_error = Some("Selection out of range.".into());
            return;
        };
        let pid = entry.id as libc::pid_t;
        let name = entry.name.clone();

        // Detach first.
        if self.process.is_some() {
            self.event_bus.publish(&Event::OnDetach);
            self.process = None;
            self.attached_name = None;
            self.clear_memory_state();
        }

        let Some(provider) = self.registry.get(&self.selected_backend) else {
            self.last_error = Some(format!("Backend '{}' not found.", self.selected_backend));
            return;
        };

        match provider.open(pid) {
            Ok(proc) => {
                self.attached_name = Some(if name.is_empty() {
                    format!("pid:{pid}")
                } else {
                    name.clone()
                });
                self.process = Some(proc);
                self.last_error = None;
                self.last_snapshot = None;
                self.event_bus.publish(&Event::OnAttach {
                    pid,
                    name: Some(name),
                });
            }
            Err(e) => {
                self.last_error = Some(format!("Attach failed: {e}"));
            }
        }
    }

    fn do_detach(&mut self) {
        if self.process.is_some() {
            self.event_bus.publish(&Event::OnDetach);
            self.process = None;
            self.attached_name = None;
            self.clear_memory_state();
            self.last_error = None;
            self.scanner_panel.on_detach();
            self.debugger_panel.on_detach();
        }
    }

    fn clear_memory_state(&mut self) {
        self.class_base = None;
        self.node_snapshots.clear();
        self.mem_buf.clear();
        self.edit_state = None;
    }

    // -----------------------------------------------------------------------
    // Project actions (called after the dialog confirms a path)
    // -----------------------------------------------------------------------

    /// Replace the in-memory project with `new_project` and update UI state.
    fn replace_project(&mut self, new_project: Project, new_dir: Option<PathBuf>) {
        // Reset selection to the first class in the new project (if any).
        let first_class = new_project.classes_in_order().next().map(|c| c.uuid);
        self.project = new_project;
        self.project_dir = new_dir;
        self.selected_class = first_class;
        self.clear_memory_state();
        self.last_snapshot = None;
        self.collapsed.clear();
    }

    /// Execute the New action: create a blank project at `dir`.
    fn exec_new(&mut self, dir: PathBuf) -> Result<(), String> {
        let new_project = Project::new(
            dir.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Untitled".into()),
        );
        create_project_at(&dir, &new_project, &self.node_registry, false)
            .map_err(|e| format!("New project failed: {e}"))?;
        let project_name = new_project.name.clone();
        self.replace_project(new_project, Some(dir.clone()));
        self.status_msg = Some(format!(
            "Created project '{}' at {}",
            project_name,
            dir.display()
        ));
        Ok(())
    }

    /// Execute the Open action: load from `path` (file or dir).
    fn exec_open(&mut self, path: PathBuf) -> Result<(), String> {
        let (loaded, proj_dir) =
            load_project_from(&path, &self.node_registry)
                .map_err(|e| format!("Open failed: {e}"))?;
        let project_name = loaded.name.clone();
        let dir_display = proj_dir.display().to_string();
        self.replace_project(loaded, Some(proj_dir));
        self.status_msg = Some(format!(
            "Opened '{}' from {}",
            project_name, dir_display
        ));
        Ok(())
    }

    /// Execute the Save action.  If `project_dir` is `None`, route to Save As dialog.
    fn exec_save(&mut self) -> Result<(), String> {
        if let Some(dir) = self.project_dir.clone() {
            save_project_to(&dir, &self.project, &self.node_registry)
                .map_err(|e| format!("Save failed: {e}"))?;
            self.status_msg = Some(format!("Saved to {}", dir.display()));
            Ok(())
        } else {
            // No project dir yet — open the Save As dialog.
            self.file_dialog = Some(FileDialog::new(FileOp::SaveAs, ""));
            Ok(())
        }
    }

    /// Execute the Save As action: save the current project to a chosen
    /// directory, scaffolding it like New (dirs + package.json/tsconfig/
    /// nemclass.d.ts). Overwrites any existing `project.nemclass` there — the
    /// directory was explicitly chosen, so overwrite is intended.
    fn exec_save_as(&mut self, dir: PathBuf) -> Result<(), String> {
        create_project_at(&dir, &self.project, &self.node_registry, true)
            .map_err(|e| format!("Save As failed: {e}"))?;
        let dir_display = dir.display().to_string();
        self.project_dir = Some(dir);
        self.status_msg = Some(format!("Saved to {dir_display}"));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Memory snapshot
    // -----------------------------------------------------------------------

    fn take_snapshot(&mut self) {
        let Some(uuid) = self.selected_class else { return; };
        let Some(proc) = &self.process else {
            self.rebuild_snapshots_from_buf(uuid);
            return;
        };

        let modules: Vec<ModuleInfoWithName> = match proc.modules() {
            Ok(it) => it.collect(),
            Err(e) => {
                self.last_error = Some(format!("modules(): {e}"));
                Vec::new()
            }
        };

        let formula = self.project.get_class(&uuid)
            .map(|c| c.address_formula.clone())
            .unwrap_or_default();

        let base = if formula.trim().is_empty() {
            None
        } else {
            let reader = ProcessReader::new(proc, modules);
            match resolve_formula(&formula, &reader, &reader) {
                Ok(addr) => Some(addr),
                Err(ModelError::ResolveError(msg)) => {
                    self.last_error = Some(format!("Formula: {msg}"));
                    None
                }
                Err(e) => {
                    self.last_error = Some(format!("Formula: {e}"));
                    None
                }
            }
        };
        self.class_base = base;

        let total_size = self.project.get_class(&uuid)
            .map(|c| c.memory_size())
            .unwrap_or(0);

        let buf = if let (Some(addr), true) = (base, total_size > 0) {
            read_process_buf(proc, addr, total_size)
        } else {
            vec![0u8; total_size]
        };
        self.mem_buf = buf;

        self.rebuild_snapshots_from_buf(uuid);
        self.last_snapshot = Some(Instant::now());
    }

    fn rebuild_snapshots_from_buf(&mut self, uuid: Uuid) {
        self.node_snapshots.clear();
        if let Some(class) = self.project.get_class(&uuid) {
            let base = self.class_base.unwrap_or(0);
            flatten_nodes(
                &class.children,
                base,
                0,
                0,
                &self.mem_buf,
                String::new(),
                &mut self.node_snapshots,
            );
        }
    }

    // -----------------------------------------------------------------------
    // Write-back
    // -----------------------------------------------------------------------

    fn commit_edit(&mut self) {
        let Some(edit) = self.edit_state.take() else { return; };
        let Some(proc) = &self.process else { return; };

        let (addr, type_tag) = match self.node_snapshots.iter().find(|s| s.id_path == edit.node_id) {
            Some(s) => (s.address, s.type_tag),
            None => return,
        };

        match write_parsed(proc, addr, type_tag, edit.text.trim()) {
            Ok(()) => {
                self.last_error = None;
                self.last_snapshot = None;
            }
            Err(e) => {
                self.last_error = Some(format!("Write: {e}"));
            }
        }
    }
}

impl Default for NemclassApp {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// eframe::App — egui 0.35 API
// ---------------------------------------------------------------------------

impl eframe::App for NemclassApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let needs_snapshot = self.selected_class.is_some()
            && self.file_dialog.is_none()   // don't snapshot while dialog is open
            && self
                .last_snapshot
                .map(|t| t.elapsed() >= self.snapshot_interval)
                .unwrap_or(true);

        if needs_snapshot {
            self.take_snapshot();
        }

        // Drive scanner freeze write-back and debugger event polling.
        self.scanner_panel.tick_freeze();
        self.debugger_panel.tick_events();

        if self.process.is_some() {
            ctx.request_repaint_after(self.snapshot_interval);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Menu bar (outermost — rendered before any panels).
        egui::Panel::top("menu_bar")
            .resizable(false)
            .show(ui, |ui| self.show_menu_bar(ui));

        // File dialog (modal overlay — rendered as a Window).
        // We drive the dialog from outside the closure to avoid borrow issues.
        if self.file_dialog.is_some() {
            self.show_file_dialog(ui.ctx());
        }

        // Address bar.
        egui::Panel::top("address_bar")
            .resizable(false)
            .show(ui, |ui| self.show_address_bar(ui));

        egui::Panel::left("left_panel")
            .resizable(true)
            .show(ui, |ui| self.show_left_panel(ui));

        egui::CentralPanel::default().show(ui, |ui| self.show_central_panel(ui));
    }
}

// ---------------------------------------------------------------------------
// Sub-panel implementations
// ---------------------------------------------------------------------------

impl NemclassApp {
    // -----------------------------------------------------------------------
    // Menu bar
    // -----------------------------------------------------------------------

    fn show_menu_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            // Project name / path indicator.
            let title = match &self.project_dir {
                Some(dir) => format!(
                    "{} — {}",
                    self.project.name,
                    dir.display()
                ),
                None => format!("{} (unsaved)", self.project.name),
            };
            ui.strong(&title);

            ui.separator();

            if ui.button("New").clicked() && self.file_dialog.is_none() {
                self.file_dialog = Some(FileDialog::new(FileOp::New, ""));
            }
            if ui.button("Open").clicked() && self.file_dialog.is_none() {
                self.file_dialog = Some(FileDialog::new(FileOp::Open, ""));
            }
            if ui.button("Save").clicked() && self.file_dialog.is_none()
                && let Err(e) = self.exec_save() {
                    self.last_error = Some(e);
            }
            if ui.button("Save As").clicked() && self.file_dialog.is_none() {
                let hint = self.project_dir
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                self.file_dialog = Some(FileDialog::new(FileOp::SaveAs, &hint));
            }

            // Status message (right-aligned).
            if let Some(msg) = &self.status_msg {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(msg);
                });
            }
        });
    }

    // -----------------------------------------------------------------------
    // File dialog (in-app path input)
    // -----------------------------------------------------------------------

    fn show_file_dialog(&mut self, ctx: &egui::Context) {
        // Extract the dialog state to avoid holding &self borrow inside closure.
        let Some(ref dialog) = self.file_dialog else { return; };
        let title = match dialog.op {
            FileOp::New    => "New Project — choose target directory",
            FileOp::Open   => "Open Project — enter path to project.nemclass or its directory",
            FileOp::SaveAs => "Save As — choose target directory",
        };
        let op = dialog.op.clone();

        // We need owned copies to avoid borrow-checker issues inside the closure.
        let mut path_text = dialog.path_text.clone();
        let dialog_error = dialog.error.clone();
        let mut close = false;
        let mut confirm = false;

        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_min_width(420.0);

                let hint = match op {
                    FileOp::New    => "e.g. /home/user/myproject",
                    FileOp::Open   => "e.g. /home/user/myproject  or  /home/user/myproject/project.nemclass",
                    FileOp::SaveAs => "e.g. /home/user/myproject",
                };
                ui.label(hint);
                ui.add_space(4.0);

                let resp = ui.add(
                    egui::TextEdit::singleline(&mut path_text)
                        .desired_width(f32::INFINITY)
                        .hint_text(hint),
                );
                // Allow confirming with Enter.
                let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));
                if resp.lost_focus() && enter_pressed {
                    confirm = true;
                }

                ui.add_space(4.0);

                if let Some(err) = &dialog_error {
                    ui.colored_label(egui::Color32::RED, err);
                    ui.add_space(4.0);
                }

                ui.horizontal(|ui| {
                    if ui.button("Confirm").clicked() {
                        confirm = true;
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });

        // Write back any edits to path_text.
        if let Some(ref mut d) = self.file_dialog {
            d.path_text = path_text.clone();
        }

        if close {
            self.file_dialog = None;
            return;
        }

        if confirm {
            let path = PathBuf::from(path_text.trim());
            if path.as_os_str().is_empty() {
                if let Some(ref mut d) = self.file_dialog {
                    d.error = Some("Path cannot be empty.".into());
                }
                return;
            }

            let result = match op {
                FileOp::New    => self.exec_new(path),
                FileOp::Open   => self.exec_open(path),
                FileOp::SaveAs => self.exec_save_as(path),
            };

            match result {
                Ok(()) => {
                    self.file_dialog = None;
                    // Clear any prior errors on success.
                    self.last_error = None;
                }
                Err(e) => {
                    // Show the error inside the dialog so the user can correct the path.
                    if let Some(ref mut d) = self.file_dialog {
                        d.error = Some(e);
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Address bar
    // -----------------------------------------------------------------------

    fn show_address_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let class_name = self
                .selected_class
                .and_then(|id| self.project.get_class(&id))
                .map(|c| c.name.clone())
                .unwrap_or_else(|| "<no class>".into());
            ui.strong("Class:");
            ui.label(&class_name);
            ui.separator();

            ui.strong("Base:");
            match self.class_base {
                Some(b) => { ui.monospace(format!("0x{b:016X}")); }
                None    => { ui.label("–"); }
            }
            ui.separator();

            if let Some(uuid) = self.selected_class
                && let Some(class) = self.project.get_class_mut(&uuid)
            {
                    ui.strong("Formula:");
                    if ui.text_edit_singleline(&mut class.address_formula).changed() {
                        self.last_snapshot = None;
                        self.class_base = None;
                    }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match &self.attached_name {
                    Some(n) => ui.colored_label(egui::Color32::GREEN, format!("Attached: {n}")),
                    None    => ui.colored_label(egui::Color32::GRAY, "Not attached"),
                };
            });
        });
    }

    // -----------------------------------------------------------------------
    // Left panel
    // -----------------------------------------------------------------------

    fn show_left_panel(&mut self, ui: &mut egui::Ui) {
        ui.set_min_width(220.0);

        // Backend selector.
        ui.heading("Backend");
        let backend_names = self.backend_names.clone();
        egui::ComboBox::from_id_salt("backend_combo")
            .selected_text(&self.selected_backend)
            .show_ui(ui, |ui| {
                for name in &backend_names {
                    ui.selectable_value(&mut self.selected_backend, name.clone(), name.as_str());
                }
            });

        ui.separator();

        // Process list.
        ui.heading("Processes");
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.do_refresh();
            }
            if self.selected_process_idx.is_some() && ui.button("Attach").clicked() {
                self.do_attach();
            }
            if self.process.is_some() && ui.button("Detach").clicked() {
                self.do_detach();
            }
        });
        ui.label(&self.process_list_status);

        egui::ScrollArea::vertical()
            .id_salt("proc_list")
            .max_height(180.0)
            .show(ui, |ui| {
                let mut new_sel = self.selected_process_idx;
                for (i, entry) in self.process_list.iter().enumerate() {
                    let label = format!("{} ({})", entry.name, entry.id);
                    let selected = self.selected_process_idx == Some(i);
                    if ui.selectable_label(selected, &label).clicked() {
                        new_sel = Some(i);
                    }
                }
                self.selected_process_idx = new_sel;
            });

        if let Some(err) = &self.last_error.clone() {
            ui.colored_label(egui::Color32::RED, err);
        }

        ui.separator();

        // Class list.
        ui.heading("Classes");
        if ui.button("+ Add class").clicked() {
            let cls = blank_class();
            let uuid = cls.uuid;
            self.project.add_class(cls);
            self.selected_class = Some(uuid);
            self.last_snapshot = None;
            self.clear_memory_state();
        }

        egui::ScrollArea::vertical()
            .id_salt("class_list")
            .show(ui, |ui| {
                let uuids: Vec<Uuid> = self
                    .project
                    .classes_in_order()
                    .map(|c| c.uuid)
                    .collect();
                for uuid in uuids {
                    let label = self
                        .project
                        .get_class(&uuid)
                        .map(|c| c.name.clone())
                        .unwrap_or_else(|| uuid.to_string());
                    let selected = self.selected_class == Some(uuid);
                    if ui.selectable_label(selected, &label).clicked()
                        && self.selected_class != Some(uuid)
                    {
                        self.selected_class = Some(uuid);
                        self.last_snapshot = None;
                        self.clear_memory_state();
                    }
                }
            });

        ui.separator();

        // Snapshot interval.
        ui.heading("Live Update");
        let mut ms = self.snapshot_interval.as_millis() as u64;
        ui.horizontal(|ui| {
            ui.label("Interval (ms):");
            if ui
                .add(egui::DragValue::new(&mut ms).range(50..=5000))
                .changed()
            {
                self.snapshot_interval = Duration::from_millis(ms);
            }
        });
    }

    // -----------------------------------------------------------------------
    // Central panel — tab bar + dispatching
    // -----------------------------------------------------------------------

    fn show_central_panel(&mut self, ui: &mut egui::Ui) {
        // Tab bar.
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.central_tab, CentralTab::MemoryView, "Memory View");
            ui.selectable_value(&mut self.central_tab, CentralTab::Scanner,    "Scanner");
            ui.selectable_value(&mut self.central_tab, CentralTab::Debugger,   "Debugger");
        });
        ui.separator();

        match self.central_tab {
            CentralTab::MemoryView => self.show_class_view(ui),
            CentralTab::Scanner    => self.show_scanner_tab(ui),
            CentralTab::Debugger   => self.show_debugger_tab(ui),
        }
    }

    fn show_scanner_tab(&mut self, ui: &mut egui::Ui) {
        // Derive the pid from the attached process on Linux; scanner accepts
        // Pid (u32 alias in nemclass-core) but ProcessTarget::attach takes Pid.
        #[cfg(target_os = "linux")]
        let pid: Option<nemclass_core::Pid> = self.process.as_ref().map(|p| p.pid());
        #[cfg(not(target_os = "linux"))]
        let pid: Option<nemclass_core::Pid> = None;

        let process_ref = self.process.as_ref();
        let selected_class = self.selected_class;
        let project = &mut self.project;

        self.scanner_panel.show(
            ui,
            process_ref,
            pid,
            |addr| {
                // "Add to class" callback: append a Hex64 address node to the
                // currently-selected class (or the first class in the project).
                use nemclass_model::node::builtins::Hex64Node;
                let uuid = selected_class
                    .or_else(|| project.classes_in_order().next().map(|c| c.uuid));
                if let Some(uuid) = uuid
                    && let Some(class) = project.get_class_mut(&uuid)
                {
                    let label = format!("scan_{addr:#x}");
                    let mut node = Hex64Node::new(&label);
                    node.comment = format!("Scanner result 0x{addr:016X}");
                    class.children.push(Box::new(node));
                }
            },
        );
    }

    fn show_debugger_tab(&mut self, ui: &mut egui::Ui) {
        #[cfg(target_os = "linux")]
        let pid: Option<libc::pid_t> = self.process.as_ref().map(|p| p.pid() as libc::pid_t);
        #[cfg(not(target_os = "linux"))]
        let pid: Option<i32> = None;

        self.debugger_panel.show(ui, pid);
    }

    // -----------------------------------------------------------------------
    // Central panel (memory table)
    // -----------------------------------------------------------------------

    fn show_class_view(&mut self, ui: &mut egui::Ui) {
        if self.selected_class.is_none() {
            ui.centered_and_justified(|ui| {
                ui.label("Select a class from the left panel.");
            });
            return;
        }

        if self.process.is_none() {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Not attached — showing demo layout (zeroed buffer).",
            );
            ui.add_space(4.0);
        }

        if self.node_snapshots.is_empty()
            && let Some(uuid) = self.selected_class
        {
            self.rebuild_snapshots_from_buf(uuid);
        }

        if self.node_snapshots.is_empty() {
            ui.label("No nodes in this class.");
            return;
        }

        let visible: Vec<usize> =
            build_visible_rows(&self.node_snapshots, &self.collapsed);

        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = text_height + 4.0;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::initial(140.0).at_least(80.0))   // Address
            .column(Column::initial(60.0).at_least(40.0))    // Offset
            .column(Column::initial(90.0).at_least(60.0))    // Type
            .column(Column::initial(120.0).at_least(60.0))   // Name
            .column(Column::remainder().at_least(80.0))      // Value
            .column(Column::initial(150.0).at_least(60.0))   // Comment
            .header(row_height + 2.0, |mut header| {
                header.col(|ui| { ui.strong("Address"); });
                header.col(|ui| { ui.strong("Offset"); });
                header.col(|ui| { ui.strong("Type"); });
                header.col(|ui| { ui.strong("Name"); });
                header.col(|ui| { ui.strong("Value"); });
                header.col(|ui| { ui.strong("Comment"); });
            })
            .body(|body| {
                body.rows(row_height, visible.len(), |mut row| {
                    let row_idx = row.index();
                    let Some(&snap_idx) = visible.get(row_idx) else { return; };
                    let snap = &self.node_snapshots[snap_idx];

                    let address     = snap.address;
                    let offset      = snap.offset;
                    let type_tag    = snap.type_tag;
                    let name        = snap.name.clone();
                    let comment     = snap.comment.clone();
                    let value       = snap.rendered.value.clone();
                    let depth       = snap.depth;
                    let has_children = snap.has_children;
                    let id_path     = snap.id_path.clone();

                    row.col(|ui| { ui.monospace(format!("0x{address:016X}")); });
                    row.col(|ui| { ui.monospace(format!("+{offset:#06X}")); });
                    row.col(|ui| { ui.label(type_tag); });

                    row.col(|ui| {
                        ui.horizontal(|ui| {
                            let indent = depth as f32 * 12.0;
                            if indent > 0.0 { ui.add_space(indent); }

                            if has_children {
                                let collapsed = self.collapsed.contains(&id_path);
                                let arrow = if collapsed { "▶" } else { "▼" };
                                if ui.small_button(arrow).clicked() {
                                    if collapsed {
                                        self.collapsed.remove(&id_path);
                                    } else {
                                        self.collapsed.insert(id_path.clone());
                                    }
                                }
                            } else {
                                ui.add_space(16.0);
                            }
                            ui.label(&name);
                        });
                    });

                    row.col(|ui| {
                        let editing = self
                            .edit_state
                            .as_ref()
                            .is_some_and(|e| e.node_id == id_path);

                        if is_editable(type_tag) && self.process.is_some() {
                            if editing {
                                let resp = ui.text_edit_singleline(
                                    &mut self.edit_state.as_mut().unwrap().text,
                                );
                                let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                                let escape = ui.input(|i| i.key_pressed(egui::Key::Escape));
                                if resp.lost_focus() || enter {
                                    self.commit_edit();
                                } else if escape {
                                    self.edit_state = None;
                                }
                            } else {
                                let resp = ui.selectable_label(false, &value);
                                if resp.double_clicked() {
                                    let seed = value
                                        .strip_prefix("0x")
                                        .or_else(|| value.strip_prefix("0X"))
                                        .unwrap_or(&value)
                                        .to_owned();
                                    self.edit_state = Some(EditState {
                                        node_id: id_path.clone(),
                                        text: seed,
                                    });
                                }
                            }
                        } else {
                            ui.label(&value);
                        }
                    });

                    row.col(|ui| { ui.label(&comment); });
                });
            });
    }
}

// ---------------------------------------------------------------------------
// Tree flattening
// ---------------------------------------------------------------------------

fn flatten_nodes(
    children: &[Box<dyn Node>],
    base_addr: usize,
    base_offset: usize,
    depth: usize,
    buf: &[u8],
    parent_id: String,
    out: &mut Vec<NodeSnapshot>,
) {
    let mut cur_offset = base_offset;
    for (i, node) in children.iter().enumerate() {
        let id_path = if parent_id.is_empty() {
            i.to_string()
        } else {
            format!("{parent_id}.{i}")
        };

        let rendered = node.render(buf, cur_offset);
        let has_children = !node.children().is_empty();
        let size = node.memory_size();

        out.push(NodeSnapshot {
            address: base_addr.wrapping_add(cur_offset),
            offset: cur_offset,
            depth,
            id_path: id_path.clone(),
            rendered,
            has_children,
            type_tag: node.type_tag(),
            name: node.name().to_owned(),
            comment: node.comment().to_owned(),
            _memory_size: size,
        });

        if has_children {
            flatten_nodes(
                node.children(),
                base_addr,
                cur_offset,
                depth + 1,
                buf,
                id_path,
                out,
            );
        }

        cur_offset = cur_offset.wrapping_add(size);
    }
}

fn build_visible_rows(
    snapshots: &[NodeSnapshot],
    collapsed: &HashSet<String>,
) -> Vec<usize> {
    let mut visible = Vec::with_capacity(snapshots.len());
    'snap: for (i, snap) in snapshots.iter().enumerate() {
        let parts: Vec<&str> = snap.id_path.split('.').collect();
        for len in 1..parts.len() {
            let ancestor = parts[..len].join(".");
            if collapsed.contains(&ancestor) {
                continue 'snap;
            }
        }
        visible.push(i);
    }
    visible
}

// ---------------------------------------------------------------------------
// Write-back
// ---------------------------------------------------------------------------

fn write_parsed(proc: &Process, addr: usize, type_tag: &str, text: &str) -> Result<(), String> {
    let raw = text.trim_start_matches("0x").trim_start_matches("0X");

    macro_rules! parse_write {
        ($ty:ty) => {{
            let v: $ty = raw.parse().map_err(|e: <$ty as std::str::FromStr>::Err| e.to_string())?;
            proc.write::<$ty>(addr, v).map_err(|e| e.to_string())
        }};
    }
    macro_rules! parse_write_hex {
        ($ty:ty) => {{
            let v = <$ty>::from_str_radix(raw, 16).map_err(|e| e.to_string())?;
            proc.write::<$ty>(addr, v).map_err(|e| e.to_string())
        }};
    }

    match type_tag {
        "Int8"    => parse_write!(i8),
        "Int16"   => parse_write!(i16),
        "Int32"   => parse_write!(i32),
        "Int64"   => parse_write!(i64),
        "UInt8"   => parse_write!(u8),
        "UInt16"  => parse_write!(u16),
        "UInt32"  => parse_write!(u32),
        "UInt64"  => parse_write!(u64),
        "Hex8"    => parse_write_hex!(u8),
        "Hex16"   => parse_write_hex!(u16),
        "Hex32"   => parse_write_hex!(u32),
        "Hex64"   => parse_write_hex!(u64),
        "Float"   => parse_write!(f32),
        "Double"  => parse_write!(f64),
        "Bool"    => {
            let v: u8 = match text.to_ascii_lowercase().as_str() {
                "true" | "1" => 1,
                _ => 0,
            };
            proc.write::<u8>(addr, v).map_err(|e| e.to_string())
        }
        "Pointer" => parse_write_hex!(u64),
        _ => Err(format!("'{type_tag}' is not directly writable")),
    }
}

fn is_editable(type_tag: &str) -> bool {
    matches!(
        type_tag,
        "Int8" | "Int16" | "Int32" | "Int64"
            | "UInt8" | "UInt16" | "UInt32" | "UInt64"
            | "Hex8" | "Hex16" | "Hex32" | "Hex64"
            | "Float" | "Double" | "Bool" | "Pointer"
    )
}

// ---------------------------------------------------------------------------
// Bulk memory read helper
// ---------------------------------------------------------------------------

fn read_process_buf(proc: &Process, addr: usize, size: usize) -> Vec<u8> {
    if size == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size];
    let _ = proc.read_buf(addr, &mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Demo project (used as the in-memory default on first launch)
// ---------------------------------------------------------------------------

fn demo_project() -> Project {
    use nemclass_model::node::builtins::{
        ArrayNode, BoolNode, Float32Node, Float64Node, Hex32Node, Hex64Node,
        Int32Node, PointerNode, UInt8Node, Utf8TextNode,
    };

    let mut project = Project::new("Demo Project");
    let mut player = ClassNode::new("PlayerObject");
    player.address_formula = String::new();
    player.comment = "Attach to a process and set a formula to go live.".into();

    { let mut n = Int32Node::new("health");      n.comment = "Current HP".into();           player.children.push(Box::new(n)); }
    { let mut n = Int32Node::new("max_health");  n.comment = "Max HP".into();               player.children.push(Box::new(n)); }
    { let mut n = Float32Node::new("mana");      n.comment = "Mana pool".into();            player.children.push(Box::new(n)); }
    { let mut n = Float64Node::new("pos_x");     n.comment = "X position".into();           player.children.push(Box::new(n)); }
    { let mut n = Float64Node::new("pos_y");     n.comment = "Y position".into();           player.children.push(Box::new(n)); }
    { let mut n = Float64Node::new("pos_z");     n.comment = "Z position".into();           player.children.push(Box::new(n)); }
    { let mut n = Hex32Node::new("flags");       n.comment = "State flags (hex)".into();    player.children.push(Box::new(n)); }
    { let mut n = Hex64Node::new("vtable");      n.comment = "vptr (hex)".into();           player.children.push(Box::new(n)); }
    { let mut n = PointerNode::new("next");      n.comment = "Linked list next".into();     player.children.push(Box::new(n)); }
    { let mut n = BoolNode::new("alive");        n.comment = "Is alive?".into();            player.children.push(Box::new(n)); }
    { let mut n = UInt8Node::new("level");       n.comment = "Level (1-255)".into();        player.children.push(Box::new(n)); }
    { let mut n = Utf8TextNode::new("name", 32); n.comment = "Name (UTF-8, 32 B)".into();  player.children.push(Box::new(n)); }
    { let mut n = ArrayNode::new("inv_ids", 10, 4); n.comment = "10 x u32 item IDs".into(); player.children.push(Box::new(n)); }

    project.add_class(player);
    project
}

/// A blank class for "Add class" in an open project.
fn blank_class() -> ClassNode {
    use nemclass_model::node::builtins::Int32Node;
    let mut cls = ClassNode::new("NewClass");
    cls.children.push(Box::new(Int32Node::new("field_0")));
    cls
}
