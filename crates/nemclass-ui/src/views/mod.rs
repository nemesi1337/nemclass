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
mod memory_viewer;
mod disassembly;

pub use scanner_panel::ScannerPanel;
pub use debugger_panel::DebuggerPanel;
pub use memory_viewer::MemoryViewer;
pub use disassembly::DisassemblyPanel;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_core::{ModuleInfoWithName, Process, ProcessEntry, ProviderRegistry};
#[cfg(target_os = "linux")]
use nemclass_core::{KernelProvider, LINUX_KERNEL};
#[cfg(target_os = "linux")]
use crate::views::debugger_panel::parse_hex_key;
use nemclass_model::{ClassNode, ModelError, Node, NodeRegistry, Project, RenderedValue, resolve_formula};
#[cfg(target_os = "linux")]
use nemclass_model::serialize::NodeDef;
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
    MemoryViewer,
    Disassembly,
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
// Live child rows injected below VTable / Function / FunctionPtr nodes
// (Linux only — on other platforms these type_tags render their static value)
// ---------------------------------------------------------------------------

/// One live child row for a VTable node: a single vtable slot.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct VtableMethodRow {
    /// Index of this slot in the vtable array (0-based).
    slot: usize,
    /// Absolute address of the function pointer this slot holds.
    fn_ptr: u64,
    /// Resolved symbol name, if `resolve_symbol` succeeded.
    symbol: Option<String>,
}

/// One live child row for a Function / FunctionPtr node: a single instruction.
#[cfg(target_os = "linux")]
#[derive(Clone)]
struct DisasmRow {
    /// Virtual address of the instruction.
    address: u64,
    /// Hex-formatted bytes of the instruction (space-separated, e.g. "48 89 e5").
    bytes_hex: String,
    /// Formatted assembly text (e.g. "push rbp").
    instruction: String,
    /// For call/jmp with a resolved target: the target address, so the UI can
    /// render a "disasm" link.
    target: Option<u64>,
}

/// The live-row cache entry for one node.
#[cfg(target_os = "linux")]
enum LiveEntry {
    Vtable(Vec<VtableMethodRow>),
    Disasm(Vec<DisasmRow>),
    /// No process attached — placeholder shown when the node is expanded.
    NotAttached,
}

/// Augmented view row: either an index into `node_snapshots` or a live child.
enum ViewRow {
    Snap(usize),
    #[cfg(target_os = "linux")]
    VtableMethod { _parent_id: String, depth: usize, row: VtableMethodRow },
    #[cfg(target_os = "linux")]
    DisasmInsn   { _parent_id: String, depth: usize, row: DisasmRow },
    #[cfg(target_os = "linux")]
    NotAttached  { _parent_id: String, depth: usize },
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
// Auto-dissect preview state
// ---------------------------------------------------------------------------

/// Pending preview from a completed `auto_dissect` call.
///
/// Displayed as an inline panel in the Memory View tab; the user can Accept
/// (replaces the class body) or Cancel (discards).
#[cfg(target_os = "linux")]
struct AutoDissectPreview {
    /// The NodeDefs returned by `auto_dissect`.
    defs: Vec<NodeDef>,
    /// The class UUID this dissect was run against (so Accept always targets
    /// the right class even if the user switches selection mid-preview).
    target_class: Uuid,
    /// Summary counts per type tag, e.g. `[("Pointer", 3), ("Int64", 5), …]`.
    summary: Vec<(String, usize)>,
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
    /// Hex text of the auth key the user typed; used by the kernel backend only.
    kernel_key: String,
    process_list: Vec<ProcessEntry>,
    process_list_status: String,
    /// Case-insensitive substring the process list is filtered by (matches the
    /// process name or pid). Empty shows everything.
    process_filter: String,
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

    // Auto-dissect controls (Memory View toolbar)
    /// Number of bytes to dissect (hex or decimal, user-editable).
    dissect_len_text: String,
    /// Pending dissect preview (Linux only; always-compiled field would need
    /// a unit-struct placeholder on other platforms, so we cfg-gate it).
    #[cfg(target_os = "linux")]
    dissect_preview: Option<AutoDissectPreview>,

    /// Live child-row cache for VTable/Function/FunctionPtr nodes.
    /// Keyed by `id_path`; populated on each snapshot tick for expanded nodes.
    /// Guarded by cfg so we don't carry dead fields on Windows.
    #[cfg(target_os = "linux")]
    live_cache: HashMap<String, LiveEntry>,
    /// Pending "open disassembly at this address" request collected during the
    /// draw phase of show_class_view; applied after the table body closes to
    /// avoid borrow conflicts.
    #[cfg(target_os = "linux")]
    pending_disasm_goto: Option<u64>,

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

    // Raw hex memory viewer panel
    memory_viewer: MemoryViewer,

    // Disassembly panel
    disassembly_panel: DisassemblyPanel,
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
            kernel_key: String::new(),
            process_list: Vec::new(),
            process_list_status: "Press Refresh to enumerate processes.".into(),
            process_filter: String::new(),
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
            dissect_len_text: "0x100".to_owned(),
            #[cfg(target_os = "linux")]
            dissect_preview: None,
            #[cfg(target_os = "linux")]
            live_cache: HashMap::new(),
            #[cfg(target_os = "linux")]
            pending_disasm_goto: None,
            event_bus: EventBus::new(),
            file_dialog: None,
            status_msg: Some("Demo project loaded. Use File > New or Open to load a project.".into()),
            central_tab: CentralTab::MemoryView,
            scanner_panel: ScannerPanel::new(),
            debugger_panel: DebuggerPanel::new(),
            memory_viewer: MemoryViewer::new(),
            disassembly_panel: DisassemblyPanel::new(),
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
            Ok(mut list) => {
                // Sort by name (case-insensitive), pid as a stable tiebreak, so a
                // busy machine — and especially a Wine prefix, where the game and
                // Wine's service processes share the loader — lists predictably
                // and is easy to scan.
                list.sort_by(|a, b| {
                    a.name
                        .to_ascii_lowercase()
                        .cmp(&b.name.to_ascii_lowercase())
                        .then(a.id.cmp(&b.id))
                });
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

    /// Re-registers a keyed `KernelProvider` when the linux-kernel backend is
    /// selected.  Called at the start of `do_attach` so the freshly-entered key
    /// is in effect before the provider's `open()` is called.  Idempotent and
    /// a no-op on non-Linux targets.
    #[cfg(target_os = "linux")]
    fn ensure_kernel_key_registered(&mut self) {
        if self.selected_backend == LINUX_KERNEL {
            self.registry.register(Box::new(
                KernelProvider::with_key(parse_hex_key(&self.kernel_key)),
            ));
        }
    }

    fn do_attach(&mut self) {
        // Ensure the keyed provider is in the registry before we look it up.
        #[cfg(target_os = "linux")]
        self.ensure_kernel_key_registered();

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
            self.memory_viewer.on_detach();
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
                self.memory_viewer.on_attach(&proc);
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
            self.memory_viewer.on_detach();
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
        #[cfg(target_os = "linux")]
        self.refresh_live_cache();
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
    // Live child-row cache — VTable / Function / FunctionPtr expansion
    // (Linux only; on other platforms these nodes just show their static value)
    // -----------------------------------------------------------------------

    #[cfg(target_os = "linux")]
    fn refresh_live_cache(&mut self) {
        use nemclass_core::{
            RegionIndex, classify_in_process, disassemble_function,
            PointerClass,
        };

        // Local helper: read 8 bytes as a little-endian u64.
        fn read_u64(proc: &Process, addr: usize) -> Option<u64> {
            let mut buf = [0u8; 8];
            let n = proc.read_buf(addr, &mut buf).unwrap_or(0);
            if n >= 8 { Some(u64::from_le_bytes(buf)) } else { None }
        }

        // Remove entries for nodes that are now collapsed or no longer present.
        let snapshots = &self.node_snapshots;
        let collapsed  = &self.collapsed;
        self.live_cache.retain(|id, _| {
            snapshots.iter().any(|s| s.id_path == *id)
                && !collapsed.contains(id)
        });

        let proc = match &self.process {
            Some(p) => p,
            None => {
                // No process: populate NotAttached for every expanded
                // VTable/Function/FunctionPtr that is not already cached.
                for snap in &self.node_snapshots {
                    if !matches!(snap.type_tag, "VTable" | "Function" | "FunctionPtr") {
                        continue;
                    }
                    if collapsed.contains(&snap.id_path) {
                        continue;
                    }
                    self.live_cache
                        .entry(snap.id_path.clone())
                        .or_insert(LiveEntry::NotAttached);
                }
                return;
            }
        };

        // Build a RegionIndex once per refresh (one /proc/<pid>/maps parse).
        let pid = proc.pid();
        let region_index = match RegionIndex::from_pid(pid) {
            Ok(idx) => idx,
            Err(_) => return,
        };

        // Clone the snapshot list metadata we need (addresses + type tags).
        // We need to avoid holding &self.process while also calling &mut self.live_cache.
        let targets: Vec<(String, &'static str, usize)> = self
            .node_snapshots
            .iter()
            .filter(|s| matches!(s.type_tag, "VTable" | "Function" | "FunctionPtr"))
            .filter(|s| !collapsed.contains(&s.id_path))
            .map(|s| (s.id_path.clone(), s.type_tag, s.address))
            .collect();

        for (id_path, type_tag, node_addr) in targets {
            // Only refresh if not already cached (cache cleared above on collapse).
            if self.live_cache.contains_key(&id_path) {
                continue;
            }

            match type_tag {
                "VTable" => {
                    // Read the 8-byte vptr stored at node_addr.
                    let vtable_addr = match read_u64(proc, node_addr) {
                        Some(v) if v != 0 => v,
                        _ => {
                            self.live_cache.insert(id_path, LiveEntry::Vtable(Vec::new()));
                            continue;
                        }
                    };

                    // Walk the vtable array: read up to 64 function pointers,
                    // stopping at the first non-executable entry.
                    const MAX_VTABLE_METHODS: usize = 64;
                    let mut methods = Vec::new();
                    for slot in 0..MAX_VTABLE_METHODS {
                        let entry_addr = match (vtable_addr as usize).checked_add(slot * 8) {
                            Some(a) => a,
                            None => break,
                        };
                        let fn_ptr = match read_u64(proc, entry_addr) {
                            Some(v) if v != 0 => v,
                            _ => break,
                        };
                        // Stop if not executable (non-code pointer ends the vtable).
                        let fn_usize = match usize::try_from(fn_ptr) {
                            Ok(a) => a,
                            Err(_) => break,
                        };
                        let class = classify_in_process(fn_ptr, &region_index, proc);
                        if !matches!(class, PointerClass::CodePtr) {
                            break;
                        }
                        // Try to resolve a symbol name.
                        let symbol = proc
                            .resolve_symbol(fn_usize)
                            .ok()
                            .flatten();
                        methods.push(VtableMethodRow { slot, fn_ptr, symbol });
                    }
                    self.live_cache.insert(id_path, LiveEntry::Vtable(methods));
                }

                "Function" | "FunctionPtr" => {
                    // For FunctionPtr: the node holds a pointer-to-function;
                    // read that pointer first, then disassemble at it.
                    // For Function: the node address is the code address directly.
                    let code_addr = if type_tag == "FunctionPtr" {
                        match read_u64(proc, node_addr) {
                            Some(v) if v != 0 => v,
                            _ => {
                                self.live_cache.insert(id_path, LiveEntry::Disasm(Vec::new()));
                                continue;
                            }
                        }
                    } else {
                        node_addr as u64
                    };

                    if code_addr == 0 {
                        self.live_cache.insert(id_path, LiveEntry::Disasm(Vec::new()));
                        continue;
                    }

                    const MAX_BYTES: usize = 512;
                    let disasm = match disassemble_function(proc, code_addr, MAX_BYTES) {
                        Ok(d) => d,
                        Err(_) => {
                            self.live_cache.insert(id_path, LiveEntry::Disasm(Vec::new()));
                            continue;
                        }
                    };

                    // Cap at 32 instructions for inline display.
                    const MAX_INLINE_INSNS: usize = 32;
                    let rows: Vec<DisasmRow> = disasm
                        .instructions
                        .into_iter()
                        .take(MAX_INLINE_INSNS)
                        .map(|ins| {
                            let bytes_hex = ins
                                .data
                                .iter()
                                .map(|b| format!("{b:02X}"))
                                .collect::<Vec<_>>()
                                .join(" ");
                            DisasmRow {
                                address: ins.address,
                                bytes_hex,
                                instruction: ins.instruction,
                                target: ins.target,
                            }
                        })
                        .collect();
                    self.live_cache.insert(id_path, LiveEntry::Disasm(rows));
                }

                _ => {}
            }
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

        // Auth-key row — only shown when the kernel backend is selected (Linux
        // only: the module gates all memory ops behind NEMCLASS_IOC_AUTH).
        #[cfg(target_os = "linux")]
        if self.selected_backend == LINUX_KERNEL {
            ui.horizontal(|ui| {
                ui.label("Auth key (hex):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.kernel_key)
                        .desired_width(160.0)
                        .hint_text("hex key the module was loaded with"),
                );
            });
        }

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

        // Filter box: type part of a process name (e.g. the game's `.exe`) or a
        // pid to narrow a long list.
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.process_filter)
                    .desired_width(140.0)
                    .hint_text("name or pid"),
            );
            if !self.process_filter.is_empty() && ui.small_button("✕").clicked() {
                self.process_filter.clear();
            }
        });

        let filter = self.process_filter.to_ascii_lowercase();
        egui::ScrollArea::vertical()
            .id_salt("proc_list")
            .max_height(180.0)
            .show(ui, |ui| {
                let mut new_sel = self.selected_process_idx;
                let mut shown = 0usize;
                for (i, entry) in self.process_list.iter().enumerate() {
                    // Match against the name or the pid; keep the original index
                    // `i` so selection still resolves into `process_list`.
                    if !filter.is_empty()
                        && !entry.name.to_ascii_lowercase().contains(&filter)
                        && !entry.id.to_string().contains(&filter)
                    {
                        continue;
                    }
                    shown += 1;
                    let label = format!("{}   [pid {}]", entry.name, entry.id);
                    let selected = self.selected_process_idx == Some(i);
                    if ui.selectable_label(selected, &label).clicked() {
                        new_sel = Some(i);
                    }
                }
                if shown == 0 && !self.process_list.is_empty() {
                    ui.weak("(no processes match the filter)");
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
            ui.selectable_value(&mut self.central_tab, CentralTab::MemoryView,   "Memory View");
            ui.selectable_value(&mut self.central_tab, CentralTab::Scanner,      "Scanner");
            ui.selectable_value(&mut self.central_tab, CentralTab::Debugger,     "Debugger");
            ui.selectable_value(&mut self.central_tab, CentralTab::MemoryViewer, "Memory");
            ui.selectable_value(&mut self.central_tab, CentralTab::Disassembly,  "Disassembly");
        });
        ui.separator();

        match self.central_tab {
            CentralTab::MemoryView   => self.show_class_view(ui),
            CentralTab::Scanner      => self.show_scanner_tab(ui),
            CentralTab::Debugger     => self.show_debugger_tab(ui),
            CentralTab::MemoryViewer => self.show_memory_viewer(ui),
            CentralTab::Disassembly  => self.show_disassembly_tab(ui),
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

    fn show_memory_viewer(&mut self, ui: &mut egui::Ui) {
        self.memory_viewer.show(ui, self.process.as_ref());
        // If the "Disassemble here" button was clicked, switch tabs and navigate.
        if let Some(addr) = self.memory_viewer.take_disassemble_request() {
            self.central_tab = CentralTab::Disassembly;
            self.disassembly_panel.goto(addr);
        }
        // If the "Dissect as class here" button was clicked, switch to the
        // Memory View tab and run auto-dissect at the viewer's current address.
        // The length comes from the existing dissect_len_text field.
        #[cfg(target_os = "linux")]
        if let Some(addr) = self.memory_viewer.take_dissect_request() {
            self.central_tab = CentralTab::MemoryView;
            self.run_auto_dissect(addr);
        }
    }

    fn show_disassembly_tab(&mut self, ui: &mut egui::Ui) {
        self.disassembly_panel.show(ui, self.process.as_ref());
    }

    // -----------------------------------------------------------------------
    // Auto-dissect helpers
    // -----------------------------------------------------------------------

    /// Parse `dissect_len_text` as hex (0x…) or decimal.  Returns a sensible
    /// default (256) if the field is empty or unparseable.
    fn parse_dissect_len(&self) -> usize {
        let s = self.dissect_len_text.trim();
        if s.is_empty() {
            return 256;
        }
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            usize::from_str_radix(hex, 16).unwrap_or(256)
        } else {
            s.parse::<usize>().unwrap_or(256)
        }
    }

    /// Run `auto_dissect` at `base` with the length from `dissect_len_text`
    /// and store the result in `dissect_preview`.  Errors are routed through
    /// `last_error`.  No-op on non-Linux targets (the caller is cfg-gated).
    #[cfg(target_os = "linux")]
    fn run_auto_dissect(&mut self, base: usize) {
        use nemclass_model::dissect::auto_dissect;

        let Some(uuid) = self.selected_class else {
            self.last_error = Some("Auto-dissect: no class selected".into());
            return;
        };
        let Some(proc) = &self.process else {
            self.last_error = Some("Auto-dissect: no process attached".into());
            return;
        };

        let len = self.parse_dissect_len();
        match auto_dissect(proc, base, len) {
            Err(e) => {
                self.last_error = Some(format!("Auto-dissect failed: {e}"));
            }
            Ok(defs) => {
                // Build a compact type-count summary for the preview banner.
                let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
                for d in &defs {
                    *counts.entry(d.type_tag.as_str()).or_insert(0) += 1;
                }
                let mut summary: Vec<(String, usize)> = counts
                    .into_iter()
                    .map(|(t, n)| (t.to_owned(), n))
                    .collect();
                summary.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                self.dissect_preview = Some(AutoDissectPreview {
                    defs,
                    target_class: uuid,
                    summary,
                });
                self.last_error = None;
            }
        }
    }

    /// Accept the pending auto-dissect preview: convert each NodeDef to a live
    /// node via the registry, replace the target class's children, and
    /// invalidate the snapshot so the new layout renders immediately.
    #[cfg(target_os = "linux")]
    fn accept_auto_dissect(&mut self) {
        let Some(preview) = self.dissect_preview.take() else { return; };

        let mut live_nodes: Vec<Box<dyn Node>> = Vec::with_capacity(preview.defs.len());
        for def in preview.defs {
            match self.node_registry.deserialize_node(def) {
                Ok(node) => live_nodes.push(node),
                Err(e) => {
                    self.last_error = Some(format!("Auto-dissect accept: {e}"));
                    return;
                }
            }
        }

        if let Some(class) = self.project.get_class_mut(&preview.target_class) {
            class.children = live_nodes;
        } else {
            self.last_error = Some("Auto-dissect accept: class no longer exists".into());
            return;
        }

        // Invalidate the snapshot so the new nodes are rendered immediately.
        self.last_snapshot = None;
        self.clear_memory_state();
        self.status_msg = Some("Auto-dissect applied.".into());
    }

    /// Draw the auto-dissect toolbar row (button + length input) and the
    /// preview panel when a result is pending.  Called from `show_class_view`
    /// before the memory table.
    ///
    /// On non-Linux the method is a no-op so the toolbar stays clean.
    fn show_auto_dissect_controls(&mut self, ui: &mut egui::Ui) {
        #[cfg(target_os = "linux")]
        {
            // -----------------------------------------------------------------
            // Toolbar row: [Auto-dissect]  Length: [____]
            // -----------------------------------------------------------------
            let has_process = self.process.is_some();
            let has_base    = self.class_base.is_some();
            let enabled     = has_process && has_base;

            // Collect actions into locals so we can mutate `self` after the
            // draw closure (same collect-during-draw, apply-after pattern used
            // throughout this file).
            let mut do_dissect = false;

            ui.horizontal(|ui| {
                let btn = ui.add_enabled(enabled, egui::Button::new("Auto-dissect"));
                if !enabled {
                    btn.on_disabled_hover_text(if !has_process {
                        "Attach to a process first"
                    } else {
                        "Class base address not resolved (set the address formula)"
                    });
                } else if btn.clicked() {
                    do_dissect = true;
                }

                ui.label("Length:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.dissect_len_text)
                        .desired_width(70.0)
                        .hint_text("0x100"),
                );
            });

            if do_dissect {
                let base = self.class_base.unwrap();
                self.run_auto_dissect(base);
            }

            // -----------------------------------------------------------------
            // Preview panel — only shown while a result is pending.
            // Collect the user's decision (accept / cancel) as a local bool,
            // then apply it after the frame closure releases its borrow.
            // -----------------------------------------------------------------
            let mut do_accept = false;
            let mut do_cancel = false;

            if let Some(preview) = &self.dissect_preview {
                let node_count   = preview.defs.len();
                let summary_text: String = preview.summary.iter()
                    .map(|(tag, n)| format!("{n}×{tag}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                let target_uuid  = preview.target_class;
                let class_name   = self.project.get_class(&target_uuid)
                    .map(|c| c.name.clone())
                    .unwrap_or_else(|| target_uuid.to_string());

                ui.separator();
                egui::Frame::new()
                    .fill(egui::Color32::from_rgb(30, 40, 55))
                    .inner_margin(egui::Margin::same(6))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(format!("Auto-dissect: {node_count} nodes"));
                            ui.weak(format!("({summary_text})"));
                        });
                        ui.label(format!("Target: {class_name}  — replaces all children"));
                        ui.horizontal(|ui| {
                            if ui.button("Accept").clicked() { do_accept = true; }
                            if ui.button("Cancel").clicked() { do_cancel = true; }
                        });
                    });
            }

            // Apply decision outside the frame closure.
            if do_accept {
                self.accept_auto_dissect();
            } else if do_cancel {
                self.dissect_preview = None;
            }
        }
        // Non-Linux: show nothing — the button is entirely absent so the
        // toolbar stays uncluttered on Windows/macOS builds.
        #[cfg(not(target_os = "linux"))]
        let _ = ui; // suppress unused warning
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
            #[cfg(target_os = "linux")]
            self.refresh_live_cache();
        }

        if self.node_snapshots.is_empty() {
            ui.label("No nodes in this class.");
            // Still show the dissect controls even when the class is empty so
            // the user can populate it via Auto-dissect.
            self.show_auto_dissect_controls(ui);
            return;
        }

        // Auto-dissect toolbar (button + length input + preview panel).
        self.show_auto_dissect_controls(ui);
        ui.separator();

        // Build the augmented visible-row list.  Normal nodes come from
        // `build_visible_rows`; after each expanded VTable/Function/FunctionPtr
        // we inject live child rows from the cache.  This leaves the static
        // flatten/collapse logic completely untouched.
        let view_rows = build_augmented_rows(
            &self.node_snapshots,
            &self.collapsed,
            #[cfg(target_os = "linux")]
            &self.live_cache,
        );

        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = text_height + 4.0;

        // Collect a pending disasm-goto request during the table draw and apply
        // it after the closure exits (avoids the borrow conflict on `self`).
        #[cfg(target_os = "linux")]
        { self.pending_disasm_goto = None; }

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
                body.rows(row_height, view_rows.len(), |mut row| {
                    let row_idx = row.index();
                    let Some(view_row) = view_rows.get(row_idx) else { return; };

                    match view_row {
                        ViewRow::Snap(snap_idx) => {
                            let snap = &self.node_snapshots[*snap_idx];

                            let address      = snap.address;
                            let offset       = snap.offset;
                            let type_tag     = snap.type_tag;
                            let name         = snap.name.clone();
                            let comment      = snap.comment.clone();
                            let value        = snap.rendered.value.clone();
                            let depth        = snap.depth;
                            let has_children = snap.has_children;
                            let id_path      = snap.id_path.clone();

                            // For live-expandable nodes, we treat them as
                            // containers (has_children for collapse toggle) even
                            // if the static model has no children.
                            #[cfg(target_os = "linux")]
                            let is_live_container = matches!(
                                type_tag, "VTable" | "Function" | "FunctionPtr"
                            );
                            #[cfg(not(target_os = "linux"))]
                            let is_live_container = false;

                            row.col(|ui| { ui.monospace(format!("0x{address:016X}")); });
                            row.col(|ui| { ui.monospace(format!("+{offset:#06X}")); });
                            row.col(|ui| { ui.label(type_tag); });

                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    let indent = depth as f32 * 12.0;
                                    if indent > 0.0 { ui.add_space(indent); }

                                    if has_children || is_live_container {
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
                        }

                        #[cfg(target_os = "linux")]
                        ViewRow::NotAttached { depth, _parent_id: _ } => {
                            row.col(|ui| { ui.label(""); });
                            row.col(|ui| { ui.label(""); });
                            row.col(|ui| { ui.label(""); });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    let indent = (*depth as f32 + 1.0) * 12.0;
                                    if indent > 0.0 { ui.add_space(indent); }
                                    ui.colored_label(
                                        egui::Color32::DARK_GRAY,
                                        "attach to inspect",
                                    );
                                });
                            });
                            row.col(|ui| { ui.label(""); });
                            row.col(|ui| { ui.label(""); });
                        }

                        #[cfg(target_os = "linux")]
                        ViewRow::VtableMethod { depth, row: method, _parent_id: _ } => {
                            let addr = method.fn_ptr;
                            let slot = method.slot;
                            let sym  = method.symbol.clone();

                            row.col(|ui| { ui.monospace(format!("0x{addr:016X}")); });
                            row.col(|ui| {
                                ui.monospace(format!("+{:#06X}", slot * 8));
                            });
                            row.col(|ui| { ui.label("VMethod"); });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    let indent = (*depth as f32 + 1.0) * 12.0;
                                    if indent > 0.0 { ui.add_space(indent); }
                                    ui.add_space(16.0); // leaf — no arrow
                                    let label = sym.as_deref()
                                        .unwrap_or("")
                                        .to_string();
                                    ui.label(format!("[{slot}] {label}"));
                                });
                            });
                            row.col(|ui| {
                                // "disasm" link — stored as pending to avoid
                                // mutably borrowing self inside the body closure.
                                if ui.small_button("disasm").clicked() {
                                    self.pending_disasm_goto = Some(addr);
                                }
                            });
                            row.col(|ui| { ui.label(""); });
                        }

                        #[cfg(target_os = "linux")]
                        ViewRow::DisasmInsn { depth, row: insn, _parent_id: _ } => {
                            let addr    = insn.address;
                            let bytes   = insn.bytes_hex.clone();
                            let text    = insn.instruction.clone();
                            let target  = insn.target;

                            row.col(|ui| { ui.monospace(format!("0x{addr:016X}")); });
                            row.col(|ui| { ui.label(""); });
                            row.col(|ui| { ui.label(""); });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    let indent = (*depth as f32 + 1.0) * 12.0;
                                    if indent > 0.0 { ui.add_space(indent); }
                                    ui.add_space(16.0);
                                    ui.monospace(&bytes);
                                });
                            });
                            row.col(|ui| {
                                if let Some(tgt) = target {
                                    // Clickable link for call/jmp with a resolved target.
                                    if ui.link(&text).clicked() {
                                        self.pending_disasm_goto = Some(tgt);
                                    }
                                } else {
                                    ui.monospace(&text);
                                }
                            });
                            row.col(|ui| { ui.label(""); });
                        }
                    }
                });
            });

        // Apply any pending disasm navigation collected during the draw phase.
        #[cfg(target_os = "linux")]
        if let Some(addr) = self.pending_disasm_goto.take() {
            self.central_tab = CentralTab::Disassembly;
            self.disassembly_panel.goto(addr as usize);
        }
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

/// Build an augmented row list that interleaves live child rows (VTable slots,
/// disassembly lines) right after each expanded live-container snapshot.
///
/// On non-Linux platforms the live_cache parameter is absent and this reduces
/// to a plain `build_visible_rows` wrapper.
fn build_augmented_rows(
    snapshots: &[NodeSnapshot],
    collapsed: &HashSet<String>,
    #[cfg(target_os = "linux")]
    live_cache: &HashMap<String, LiveEntry>,
) -> Vec<ViewRow> {
    let snap_indices = build_visible_rows(snapshots, collapsed);
    let mut out: Vec<ViewRow> = Vec::with_capacity(snap_indices.len() * 2);

    for snap_idx in snap_indices {
        out.push(ViewRow::Snap(snap_idx));

        let snap = &snapshots[snap_idx];

        // Only inject live rows for the three live-expandable type tags,
        // and only when the node is not collapsed.
        #[cfg(target_os = "linux")]
        if matches!(snap.type_tag, "VTable" | "Function" | "FunctionPtr")
            && !collapsed.contains(&snap.id_path)
        {
            match live_cache.get(&snap.id_path) {
                Some(LiveEntry::Vtable(methods)) => {
                    for m in methods {
                        out.push(ViewRow::VtableMethod {
                            _parent_id: snap.id_path.clone(),
                            depth: snap.depth,
                            row: m.clone(),
                        });
                    }
                }
                Some(LiveEntry::Disasm(insns)) => {
                    for insn in insns {
                        out.push(ViewRow::DisasmInsn {
                            _parent_id: snap.id_path.clone(),
                            depth: snap.depth,
                            row: insn.clone(),
                        });
                    }
                }
                Some(LiveEntry::NotAttached) => {
                    out.push(ViewRow::NotAttached {
                        _parent_id: snap.id_path.clone(),
                        depth: snap.depth,
                    });
                }
                None => {}
            }
        }
    }

    out
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
