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
mod dock;
mod navigator;
mod settings;
mod key_file;
mod script_host;
mod script_log;
mod scripts_panel;
mod host_api_impl;
mod pointer_scan_panel;
pub(crate) mod cheat_table_panel;
mod tasks;

pub use scanner_panel::ScannerPanel;
pub use debugger_panel::DebuggerPanel;
pub use memory_viewer::MemoryViewer;
pub use disassembly::DisassemblyPanel;

use script_host::ScriptHost;
use script_log::{LogKind, ScriptLog, new_script_log};
use scripts_panel::{ScriptsPanel, ScriptsPanelAction};
use pointer_scan_panel::{PointerScanPanel, PointerScanAction};
use cheat_table_panel::{CheatTablePanel, CheatTablePanelAction};

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tasks::{BackgroundJob, Poll as JobPoll, Runtime as BgRuntime};

use eframe::egui;
use egui_dock::DockState;
use egui_extras::{Column, TableBuilder};

use dock::TabKind;

use nemclass_core::{ModuleInfoWithName, Process, ProcessEntry, ProviderRegistry};
#[cfg(target_os = "linux")]
use nemclass_core::{KernelProvider, LINUX_KERNEL};
#[cfg(target_os = "linux")]
use crate::views::debugger_panel::parse_hex_key;
use nemclass_model::{ClassNode, ModelError, Node, NodeRegistry, Project, RenderedValue, resolve_formula};
#[cfg(target_os = "linux")]
use nemclass_model::serialize::NodeDef;
use nemclass_script::{ClassAddressQuery, Event, EventBus};
use uuid::Uuid;

use crate::process_reader::ProcessReader;
use crate::project_io::{create_project_at, load_project_from, save_project_to};

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
    /// For pointer-to-class nodes: the UUID of the class the pointer targets, so
    /// the UI can offer a "follow pointer → open target class" action.
    pointer_target: Option<Uuid>,
    /// Which class owns this node (may differ from selected_class for future
    /// cross-class inline expansion; currently always equals selected_class).
    owner_class: Uuid,
    /// Index path within owner_class — e.g. `[0]` for first child, `[0, 2]` for
    /// third child of first child.  Used to locate the node for edits.
    local_path: Vec<usize>,
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
// Node edit operations (deferred to after the table-draw closure)
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum NodeEditOp {
    ChangeType   { owner: Uuid, path: Vec<usize>, new_tag: &'static str },
    Delete       { owner: Uuid, path: Vec<usize> },
    AddBytes     { owner: Uuid, path: Vec<usize>, count: usize },
    InsertBytes  { owner: Uuid, path: Vec<usize>, count: usize },
    SetName      { owner: Uuid, path: Vec<usize>, name: String },
    SetComment   { owner: Uuid, path: Vec<usize>, comment: String },
    SetPtrTarget { owner: Uuid, path: Vec<usize>, target: Option<Uuid> },
    SetInstance  { owner: Uuid, path: Vec<usize>, target: Uuid },
}

// ---------------------------------------------------------------------------
// Class-picker modal state
// ---------------------------------------------------------------------------

struct ClassPickerState {
    filter: String,
    purpose: PickerPurpose,
}

#[derive(Clone)]
enum PickerPurpose {
    SetPtrTarget     { owner: Uuid, path: Vec<usize> },
    SetInstance      { owner: Uuid, path: Vec<usize> },
    ChangeToInstance { owner: Uuid, path: Vec<usize> },
}

// ---------------------------------------------------------------------------
// Add-bytes dialog state
// ---------------------------------------------------------------------------

struct AddBytesState {
    owner: Uuid,
    path: Vec<usize>,
    count_text: String,
    insert: bool,
}

// ---------------------------------------------------------------------------
// Active cell edit
// ---------------------------------------------------------------------------

#[derive(Clone, PartialEq)]
enum EditField { Value, Name, Comment }

#[derive(Clone)]
struct EditState {
    node_id: String,
    text: String,
    field: EditField,
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

/// The last-saved window inner size (`[width, height]`), if any. Called by the
/// launcher before creating the window so it can restore the user's size.
pub fn saved_window_size() -> Option<[f32; 2]> {
    settings::Settings::load()
        .window
        .map(|w| [w.width, w.height])
}

// ---------------------------------------------------------------------------
// NemclassApp
// ---------------------------------------------------------------------------

/// Result of a background attach: the pid and display name captured at spawn
/// time, plus the opened [`Process`] (or an error message). The UI-thread-only
/// follow-ups (`on_attach`, `OnAttach` event) run when this is ingested.
type AttachOutcome = (libc::pid_t, String, Result<Process, String>);

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
    /// The attached target, shared as `Arc` so background workers (scans, dissect,
    /// project I/O) can hold a clone while the UI keeps rendering.
    process: Option<Arc<Process>>,
    attached_name: Option<String>,
    last_error: Option<String>,

    /// Shared background thread pool for discrete long-running operations. `Option`
    /// so `Drop` can `take()` it and shut it down without blocking on exit.
    runtime: Option<BgRuntime>,
    /// In-flight process enumeration (the "Refresh" button); result merged in
    /// `logic`. See [`tasks`].
    enumerate_job: BackgroundJob<(String, Result<Vec<ProcessEntry>, String>)>,
    /// In-flight attach (the "Attach" button). Payload: `(pid, name, result)`.
    attach_job: BackgroundJob<AttachOutcome>,
    /// In-flight script class-address resolve (the "Try resolve (script)" button).
    /// Payload: `(class uuid, resolved address)`. The v8 round-trip blocks, so it
    /// runs on the pool. See [`Self::do_resolve_class_address`].
    resolve_job: BackgroundJob<(Uuid, Option<usize>)>,

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
    /// Last time an `OnTick` script event fired (throttled to the snapshot
    /// interval). Only meaningful under the `scripting` feature.
    #[cfg(feature = "scripting")]
    last_tick: Option<Instant>,
    snapshot_interval: Duration,
    collapsed: HashSet<String>,
    expanded_ptrs: HashSet<String>,
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
    /// Compile-time `Plugin` seam. Lifecycle events are published here.
    event_bus: EventBus,
    /// The JS engine (or a no-op `Disabled` host when the `scripting` feature is
    /// off or the engine failed to spawn). Driven directly — not registered on
    /// the bus — so `pump` stays reachable each frame.
    script_host: ScriptHost,
    /// Shared script log buffer, written by the per-frame `UiHostApi` and read by
    /// the Scripts panel.
    script_log: ScriptLog,
    /// Transient UI state for the Scripts tab.
    scripts_panel: ScriptsPanel,
    /// Script-registered global hotkeys, polled each frame in `logic`. A match
    /// fires `Event::OnHotkey { id }` into the engine.
    #[cfg(feature = "scripting")]
    script_hotkeys: Vec<HotkeyReg>,
    /// Monotonic id counter for `hotkeys.register`.
    #[cfg(feature = "scripting")]
    next_hotkey_id: u32,
    /// Direct script freezes (not tied to the cheat table): `(addr, type, value
    /// text)`. Applied on the throttled freeze tick in `logic`.
    #[cfg(feature = "scripting")]
    script_freezes: Vec<(usize, nemclass_scan::ScanValueType, String)>,
    /// Cheat-Engine-style iterative scan session driven by the JS
    /// `scan.first`/`scan.next`/`scan.results`/`scan.reset` API. Holds the live
    /// `Scanner` between calls so a script can narrow a result set over time.
    /// Reset to `None` on detach and project change.
    #[cfg(all(feature = "scripting", target_os = "linux"))]
    script_scanner: Option<nemclass_scan::Scanner<nemclass_scan::ProcessTarget>>,
    /// Throttle clock for [`Self::tick_script_freezes`] (mirrors the cheat
    /// table's own freeze cadence).
    #[cfg(all(feature = "scripting", target_os = "linux"))]
    last_script_freeze: Option<Instant>,
    /// A class base address supplied by a script resolver via the "Try resolve
    /// (script)" button. When set, it takes precedence over the address formula
    /// in `take_snapshot`; cleared on detach or when the formula is edited.
    script_resolved_base: Option<usize>,
    /// Pending "follow pointer" request collected during the class-table draw and
    /// applied after the closure. `(target_addr, target_class_uuid)`.
    pending_follow_pointer: Option<(usize, Option<Uuid>)>,
    /// Deferred structural edits applied after the table-draw closure exits.
    pending_node_edits: Vec<NodeEditOp>,
    /// Class-picker modal (for SetPtrTarget / SetInstance / ChangeToInstance).
    class_picker: Option<ClassPickerState>,
    /// Add/Insert bytes dialog.
    add_bytes_dialog: Option<AddBytesState>,
    /// Rename-class modal: `(class uuid, edited name)`. `Some` while open.
    class_rename: Option<(Uuid, String)>,

    /// Non-modal status message shown below the menu bar (e.g. last save path).
    status_msg: Option<String>,

    // Central-panel dock layout. `Option` so `show_central_panel` can
    // `take()` it into a local while the `DockViewer` borrows `&mut self`.
    dock_state: Option<DockState<TabKind>>,
    /// Cross-panel navigation request: bring this tab to the front of its dock
    /// group after the frame draws (e.g. "Disassemble here" → focus Disassembly).
    pending_focus: Option<TabKind>,

    // Scanner panel
    scanner_panel: ScannerPanel,

    // Debugger panel
    debugger_panel: DebuggerPanel,

    // Raw hex memory viewer panel
    memory_viewer: MemoryViewer,

    // Disassembly panel
    disassembly_panel: DisassemblyPanel,

    // Pointer-scan panel
    pointer_scan_panel: PointerScanPanel,
    /// Deferred action from the pointer-scan panel; applied after the dock draw
    /// to avoid borrow conflicts with `self.project` / `self.selected_class`.
    pending_pointer_scan_action: Option<PointerScanAction>,

    // Cheat table panel
    cheat_table_panel: CheatTablePanel,

    // Navigator side panel (strings / functions / calls)
    navigator_panel: navigator::NavigatorPanel,

    // Persistent user settings (~/.local/share/nemclass/settings.json).
    settings: settings::Settings,
    /// Set when a persisted setting changed; drives a debounced save in `logic`.
    settings_dirty: bool,
    /// Last time settings were written, for debouncing.
    last_settings_save: Option<Instant>,
}

/// A script-registered global hotkey: an id (returned to JS) plus the parsed
/// modifier set and trigger key. Polled each frame in `logic`; a match fires
/// `Event::OnHotkey { id }`. Only compiled under the `scripting` feature.
#[cfg(feature = "scripting")]
#[derive(Debug, Clone, PartialEq)]
pub struct HotkeyReg {
    /// Registration id handed back to the script.
    pub id: u32,
    /// Whether Ctrl must be held.
    pub ctrl: bool,
    /// Whether Shift must be held.
    pub shift: bool,
    /// Whether Alt must be held.
    pub alt: bool,
    /// The trigger key.
    pub key: egui::Key,
}

/// Parse a CE-style hotkey combo string like `"Ctrl+Shift+H"`, `"F6"`, or
/// `"Alt+K"` into `(ctrl, shift, alt, key)`. Segments are split on `+`,
/// case-insensitively; `Ctrl`/`Control`, `Shift`, and `Alt`/`Option` are
/// modifiers and everything else must be exactly one egui-nameable key. Returns
/// `None` for empty input, an unknown key, or more than one non-modifier token.
#[cfg(feature = "scripting")]
pub fn parse_hotkey(combo: &str) -> Option<(bool, bool, bool, egui::Key)> {
    let (mut ctrl, mut shift, mut alt) = (false, false, false);
    let mut key: Option<egui::Key> = None;
    for raw in combo.split('+') {
        let seg = raw.trim();
        if seg.is_empty() {
            return None;
        }
        match seg.to_ascii_lowercase().as_str() {
            "ctrl" | "control" => ctrl = true,
            "shift" => shift = true,
            "alt" | "option" => alt = true,
            _ => {
                if key.is_some() {
                    return None; // more than one non-modifier key
                }
                key = egui::Key::from_name(seg);
                key?; // unknown key name
            }
        }
    }
    key.map(|k| (ctrl, shift, alt, k))
}

impl NemclassApp {
    pub fn new() -> Self {
        let registry = ProviderRegistry::default();
        let mut backend_names: Vec<String> = registry.names().map(str::to_owned).collect();
        backend_names.sort();
        let node_registry = NodeRegistry::new().with_builtins();

        // Load persisted user settings; any error falls back to defaults.
        let settings = settings::Settings::load();

        // Prefer the last-used backend if it still exists, else the first.
        let selected_backend = settings
            .last_backend
            .clone()
            .filter(|b| backend_names.iter().any(|n| n == b))
            .or_else(|| backend_names.first().cloned())
            .unwrap_or_default();

        // Auto-reopen the last project (best-effort); otherwise load the demo.
        let (project, project_dir) = settings
            .last_project
            .clone()
            .and_then(|dir| {
                load_project_from(&dir, &node_registry)
                    .ok()
                    .map(|(p, resolved)| (p, Some(resolved)))
            })
            .unwrap_or_else(|| (demo_project(), None));

        // Pre-select the first class.
        let selected_class = project.classes_in_order().next().map(|c| c.uuid);

        // Auto-load the kernel auth-key from the well-known file (or env
        // override).  The fields remain freely editable; this just saves a
        // paste step for users who have already run `cargo make gen-key`.
        let (kernel_key, key_status) = match key_file::read_kernel_key() {
            Some(k) => {
                let path_str = key_file::kernel_key_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_owned());
                let msg = format!("Loaded kernel auth key from {}.", path_str);
                (k, Some(msg))
            }
            None => (String::new(), None),
        };

        // Spawn the JS engine (feature-gated; `Disabled` otherwise). Any spawn
        // error is surfaced in the initial status message.
        let (script_host, script_spawn_msg) = ScriptHost::spawn();
        let script_log = new_script_log();

        let mut app = Self {
            registry,
            backend_names,
            selected_backend,
            kernel_key: kernel_key.clone(),
            process_list: Vec::new(),
            process_list_status: "Press Refresh to enumerate processes.".into(),
            process_filter: String::new(),
            selected_process_idx: None,
            process: None,
            attached_name: None,
            last_error: None,
            runtime: Some(BgRuntime::new()),
            enumerate_job: BackgroundJob::default(),
            attach_job: BackgroundJob::default(),
            resolve_job: BackgroundJob::default(),
            project,
            node_registry,
            project_dir,
            selected_class,
            node_snapshots: Vec::new(),
            class_base: None,
            mem_buf: Vec::new(),
            last_snapshot: None,
            #[cfg(feature = "scripting")]
            last_tick: None,
            snapshot_interval: Duration::from_millis(settings.live_interval_ms.unwrap_or(100)),
            collapsed: HashSet::new(),
            expanded_ptrs: HashSet::new(),
            edit_state: None,
            dissect_len_text: "0x100".to_owned(),
            #[cfg(target_os = "linux")]
            dissect_preview: None,
            #[cfg(target_os = "linux")]
            live_cache: HashMap::new(),
            #[cfg(target_os = "linux")]
            pending_disasm_goto: None,
            event_bus: EventBus::new(),
            script_host,
            script_log,
            scripts_panel: ScriptsPanel::new(),
            #[cfg(feature = "scripting")]
            script_hotkeys: Vec::new(),
            #[cfg(feature = "scripting")]
            next_hotkey_id: 1,
            #[cfg(feature = "scripting")]
            script_freezes: Vec::new(),
            #[cfg(all(feature = "scripting", target_os = "linux"))]
            script_scanner: None,
            #[cfg(all(feature = "scripting", target_os = "linux"))]
            last_script_freeze: None,
            script_resolved_base: None,
            pending_follow_pointer: None,
            pending_node_edits: Vec::new(),
            class_picker: None,
            add_bytes_dialog: None,
            class_rename: None,
            status_msg: script_spawn_msg
                .map(|m| format!("Scripting: {m}"))
                .or(key_status)
                .or_else(|| Some("Demo project loaded. Use File > New or Open to load a project.".into())),
            dock_state: Some(settings.dock_state().unwrap_or_else(dock::default_layout)),
            pending_focus: None,
            scanner_panel: ScannerPanel::new(),
            debugger_panel: DebuggerPanel::with_key(kernel_key),
            memory_viewer: MemoryViewer::new(),
            disassembly_panel: DisassemblyPanel::new(),
            pointer_scan_panel: PointerScanPanel::new(),
            pending_pointer_scan_action: None,
            cheat_table_panel: CheatTablePanel::new(),
            navigator_panel: navigator::NavigatorPanel::new(),
            settings,
            settings_dirty: false,
            // Start the heartbeat clock now so dock-layout drags get persisted on
            // the ~30s cadence even without an explicit dirty flag.
            last_settings_save: Some(Instant::now()),
        };

        // Auto-load the auto-reopened project's scripts at launch so their
        // lifecycle handlers (OnAttach, OnTick, hotkeys, …) get registered. The
        // File > Open path does this in `replace_project`; startup goes through
        // `new()`, which previously skipped it — so nothing fired until the user
        // manually clicked Reload in the Scripts panel.
        if let Some(dir) = app.project_dir.clone() {
            let src = dir.join("src");
            match app.script_host.load_scripts(&src) {
                Ok(()) if app.script_host.is_active() => script_log::push(
                    &app.script_log,
                    LogKind::Lifecycle,
                    format!("Loaded scripts from {}", src.display()),
                ),
                Ok(()) => {}
                Err(e) => script_log::push(
                    &app.script_log,
                    LogKind::Error,
                    format!("load scripts: {e}"),
                ),
            }
            // Fire OnProjectLoad AFTER load so handlers registered during load
            // can catch it (the worker processes the commands in order).
            app.emit(Event::OnProjectLoad { path: dir.display().to_string() });
        }

        app
    }

    /// Marks settings as needing a save; the debounced writer in `logic` picks
    /// it up. Call after mutating anything persisted (backend, interval, project).
    fn mark_settings_dirty(&mut self) {
        self.settings_dirty = true;
    }

    /// Snapshots the current live state (dock layout, window size, backend,
    /// interval) into `self.settings` and writes it to disk. `ctx` is optional
    /// so `eframe::App::save` (which has no context) can also drive it — window
    /// size is only refreshed when a context is available.
    fn persist_settings(&mut self, ctx: Option<&egui::Context>) {
        // Fold the current UI state into the settings document.
        if let Some(dock) = &self.dock_state {
            self.settings.set_dock(dock);
        }
        if let Some(ctx) = ctx {
            let size = ctx.input(|i| i.viewport_rect().size());
            self.settings.window = Some(settings::WindowGeom {
                width: size.x,
                height: size.y,
            });
        }
        self.settings.last_backend = Some(self.selected_backend.clone());
        self.settings.live_interval_ms = Some(self.snapshot_interval.as_millis() as u64);

        if let Err(e) = self.settings.save() {
            self.last_error = Some(format!("Settings save failed: {e}"));
        }
        self.settings_dirty = false;
        self.last_settings_save = Some(Instant::now());
    }

    /// Debounced settings writer, called each frame: saves ~2s after an explicit
    /// change, and on a ~30s heartbeat so dock-layout drags are captured even
    /// without an explicit dirty flag.
    fn maybe_persist_settings(&mut self, ctx: &egui::Context) {
        let elapsed = self.last_settings_save.map(|t| t.elapsed());
        let dirty_due = self.settings_dirty
            && elapsed.map(|e| e >= Duration::from_secs(2)).unwrap_or(true);
        let heartbeat_due = elapsed.map(|e| e >= Duration::from_secs(30)).unwrap_or(false);
        if dirty_due || heartbeat_due {
            self.persist_settings(Some(ctx));
        }
    }

    // -----------------------------------------------------------------------
    // Process actions
    // -----------------------------------------------------------------------

    /// Kicks off process enumeration on the background pool (it scans `/proc` /
    /// Toolhelp, which can stall for hundreds of ms on a busy machine). The result
    /// is merged in `logic` via [`Self::ingest_enumerate`]; the button is gated on
    /// the job already running so it can't stack.
    fn do_refresh(&mut self, ctx: &egui::Context) {
        if self.enumerate_job.is_running() {
            return;
        }
        let backend = self.selected_backend.clone();
        let Some(provider) = self.registry.get_arc(&backend) else {
            self.process_list_status = format!("Backend '{backend}' not found.");
            return;
        };
        let Some(rt) = self.runtime.as_ref().map(|r| r.handle()) else {
            return;
        };
        self.process_list_status = "Enumerating…".into();
        self.enumerate_job.spawn(&rt, ctx.clone(), move || {
            let result = provider.enumerate_processes().map(|mut list| {
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
                list
            });
            (backend, result.map_err(|e| e.to_string()))
        });
    }

    /// Merges a completed enumeration result into the process list.
    fn ingest_enumerate(&mut self, result: Result<Vec<ProcessEntry>, String>) {
        match result {
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

    /// Kicks off an attach on the background pool (`provider.open` may do device
    /// opens / permission checks). The detach-first teardown runs on the UI thread
    /// here; the opened handle and its `on_attach`/`OnAttach` follow-ups are
    /// applied in `logic` via [`Self::ingest_attach`].
    fn do_attach(&mut self, ctx: &egui::Context) {
        // Ensure the keyed provider is in the registry before we look it up.
        #[cfg(target_os = "linux")]
        self.ensure_kernel_key_registered();

        if self.attach_job.is_running() {
            return;
        }

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

        // Detach first (UI thread; touches panel state the worker can't).
        if self.process.is_some() {
            self.emit(Event::OnDetach);
            self.process = None;
            self.attached_name = None;
            self.clear_memory_state();
            self.memory_viewer.on_detach();
            self.disassembly_panel.on_detach();
        }

        let Some(provider) = self.registry.get_arc(&self.selected_backend) else {
            self.last_error = Some(format!("Backend '{}' not found.", self.selected_backend));
            return;
        };
        let Some(rt) = self.runtime.as_ref().map(|r| r.handle()) else {
            return;
        };
        self.last_error = None;
        self.status_msg = Some(format!(
            "Attaching to {}…",
            if name.is_empty() { format!("pid:{pid}") } else { name.clone() }
        ));
        self.attach_job.spawn(&rt, ctx.clone(), move || {
            let result = provider.open(pid).map_err(|e| format!("Attach failed: {e}"));
            (pid, name, result)
        });
    }

    /// Applies a completed attach: wires the opened handle into the panels and
    /// fires `OnAttach`, or surfaces the error. Runs on the UI thread from `logic`.
    fn ingest_attach(&mut self, outcome: AttachOutcome) {
        let (pid, name, result) = outcome;
        self.status_msg = None;
        match result {
            Ok(proc) => {
                let proc = Arc::new(proc);
                self.attached_name = Some(if name.is_empty() {
                    format!("pid:{pid}")
                } else {
                    name.clone()
                });
                self.memory_viewer.on_attach(&proc);
                self.disassembly_panel.on_attach(&proc);
                self.process = Some(proc);
                self.last_error = None;
                self.last_snapshot = None;
                self.emit(Event::OnAttach {
                    pid,
                    name: Some(name),
                });
            }
            Err(e) => {
                self.last_error = Some(e);
            }
        }
    }

    /// Debug/screenshot hook: attach to `pid` via `backend` and drive the
    /// disassembler into linear mode over a module (matched by `module_substr`),
    /// focusing the Disassembly tab. Used by the `--screenshot --attach` smoke.
    pub fn debug_attach_disasm(
        &mut self,
        backend: &str,
        pid: i32,
        module_substr: Option<&str>,
    ) -> Result<(), String> {
        self.selected_backend = backend.to_string();
        #[cfg(target_os = "linux")]
        self.ensure_kernel_key_registered();

        let provider = self
            .registry
            .get(&self.selected_backend)
            .ok_or_else(|| format!("Backend '{backend}' not found"))?;
        let proc = provider
            .open(pid as libc::pid_t)
            .map_err(|e| format!("open({pid}): {e}"))?;

        self.memory_viewer.on_attach(&proc);
        self.disassembly_panel.on_attach(&proc);
        self.attached_name = Some(format!("pid:{pid}"));
        self.process = Some(Arc::new(proc));
        self.last_error = None;

        // Take the process out to satisfy the borrow checker, drive the panel,
        // then put it back.
        if let Some(proc) = self.process.take() {
            self.disassembly_panel.debug_enter_module(&proc, module_substr);
            self.process = Some(proc);
        }
        self.pending_focus = Some(TabKind::Disassembly);
        Ok(())
    }

    /// Debug/screenshot hook: collapse the dock to a single maximized
    /// Disassembly tab so a capture shows it full-window.
    pub fn debug_solo_disasm(&mut self) {
        self.dock_state = Some(DockState::new(vec![TabKind::Disassembly]));
    }

    /// Debug/screenshot hook: maximize the Navigator tab.
    pub fn debug_solo_navigator(&mut self) {
        self.dock_state = Some(DockState::new(vec![TabKind::Navigator]));
    }

    /// Debug/screenshot hook: run a dissect over the disassembler's selected
    /// module (populates the Navigator).
    pub fn debug_dissect(&mut self) {
        #[cfg(target_os = "linux")]
        if let Some(proc) = self.process.take() {
            // Synchronous so the screenshot capture sees the result this frame.
            self.disassembly_panel.dissect_selected_blocking(&proc);
            self.process = Some(proc);
        }
    }

    /// Ingests results from all in-flight background jobs. Called first each frame
    /// from `logic` so completed work is merged before the snapshot/draw pass.
    fn poll_background_jobs(&mut self) {
        if let JobPoll::Done((backend, result)) = self.enumerate_job.poll() {
            // Ignore a stale result from a backend the user has since switched away
            // from, so it can't clobber the current list.
            if backend == self.selected_backend {
                self.ingest_enumerate(result);
            }
        }
        if let JobPoll::Done(outcome) = self.attach_job.poll() {
            self.ingest_attach(outcome);
        }
        if let JobPoll::Done((uuid, resolved)) = self.resolve_job.poll() {
            self.ingest_resolve(uuid, resolved);
        }
    }

    fn do_detach(&mut self) {
        if self.process.is_some() {
            self.emit(Event::OnDetach);
            self.process = None;
            self.attached_name = None;
            self.clear_memory_state();
            self.last_error = None;
            self.scanner_panel.on_detach();
            self.debugger_panel.on_detach();
            self.memory_viewer.on_detach();
            self.disassembly_panel.on_detach();
            self.pointer_scan_panel.on_detach();
            self.cheat_table_panel.on_detach();
            // The script scan session is bound to the detached process; drop it.
            #[cfg(all(feature = "scripting", target_os = "linux"))]
            {
                self.script_scanner = None;
            }
        }
    }

    fn clear_memory_state(&mut self) {
        self.class_base = None;
        self.node_snapshots.clear();
        self.mem_buf.clear();
        self.edit_state = None;
        // A script-resolved base is tied to the previous attach/class; drop it so
        // it doesn't leak across detach or project changes.
        self.script_resolved_base = None;
    }

    /// Applies a deferred `ui.*` action queued by a script during host-request
    /// pumping. Kept out of `UiHostApi` because it touches panel state the
    /// transient host struct does not borrow. Goto actions no-op the panel move
    /// on non-Linux (mirroring the rest of the memory/disasm UI).
    #[cfg(feature = "scripting")]
    fn apply_ui_action(&mut self, action: host_api_impl::UiAction) {
        match action {
            host_api_impl::UiAction::GotoMemory(addr) => {
                self.pending_focus = Some(TabKind::Memory);
                self.memory_viewer.goto(addr);
            }
            host_api_impl::UiAction::GotoDisasm(addr) => {
                self.pending_focus = Some(TabKind::Disassembly);
                self.disassembly_panel.goto(addr);
            }
            host_api_impl::UiAction::SelectClass(uuid) => {
                if self.project.get_class(&uuid).is_some() {
                    self.selected_class = Some(uuid);
                    self.clear_memory_state();
                    self.pending_focus = Some(TabKind::ClassView);
                }
            }
            host_api_impl::UiAction::SaveTable(name) => {
                self.apply_cheat_table_action(CheatTablePanelAction::Save(name));
            }
            host_api_impl::UiAction::LoadTable(name) => {
                self.apply_cheat_table_action(CheatTablePanelAction::Load(name));
            }
        }
    }

    /// Apply direct script freezes (`mem.freeze`), throttled to the same cadence
    /// as the cheat table's freeze tick. Each freeze parses its value text with
    /// its type into little-endian bytes and pins it via a `ProcessTarget`.
    /// Derived from `script_freezes` every tick so edits take effect immediately
    /// and no stale byte-cache can revert a change.
    #[cfg(all(feature = "scripting", target_os = "linux"))]
    fn tick_script_freezes(&mut self) {
        const INTERVAL: Duration = Duration::from_millis(200);
        if self.script_freezes.is_empty() {
            return;
        }
        let due = self
            .last_script_freeze
            .map(|t| t.elapsed() >= INTERVAL)
            .unwrap_or(true);
        if !due {
            return;
        }
        self.last_script_freeze = Some(Instant::now());

        let Some(pid) = self.process.as_ref().map(|p| p.pid()) else {
            return;
        };
        let mut set = nemclass_scan::FreezeSet::new();
        for (addr, vt, text) in &self.script_freezes {
            if let Some(bytes) = cheat_table_panel::value_text_to_bytes(*vt, text) {
                set.set(*addr, bytes);
            }
        }
        if set.is_empty() {
            return;
        }
        if let Ok(target) = nemclass_scan::ProcessTarget::attach(pid) {
            let _ = set.apply(&target);
        }
    }

    /// Publishes a lifecycle event to BOTH the compile-time plugin bus and the
    /// JS engine. Route every lifecycle publish through here so the two sinks
    /// never drift.
    fn emit(&mut self, ev: Event) {
        self.event_bus.publish(&ev);
        self.script_host.on_event(&ev);
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

        // Drop script-registered hotkeys/freezes from the previous project so
        // handlers referencing stale ids don't fire against the new one.
        #[cfg(feature = "scripting")]
        {
            self.script_hotkeys.clear();
            self.next_hotkey_id = 1;
            self.script_freezes.clear();
            #[cfg(target_os = "linux")]
            {
                self.script_scanner = None;
            }
        }

        // Notify the scripting layer and auto-load the project's scripts.
        if let Some(dir) = self.project_dir.clone() {
            self.emit(Event::OnProjectLoad {
                path: dir.display().to_string(),
            });
            let src = dir.join("src");
            match self.script_host.load_scripts(&src) {
                Ok(()) if self.script_host.is_active() => script_log::push(
                    &self.script_log,
                    LogKind::Lifecycle,
                    format!("Loaded scripts from {}", src.display()),
                ),
                Ok(()) => {}
                Err(e) => script_log::push(
                    &self.script_log,
                    LogKind::Error,
                    format!("Load scripts failed: {e}"),
                ),
            }
        }
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
            // No project dir yet — route to the native Save As picker.
            self.pick_save_as();
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

        // A script-resolved base (from the "Try resolve (script)" button) takes
        // precedence over the address formula and is sticky until the user edits
        // the formula or detaches.
        let base = if let Some(sb) = self.script_resolved_base {
            Some(sb)
        } else if formula.trim().is_empty() {
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
            .map(|c| {
                let mut visited = std::collections::HashSet::new();
                nemclass_model::resolved_class_size(c, &self.project, &mut visited)
            })
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
        const MAX_DEREF_DEPTH: usize = 8;

        let base = self.class_base.unwrap_or(0);
        let collapsed = self.collapsed.clone();
        let expanded_ptrs = self.expanded_ptrs.clone();
        let mut deref_bufs: HashMap<String, (usize, Vec<u8>)> = HashMap::new();

        loop {
            self.node_snapshots.clear();
            if let Some(class) = self.project.get_class(&uuid) {
                let mut visited = HashSet::new();
                flatten_nodes(
                    &class.children,
                    base,
                    0,
                    0,
                    &self.mem_buf,
                    String::new(),
                    uuid,
                    &[],
                    &mut self.node_snapshots,
                    &self.project,
                    &collapsed,
                    &expanded_ptrs,
                    &deref_bufs,
                    &mut visited,
                    MAX_DEREF_DEPTH,
                );
            }

            // Find expanded pointers that still need a deref buffer.
            let needed: Vec<(String, usize, Uuid)> = self
                .node_snapshots
                .iter()
                .filter(|s| {
                    s.type_tag == "Pointer"
                        && s.pointer_target.is_some()
                        && expanded_ptrs.contains(&s.id_path)
                        && !deref_bufs.contains_key(&s.id_path)
                })
                .map(|s| (s.id_path.clone(), s.address, s.pointer_target.unwrap()))
                .collect();

            if needed.is_empty() {
                break;
            }

            let Some(proc) = &self.process else {
                for (id, _, _) in needed {
                    deref_bufs.insert(id, (0, Vec::new()));
                }
                break;
            };

            let mut any_filled = false;
            for (id, addr, t_uuid) in needed {
                let mut ptr_bytes = [0u8; 8];
                let n = proc.read_buf(addr, &mut ptr_bytes).unwrap_or(0);
                let deref_addr = if n >= 8 {
                    u64::from_le_bytes(ptr_bytes) as usize
                } else {
                    0
                };

                if deref_addr == 0 {
                    deref_bufs.insert(id, (0, Vec::new()));
                    any_filled = true;
                    continue;
                }

                let target_size = self
                    .project
                    .get_class(&t_uuid)
                    .map(|tc| {
                        let mut vis = HashSet::new();
                        nemclass_model::resolved_class_size(tc, &self.project, &mut vis)
                    })
                    .unwrap_or(0);

                let dbuf = if target_size > 0 {
                    read_process_buf(proc, deref_addr, target_size)
                } else {
                    Vec::new()
                };
                deref_bufs.insert(id, (deref_addr, dbuf));
                any_filled = true;
            }

            if !any_filled {
                break;
            }
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
        let Some(edit) = self.edit_state.as_ref() else { return; };
        // Name/comment edits are handled inline in the draw loop via NodeEditOp.
        if edit.field != EditField::Value {
            self.edit_state = None;
            return;
        }
        let edit = self.edit_state.take().unwrap();
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

impl Drop for NemclassApp {
    fn drop(&mut self) {
        // Tear the background runtime down without waiting on in-flight
        // `spawn_blocking` work, so quitting mid-scan doesn't hang the window.
        if let Some(rt) = self.runtime.take() {
            rt.shutdown();
        }
    }
}

impl eframe::App for NemclassApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Drain any background operations that finished since the last frame.
        self.poll_background_jobs();

        let needs_snapshot = self.selected_class.is_some()
            && self
                .last_snapshot
                .map(|t| t.elapsed() >= self.snapshot_interval)
                .unwrap_or(true);

        if needs_snapshot {
            self.take_snapshot();
        }

        // Emit a lightweight OnTick to scripts once per snapshot interval, so
        // scripts can poll/freeze without a timer of their own. Independent of
        // `selected_class` (which gates the class-view snapshot above).
        #[cfg(feature = "scripting")]
        {
            let due = self
                .last_tick
                .map(|t| t.elapsed() >= self.snapshot_interval)
                .unwrap_or(true);
            if due && self.script_host.is_active() {
                self.last_tick = Some(Instant::now());
                let pid = self.process.as_ref().map(|p| p.pid());
                self.script_host
                    .on_event(&Event::OnTick { pid });
            }

            // Poll script-registered global hotkeys. For each match this frame,
            // dispatch `OnHotkey { id }` into the engine. Collect ids first so we
            // don't hold the `ctx.input` closure while borrowing `script_host`.
            if !self.script_hotkeys.is_empty() && self.script_host.is_active() {
                let fired: Vec<u32> = ctx.input(|i| {
                    self.script_hotkeys
                        .iter()
                        .filter(|h| {
                            i.key_pressed(h.key)
                                && i.modifiers.ctrl == h.ctrl
                                && i.modifiers.shift == h.shift
                                && i.modifiers.alt == h.alt
                        })
                        .map(|h| h.id)
                        .collect()
                });
                for id in fired {
                    self.script_host.on_event(&Event::OnHotkey { id });
                }
            }
        }

        // Drive scanner freeze write-back and debugger event polling.
        self.scanner_panel.poll();
        self.scanner_panel.tick_freeze();
        #[cfg(target_os = "linux")]
        self.pointer_scan_panel.poll();
        #[cfg(target_os = "linux")]
        self.disassembly_panel.poll();
        self.debugger_panel.tick_events();
        #[cfg(target_os = "linux")]
        self.cheat_table_panel.tick_freeze(
            self.process.as_deref(),
            self.process.as_ref().map(|p| p.pid()),
        );
        #[cfg(all(feature = "scripting", target_os = "linux"))]
        self.tick_script_freezes();

        // Service host-API requests raised by worker-thread JS. Build a transient
        // `UiHostApi` from disjoint field borrows (never `&mut self`) so the
        // borrow checker is satisfied while the engine mutates the project/log.
        #[cfg(feature = "scripting")]
        {
            let mut ui_actions: Vec<host_api_impl::UiAction> = Vec::new();
            {
                let mut host = host_api_impl::UiHostApi {
                    project: &mut self.project,
                    node_registry: &self.node_registry,
                    process: self.process.as_deref(),
                    log: self.script_log.clone(),
                    last_error: &mut self.last_error,
                    ui_actions: &mut ui_actions,
                    cheat_table: self.cheat_table_panel.table_mut(),
                    script_hotkeys: &mut self.script_hotkeys,
                    next_hotkey_id: &mut self.next_hotkey_id,
                    script_freezes: &mut self.script_freezes,
                    #[cfg(target_os = "linux")]
                    script_scanner: &mut self.script_scanner,
                };
                self.script_host.pump(&mut host);
            }
            // Apply the `ui.*` actions the scripts queued (needs panel state the
            // transient `UiHostApi` deliberately does not borrow).
            for action in ui_actions {
                self.apply_ui_action(action);
            }
        }

        // Keep repainting while attached OR while a live engine is running (so
        // pending host-API requests drain even when not attached).
        if self.process.is_some() || self.script_host.is_active() {
            ctx.request_repaint_after(self.snapshot_interval);
        }

        // ── Ctrl+F: toggle freeze on all cheat-table entries ─────────────
        let freeze_hotkey = ctx.input(|i| {
            i.key_pressed(egui::Key::F) && i.modifiers.ctrl && !i.modifiers.shift && !i.modifiers.alt
        });
        if freeze_hotkey {
            let process = self.process.as_deref();
            let now_frozen = self.cheat_table_panel.toggle_freeze_all(process);
            self.cheat_table_panel.status_msg = Some(if now_frozen {
                "All entries frozen (Ctrl+F to unfreeze)".to_owned()
            } else {
                "All entries unfrozen".to_owned()
            });
        }

        // Persist settings (debounced on change, ~30s heartbeat for layout).
        self.maybe_persist_settings(ctx);
    }

    fn save(&mut self, _storage: &mut dyn eframe::Storage) {
        // Best-effort flush on eframe's periodic/exit save. No context here, so
        // the window size keeps its last-known value.
        self.persist_settings(None);
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Menu bar (outermost — rendered before any panels).
        egui::Panel::top("menu_bar")
            .resizable(false)
            .show(ui, |ui| self.show_menu_bar(ui));

        // Address bar.
        egui::Panel::top("address_bar")
            .resizable(false)
            .show(ui, |ui| self.show_address_bar(ui));

        egui::Panel::left("left_panel")
            .resizable(true)
            .show(ui, |ui| self.show_left_panel(ui));

        egui::CentralPanel::default().show(ui, |ui| self.show_central_panel(ui));

        // Modal dialogs (rendered on top of everything else).
        self.show_class_picker(ui.ctx());
        self.show_add_bytes_dialog(ui.ctx());
        self.show_class_rename_modal(ui.ctx());
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

            // Deferred file actions (native rfd dialogs block the UI thread, so
            // we collect the intent and run it after the menu-bar closure).
            let mut do_new = false;
            let mut do_open = false;
            let mut do_save = false;
            let mut do_save_as = false;
            let mut open_recent: Option<PathBuf> = None;

            ui.menu_button("File", |ui| {
                if ui.button("New Project…").clicked() {
                    do_new = true;
                    ui.close();
                }
                if ui.button("Open Project…").clicked() {
                    do_open = true;
                    ui.close();
                }
                if ui.button("Save").clicked() {
                    do_save = true;
                    ui.close();
                }
                if ui.button("Save As…").clicked() {
                    do_save_as = true;
                    ui.close();
                }
                // Recent projects submenu.
                if !self.settings.recent_projects.is_empty() {
                    ui.separator();
                    ui.menu_button("Recent Projects", |ui| {
                        for dir in &self.settings.recent_projects {
                            if ui.button(dir.display().to_string()).clicked() {
                                open_recent = Some(dir.clone());
                                ui.close();
                            }
                        }
                    });
                }
            });

            // View menu: toggle dock panels on/off and reset the layout.
            ui.menu_button("View", |ui| self.show_view_menu(ui));

            // Apply the collected file action after the closures release `self`.
            if do_new {
                self.pick_new_project();
            } else if do_open {
                self.pick_open_project();
            } else if do_save {
                if let Err(e) = self.exec_save() {
                    self.last_error = Some(e);
                }
            } else if do_save_as {
                self.pick_save_as();
            } else if let Some(dir) = open_recent {
                self.open_project_path(dir);
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
    // Native file dialogs (rfd) + recent projects
    // -----------------------------------------------------------------------

    /// The directory to start a native dialog in: the current project dir, else
    /// the most recent project, else the user's home.
    fn dialog_start_dir(&self) -> PathBuf {
        self.project_dir
            .clone()
            .or_else(|| self.settings.recent_projects.first().cloned())
            .or_else(dirs::home_dir)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// New Project: pick a target directory, scaffold + load it there.
    fn pick_new_project(&mut self) {
        if let Some(dir) = rfd::FileDialog::new()
            .set_title("New Project — choose a directory")
            .set_directory(self.dialog_start_dir())
            .pick_folder()
        {
            match self.exec_new(dir.clone()) {
                Ok(()) => self.on_project_path_used(&dir),
                Err(e) => self.last_error = Some(e),
            }
        }
    }

    /// Open Project: pick a `project.nemclass` file (or, failing a filtered
    /// pick, a directory) and load it.
    fn pick_open_project(&mut self) {
        let picked = rfd::FileDialog::new()
            .set_title("Open Project — select project.nemclass")
            .set_directory(self.dialog_start_dir())
            .add_filter("NemClass project", &["nemclass"])
            .pick_file()
            .or_else(|| {
                rfd::FileDialog::new()
                    .set_title("Open Project — select the project directory")
                    .set_directory(self.dialog_start_dir())
                    .pick_folder()
            });
        if let Some(path) = picked {
            self.open_project_path(path);
        }
    }

    /// Save As: pick a target directory and save the project there.
    fn pick_save_as(&mut self) {
        if let Some(dir) = rfd::FileDialog::new()
            .set_title("Save As — choose a directory")
            .set_directory(self.dialog_start_dir())
            .pick_folder()
        {
            match self.exec_save_as(dir.clone()) {
                Ok(()) => self.on_project_path_used(&dir),
                Err(e) => self.last_error = Some(e),
            }
        }
    }

    /// Loads a project from an explicit path (recent-projects entry).
    fn open_project_path(&mut self, path: PathBuf) {
        match self.exec_open(path) {
            Ok(()) => {
                if let Some(dir) = self.project_dir.clone() {
                    self.on_project_path_used(&dir);
                }
            }
            Err(e) => self.last_error = Some(e),
        }
    }

    /// Records a successfully-used project path in the MRU list and schedules a
    /// settings save.
    fn on_project_path_used(&mut self, dir: &std::path::Path) {
        self.last_error = None;
        self.settings.note_project(dir);
        self.mark_settings_dirty();
    }

    // -----------------------------------------------------------------------
    // Address bar
    // -----------------------------------------------------------------------

    fn show_address_bar(&mut self, ui: &mut egui::Ui) {
        // Collect actions during the draw and apply after the closure releases
        // its borrow on `self` (the pattern used throughout this file).
        let mut do_resolve = false;
        let mut formula_changed = false;
        let resolved_active = self.script_resolved_base.is_some();
        let attached = self.process.is_some();

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
            if resolved_active {
                ui.colored_label(egui::Color32::LIGHT_BLUE, "(script)");
            }

            // "Try get class address" via the script/plugin resolver chain.
            let resolving = self.resolve_job.is_running();
            if ui
                .add_enabled(attached && !resolving, egui::Button::new("Try resolve (script)"))
                .on_hover_text("Ask a script's tryResolveClassAddress resolver for this class's base address")
                .on_disabled_hover_text("Attach to a process first")
                .clicked()
            {
                do_resolve = true;
            }
            if resolving {
                ui.spinner();
            }
            ui.separator();

            if let Some(uuid) = self.selected_class
                && let Some(class) = self.project.get_class_mut(&uuid)
            {
                    ui.strong("Formula:");
                    if ui.text_edit_singleline(&mut class.address_formula).changed() {
                        formula_changed = true;
                    }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match &self.attached_name {
                    Some(n) => ui.colored_label(egui::Color32::GREEN, format!("Attached: {n}")),
                    None    => ui.colored_label(egui::Color32::GRAY, "Not attached"),
                };
            });
        });

        if formula_changed {
            self.last_snapshot = None;
            self.class_base = None;
            // Editing the formula re-takes control from any script-resolved base.
            self.script_resolved_base = None;
        }
        if do_resolve {
            self.do_resolve_class_address(ui.ctx());
        }
    }

    /// Runs the script/plugin resolver chain for the selected class and, on
    /// success, sets a sticky script-resolved base. Triggered only by the explicit
    /// "Try resolve (script)" button. The live engine's resolve is a blocking v8
    /// round-trip, so it runs on the background pool (via a detached
    /// [`nemclass_script::ScriptResolver`]) to keep the window responsive; the
    /// answer is merged in `logic` via [`Self::ingest_resolve`].
    #[cfg_attr(not(feature = "scripting"), allow(unused_variables))]
    fn do_resolve_class_address(&mut self, ctx: &egui::Context) {
        let (Some(uuid), Some(proc)) = (self.selected_class, self.process.as_ref()) else {
            return;
        };
        let q = ClassAddressQuery { pid: proc.pid(), class: uuid };

        #[cfg(feature = "scripting")]
        {
            if self.resolve_job.is_running() {
                return;
            }
            // A live engine → run the blocking resolve off-thread.
            if let Some(resolver) = self.script_host.resolver() {
                let Some(rt) = self.runtime.as_ref().map(|r| r.handle()) else {
                    return;
                };
                self.status_msg = Some("Resolving class address…".into());
                self.resolve_job.spawn(&rt, ctx.clone(), move || {
                    (uuid, resolver.resolve(&q))
                });
                return;
            }
        }

        // No live resolver (feature off, or engine disabled): resolves instantly.
        self.ingest_resolve(uuid, None);
    }

    /// Applies a completed class-address resolve: sets the sticky script-resolved
    /// base and logs, or reports that nothing resolved. Runs on the UI thread.
    fn ingest_resolve(&mut self, uuid: Uuid, resolved: Option<usize>) {
        self.status_msg = None;
        // Ignore a stale result if the user changed the selected class meanwhile.
        if self.selected_class != Some(uuid) {
            return;
        }
        match resolved {
            Some(addr) => {
                self.script_resolved_base = Some(addr);
                self.class_base = Some(addr);
                self.last_snapshot = None;
                script_log::push(
                    &self.script_log,
                    LogKind::Lifecycle,
                    format!("Resolved class {uuid} → 0x{addr:016X}"),
                );
            }
            None => {
                let msg = "No script resolver returned an address.".to_string();
                script_log::push(&self.script_log, LogKind::Warn, msg.clone());
                self.last_error = Some(msg);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Left panel
    // -----------------------------------------------------------------------

    fn show_left_panel(&mut self, ui: &mut egui::Ui) {
        ui.set_min_width(220.0);

        // Backend selector.
        ui.heading("Backend");
        let backend_names = self.backend_names.clone();
        let prev_backend = self.selected_backend.clone();
        egui::ComboBox::from_id_salt("backend_combo")
            .selected_text(&self.selected_backend)
            .show_ui(ui, |ui| {
                for name in &backend_names {
                    ui.selectable_value(&mut self.selected_backend, name.clone(), name.as_str());
                }
            });
        if self.selected_backend != prev_backend {
            self.mark_settings_dirty();
        }

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
            let refresh = ui.add_enabled(
                !self.enumerate_job.is_running(),
                egui::Button::new("Refresh"),
            );
            if refresh.clicked() {
                self.do_refresh(ui.ctx());
            }
            if self.enumerate_job.is_running() {
                ui.spinner();
            }
            if self.selected_process_idx.is_some() {
                let attach = ui.add_enabled(
                    !self.attach_job.is_running(),
                    egui::Button::new("Attach"),
                );
                if attach.clicked() {
                    self.do_attach(ui.ctx());
                }
            }
            if self.attach_job.is_running() {
                ui.spinner();
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
        ui.horizontal(|ui| {
            ui.heading("Classes");
            // Create an empty, auto-named class container; rename via double-click,
            // delete via the trash button (both below).
            if ui.button("+ Add class").on_hover_text("Create an empty class").clicked() {
                let cls = blank_class(&self.project);
                let uuid = cls.uuid;
                self.project.add_class(cls);
                self.selected_class = Some(uuid);
                self.last_snapshot = None;
                self.clear_memory_state();
            }
        });

        // Deferred class-list mutations (can't mutate the project while the list
        // borrows it in the scroll closure).
        let mut to_delete: Option<Uuid> = None;
        let mut start_rename: Option<Uuid> = None;
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
                    ui.horizontal(|ui| {
                        if ui
                            .small_button("🗑")
                            .on_hover_text("Delete class")
                            .clicked()
                        {
                            to_delete = Some(uuid);
                        }
                        let resp = ui
                            .selectable_label(selected, &label)
                            .on_hover_text("Double-click to rename");
                        if resp.clicked() && self.selected_class != Some(uuid) {
                            self.selected_class = Some(uuid);
                            self.last_snapshot = None;
                            self.clear_memory_state();
                        }
                        if resp.double_clicked() {
                            start_rename = Some(uuid);
                        }
                    });
                }
            });

        // Apply deferred class deletion (guarded against removing a class another
        // class still references) and open the rename modal.
        if let Some(uuid) = to_delete {
            match self.project.remove_class(&uuid) {
                Ok(_) => {
                    if self.selected_class == Some(uuid) {
                        self.selected_class =
                            self.project.classes_in_order().next().map(|c| c.uuid);
                        self.clear_memory_state();
                        self.last_snapshot = None;
                    }
                }
                Err(e) => self.last_error = Some(e.to_string()),
            }
        }
        if let Some(uuid) = start_rename {
            let cur = self
                .project
                .get_class(&uuid)
                .map(|c| c.name.clone())
                .unwrap_or_default();
            self.class_rename = Some((uuid, cur));
        }

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
                self.mark_settings_dirty();
            }
        });
    }

    // -----------------------------------------------------------------------
    // Central panel — tab bar + dispatching
    // -----------------------------------------------------------------------

    fn show_central_panel(&mut self, ui: &mut egui::Ui) {
        // Take the dock state into a local so the `DockViewer` can borrow the
        // rest of `self` mutably without aliasing the `dock_state` field.
        let mut dock = self
            .dock_state
            .take()
            .unwrap_or_else(dock::default_layout);

        egui_dock::DockArea::new(&mut dock)
            .style(egui_dock::Style::from_egui(ui.style().as_ref()))
            .show_inside(ui, &mut dock::DockViewer { app: self });

        // Honour a cross-panel focus request raised during the draw (e.g. a
        // "Disassemble here" click bringing the Disassembly tab to the front).
        if let Some(target) = self.pending_focus.take()
            && let Some(path) = dock.find_tab(&target)
        {
            let _ = dock.set_active_tab(path);
        }

        self.dock_state = Some(dock);

        // Apply any deferred pointer-scan action (collected during the tab draw
        // to avoid borrow conflicts with `self.project` / `self.selected_class`).
        if let Some(action) = self.pending_pointer_scan_action.take() {
            self.apply_pointer_scan_action(action);
        }
    }

    /// The "View" menu: re-open any dock tab that was closed (adds it to the
    /// focused leaf) and reset the layout to the default arrangement.
    fn show_view_menu(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        let dock = self.dock_state.get_or_insert_with(dock::default_layout);
        for kind in TabKind::ALL {
            let open = dock.find_tab(&kind).is_some();
            let mut checked = open;
            if ui.checkbox(&mut checked, kind.title()).clicked() {
                if checked && !open {
                    dock.push_to_focused_leaf(kind);
                } else if !checked && open
                    && let Some(path) = dock.find_tab(&kind)
                {
                    dock.remove_tab(path);
                }
                changed = true;
                ui.close();
            }
        }
        ui.separator();
        if ui.button("Reset layout").clicked() {
            self.dock_state = Some(dock::default_layout());
            changed = true;
            ui.close();
        }
        if changed {
            self.mark_settings_dirty();
        }
    }

    /// The "Scripts" tab: engine status, script-file list, host functions, and
    /// the shared log. Applies the panel's returned action after the draw.
    fn show_scripts_tab(&mut self, ui: &mut egui::Ui) {
        // The legacy named host functions plus every catalog-driven namespaced
        // method (`mem.readU32`, ...), so the panel reference stays in lock-step
        // with the actual API surface.
        let mut host_fns: Vec<&str> = vec!["pattern_scan", "declare_class", "declare_type", "log"];
        host_fns.extend(nemclass_script::host_method_names());
        let host_fns_ref: &[&str] = &host_fns;

        let scripts_dir = self.project_dir.as_ref().map(|d| d.join("src"));
        let engine_active = self.script_host.is_active();
        let status = if engine_active {
            String::new()
        } else if cfg!(feature = "scripting") {
            "Engine not running — spawn failed; see startup status.".to_string()
        } else {
            "Built without the `scripting` feature — rebuild with --features scripting for JS.".to_string()
        };

        let action = self.scripts_panel.show(
            ui,
            scripts_dir.as_deref(),
            engine_active,
            &status,
            host_fns_ref,
            &self.script_log,
        );

        match action {
            ScriptsPanelAction::None => {}
            ScriptsPanelAction::LoadAll => {
                if let Some(dir) = scripts_dir {
                    match self.script_host.load_scripts(&dir) {
                        Ok(()) => script_log::push(
                            &self.script_log,
                            LogKind::Lifecycle,
                            format!("Loaded scripts from {}", dir.display()),
                        ),
                        Err(e) => script_log::push(
                            &self.script_log,
                            LogKind::Error,
                            format!("Load scripts failed: {e}"),
                        ),
                    }
                }
            }
            ScriptsPanelAction::Reload(path) => {
                // The engine loads a whole directory; reload the file's parent so
                // a single-file reload still refreshes it.
                let dir = path.parent().map(|p| p.to_path_buf());
                if let Some(dir) = dir {
                    match self.script_host.load_scripts(&dir) {
                        Ok(()) => script_log::push(
                            &self.script_log,
                            LogKind::Lifecycle,
                            format!("Reloaded {}", path.display()),
                        ),
                        Err(e) => script_log::push(
                            &self.script_log,
                            LogKind::Error,
                            format!("Reload failed: {e}"),
                        ),
                    }
                }
            }
            ScriptsPanelAction::Clear => {
                self.script_log.borrow_mut().clear();
            }
        }
    }

    fn show_scanner_tab(&mut self, ui: &mut egui::Ui) {
        // Derive the pid from the attached process on Linux; scanner accepts
        // Pid (u32 alias in nemclass-core) but ProcessTarget::attach takes Pid.
        #[cfg(target_os = "linux")]
        let pid: Option<nemclass_core::Pid> = self.process.as_ref().map(|p| p.pid());
        #[cfg(not(target_os = "linux"))]
        let pid: Option<nemclass_core::Pid> = None;

        let process_ref = self.process.as_deref();
        // Owned handle (cloned) so it doesn't borrow `self` across the panel call.
        let rt = self.runtime.as_ref().expect("bg runtime").handle();

        let mut add_to_class_addr: Option<usize> = None;
        let mut add_to_table: Option<(usize, String)> = None;
        let mut ptr_scan_addr: Option<usize> = None;

        self.scanner_panel.show(
            ui,
            process_ref,
            pid,
            &rt,
            |addr| { add_to_class_addr = Some(addr); },
            |addr, tag| { add_to_table = Some((addr, tag.to_owned())); },
            |addr| { ptr_scan_addr = Some(addr); },
        );

        // Apply deferred callbacks (all need self borrows unavailable inside the closure).
        if let Some(addr) = add_to_class_addr {
            // "Add to class": append a Hex64 address node to the currently-selected
            // class (or the first class in the project).
            use nemclass_model::node::builtins::Hex64Node;
            let selected_class = self.selected_class;
            let uuid = selected_class
                .or_else(|| self.project.classes_in_order().next().map(|c| c.uuid));
            if let Some(uuid) = uuid
                && let Some(class) = self.project.get_class_mut(&uuid)
            {
                let label = format!("scan_{addr:#x}");
                let mut node = Hex64Node::new(&label);
                node.comment = format!("Scanner result 0x{addr:016X}");
                class.children.push(Box::new(node));
            }
        }
        if let Some((addr, tag)) = add_to_table {
            self.cheat_table_panel.table_mut().push(nemclass_model::CheatEntry {
                description: format!("0x{addr:X}"),
                address: format!("0x{addr:X}"),
                value_type: tag,
                frozen: false,
                frozen_value: String::new(),
                group: String::new(),
            });
        }
        if let Some(addr) = ptr_scan_addr {
            self.pointer_scan_panel.set_goal(addr);
            self.pending_focus = Some(TabKind::PointerScan);
        }
    }

    fn show_pointer_scan_tab(&mut self, ui: &mut egui::Ui) {
        #[cfg(target_os = "linux")]
        let pid: Option<nemclass_core::Pid> = self.process.as_ref().map(|p| p.pid());
        #[cfg(not(target_os = "linux"))]
        let pid: Option<nemclass_core::Pid> = None;

        let modules: Vec<nemclass_core::ModuleInfoWithName> = self
            .process
            .as_ref()
            .and_then(|p| p.modules().ok())
            .map(|it| it.collect())
            .unwrap_or_default();

        let rt = self.runtime.as_ref().expect("bg runtime").handle();
        let action = self.pointer_scan_panel.show(
            ui,
            self.process.clone(),
            pid,
            &modules,
            &rt,
        );

        // Stash the action for application after the dock draw closes all borrows.
        match action {
            PointerScanAction::None => {}
            other => { self.pending_pointer_scan_action = Some(other); }
        }
    }

    /// Apply a [`PointerScanAction`] deferred from the pointer-scan tab draw.
    fn apply_pointer_scan_action(&mut self, action: PointerScanAction) {
        match action {
            PointerScanAction::None => {}
            PointerScanAction::CreateClass { name, formula } => {
                let mut cls = blank_class(&self.project);
                if !name.is_empty() {
                    cls.name = name;
                }
                cls.address_formula = formula;
                let uuid = cls.uuid;
                self.project.add_class(cls);
                self.selected_class = Some(uuid);
                self.clear_memory_state();
                self.last_snapshot = None;
            }
            PointerScanAction::Goto(addr) => {
                self.pending_focus = Some(TabKind::Memory);
                #[cfg(target_os = "linux")]
                self.memory_viewer.goto(addr);
                #[cfg(not(target_os = "linux"))]
                let _ = addr;
            }
        }
    }

    pub(crate) fn show_cheat_table_tab(&mut self, ui: &mut egui::Ui) {
        let process = self.process.as_deref();
        #[cfg(target_os = "linux")]
        let pid: Option<nemclass_core::Pid> = self.process.as_ref().map(|p| p.pid());
        #[cfg(not(target_os = "linux"))]
        let pid: Option<nemclass_core::Pid> = None;
        let project_dir = self.project_dir.as_deref();
        let action = self.cheat_table_panel.show(ui, process, pid, project_dir);
        self.apply_cheat_table_action(action);
    }

    fn apply_cheat_table_action(&mut self, action: CheatTablePanelAction) {
        match action {
            CheatTablePanelAction::None => {}
            CheatTablePanelAction::Save(name) => {
                if let Some(dir) = &self.project_dir {
                    let tables_dir = dir.join("tables");
                    let _ = std::fs::create_dir_all(&tables_dir);
                    let path = tables_dir.join(format!("{name}.toml"));
                    match self.cheat_table_panel.table_mut().to_toml() {
                        Ok(s) => { let _ = std::fs::write(&path, s); }
                        Err(e) => {
                            self.cheat_table_panel.status_msg =
                                Some(format!("Save failed: {e}"));
                        }
                    }
                }
            }
            CheatTablePanelAction::Load(name) => {
                if let Some(dir) = &self.project_dir {
                    let path = dir.join("tables").join(format!("{name}.toml"));
                    match std::fs::read_to_string(&path) {
                        Ok(s) => match nemclass_model::CheatTable::from_toml(&s) {
                            Ok(t) => { self.cheat_table_panel.set_table(t); }
                            Err(e) => {
                                self.cheat_table_panel.status_msg =
                                    Some(format!("Parse error: {e}"));
                            }
                        },
                        Err(e) => {
                            self.cheat_table_panel.status_msg =
                                Some(format!("Load failed: {e}"));
                        }
                    }
                }
            }
            CheatTablePanelAction::GotoAddr(addr) => {
                self.memory_viewer.goto(addr);
                self.pending_focus = Some(TabKind::Memory);
            }
        }
    }

    fn show_debugger_tab(&mut self, ui: &mut egui::Ui) {
        #[cfg(target_os = "linux")]
        let pid: Option<libc::pid_t> = self.process.as_ref().map(|p| p.pid() as libc::pid_t);
        #[cfg(not(target_os = "linux"))]
        let pid: Option<i32> = None;

        self.debugger_panel.show(ui, pid);
    }

    fn show_memory_viewer(&mut self, ui: &mut egui::Ui) {
        self.memory_viewer.show(ui, self.process.as_deref());
        // If the "Disassemble here" button was clicked, switch tabs and navigate.
        if let Some(addr) = self.memory_viewer.take_disassemble_request() {
            self.pending_focus = Some(TabKind::Disassembly);
            self.disassembly_panel.goto(addr);
        }
        // If the "Dissect as class here" button was clicked, switch to the
        // Memory View tab and run auto-dissect at the viewer's current address.
        // The length comes from the existing dissect_len_text field.
        #[cfg(target_os = "linux")]
        if let Some(addr) = self.memory_viewer.take_dissect_request() {
            self.pending_focus = Some(TabKind::ClassView);
            self.run_auto_dissect(addr);
        }
    }

    /// The Navigator side panel: strings / functions / calls from a dissect.
    /// Routes its click actions to the disassembler / hex viewer.
    fn show_navigator_tab(&mut self, ui: &mut egui::Ui) {
        use navigator::NavAction;

        #[cfg(target_os = "linux")]
        let action = {
            let epoch = self.disassembly_panel.dissect_epoch();
            let dissect = self.disassembly_panel.dissect_result().map(|d| (epoch, d));
            self.navigator_panel.show(ui, dissect, self.process.as_deref())
        };
        #[cfg(not(target_os = "linux"))]
        let action = self.navigator_panel.show(ui);

        match action {
            Some(NavAction::GotoDisasm(addr)) => {
                self.disassembly_panel.goto(addr);
                self.pending_focus = Some(TabKind::Disassembly);
            }
            Some(NavAction::GotoMemory(addr)) => {
                self.memory_viewer.goto(addr);
                self.pending_focus = Some(TabKind::Memory);
            }
            Some(NavAction::RunDissect) => {
                #[cfg(target_os = "linux")]
                if let Some(proc) = self.process.clone() {
                    let rt = self.runtime.as_ref().expect("bg runtime").handle();
                    self.disassembly_panel
                        .dissect_selected(proc, &rt, ui.ctx().clone());
                }
            }
            None => {}
        }
    }

    fn show_disassembly_tab(&mut self, ui: &mut egui::Ui) {
        let rt = self.runtime.as_ref().expect("bg runtime").handle();
        self.disassembly_panel.show(ui, self.process.clone(), &rt);

        // Apply a row-context-menu action (set-as-class-base / add-address-node)
        // raised inside the disassembler, targeting the selected class.
        if let Some(action) = self.disassembly_panel.take_action() {
            use disassembly::DisasmAction;
            use nemclass_model::node::builtins::Hex64Node;
            let uuid = self
                .selected_class
                .or_else(|| self.project.classes_in_order().next().map(|c| c.uuid));
            if let Some(uuid) = uuid
                && let Some(class) = self.project.get_class_mut(&uuid)
            {
                match action {
                    DisasmAction::SetClassAddress(addr) => {
                        class.address_formula = format!("{addr:#x}");
                        self.status_msg =
                            Some(format!("Set {} base to {addr:#x}", class.name));
                    }
                    DisasmAction::AddAddressToClass(addr) => {
                        let mut node = Hex64Node::new(format!("disasm_{addr:#x}"));
                        node.comment = format!("From disassembler {addr:#018X}");
                        class.children.push(Box::new(node));
                    }
                }
            }
        }
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

                            let address        = snap.address;
                            let offset         = snap.offset;
                            let type_tag       = snap.type_tag;
                            let name           = snap.name.clone();
                            let comment        = snap.comment.clone();
                            let value          = snap.rendered.value.clone();
                            let depth          = snap.depth;
                            let has_children   = snap.has_children;
                            let id_path        = snap.id_path.clone();
                            let pointer_target = snap.pointer_target;
                            let snap_owner     = snap.owner_class;
                            let snap_local_path = snap.local_path.clone();

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
                                        if type_tag == "Pointer" {
                                            let is_expanded = self.expanded_ptrs.contains(&id_path);
                                            let arrow = if is_expanded { "▼" } else { "▶" };
                                            if ui.small_button(arrow).clicked() {
                                                if is_expanded {
                                                    self.expanded_ptrs.remove(&id_path);
                                                } else {
                                                    self.expanded_ptrs.insert(id_path.clone());
                                                }
                                            }
                                        } else {
                                            let is_collapsed = self.collapsed.contains(&id_path);
                                            let arrow = if is_collapsed { "▶" } else { "▼" };
                                            if ui.small_button(arrow).clicked() {
                                                if is_collapsed {
                                                    self.collapsed.remove(&id_path);
                                                } else {
                                                    self.collapsed.insert(id_path.clone());
                                                }
                                            }
                                        }
                                    } else {
                                        ui.add_space(16.0);
                                    }
                                    // Name cell: double-click to edit inline.
                                    let name_editing = self.edit_state.as_ref()
                                        .is_some_and(|e| e.node_id == id_path && e.field == EditField::Name);
                                    if name_editing {
                                        let resp = ui.text_edit_singleline(
                                            &mut self.edit_state.as_mut().unwrap().text,
                                        );
                                        let enter  = ui.input(|i| i.key_pressed(egui::Key::Enter));
                                        let escape = ui.input(|i| i.key_pressed(egui::Key::Escape));
                                        if resp.lost_focus() || enter {
                                            let edit = self.edit_state.take().unwrap();
                                            self.pending_node_edits.push(NodeEditOp::SetName {
                                                owner: snap_owner,
                                                path: snap_local_path.clone(),
                                                name: edit.text,
                                            });
                                        } else if escape {
                                            self.edit_state = None;
                                        }
                                    } else {
                                        let resp = ui.label(&name);
                                        if resp.double_clicked() {
                                            self.edit_state = Some(EditState {
                                                node_id: id_path.clone(),
                                                text: name.clone(),
                                                field: EditField::Name,
                                            });
                                        }
                                    }
                                });
                            });

                            row.col(|ui| {
                                let editing = self
                                    .edit_state
                                    .as_ref()
                                    .is_some_and(|e| e.node_id == id_path && e.field == EditField::Value);

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
                                                field: EditField::Value,
                                            });
                                        }
                                        resp.context_menu(|ui| {
                                            self.build_node_context_menu(
                                                ui, snap_owner, snap_local_path.clone(),
                                                type_tag, &value, pointer_target,
                                            );
                                        });
                                    }
                                } else {
                                    let resp = ui.label(&value);
                                    resp.context_menu(|ui| {
                                        self.build_node_context_menu(
                                            ui, snap_owner, snap_local_path.clone(),
                                            type_tag, &value, pointer_target,
                                        );
                                    });
                                }
                            });

                            // Comment column: double-click to edit inline.
                            row.col(|ui| {
                                let comment_editing = self.edit_state.as_ref()
                                    .is_some_and(|e| e.node_id == id_path && e.field == EditField::Comment);
                                if comment_editing {
                                    let resp = ui.text_edit_singleline(
                                        &mut self.edit_state.as_mut().unwrap().text,
                                    );
                                    let enter  = ui.input(|i| i.key_pressed(egui::Key::Enter));
                                    let escape = ui.input(|i| i.key_pressed(egui::Key::Escape));
                                    if resp.lost_focus() || enter {
                                        let edit = self.edit_state.take().unwrap();
                                        self.pending_node_edits.push(NodeEditOp::SetComment {
                                            owner: snap_owner,
                                            path: snap_local_path.clone(),
                                            comment: edit.text,
                                        });
                                    } else if escape {
                                        self.edit_state = None;
                                    }
                                } else {
                                    let resp = ui.label(&comment);
                                    if resp.double_clicked() {
                                        self.edit_state = Some(EditState {
                                            node_id: id_path.clone(),
                                            text: comment.clone(),
                                            field: EditField::Comment,
                                        });
                                    }
                                }
                            });
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
            self.pending_focus = Some(TabKind::Disassembly);
            self.disassembly_panel.goto(addr as usize);
        }

        // Apply any pending "follow pointer" request collected during the draw.
        if let Some((addr, target_uuid)) = self.pending_follow_pointer.take() {
            self.follow_pointer(addr, target_uuid);
        }

        // Apply any deferred structural node edits (ChangeType, Delete, …).
        let ops: Vec<NodeEditOp> = self.pending_node_edits.drain(..).collect();
        for op in ops {
            self.apply_node_edit(op);
        }
    }

    /// Opens a pointer's target: if the `PointerNode` names a target class, select
    /// it and pin its base to the followed address (via the sticky script-resolved
    /// base). Otherwise fall back to the raw Memory viewer at that address.
    fn follow_pointer(&mut self, addr: usize, target_uuid: Option<Uuid>) {
        match target_uuid {
            Some(uuid) if self.project.get_class(&uuid).is_some() => {
                self.selected_class = Some(uuid);
                self.script_resolved_base = Some(addr);
                self.class_base = Some(addr);
                self.node_snapshots.clear();
                self.mem_buf.clear();
                self.edit_state = None;
                self.last_snapshot = None;
                self.pending_focus = Some(TabKind::ClassView);
            }
            _ => {
                // No target class → show raw bytes at the pointed-to address.
                self.pending_focus = Some(TabKind::Memory);
                #[cfg(target_os = "linux")]
                self.memory_viewer.goto(addr);
                self.status_msg =
                    Some(format!("Pointer target 0x{addr:016X} (no class set)"));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Per-row context menu
    // -----------------------------------------------------------------------

    /// Populate the right-click context menu for a node's value cell.
    ///
    /// Called on both the editable (`selectable_label`) and non-editable
    /// (`label`) response so every row has a full context menu.
    fn build_node_context_menu(
        &mut self,
        ui: &mut egui::Ui,
        snap_owner: Uuid,
        snap_local_path: Vec<usize>,
        type_tag: &'static str,
        value: &str,
        pointer_target: Option<Uuid>,
    ) {
        ui.menu_button("Change type ▸", |ui| {
            for &(label, tag) in &[
                ("Hex 8",    "Hex8"),    ("Hex 16",  "Hex16"),
                ("Hex 32",   "Hex32"),   ("Hex 64",  "Hex64"),
                ("Int 8",    "Int8"),    ("Int 16",  "Int16"),
                ("Int 32",   "Int32"),   ("Int 64",  "Int64"),
                ("UInt 8",   "UInt8"),   ("UInt 16", "UInt16"),
                ("UInt 32",  "UInt32"),  ("UInt 64", "UInt64"),
                ("Float",    "Float"),   ("Double",  "Double"),
                ("Bool",     "Bool"),    ("Pointer", "Pointer"),
            ] {
                if ui.button(label).clicked() {
                    self.pending_node_edits.push(NodeEditOp::ChangeType {
                        owner: snap_owner,
                        path: snap_local_path.clone(),
                        new_tag: tag,
                    });
                    ui.close();
                }
            }
            ui.separator();
            if ui.button("Class Instance…").clicked() {
                self.class_picker = Some(ClassPickerState {
                    filter: String::new(),
                    purpose: PickerPurpose::ChangeToInstance {
                        owner: snap_owner,
                        path: snap_local_path.clone(),
                    },
                });
                ui.close();
            }
        });

        if type_tag == "Pointer" || type_tag == "ClassInstance" {
            ui.separator();
            if ui.button("Set target class…").clicked() {
                let purpose = if type_tag == "Pointer" {
                    PickerPurpose::SetPtrTarget {
                        owner: snap_owner,
                        path: snap_local_path.clone(),
                    }
                } else {
                    PickerPurpose::SetInstance {
                        owner: snap_owner,
                        path: snap_local_path.clone(),
                    }
                };
                self.class_picker = Some(ClassPickerState {
                    filter: String::new(),
                    purpose,
                });
                ui.close();
            }
        }

        ui.separator();
        if ui.button("Add bytes…").clicked() {
            self.add_bytes_dialog = Some(AddBytesState {
                owner: snap_owner,
                path: snap_local_path.clone(),
                count_text: "8".into(),
                insert: false,
            });
            ui.close();
        }
        if ui.button("Insert bytes…").clicked() {
            self.add_bytes_dialog = Some(AddBytesState {
                owner: snap_owner,
                path: snap_local_path.clone(),
                count_text: "8".into(),
                insert: true,
            });
            ui.close();
        }
        ui.separator();
        if ui.button("Delete").clicked() {
            self.pending_node_edits.push(NodeEditOp::Delete {
                owner: snap_owner,
                path: snap_local_path.clone(),
            });
            ui.close();
        }

        if type_tag == "Pointer" {
            ui.separator();
            let target_addr = value
                .strip_prefix("0x").or_else(|| value.strip_prefix("0X"))
                .and_then(|h| usize::from_str_radix(h, 16).ok());
            let enabled = target_addr.is_some_and(|a| a != 0);
            if ui.add_enabled(
                enabled,
                egui::Button::new("Follow pointer → open target"),
            ).clicked() {
                if let Some(addr) = target_addr {
                    self.pending_follow_pointer = Some((addr, pointer_target));
                }
                ui.close();
            }
            if ui.add_enabled(
                enabled,
                egui::Button::new("Pointer-scan this address"),
            ).clicked() {
                if let Some(addr) = target_addr {
                    self.pointer_scan_panel.set_goal(addr);
                    self.pending_focus = Some(TabKind::PointerScan);
                }
                ui.close();
            }
        }
    }

    // -----------------------------------------------------------------------
    // Class picker modal
    // -----------------------------------------------------------------------

    fn show_class_picker(&mut self, ctx: &egui::Context) {
        if self.class_picker.is_none() { return; }

        let mut selected_uuid: Option<Uuid> = None;
        let mut cancel = false;

        // Clone what we need to avoid borrow conflict while the window borrows ctx.
        let (filter, purpose) = {
            let p = self.class_picker.as_ref().unwrap();
            (p.filter.clone(), p.purpose.clone())
        };

        egui::Window::new("Select Class")
            .resizable(true)
            .show(ctx, |ui| {
                let mut f = filter.clone();
                if ui.text_edit_singleline(&mut f).changed()
                    && let Some(p) = &mut self.class_picker
                {
                    p.filter = f.clone();
                }
                let filter_lc = f.to_lowercase();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let uuids: Vec<(Uuid, String)> = self
                        .project
                        .classes_in_order()
                        .map(|c| (c.uuid, c.name.clone()))
                        .collect();
                    for (uuid, name) in uuids {
                        if !filter_lc.is_empty() && !name.to_lowercase().contains(&filter_lc) {
                            continue;
                        }
                        if ui.selectable_label(false, &name).clicked() {
                            selected_uuid = Some(uuid);
                        }
                    }
                });
                if ui.button("Cancel").clicked() {
                    cancel = true;
                }
            });

        if cancel {
            self.class_picker = None;
            return;
        }

        if let Some(uuid) = selected_uuid {
            let (owner, _path) = match &purpose {
                PickerPurpose::SetPtrTarget     { owner, path } => (*owner, path.clone()),
                PickerPurpose::SetInstance      { owner, path } => (*owner, path.clone()),
                PickerPurpose::ChangeToInstance { owner, path } => (*owner, path.clone()),
            };
            let would_cycle = self
                .project
                .get_class(&uuid)
                .map(|c| c.references_class(&owner) || uuid == owner)
                .unwrap_or(false);
            if would_cycle {
                self.status_msg = Some("Cannot select: would create a class cycle.".into());
            } else {
                let op = match &purpose {
                    PickerPurpose::SetPtrTarget { owner, path } => NodeEditOp::SetPtrTarget {
                        owner: *owner, path: path.clone(), target: Some(uuid),
                    },
                    PickerPurpose::SetInstance { owner, path } => NodeEditOp::SetInstance {
                        owner: *owner, path: path.clone(), target: uuid,
                    },
                    PickerPurpose::ChangeToInstance { owner, path } => NodeEditOp::SetInstance {
                        owner: *owner, path: path.clone(), target: uuid,
                    },
                };
                self.pending_node_edits.push(op);
            }
            self.class_picker = None;
        }
    }

    // -----------------------------------------------------------------------
    // Add-bytes dialog
    // -----------------------------------------------------------------------

    fn show_add_bytes_dialog(&mut self, ctx: &egui::Context) {
        if self.add_bytes_dialog.is_none() { return; }

        let title = if self.add_bytes_dialog.as_ref().unwrap().insert {
            "Insert Bytes"
        } else {
            "Add Bytes"
        };

        let mut confirm = false;
        let mut cancel = false;

        egui::Window::new(title)
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Count:");
                    let mut t = self.add_bytes_dialog.as_ref().unwrap().count_text.clone();
                    if ui.text_edit_singleline(&mut t).changed()
                        && let Some(s) = &mut self.add_bytes_dialog
                    {
                        s.count_text = t;
                    }
                });
                ui.horizontal(|ui| {
                    for &preset in &[4usize, 8, 64, 256, 1024] {
                        if ui.small_button(preset.to_string()).clicked()
                            && let Some(s) = &mut self.add_bytes_dialog
                        {
                            s.count_text = preset.to_string();
                        }
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() { confirm = true; }
                    if ui.button("Cancel").clicked() { cancel = true; }
                });
            });

        if cancel {
            self.add_bytes_dialog = None;
            return;
        }
        if confirm {
            let state = self.add_bytes_dialog.take().unwrap();
            let count = state.count_text.trim().parse::<usize>().unwrap_or(0);
            if count > 0 {
                let op = if state.insert {
                    NodeEditOp::InsertBytes {
                        owner: state.owner, path: state.path, count,
                    }
                } else {
                    NodeEditOp::AddBytes {
                        owner: state.owner, path: state.path, count,
                    }
                };
                self.pending_node_edits.push(op);
            }
        }
    }

    /// Modal to rename the selected class (opened by double-clicking it in the
    /// class list).
    fn show_class_rename_modal(&mut self, ctx: &egui::Context) {
        if self.class_rename.is_none() {
            return;
        }
        let mut confirm = false;
        let mut cancel = false;
        egui::Window::new("Rename class")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name:");
                    // Clone out / write back to avoid borrowing self twice.
                    let mut text = self.class_rename.as_ref().unwrap().1.clone();
                    let resp = ui.text_edit_singleline(&mut text);
                    if let Some(s) = &mut self.class_rename {
                        s.1 = text;
                    }
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        confirm = true;
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        confirm = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });

        if cancel {
            self.class_rename = None;
            return;
        }
        if confirm
            && let Some((uuid, name)) = self.class_rename.take()
        {
            let name = name.trim().to_string();
            if !name.is_empty()
                && let Some(c) = self.project.get_class_mut(&uuid)
            {
                c.name = name;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Apply node edits
    // -----------------------------------------------------------------------

    fn apply_node_edit(&mut self, op: NodeEditOp) {
        use nemclass_model::node::builtins::{ClassInstanceNode, PointerNode};

        let invalidate = |app: &mut NemclassApp| {
            app.node_snapshots.clear();
            app.mem_buf.clear();
            app.edit_state = None;
            app.last_snapshot = None;
        };

        match op {
            NodeEditOp::ChangeType { owner, path, new_tag } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let old_name    = vec[idx].name().to_owned();
                    let old_comment = vec[idx].comment().to_owned();
                    if let Some(mut new_node) = self.node_registry.construct(new_tag) {
                        new_node.set_name(old_name);
                        new_node.set_comment(old_comment);
                        vec[idx] = new_node;
                    }
                }
                invalidate(self);
            }
            NodeEditOp::Delete { owner, path } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    vec.remove(idx);
                }
                invalidate(self);
            }
            NodeEditOp::AddBytes { owner, path, count } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let insert_at = idx + 1;
                    let fill = hex_fill(count);
                    for (j, node) in fill.into_iter().enumerate() {
                        vec.insert(insert_at + j, node);
                    }
                }
                invalidate(self);
            }
            NodeEditOp::InsertBytes { owner, path, count } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let fill = hex_fill(count);
                    for (j, node) in fill.into_iter().enumerate() {
                        vec.insert(idx + j, node);
                    }
                }
                invalidate(self);
            }
            NodeEditOp::SetName { owner, path, name } => {
                if let Some(node) = resolve_node_mut(&mut self.project, owner, &path) {
                    node.set_name(name);
                }
                invalidate(self);
            }
            NodeEditOp::SetComment { owner, path, comment } => {
                if let Some(node) = resolve_node_mut(&mut self.project, owner, &path) {
                    node.set_comment(comment);
                }
                invalidate(self);
            }
            NodeEditOp::SetPtrTarget { owner, path, target } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let old_name    = vec[idx].name().to_owned();
                    let old_comment = vec[idx].comment().to_owned();
                    let new_node = Box::new(PointerNode {
                        name:              old_name,
                        comment:           old_comment,
                        target_class_uuid: target,
                    });
                    vec[idx] = new_node;
                }
                invalidate(self);
            }
            NodeEditOp::SetInstance { owner, path, target } => {
                if let Some((vec, idx)) = resolve_parent_vec_mut(&mut self.project, owner, &path) {
                    let old_name    = vec[idx].name().to_owned();
                    let old_comment = vec[idx].comment().to_owned();
                    let mut new_node = Box::new(ClassInstanceNode::new(old_name, target));
                    new_node.set_comment(old_comment);
                    vec[idx] = new_node;
                }
                invalidate(self);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Node-tree structural helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tree flattening
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn flatten_nodes(
    children: &[Box<dyn Node>],
    base_addr: usize,
    base_offset: usize,
    depth: usize,
    buf: &[u8],
    parent_id: String,
    owner_class: Uuid,
    parent_path: &[usize],
    out: &mut Vec<NodeSnapshot>,
    project: &nemclass_model::Project,
    collapsed: &HashSet<String>,
    expanded_ptrs: &HashSet<String>,
    deref_bufs: &HashMap<String, (usize, Vec<u8>)>,
    visited: &mut HashSet<Uuid>,
    depth_budget: usize,
) {
    let mut cur_offset = base_offset;
    for (i, node) in children.iter().enumerate() {
        let id_path = if parent_id.is_empty() {
            i.to_string()
        } else {
            format!("{parent_id}.{i}")
        };

        let mut local_path = parent_path.to_vec();
        local_path.push(i);

        let type_tag = node.type_tag();
        let rendered = node.render(buf, cur_offset);

        let ci_target = class_instance_target(node.as_ref());
        let ptr_target = node.pointer_target_class();

        let has_children = !node.children().is_empty()
            || ci_target.is_some()
            || ptr_target.is_some();

        let size = if type_tag == "ClassInstance" {
            if let Some(t_uuid) = ci_target {
                if let Some(tc) = project.get_class(&t_uuid) {
                    if !visited.contains(&t_uuid) {
                        visited.insert(t_uuid);
                        let sz = nemclass_model::resolved_class_size(tc, project, &mut HashSet::new());
                        visited.remove(&t_uuid);
                        sz
                    } else { 0 }
                } else { 0 }
            } else { 0 }
        } else {
            node.memory_size()
        };

        out.push(NodeSnapshot {
            address: base_addr.wrapping_add(cur_offset),
            offset: cur_offset,
            depth,
            id_path: id_path.clone(),
            rendered,
            has_children,
            type_tag,
            name: node.name().to_owned(),
            comment: node.comment().to_owned(),
            _memory_size: size,
            pointer_target: ptr_target,
            owner_class,
            local_path: local_path.clone(),
        });

        // Static children (unchanged).
        if !node.children().is_empty() {
            flatten_nodes(
                node.children(),
                base_addr,
                cur_offset,
                depth + 1,
                buf,
                id_path.clone(),
                owner_class,
                &local_path,
                out,
                project,
                collapsed,
                expanded_ptrs,
                deref_bufs,
                visited,
                depth_budget.saturating_sub(1),
            );
        }

        // ClassInstance inline expansion: default-expanded, gated by collapsed.
        if let Some(t_uuid) = ci_target
            && !collapsed.contains(&id_path)
            && !visited.contains(&t_uuid)
            && depth_budget > 0
            && let Some(target_class) = project.get_class(&t_uuid)
        {
            visited.insert(t_uuid);
            flatten_nodes(
                &target_class.children,
                base_addr,
                cur_offset,
                depth + 1,
                buf,
                id_path.clone(),
                t_uuid,
                &[],
                out,
                project,
                collapsed,
                expanded_ptrs,
                deref_bufs,
                visited,
                depth_budget - 1,
            );
            visited.remove(&t_uuid);
        }

        // Pointer inline expansion: default-collapsed, gated by expanded_ptrs.
        if let Some(t_uuid) = ptr_target
            && expanded_ptrs.contains(&id_path)
            && !visited.contains(&t_uuid)
            && depth_budget > 0
            && let Some((deref_addr, dbuf)) = deref_bufs.get(&id_path)
            && let Some(target_class) = project.get_class(&t_uuid)
        {
            visited.insert(t_uuid);
            flatten_nodes(
                &target_class.children,
                *deref_addr,
                0,
                depth + 1,
                dbuf,
                id_path.clone(),
                t_uuid,
                &[],
                out,
                project,
                collapsed,
                expanded_ptrs,
                deref_bufs,
                visited,
                depth_budget - 1,
            );
            visited.remove(&t_uuid);
        }

        cur_offset = cur_offset.wrapping_add(size);
    }
}

fn class_instance_target(node: &dyn Node) -> Option<Uuid> {
    if node.type_tag() != "ClassInstance" { return None; }
    let def = node.to_node_def();
    def.attrs
        .get("class_uuid")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<Uuid>().ok())
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
// Structural mutation helpers
// ---------------------------------------------------------------------------

/// Greedy-fill: produce nodes summing to `count` bytes using Hex64/32/16/8.
fn hex_fill(count: usize) -> Vec<Box<dyn Node>> {
    use nemclass_model::node::builtins::{Hex8Node, Hex16Node, Hex32Node, Hex64Node};
    let mut nodes: Vec<Box<dyn Node>> = Vec::new();
    let mut rem = count;
    while rem >= 8 { nodes.push(Box::new(Hex64Node::new(""))); rem -= 8; }
    while rem >= 4 { nodes.push(Box::new(Hex32Node::new(""))); rem -= 4; }
    while rem >= 2 { nodes.push(Box::new(Hex16Node::new(""))); rem -= 2; }
    while rem >= 1 { nodes.push(Box::new(Hex8Node::new("")));  rem -= 1; }
    nodes
}

/// Walk `project` to find the parent `Vec<Box<dyn Node>>` and the last index
/// for `local_path`. Returns `None` if path is empty, owner not found, or any
/// index is out of bounds.
fn resolve_parent_vec_mut<'a>(
    project: &'a mut Project,
    owner: Uuid,
    local_path: &[usize],
) -> Option<(&'a mut Vec<Box<dyn Node>>, usize)> {
    if local_path.is_empty() { return None; }
    let class = project.get_class_mut(&owner)?;
    let (last, prefix) = local_path.split_last()?;
    let mut vec: &mut Vec<Box<dyn Node>> = &mut class.children;
    for &idx in prefix {
        let node = vec.get_mut(idx)?;
        vec = node.children_mut()?;
    }
    if *last < vec.len() { Some((vec, *last)) } else { None }
}

/// Resolve the node itself (mutable) at `local_path` inside `owner`.
fn resolve_node_mut<'a>(
    project: &'a mut Project,
    owner: Uuid,
    local_path: &[usize],
) -> Option<&'a mut Box<dyn Node>> {
    let (vec, idx) = resolve_parent_vec_mut(project, owner, local_path)?;
    vec.get_mut(idx)
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

/// Build an empty, auto-named class container for the "+ Add class" button.
///
/// The name is generated to be unique within `project` (`Class1`, `Class2`, …)
/// rather than user-typed — classes are created but not manually renamed. It
/// seeds one `Hex64` field so the new class renders a row immediately; the user
/// then reshapes it with the node editor, auto-dissect, or a script.
fn blank_class(project: &Project) -> ClassNode {
    use nemclass_model::node::builtins::Hex64Node;

    let mut n = 1usize;
    let name = loop {
        let candidate = format!("Class{n}");
        if !project.classes_in_order().any(|c| c.name == candidate) {
            break candidate;
        }
        n += 1;
    };

    let mut cls = ClassNode::new(name);
    cls.children.push(Box::new(Hex64Node::new("field_0")));
    cls
}

// ---------------------------------------------------------------------------
// Unit tests — pure helpers that don't need an egui context
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use nemclass_model::node::builtins::Int32Node;
    use nemclass_model::{ClassNode, NodeRegistry, Project};

    #[test]
    fn hex_fill_greedy() {
        // 8 → exactly one Hex64
        let nodes = hex_fill(8);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].type_tag(), "Hex64");

        // 13 = 8+4+1 → Hex64, Hex32, Hex8
        let nodes = hex_fill(13);
        assert_eq!(nodes.len(), 3);
        assert_eq!(nodes[0].type_tag(), "Hex64");
        assert_eq!(nodes[1].type_tag(), "Hex32");
        assert_eq!(nodes[2].type_tag(), "Hex8");

        // 3 = 2+1 → Hex16, Hex8
        let nodes = hex_fill(3);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].type_tag(), "Hex16");
        assert_eq!(nodes[1].type_tag(), "Hex8");

        // 0 → empty
        assert!(hex_fill(0).is_empty());

        // sum is always exact
        let nodes = hex_fill(100);
        let sum: usize = nodes.iter().map(|n| n.memory_size()).sum();
        assert_eq!(sum, 100);
    }

    #[cfg(feature = "scripting")]
    #[test]
    fn parse_hotkey_combos() {
        use egui::Key;
        assert_eq!(parse_hotkey("Ctrl+Shift+H"), Some((true, true, false, Key::H)));
        assert_eq!(parse_hotkey("F6"), Some((false, false, false, Key::F6)));
        assert_eq!(parse_hotkey("Alt+K"), Some((false, false, true, Key::K)));
        // Case-insensitive modifiers + whitespace tolerance.
        assert_eq!(parse_hotkey(" control + k "), Some((true, false, false, Key::K)));
        // Bad input.
        assert_eq!(parse_hotkey(""), None);
        assert_eq!(parse_hotkey("Ctrl+"), None);
        assert_eq!(parse_hotkey("Ctrl+Nonsense"), None);
        assert_eq!(parse_hotkey("A+B"), None); // two non-modifier keys
    }

    #[test]
    fn enums_round_trip_through_project() {
        use nemclass_model::EnumDescription;
        let mut project = Project::new("t");
        let mut e = EnumDescription::new("Team");
        e.size = 2;
        e.use_flags = true;
        e.values = vec![("Red".into(), 0), ("Blue".into(), 1)];
        // Upsert by name (mirrors what `enums.define` does via declare_type).
        project.enums.push(e.clone());
        let got = project.enums.iter().find(|x| x.name == "Team").unwrap();
        assert_eq!(got.size, 2);
        assert!(got.use_flags);
        assert_eq!(got.values, vec![("Red".to_string(), 0), ("Blue".to_string(), 1)]);
        // Overwrite in place keeps a single entry.
        if let Some(slot) = project.enums.iter_mut().find(|x| x.name == "Team") {
            slot.values = vec![("Green".into(), 2)];
        }
        assert_eq!(project.enums.iter().filter(|x| x.name == "Team").count(), 1);
        assert_eq!(project.enums[0].values, vec![("Green".to_string(), 2)]);
    }

    #[test]
    fn resolve_parent_vec_mut_basic() {
        let mut project = Project::new("Test");
        let mut cls = ClassNode::new("Root");
        cls.children.push(Box::new(Int32Node::new("a")));
        cls.children.push(Box::new(Int32Node::new("b")));
        let uuid = cls.uuid;
        project.add_class(cls);

        // path [1] → parent is Root.children, index 1
        let result = resolve_parent_vec_mut(&mut project, uuid, &[1]);
        assert!(result.is_some());
        let (vec, idx) = result.unwrap();
        assert_eq!(idx, 1);
        assert_eq!(vec[idx].name(), "b");

        // empty path → None
        assert!(resolve_parent_vec_mut(&mut project, uuid, &[]).is_none());

        // out-of-bounds → None
        assert!(resolve_parent_vec_mut(&mut project, uuid, &[99]).is_none());
    }

    #[test]
    fn change_type_preserves_name_comment() {
        let registry = NodeRegistry::new().with_builtins();
        let mut project = Project::new("Test");
        let mut cls = ClassNode::new("Root");
        let mut n = Int32Node::new("my_field");
        n.comment = "my_comment".into();
        cls.children.push(Box::new(n));
        let owner = cls.uuid;
        project.add_class(cls);

        // Simulate ChangeType: construct Hex32, copy name/comment from the old node
        let (vec, idx) = resolve_parent_vec_mut(&mut project, owner, &[0]).unwrap();
        let old_name    = vec[idx].name().to_owned();
        let old_comment = vec[idx].comment().to_owned();
        let mut new_node = registry.construct("Hex32").unwrap();
        new_node.set_name(old_name);
        new_node.set_comment(old_comment);
        vec[idx] = new_node;

        let cls = project.get_class(&owner).unwrap();
        assert_eq!(cls.children[0].type_tag(), "Hex32");
        assert_eq!(cls.children[0].name(), "my_field");
        assert_eq!(cls.children[0].comment(), "my_comment");
    }

    #[test]
    fn flatten_nodes_inline_class_instance() {
        use nemclass_model::node::builtins::{ClassInstanceNode, Int32Node};

        let mut project = Project::new("Test");

        let b_uuid = {
            let mut b = ClassNode::new("B");
            b.children.push(Box::new(Int32Node::new("x")));
            b.children.push(Box::new(Int32Node::new("y")));
            let uuid = b.uuid;
            project.add_class(b);
            uuid
        };

        let a_uuid = {
            let mut a = ClassNode::new("A");
            a.children.push(Box::new(ClassInstanceNode::new("b_field", b_uuid)));
            a.children.push(Box::new(Int32Node::new("after")));
            let uuid = a.uuid;
            project.add_class(a);
            uuid
        };

        let buf = vec![0u8; 64];
        let collapsed: HashSet<String> = HashSet::new();
        let expanded_ptrs: HashSet<String> = HashSet::new();
        let deref_bufs: HashMap<String, (usize, Vec<u8>)> = HashMap::new();
        let mut visited: HashSet<Uuid> = HashSet::new();
        let mut snapshots: Vec<NodeSnapshot> = Vec::new();

        {
            let cls = project.get_class(&a_uuid).unwrap();
            flatten_nodes(
                &cls.children,
                0,
                0,
                0,
                &buf,
                String::new(),
                a_uuid,
                &[],
                &mut snapshots,
                &project,
                &collapsed,
                &expanded_ptrs,
                &deref_bufs,
                &mut visited,
                8,
            );
        }

        assert_eq!(snapshots.len(), 4, "expected 4 rows: instance + 2 B children + after");

        let ci = &snapshots[0];
        assert_eq!(ci.type_tag, "ClassInstance");
        assert_eq!(ci.offset, 0);
        assert_eq!(ci.owner_class, a_uuid);

        let x = &snapshots[1];
        assert_eq!(x.type_tag, "Int32");
        assert_eq!(x.name, "x");
        assert_eq!(x.offset, 0);
        assert_eq!(x.owner_class, b_uuid);

        let y = &snapshots[2];
        assert_eq!(y.type_tag, "Int32");
        assert_eq!(y.name, "y");
        assert_eq!(y.offset, 4);
        assert_eq!(y.owner_class, b_uuid);

        let after = &snapshots[3];
        assert_eq!(after.type_tag, "Int32");
        assert_eq!(after.name, "after");
        assert_eq!(after.offset, 8, "field after instance must sit at resolved_class_size(B) = 8");
        assert_eq!(after.owner_class, a_uuid);
    }
}
