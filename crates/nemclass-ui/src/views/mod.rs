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

mod generator_panel;
mod scanner_panel;
mod debugger_panel;
mod memory_viewer;
mod disassembly;
mod dock;
mod navigator;
mod modules_panel;
mod settings;
mod key_file;
mod script_host;
mod script_log;
mod scripts_panel;
mod host_api_impl;
mod node_edit;
mod pointer_scan_panel;
mod spider_panel;
pub(crate) mod cheat_table_panel;
mod tasks;

pub use scanner_panel::ScannerPanel;
pub use debugger_panel::DebuggerPanel;
pub use memory_viewer::MemoryViewer;
pub use disassembly::DisassemblyPanel;

use generator_panel::GeneratorPanel;
use script_host::ScriptHost;
use script_log::{LogKind, ScriptLog, new_script_log};
use scripts_panel::{ScriptsPanel, ScriptsPanelAction};
use pointer_scan_panel::{PointerScanPanel, PointerScanAction};
use spider_panel::{SpiderPanel, SpiderAction};
use cheat_table_panel::{CheatTablePanel, CheatTablePanelAction};
use node_edit::{
    EditHistory, NodeEditOp, NodeRef, Selection, TYPE_GROUPS,
};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the scanner's module list stays valid before `/proc/<pid>/maps` is
/// re-parsed. Modules load and unload rarely; a per-frame walk was pure waste.
const MODULE_CACHE_TTL: Duration = Duration::from_secs(1);

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
use nemclass_model::{
    ClassNode, FloatWidth, MATRIX_SHAPES, ModelError, Node, NodeRegistry, Project, RenderedValue,
    VECTOR_SHAPES, matrix_shape, resolve_formula, vector_shape,
};
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
    /// For vector/matrix nodes: the individual float components read out of the
    /// snapshot buffer, in declaration (row-major, for matrices) order. Empty
    /// for every other node type, and also empty when the buffer was too short
    /// to read the whole node.
    components: Vec<f64>,
    /// Component width for vector/matrix nodes; `None` for everything else.
    /// Carried so the UI can write an edited component back at the right size.
    float_width: Option<FloatWidth>,
    /// The node's `hidden` flag — the row is still drawn, but dimmed, so a
    /// hidden field can be found and unhidden.
    hidden: bool,
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
    /// One row of an expanded matrix node: `snap_idx` names the matrix snapshot,
    /// `row` is the 0-based matrix row. Purely derived from the snapshot's
    /// `components`, so no cache is involved.
    MatrixRow { snap_idx: usize, row: usize },
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

// ---------------------------------------------------------------------------
// Toolbar actions
// ---------------------------------------------------------------------------

/// A class-toolbar button press, collected inside the layout closures and acted
/// on once they have released the borrow on `self`.
#[derive(Clone, Copy)]
enum ToolbarAction {
    Undo,
    Redo,
    Copy,
    Cut,
    Paste,
    Hide,
    Unhide,
    DeleteSelection,
    SelectAll,
    ExtractClass,
}

/// A destructive project action held back until the user says what to do about
/// unsaved changes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingDiscard {
    New,
    Open,
}

/// The "make a class out of these fields" prompt.
struct ExtractClassState {
    owner: Uuid,
    paths: Vec<Vec<usize>>,
    name: String,
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
enum EditField {
    Value,
    Name,
    Comment,
    /// A single component of a vector/matrix node, by index into its
    /// `components` (row-major for matrices).
    Component(usize),
}

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
type AttachOutcome = (u64, libc::pid_t, String, Result<Process, String>);

/// How often the attached target is checked for having exited. A syscall per
/// check, so well below the frame rate but fast enough that the user is not
/// left interacting with a dead process.
const LIVENESS_INTERVAL: Duration = Duration::from_millis(1000);

/// Whether a text field currently has keyboard focus.
///
/// Global shortcuts must not fire while the user is typing: the keystroke
/// belongs to the widget, not to the app.
fn typing_in_a_text_field(ctx: &egui::Context) -> bool {
    ctx.memory(|m| m.focused().is_some())
}

/// Whether `pid` is gone.
///
/// `kill(pid, 0)` performs the existence/permission check without delivering a
/// signal. Only `ESRCH` means "no such process" — `EPERM` means it exists but
/// belongs to someone else, which is emphatically not an exit.
#[cfg(unix)]
fn target_has_exited(pid: libc::pid_t) -> bool {
    // SAFETY: `kill` takes two scalars and delivers nothing for signal 0; it has
    // no memory-safety preconditions and cannot affect this process's state.
    let rc = unsafe { libc::kill(pid, 0) };
    rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn target_has_exited(_pid: libc::pid_t) -> bool {
    // No portable check wired up yet; never claim the target died.
    false
}

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
    /// Bumped by every attach *and* every detach. An in-flight attach whose
    /// epoch no longer matches is discarded: without this, clicking Attach and
    /// then Detach before the worker finished re-installed the process and
    /// re-fired `OnAttach`, silently reattaching the user to a session they had
    /// just closed. `enumerate_job` already guards its result this way.
    attach_epoch: u64,
    /// When the attached target's liveness was last checked. See
    /// [`NemclassApp::check_target_alive`].
    last_liveness_check: Option<Instant>,
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
    /// The class-view row the user last clicked, as `(owner class, local path)`.
    /// This is what the class toolbar's Add/Insert/Delete/type buttons act on;
    /// with nothing selected they fall back to appending at the end of the class.
    /// Which class-view rows are selected. Replaces a single `Option`: every
    /// ReClass "…Node(s)" action is plural, and changing eight rows to `Int32`
    /// at once is the workflow the tool exists for.
    selection: Selection,
    /// The rows the class view drew last frame, in display order. Shift-click
    /// and the arrow keys range over *this*, not over sibling indices, so a
    /// range spanning an expanded container selects what the user can see.
    visible_order: Vec<NodeRef>,
    /// Whole-project snapshots for undo/redo.
    history: EditHistory,
    /// Nodes copied out of a class, ready to paste.
    node_clipboard: Vec<nemclass_model::serialize::NodeDef>,
    /// Set by every edit, cleared by a save. Drives the title-bar marker and
    /// the prompt before New/Open discards work.
    project_dirty: bool,
    /// Substring filter for the class view; empty shows every row.
    class_search: String,
    /// Open "new class from selection" prompt, if any.
    extract_class_dialog: Option<ExtractClassState>,
    /// Whether the project's enum editor window is open.
    enum_editor_open: bool,
    /// A New/Open the user asked for while the project had unsaved changes.
    pending_discard: Option<PendingDiscard>,
    /// Code-generator panel state (language choice + last generated output).
    generator_panel: GeneratorPanel,

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
    /// Last time the script-file watcher polled mtimes (auto-reload throttle).
    #[cfg(feature = "scripting")]
    last_script_watch: Option<Instant>,
    /// Known modified-times of the files in the scripts dir, used to detect edits
    /// for auto-reload. Refreshed on every (re)load via `reload_scripts_dir`.
    #[cfg(feature = "scripting")]
    script_mtimes: HashMap<PathBuf, std::time::SystemTime>,
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
    /// Whether the saved address list is docked beneath the scan results, the
    /// Cheat Engine layout. It has no tab of its own, so this is the only way to
    /// reach it — hence on by default.
    show_address_list: bool,
    /// Module list for the scanner's scope picker, refreshed at most once per
    /// [`MODULE_CACHE_TTL`] (see [`NemclassApp::scanner_modules`]).
    module_cache: Vec<nemclass_core::ModuleInfoWithName>,
    module_cache_at: Option<Instant>,

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
    /// Structure spider: find a value inside a known object.
    spider_panel: SpiderPanel,
    /// Deferred action from the pointer-scan panel; applied after the dock draw
    /// to avoid borrow conflicts with `self.project` / `self.selected_class`.
    pending_pointer_scan_action: Option<PointerScanAction>,
    /// Spider action deferred out of the tab draw, applied once the dock's
    /// borrows are released (same reason as the pointer-scan one above).
    pending_spider_action: Option<SpiderAction>,

    // Cheat table panel
    cheat_table_panel: CheatTablePanel,

    // Navigator side panel (strings / functions / calls)
    navigator_panel: navigator::NavigatorPanel,

    // Modules panel (multi-select modules → disassembler linear view)
    modules_panel: modules_panel::ModulesPanel,

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
            attach_epoch: 0,
            last_liveness_check: None,
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
            selection: Selection::default(),
            visible_order: Vec::new(),
            history: EditHistory::default(),
            node_clipboard: Vec::new(),
            project_dirty: false,
            class_search: String::new(),
            extract_class_dialog: None,
            enum_editor_open: false,
            pending_discard: None,
            generator_panel: GeneratorPanel::default(),
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
            last_script_watch: None,
            #[cfg(feature = "scripting")]
            script_mtimes: HashMap::new(),
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
            show_address_list: true,
            module_cache: Vec::new(),
            module_cache_at: None,
            scanner_panel: ScannerPanel::new(),
            debugger_panel: DebuggerPanel::with_key(kernel_key),
            memory_viewer: MemoryViewer::new(),
            disassembly_panel: DisassemblyPanel::new(),
            pointer_scan_panel: PointerScanPanel::new(),
            pending_pointer_scan_action: None,
            spider_panel: SpiderPanel::new(),
            pending_spider_action: None,
            cheat_table_panel: CheatTablePanel::new(),
            navigator_panel: navigator::NavigatorPanel::new(),
            modules_panel: modules_panel::ModulesPanel::new(),
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
            app.reload_scripts_dir(&src, "Loaded scripts from");
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

        // Resolve everything that can fail *before* tearing down the current
        // session: this used to detach first, so a bad backend name or a missing
        // runtime left the user detached from the process they were using with
        // nothing but an error string.
        let Some(provider) = self.registry.get_arc(&self.selected_backend) else {
            self.last_error = Some(format!("Backend '{}' not found.", self.selected_backend));
            return;
        };
        let Some(rt) = self.runtime.as_ref().map(|r| r.handle()) else {
            return;
        };

        // Detach fully (UI thread; touches panel state the worker can't).
        self.detach_all();
        self.last_error = None;
        self.status_msg = Some(format!(
            "Attaching to {}…",
            if name.is_empty() { format!("pid:{pid}") } else { name.clone() }
        ));
        let epoch = self.attach_epoch;
        self.attach_job.spawn(&rt, ctx.clone(), move || {
            let result = provider.open(pid).map_err(|e| format!("Attach failed: {e}"));
            (epoch, pid, name, result)
        });
    }

    /// Applies a completed attach: wires the opened handle into the panels and
    /// fires `OnAttach`, or surfaces the error. Runs on the UI thread from `logic`.
    fn ingest_attach(&mut self, outcome: AttachOutcome) {
        let (_epoch, pid, name, result) = outcome;
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
                #[cfg(target_os = "linux")]
                self.modules_panel.on_attach(&Self::sorted_modules(&proc));
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

        // Unbind any previous session first — this path had no teardown at all,
        // so a second call left every other panel on the old process.
        self.detach_all();

        self.memory_viewer.on_attach(&proc);
        self.disassembly_panel.on_attach(&proc);
        #[cfg(target_os = "linux")]
        self.modules_panel.on_attach(&Self::sorted_modules(&proc));
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

    /// Debug/screenshot hook: navigate the disassembler to `addr` — the path a
    /// "Disassemble here" click takes, which must keep the code around it.
    pub fn debug_goto_disasm(&mut self, addr: usize) {
        self.disassembly_panel.goto(addr);
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
            // Drop an attach the user has since cancelled by detaching.
            if outcome.0 == self.attach_epoch {
                self.ingest_attach(outcome);
            }
        }
        if let JobPoll::Done((uuid, resolved)) = self.resolve_job.poll() {
            self.ingest_resolve(uuid, resolved);
        }
    }

    fn do_detach(&mut self) {
        self.detach_all();
        self.last_error = None;
    }

    /// Detach automatically once the attached target exits.
    ///
    /// Nothing used to notice a dead target: the address bar kept showing a
    /// green "Attached", the class view rendered a buffer of zeros that looked
    /// like real data, the scanner reported `??`, and the cheat table kept
    /// firing writes at a recycled pid. ReClass.NET polls and detaches; so do
    /// we.
    ///
    /// Throttled to [`LIVENESS_INTERVAL`] — this runs from the frame loop, and
    /// the check is a syscall.
    fn check_target_alive(&mut self) {
        let Some(proc) = self.process.as_ref() else {
            self.last_liveness_check = None;
            return;
        };
        let due = self
            .last_liveness_check
            .is_none_or(|t| t.elapsed() >= LIVENESS_INTERVAL);
        if !due {
            return;
        }
        self.last_liveness_check = Some(Instant::now());

        let pid = proc.pid();
        if !target_has_exited(pid) {
            return;
        }
        let name = self
            .attached_name
            .clone()
            .unwrap_or_else(|| format!("pid:{pid}"));
        self.detach_all();
        self.status_msg = None;
        self.last_error = Some(format!("{name} exited — detached."));
    }

    /// Unbind **every** panel from the current process.
    ///
    /// This must be the only place that tears a session down. `do_attach`
    /// previously inlined its own shorter version that cleared the memory
    /// viewer, disassembler and modules panel but not the scanner, debugger,
    /// pointer scan, spider, cheat table or script scan session. Attaching to a
    /// second process without pressing Detach first therefore left those five
    /// panels bound to the *old* process: `Next Scan` silently scanned the dead
    /// pid, the debugger header reported the new pid while debugging the old
    /// one, and — worst — the cheat table kept re-writing values captured
    /// against process A into process B's address space every freeze tick.
    ///
    /// Anything that unbinds the process belongs here, not at a call site.
    fn detach_all(&mut self) {
        // Bumped unconditionally, *before* the "nothing attached" early return:
        // the case that matters most is detaching while an attach is still in
        // flight, and at that moment `self.process` is still `None`. Guarding
        // the bump behind it would let the in-flight attach land and silently
        // reattach.
        self.attach_epoch = self.attach_epoch.wrapping_add(1);
        if self.process.is_none() {
            return;
        }
        self.emit(Event::OnDetach);
        self.process = None;
        self.attached_name = None;
        self.clear_memory_state();
        self.scanner_panel.on_detach();
        self.debugger_panel.on_detach();
        self.memory_viewer.on_detach();
        self.disassembly_panel.on_detach();
        self.modules_panel.on_detach();
        self.pointer_scan_panel.on_detach();
        self.spider_panel.on_detach();
        self.cheat_table_panel.on_detach();
        // The script scan session is bound to the detached process; drop it.
        #[cfg(all(feature = "scripting", target_os = "linux"))]
        {
            self.script_scanner = None;
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

    /// (Re)loads every script in `dir` into the engine, logs the outcome under
    /// `label`, and — under the scripting feature — refreshes the mtime cache the
    /// auto-reload watcher compares against, so a manual load doesn't immediately
    /// re-trigger it. Central entry point for startup, project-open, the Scripts
    /// panel Load/Reload buttons, and the file watcher.
    fn reload_scripts_dir(&mut self, dir: &Path, label: &str) {
        match self.script_host.load_scripts(dir) {
            Ok(()) if self.script_host.is_active() => script_log::push(
                &self.script_log,
                LogKind::Lifecycle,
                format!("{label} {}", dir.display()),
            ),
            Ok(()) => {}
            Err(e) => script_log::push(
                &self.script_log,
                LogKind::Error,
                format!("{label} failed: {e}"),
            ),
        }
        #[cfg(feature = "scripting")]
        {
            self.script_mtimes = scan_script_mtimes(dir);
        }
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
        self.selection.clear();
        // A different project's history is not this project's history, and
        // undoing into it would restore classes that no longer exist.
        self.history.clear();
        self.project_dirty = false;

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
            self.reload_scripts_dir(&src, "Loaded scripts from");
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
            self.project_dirty = false;
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
        self.project_dirty = false;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Memory snapshot
    // -----------------------------------------------------------------------

    fn take_snapshot(&mut self) {
        let Some(uuid) = self.selected_class else { return; };
        let Some(proc) = &self.process else {
            // Detached: still size the buffer to the class so every node renders
            // a zero rather than the `<?>` short-buffer placeholder. The layout
            // is the point of the detached view; `<?>` on every row hid it.
            let total_size = self
                .project
                .get_class(&uuid)
                .map(|c| nemclass_model::class_size(c, &self.project))
                .unwrap_or(0);
            self.class_base = None;
            self.mem_buf = vec![0u8; total_size];
            self.rebuild_snapshots_from_buf(uuid);
            self.last_snapshot = Some(Instant::now());
            return;
        };

        let formula = self.project.get_class(&uuid)
            .map(|c| c.address_formula.clone())
            .unwrap_or_default();

        // A script-resolved base (from the "Try resolve (script)" button) takes
        // precedence over the address formula and is sticky until the user edits
        // the formula or detaches.
        //
        // The module list is enumerated *inside* this branch, not before it:
        // `proc.modules()` parses the whole of /proc/<pid>/maps, and this runs on
        // the snapshot tick (10 Hz by default). Enumerating up front meant paying
        // for it ten times a second even when the class had no address formula
        // to resolve, or when a sticky script-resolved base made it moot.
        let base = if let Some(sb) = self.script_resolved_base {
            Some(sb)
        } else if formula.trim().is_empty() {
            None
        } else {
            let modules: Vec<ModuleInfoWithName> = match proc.modules() {
                Ok(it) => it.collect(),
                Err(e) => {
                    self.last_error = Some(format!("modules(): {e}"));
                    Vec::new()
                }
            };
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
            .map(|c| nemclass_model::class_size(c, &self.project))
            .unwrap_or(0);

        let (buf, readable) = if let (Some(addr), true) = (base, total_size > 0) {
            read_process_buf(proc, addr, total_size)
        } else {
            (vec![0u8; total_size], 0)
        };
        // Surface an unreadable base rather than rendering zeros that look like
        // real values. `readable == 0` with a resolved base means the address is
        // not mapped (or the target is gone).
        if base.is_some() && total_size > 0 && readable == 0 {
            self.last_error = Some(format!(
                "Address {:#x} is not readable — the class shows zeros, not data.",
                base.unwrap_or(0)
            ));
        }
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
                    .map(|tc| nemclass_model::class_size(tc, &self.project))
                    .unwrap_or(0);

                let dbuf = if target_size > 0 {
                    read_process_buf(proc, deref_addr, target_size).0
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

        // StrPtr: dereference each pointer against the live process and replace
        // its rendered value (a raw pointer, all `render` can produce from the
        // class buffer) with the NUL-terminated UTF-8 string it points at.
        if let Some(proc) = &self.process {
            const STR_PTR_MAX: usize = 256;
            for snap in &mut self.node_snapshots {
                if snap.type_tag != "StrPtr" {
                    continue;
                }
                let mut ptr_bytes = [0u8; 8];
                let n = proc.read_buf(snap.address, &mut ptr_bytes).unwrap_or(0);
                let target = if n >= 8 {
                    u64::from_le_bytes(ptr_bytes) as usize
                } else {
                    0
                };
                if target == 0 {
                    snap.rendered.value = "0x0 → (null)".to_string();
                    continue;
                }
                let (bytes, _) = read_process_buf(proc, target, STR_PTR_MAX);
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                let s = String::from_utf8_lossy(&bytes[..end]);
                snap.rendered.value = format!("0x{target:X} → \"{s}\"");
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

        // Work out what actually needs resolving *before* building the region
        // index. `RegionIndex::from_pid` parses the whole of /proc/<pid>/maps,
        // and this runs on the snapshot tick (10 Hz by default) — so a class
        // with no VTable/Function/FunctionPtr node, which is most classes, paid
        // a full maps parse ten times a second for a result it never used.
        //
        // We clone the metadata we need (addresses + type tags) because we
        // cannot hold `&self.process` while also taking `&mut self.live_cache`.
        let targets: Vec<(String, &'static str, usize)> = self
            .node_snapshots
            .iter()
            .filter(|s| matches!(s.type_tag, "VTable" | "Function" | "FunctionPtr"))
            .filter(|s| !collapsed.contains(&s.id_path))
            .filter(|s| !self.live_cache.contains_key(&s.id_path))
            .map(|s| (s.id_path.clone(), s.type_tag, s.address))
            .collect();
        if targets.is_empty() {
            return;
        }

        // Build a RegionIndex once per refresh (one /proc/<pid>/maps parse).
        let pid = proc.pid();
        let region_index = match RegionIndex::from_pid(pid) {
            Ok(idx) => idx,
            Err(_) => return,
        };

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

    // -----------------------------------------------------------------------
    // Vector / matrix components
    // -----------------------------------------------------------------------

    /// Draw one float component of a vector/matrix node: a monospace value that
    /// becomes an inline edit box on double-click, committed straight to the
    /// target's memory.
    ///
    /// `index` is the component's position in the node (row-major for matrices)
    /// and, together with `id_path`, keys the edit state so only the clicked
    /// component turns into a text box.
    fn float_component_cell(
        &mut self,
        ui: &mut egui::Ui,
        id_path: &str,
        index: usize,
        value: f64,
        width: FloatWidth,
        addr: usize,
    ) {
        let editing = self
            .edit_state
            .as_ref()
            .is_some_and(|e| e.node_id == id_path && e.field == EditField::Component(index));

        if editing {
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.edit_state.as_mut().unwrap().text)
                    .desired_width(72.0),
            );
            let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
            let escape = ui.input(|i| i.key_pressed(egui::Key::Escape));
            if resp.lost_focus() || enter {
                let edit = self.edit_state.take().unwrap();
                self.write_float_component(addr, width, edit.text.trim());
            } else if escape {
                self.edit_state = None;
            }
        } else {
            let resp = ui.add(
                egui::Label::new(egui::RichText::new(width.format(value)).monospace())
                    .truncate()
                    .sense(egui::Sense::click()),
            );
            if resp.double_clicked() && self.process.is_some() {
                self.edit_state = Some(EditState {
                    node_id: id_path.to_owned(),
                    // Seed with the full-precision value, not the 3-decimal
                    // display form, so re-committing an untouched cell doesn't
                    // quietly round the target's memory.
                    text: value.to_string(),
                    field: EditField::Component(index),
                });
            }
        }
    }

    /// Write one edited float component back to the target.
    fn write_float_component(&mut self, addr: usize, width: FloatWidth, text: &str) {
        let Some(proc) = &self.process else {
            self.last_error = Some("Write: not attached".to_owned());
            return;
        };
        let Some(bytes) = width.parse_to_ne_bytes(text) else {
            self.last_error = Some(format!("Write: '{text}' is not a valid {}", width.rust_ty()));
            return;
        };
        match proc.write_buf(addr, &bytes) {
            Ok(_) => {
                self.last_error = None;
                self.last_snapshot = None;
            }
            Err(e) => self.last_error = Some(format!("Write: {e}")),
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
        self.check_target_alive();

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

            // Auto-reload: once per second, poll the scripts dir for a changed
            // file (by modified-time) and reload once when an edit is detected.
            // Gated by the Scripts-panel toggle and a live engine.
            if self.scripts_panel.auto_reload() && self.script_host.is_active() {
                let watch_due = self
                    .last_script_watch
                    .map(|t| t.elapsed() >= Duration::from_millis(1000))
                    .unwrap_or(true);
                if watch_due {
                    self.last_script_watch = Some(Instant::now());
                    if let Some(dir) = self.project_dir.as_ref().map(|d| d.join("src"))
                        && scan_script_mtimes(&dir) != self.script_mtimes
                    {
                        self.reload_scripts_dir(&dir, "Auto-reloaded (file changed):");
                    }
                }
            }

            // Poll script-registered global hotkeys. For each match this frame,
            // dispatch `OnHotkey { id }` into the engine. Collect ids first so we
            // don't hold the `ctx.input` closure while borrowing `script_host`.
            // Same focus guard as Ctrl+F below: a script-registered hotkey must
            // not fire because the user typed its letter into a text box.
            if !self.script_hotkeys.is_empty()
                && self.script_host.is_active()
                && !typing_in_a_text_field(ctx)
            {
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

        // Drain background scans and drive debugger event polling. Freeze
        // write-back lives entirely in the cheat-table panel below — the scanner
        // routes its Freeze button there rather than keeping a second set.
        self.scanner_panel.poll();
        #[cfg(target_os = "linux")]
        self.pointer_scan_panel.poll();
        self.spider_panel.poll();
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
        // Only when no text field has focus. Without the guard, pressing Ctrl+F
        // while editing an address formula, a node name, a scanner needle or a
        // cheat-table description froze the entire cheat table — the shortcut
        // fired straight off `ctx.input` regardless of where the keystroke was
        // aimed. `DisassemblyPanel::handle_keyboard` already models this.
        let freeze_hotkey = !typing_in_a_text_field(ctx)
            && ctx.input_mut(|i| {
                i.consume_key(
                    egui::Modifiers {
                        ctrl: true,
                        shift: false,
                        alt: false,
                        ..Default::default()
                    },
                    egui::Key::F,
                )
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
        self.show_extract_class_dialog(ui.ctx());
        self.show_enum_editor(ui.ctx());
        self.show_unsaved_changes_prompt(ui.ctx());
        // After the dialogs: a modal that has keyboard focus must get the
        // keystroke, and `typing_in_a_text_field` only reports focus once the
        // widget has been drawn this frame.
        self.handle_class_view_keys(ui.ctx());
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
            // A leading dot is the conventional "there are unsaved changes"
            // marker; without one the only way to know was to remember.
            let marker = if self.project_dirty { "\u{2022} " } else { "" };
            let title = match &self.project_dir {
                Some(dir) => format!(
                    "{marker}{} — {}",
                    self.project.name,
                    dir.display()
                ),
                None => format!("{marker}{} (unsaved)", self.project.name),
            };
            ui.strong(&title);

            ui.separator();

            // Deferred file actions (native rfd dialogs block the UI thread, so
            // we collect the intent and run it after the menu-bar closure).
            let mut do_new = false;
            let mut do_open = false;
            let mut do_save = false;
            let mut do_save_as = false;
            let mut do_import_rcnet = false;
            let mut do_export_rcnet = false;
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
                ui.separator();
                if ui
                    .button("Import ReClass.NET (.rcnet)…")
                    .on_hover_text("Open a project saved by ReClass.NET")
                    .clicked()
                {
                    do_import_rcnet = true;
                    ui.close();
                }
                if ui
                    .button("Export ReClass.NET (.rcnet)…")
                    .on_hover_text("Write this project in ReClass.NET's format")
                    .clicked()
                {
                    do_export_rcnet = true;
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

            ui.menu_button("Project", |ui| {
                if ui.button("Enums…").clicked() {
                    self.enum_editor_open = true;
                    ui.close();
                }
                ui.separator();
                let ptr_size = self.project.pointer_size();
                ui.label("Target pointer width");
                let mut chosen = ptr_size;
                ui.radio_value(&mut chosen, 8, "64-bit");
                ui.radio_value(&mut chosen, 4, "32-bit");
                if chosen != ptr_size {
                    self.record_undo();
                    if let Err(e) = self.project.set_pointer_size(chosen) {
                        self.last_error = Some(e.to_string());
                    }
                    self.invalidate_class_view();
                }
            });

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
            } else if do_import_rcnet {
                self.pick_import_rcnet();
            } else if do_export_rcnet {
                self.pick_export_rcnet();
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
    ///
    /// Guarded on unsaved changes — this used to discard the open project
    /// silently.
    fn pick_new_project(&mut self) {
        if self.project_dirty {
            self.pending_discard = Some(PendingDiscard::New);
            return;
        }
        self.pick_new_project_now();
    }

    fn pick_new_project_now(&mut self) {
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
        if self.project_dirty {
            self.pending_discard = Some(PendingDiscard::Open);
            return;
        }
        self.pick_open_project_now();
    }

    fn pick_open_project_now(&mut self) {
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
        let mut comment_changed = false;
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
                    ui.strong("Comment:");
                    // The field round-tripped through the project file and into
                    // generated source, but nothing in the UI ever wrote it.
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut class.comment)
                                .desired_width(160.0)
                                .hint_text("class comment"),
                        )
                        .changed()
                    {
                        comment_changed = true;
                    }
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                match &self.attached_name {
                    Some(n) => ui.colored_label(egui::Color32::GREEN, format!("Attached: {n}")),
                    None    => ui.colored_label(egui::Color32::GRAY, "Not attached"),
                };
            });
        });

        if comment_changed {
            self.mark_project_dirty();
        }
        if formula_changed {
            self.mark_project_dirty();
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
                self.record_undo();
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
            self.record_undo();
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
        if let Some(action) = self.pending_spider_action.take() {
            self.apply_spider_action(action);
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
                    self.reload_scripts_dir(&dir, "Loaded scripts from");
                }
            }
            ScriptsPanelAction::Reload(path) => {
                // The engine loads a whole directory; reload the file's parent so
                // a single-file reload still refreshes it.
                if let Some(dir) = path.parent().map(|p| p.to_path_buf()) {
                    self.reload_scripts_dir(&dir, "Reloaded scripts from");
                }
            }
            ScriptsPanelAction::Clear => {
                self.script_log.borrow_mut().clear();
            }
        }
    }

    fn show_scanner_tab(&mut self, ui: &mut egui::Ui) {
        // Cheat Engine's layout: scan results on top, the saved address list
        // docked directly beneath, in one window. Declared before the results so
        // the bottom panel reserves its height first.
        if self.show_address_list {
            egui::Panel::bottom("scanner_address_list")
                .resizable(true)
                .default_size(220.0)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        self.show_cheat_table_tab(ui);
                    });
                });
        }
        egui::CentralPanel::default().show(ui, |ui| self.show_scanner_body(ui));
    }

    /// The attached process's module list for the scanner's scope picker, cached
    /// for [`MODULE_CACHE_TTL`].
    ///
    /// This re-parsed `/proc/<pid>/maps` on every frame — 60 times a second, to
    /// fill a combo box that is only read when the collapsed "Scan range" section
    /// is expanded. Modules load and unload rarely enough that a second-old list
    /// is indistinguishable from a fresh one.
    fn scanner_modules(&mut self) -> Vec<nemclass_core::ModuleInfoWithName> {
        let fresh = self
            .module_cache_at
            .is_some_and(|t| t.elapsed() < MODULE_CACHE_TTL);
        if !fresh {
            self.module_cache = self
                .process
                .as_ref()
                .and_then(|p| p.modules().ok())
                .map(|it| it.collect())
                .unwrap_or_default();
            self.module_cache_at = Some(Instant::now());
        }
        self.module_cache.clone()
    }

    fn show_scanner_body(&mut self, ui: &mut egui::Ui) {
        // Owned snapshot: `process_ref` below holds an immutable borrow of
        // `self.process` across the `&mut self.scanner_panel` call, so a
        // borrowing iterator wouldn't compile.
        let modules = self.scanner_modules();

        // The shared handle, not a fresh attach: the scanner reads through the
        // backend the user actually attached with.
        let process_ref = self.process.as_ref();
        // Owned handle (cloned) so it doesn't borrow `self` across the panel call.
        let rt = self.runtime.as_ref().expect("bg runtime").handle();

        let mut add_to_class_addr: Option<usize> = None;
        let mut add_to_table: Option<(usize, String)> = None;
        let mut ptr_scan_addr: Option<usize> = None;
        let mut freeze_addr: Option<(usize, String, String)> = None;

        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_address_list, "Address list")
                .on_hover_text("Show the saved address list docked below the results.");
        });

        self.scanner_panel.set_live_interval(self.snapshot_interval);
        self.scanner_panel.show(
            ui,
            process_ref,
            &modules,
            &rt,
            |addr| { add_to_class_addr = Some(addr); },
            |addr, tag| { add_to_table = Some((addr, tag.to_owned())); },
            |addr| { ptr_scan_addr = Some(addr); },
            |addr, tag, value| { freeze_addr = Some((addr, tag.to_owned(), value)); },
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
        if let Some((addr, tag, value)) = freeze_addr {
            // Freezing from a scan result *is* adding a frozen row to the
            // address list — that panel owns freezing, so there is one write-back
            // loop rather than two that can disagree. Toggles an existing row
            // rather than stacking duplicates.
            let key = format!("0x{addr:X}");
            let table = self.cheat_table_panel.table_mut();
            match table.entries.iter_mut().find(|e| e.address == key) {
                Some(existing) => {
                    existing.frozen = !existing.frozen;
                    existing.frozen_value = if existing.frozen { value } else { String::new() };
                }
                None => table.push(nemclass_model::CheatEntry {
                    description: key.clone(),
                    address: key,
                    value_type: tag,
                    frozen: true,
                    frozen_value: value,
                    group: String::new(),
                }),
            }
        }
        if let Some(addr) = ptr_scan_addr {
            self.pointer_scan_panel.set_goal(addr);
            self.pending_focus = Some(TabKind::PointerScan);
        }
    }

    /// Code-generator tab. `project`/`node_registry` are disjoint field borrows,
    /// so the panel can read them while it mutably holds its own state.
    fn show_generator_tab(&mut self, ui: &mut egui::Ui) {
        self.generator_panel.ui(ui, &self.project, &self.node_registry);
    }

    fn show_pointer_scan_tab(&mut self, ui: &mut egui::Ui) {
        #[cfg(target_os = "linux")]
        let pid: Option<nemclass_core::Pid> = self.process.as_ref().map(|p| p.pid());
        #[cfg(not(target_os = "linux"))]
        let pid: Option<nemclass_core::Pid> = None;

        // Through the TTL cache, not a fresh enumeration: this ran every frame
        // the tab was visible, and `p.modules()` parses the whole of
        // /proc/<pid>/maps. `scanner_modules` exists precisely to prevent that.
        let modules = self.scanner_modules();

        // A chain is anchored in a module image, so the Modules tab's selection
        // is exactly the set of anchors worth searching. Unscoped, every `.so`
        // in the process is an anchor and the result list fills with chains
        // rooted in libc and ld.so. An empty selection stays unfiltered.
        let modules = self.modules_panel.scope(&modules);
        if let Some(hint) = self.modules_panel.scope_hint(&modules) {
            ui.weak(hint);
        }

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

    fn show_spider_tab(&mut self, ui: &mut egui::Ui) {
        // Cached module list (TTL'd) — used to anchor a hit's formula in a module
        // image so the path survives a restart. Re-parsing /proc/<pid>/maps every
        // frame is what this cache exists to avoid.
        let modules = self.scanner_modules();

        // Same scope as the pointer scan: a hit's formula is anchored in one of
        // these images, so narrowing the list keeps spider formulas expressed
        // relative to the modules the user is actually working in. A hit whose
        // base falls outside them still resolves — `hit_row` falls back to an
        // absolute anchor.
        let modules = self.modules_panel.scope(&modules);
        if let Some(hint) = self.modules_panel.scope_hint(&modules) {
            ui.weak(hint);
        }

        let rt = self.runtime.as_ref().expect("bg runtime").handle();

        self.spider_panel.set_live_interval(self.snapshot_interval);
        let action = self.spider_panel.show(ui, self.process.as_ref(), &modules, &rt);

        // Stash for application after the dock draw closes all borrows.
        match action {
            SpiderAction::None => {}
            other => {
                self.pending_spider_action = Some(other);
            }
        }
    }

    /// Apply a [`SpiderAction`] deferred from the spider tab draw.
    ///
    /// The address-list and freeze routes store the *formula*, not a resolved
    /// literal, so the entry re-walks its pointer chain every tick and keeps
    /// working after the target relocates — which is the whole point of a spider
    /// result over a bare address.
    fn apply_spider_action(&mut self, action: SpiderAction) {
        match action {
            SpiderAction::None => {}
            SpiderAction::AddToTable { formula, tag } => {
                self.cheat_table_panel.table_mut().push(nemclass_model::CheatEntry {
                    description: formula.clone(),
                    address: formula,
                    value_type: tag.to_string(),
                    frozen: false,
                    frozen_value: String::new(),
                    group: String::new(),
                });
            }
            SpiderAction::Freeze { formula, tag, value } => {
                // Freezing is owned by the address list, so there stays exactly
                // one write-back loop. Toggle an existing row rather than
                // stacking duplicates for the same path.
                let table = self.cheat_table_panel.table_mut();
                match table.entries.iter_mut().find(|e| e.address == formula) {
                    Some(existing) => {
                        existing.frozen = !existing.frozen;
                        existing.frozen_value =
                            if existing.frozen { value } else { String::new() };
                    }
                    None => table.push(nemclass_model::CheatEntry {
                        description: formula.clone(),
                        address: formula,
                        value_type: tag.to_string(),
                        frozen: true,
                        frozen_value: value,
                        group: String::new(),
                    }),
                }
            }
            SpiderAction::CreateClass { name, formula } => {
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
            SpiderAction::Goto(addr) => {
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
                // Every failure here used to be discarded: both IO errors went
                // into `let _ =`, and with no project directory the whole block
                // was skipped — so "Save" was a silent no-op and the user had no
                // way to know their table was never written. (Load already said
                // "No project directory"; Save did not.)
                let Some(dir) = self.project_dir.clone() else {
                    self.cheat_table_panel.status_msg =
                        Some("No project directory — save or open a project first.".to_owned());
                    return;
                };
                let tables_dir = dir.join("tables");
                let result = std::fs::create_dir_all(&tables_dir)
                    .map_err(|e| format!("{}: {e}", tables_dir.display()))
                    .and_then(|()| {
                        self.cheat_table_panel
                            .table_mut()
                            .to_toml()
                            .map_err(|e| e.to_string())
                    })
                    .and_then(|s| {
                        let path = tables_dir.join(format!("{name}.toml"));
                        match std::fs::write(&path, s) {
                            Ok(()) => Ok(path),
                            Err(e) => Err(format!("{}: {e}", path.display())),
                        }
                    });
                self.cheat_table_panel.status_msg = Some(match result {
                    Ok(path) => format!("Saved {}", path.display()),
                    Err(e) => format!("Save failed: {e}"),
                });
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

    /// The target's loaded modules, base-sorted — the canonical ordering shared by
    /// the disassembler and the Modules panel so their indices stay aligned.
    #[cfg(target_os = "linux")]
    fn sorted_modules(proc: &Process) -> Vec<ModuleInfoWithName> {
        let mut v: Vec<ModuleInfoWithName> = proc.modules().map(|it| it.collect()).unwrap_or_default();
        v.sort_by_key(|m| m.base);
        v
    }

    /// The Modules panel: a checkbox list picking which modules the disassembler
    /// unions into its concatenated linear view.
    fn show_modules_tab(&mut self, ui: &mut egui::Ui) {
        #[cfg(target_os = "linux")]
        {
            // Sort the cached list rather than re-enumerating every frame —
            // `sorted_modules` parses /proc/<pid>/maps, and this tab redraws at
            // the frame rate.
            let mut modules = self.scanner_modules();
            modules.sort_by_key(|m| m.base);
            if let Some(sel) = self.modules_panel.show(ui, &modules)
                && let Some(proc) = self.process.clone()
            {
                self.disassembly_panel.set_selected_modules(&sel, &proc);
                self.pending_focus = Some(TabKind::Disassembly);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            ui.centered_and_justified(|ui| {
                ui.label("Modules are Linux-only for now.");
            });
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

        // Recorded first: accepting a dissect replaces the whole class body,
        // which was previously irreversible.
        self.record_undo();

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

    /// The class-view field toolbar: bulk add/insert/delete of bytes, type
    /// changes, clipboard and history — the ReClass/yclass "top header".
    ///
    /// Everything acts on [`Self::selection`], which may hold many rows. With
    /// nothing selected, `Add` still works and appends to the end of the class,
    /// so a brand-new empty class can be filled from here.
    fn show_class_toolbar(&mut self, ui: &mut egui::Ui) {
        let Some(class_uuid) = self.selected_class else { return };
        let anchor = self.selection.anchor().cloned();
        let has_sel = !self.selection.is_empty();
        let sel_count = self.selection.len();

        // Collected inside the closures, applied once they release `self`.
        let mut single_op: Option<NodeEditOp> = None;
        let mut bulk_tag: Option<&'static str> = None;
        let mut action: Option<ToolbarAction> = None;

        /// One-click type button, coloured by family like ReClass/yclass.
        fn type_button(
            ui: &mut egui::Ui,
            label: &str,
            fill: egui::Color32,
            enabled: bool,
        ) -> bool {
            ui.add_enabled(
                enabled,
                egui::Button::new(
                    egui::RichText::new(label).color(egui::Color32::BLACK).monospace(),
                )
                .fill(fill),
            )
            .clicked()
        }

        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 2.0;

            if ui
                .add_enabled(self.history.can_undo(), egui::Button::new("↶"))
                .on_hover_text("Undo (Ctrl+Z)")
                .clicked()
            {
                action = Some(ToolbarAction::Undo);
            }
            if ui
                .add_enabled(self.history.can_redo(), egui::Button::new("↷"))
                .on_hover_text("Redo (Ctrl+Shift+Z)")
                .clicked()
            {
                action = Some(ToolbarAction::Redo);
            }

            ui.separator();

            ui.menu_button("Add", |ui| {
                ui.set_width(76.0);
                for n in [8usize, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096] {
                    if ui.button(n.to_string()).clicked() {
                        single_op = Some(match &anchor {
                            Some((owner, path)) => NodeEditOp::AddBytes {
                                owner: *owner,
                                path: path.clone(),
                                count: n,
                            },
                            None => NodeEditOp::AppendBytes { owner: class_uuid, count: n },
                        });
                        ui.close();
                    }
                }
            })
            .response
            .on_hover_text("Add N bytes after the selected field (or at the end of the class)");

            // NOTE: the selection-dependent widgets are greyed out one at a
            // time rather than by wrapping a group in `add_enabled_ui` — a
            // nested `Ui` inside `horizontal_wrapped` claims the whole
            // remaining row and wraps independently, which tore the toolbar
            // into a stray vertical column.
            ui.menu_button("Insert", |ui| {
                ui.set_width(76.0);
                for n in [1usize, 2, 4, 8, 16, 64, 256, 1024] {
                    if ui.add_enabled(has_sel, egui::Button::new(n.to_string())).clicked() {
                        if let Some((owner, path)) = &anchor {
                            single_op = Some(NodeEditOp::InsertBytes {
                                owner: *owner,
                                path: path.clone(),
                                count: n,
                            });
                        }
                        ui.close();
                    }
                }
                if !has_sel {
                    ui.weak("select a field first");
                }
            })
            .response
            .on_hover_text("Insert N bytes before the selected field");

            ui.menu_button("Delete", |ui| {
                ui.set_width(96.0);
                if ui
                    .add_enabled(has_sel, egui::Button::new(format!("Selected ({sel_count})")))
                    .clicked()
                {
                    action = Some(ToolbarAction::DeleteSelection);
                    ui.close();
                }
                ui.separator();
                for n in [1usize, 2, 4, 16, 64, 256, 1024] {
                    if ui.add_enabled(has_sel, egui::Button::new(n.to_string())).clicked() {
                        if let Some((owner, path)) = &anchor {
                            single_op = Some(NodeEditOp::DeleteRange {
                                owner: *owner,
                                path: path.clone(),
                                count: n,
                            });
                        }
                        ui.close();
                    }
                }
                if !has_sel {
                    ui.weak("select a field first");
                }
            })
            .response
            .on_hover_text("Delete the selection, or N fields from the selected one");

            ui.separator();

            // Type-change buttons. Each family gets one fill colour so the row
            // is scannable at a glance. Every one applies to the whole
            // selection, not just the anchor.
            let mut change = |ui: &mut egui::Ui, label: &str, tag: &'static str, fill| {
                if type_button(ui, label, fill, has_sel) {
                    bulk_tag = Some(tag);
                }
            };

            const GOLD: egui::Color32 = egui::Color32::from_rgb(230, 190, 80);
            const GREEN: egui::Color32 = egui::Color32::from_rgb(150, 210, 150);
            const BLUE: egui::Color32 = egui::Color32::from_rgb(150, 190, 230);
            const RED: egui::Color32 = egui::Color32::from_rgb(230, 160, 160);
            const GRAY: egui::Color32 = egui::Color32::from_rgb(170, 170, 170);
            const BROWN: egui::Color32 = egui::Color32::from_rgb(200, 170, 130);

            change(ui, "Bool", "Bool", GOLD);
            ui.separator();
            change(ui, "U8", "UInt8", GREEN);
            change(ui, "U16", "UInt16", GREEN);
            change(ui, "U32", "UInt32", GREEN);
            change(ui, "U64", "UInt64", GREEN);
            ui.separator();
            change(ui, "I8", "Int8", BLUE);
            change(ui, "I16", "Int16", BLUE);
            change(ui, "I32", "Int32", BLUE);
            change(ui, "I64", "Int64", BLUE);
            ui.separator();
            change(ui, "F32", "Float", RED);
            change(ui, "F64", "Double", RED);
            ui.separator();
            change(ui, "H8", "Hex8", GRAY);
            change(ui, "H16", "Hex16", GRAY);
            change(ui, "H32", "Hex32", GRAY);
            change(ui, "H64", "Hex64", GRAY);
            ui.separator();
            change(ui, "Ptr", "Pointer", BROWN);
            change(ui, "Str", "Utf8TextPtr", BROWN);
            ui.separator();

            // Everything else lives under one menu, grouped by family. Before
            // this the menu offered scalars, vectors and matrices only, so
            // Array, the text types, VTable and Function existed in the model
            // and in saved projects but were unreachable from the UI.
            ui.menu_button("Type ▸", |ui| {
                ui.set_width(190.0);
                for group in TYPE_GROUPS {
                    ui.menu_button(format!("{} ▸", group.label), |ui| {
                        for (label, tag) in group.types {
                            if ui.add_enabled(has_sel, egui::Button::new(*label)).clicked() {
                                bulk_tag = Some(tag);
                                ui.close();
                            }
                        }
                    });
                }
                ui.menu_button("Vector ▸", |ui| {
                    for (tag, components, width) in VECTOR_SHAPES {
                        let label = format!("Vec{components} {}", width.rust_ty());
                        if ui.add_enabled(has_sel, egui::Button::new(label)).clicked() {
                            bulk_tag = Some(tag);
                            ui.close();
                        }
                    }
                });
                ui.menu_button("Matrix ▸", |ui| {
                    for (tag, rows, cols, width) in MATRIX_SHAPES {
                        let label = format!("Mat{rows}x{cols} {}", width.rust_ty());
                        if ui.add_enabled(has_sel, egui::Button::new(label)).clicked() {
                            bulk_tag = Some(tag);
                            ui.close();
                        }
                    }
                });
                ui.separator();
                if ui.add_enabled(has_sel, egui::Button::new("Class instance…")).clicked() {
                    if let Some((owner, path)) = &anchor {
                        self.class_picker = Some(ClassPickerState {
                            filter: String::new(),
                            purpose: PickerPurpose::ChangeToInstance {
                                owner: *owner,
                                path: path.clone(),
                            },
                        });
                    }
                    ui.close();
                }
                if !has_sel {
                    ui.weak("select a field first");
                }
            });

            ui.separator();

            ui.menu_button("Edit ▸", |ui| {
                ui.set_width(200.0);
                if ui.add_enabled(has_sel, egui::Button::new("Copy\t\tCtrl+C")).clicked() {
                    action = Some(ToolbarAction::Copy);
                    ui.close();
                }
                if ui.add_enabled(has_sel, egui::Button::new("Cut\t\tCtrl+X")).clicked() {
                    action = Some(ToolbarAction::Cut);
                    ui.close();
                }
                let can_paste = !self.node_clipboard.is_empty();
                if ui.add_enabled(can_paste, egui::Button::new("Paste\t\tCtrl+V")).clicked() {
                    action = Some(ToolbarAction::Paste);
                    ui.close();
                }
                ui.separator();
                if ui.add_enabled(has_sel, egui::Button::new("Hide")).clicked() {
                    action = Some(ToolbarAction::Hide);
                    ui.close();
                }
                if ui.add_enabled(has_sel, egui::Button::new("Unhide")).clicked() {
                    action = Some(ToolbarAction::Unhide);
                    ui.close();
                }
                ui.separator();
                if ui
                    .add_enabled(has_sel, egui::Button::new("Make class from selection…"))
                    .clicked()
                {
                    action = Some(ToolbarAction::ExtractClass);
                    ui.close();
                }
                ui.separator();
                if ui.button("Select all\tCtrl+A").clicked() {
                    action = Some(ToolbarAction::SelectAll);
                    ui.close();
                }
            });

            ui.separator();
            ui.label("🔍");
            let search = ui.add(
                egui::TextEdit::singleline(&mut self.class_search)
                    .desired_width(110.0)
                    .hint_text("filter fields"),
            );
            if search.changed() && !self.class_search.is_empty() {
                // A filtered-out row must not stay selected: the next bulk
                // action would hit a field the user can no longer see.
                self.selection.clear();
            }

            // Selection indicator — without it, the disabled buttons above look
            // broken rather than "nothing is selected".
            ui.separator();
            match sel_count {
                0 => {
                    ui.weak("click a field to select it");
                }
                1 => {
                    let name = anchor
                        .as_ref()
                        .and_then(|(owner, path)| {
                            self.node_snapshots
                                .iter()
                                .find(|s| s.owner_class == *owner && s.local_path == *path)
                        })
                        .map(|s| {
                            if s.name.is_empty() {
                                format!("<{}>", s.type_tag)
                            } else {
                                s.name.clone()
                            }
                        })
                        .unwrap_or_else(|| "(field)".to_owned());
                    ui.label(format!("→ {name}"));
                }
                n => {
                    ui.label(format!("→ {n} fields"));
                }
            }
        });

        if let Some(tag) = bulk_tag {
            self.apply_to_selection(move |owner, path| NodeEditOp::ChangeType {
                owner,
                path,
                new_tag: tag,
            });
        }

        if let Some(action) = action {
            match action {
                ToolbarAction::Undo => self.undo(),
                ToolbarAction::Redo => self.redo(),
                ToolbarAction::Copy => self.copy_selection(),
                ToolbarAction::Cut => self.cut_selection(),
                ToolbarAction::Paste => self.paste_clipboard(),
                ToolbarAction::Hide => self.set_selection_hidden(true),
                ToolbarAction::Unhide => self.set_selection_hidden(false),
                ToolbarAction::DeleteSelection => self.delete_selection(),
                ToolbarAction::SelectAll => {
                    let order = self.visible_order.clone();
                    self.selection.select_all(&order);
                }
                ToolbarAction::ExtractClass => self.begin_extract_class(),
            }
        }

        if let Some(op) = single_op {
            self.apply_node_edit(op);
        }
    }

    /// Open the "name the new class" prompt for the current selection.
    fn begin_extract_class(&mut self) {
        let Some(owner) = self.selected_class else { return };
        let paths = self.selection.paths_descending(owner);
        if paths.is_empty() {
            return;
        }
        self.extract_class_dialog = Some(ExtractClassState {
            owner,
            paths,
            name: "NewClass".to_string(),
        });
    }

    /// The "make a class out of these fields" prompt.
    fn show_extract_class_dialog(&mut self, ctx: &egui::Context) {
        let Some(state) = &mut self.extract_class_dialog else { return };
        let mut confirm = false;
        let mut cancel = false;
        let count = state.paths.len();

        egui::Window::new("New class from selection")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!("Move {count} field(s) into a new class."));
                ui.add_space(4.0);
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.name).hint_text("class name"),
                );
                resp.request_focus();
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    confirm = true;
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Create").clicked() {
                        confirm = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    cancel = true;
                }
            });

        if confirm {
            let state = self.extract_class_dialog.take().unwrap();
            self.selection.clear();
            self.apply_node_edit(NodeEditOp::ExtractClass {
                owner: state.owner,
                paths: state.paths,
                name: state.name,
            });
        } else if cancel {
            self.extract_class_dialog = None;
        }
    }

    /// Keyboard shortcuts for the class view.
    ///
    /// Guarded on text focus throughout: a Delete pressed while renaming a
    /// field belongs to the text box, not to the class.
    fn handle_class_view_keys(&mut self, ctx: &egui::Context) {
        if typing_in_a_text_field(ctx) || self.selected_class.is_none() {
            return;
        }

        let (delete, up, down, shift, ctrl, copy, cut, paste, select_all, undo, redo, escape) =
            ctx.input_mut(|i| {
                (
                    i.key_pressed(egui::Key::Delete),
                    i.key_pressed(egui::Key::ArrowUp),
                    i.key_pressed(egui::Key::ArrowDown),
                    i.modifiers.shift,
                    i.modifiers.command,
                    i.consume_key(egui::Modifiers::COMMAND, egui::Key::C),
                    i.consume_key(egui::Modifiers::COMMAND, egui::Key::X),
                    i.consume_key(egui::Modifiers::COMMAND, egui::Key::V),
                    i.consume_key(egui::Modifiers::COMMAND, egui::Key::A),
                    i.consume_key(egui::Modifiers::COMMAND, egui::Key::Z),
                    i.consume_key(egui::Modifiers::COMMAND | egui::Modifiers::SHIFT, egui::Key::Z)
                        || i.consume_key(egui::Modifiers::COMMAND, egui::Key::Y),
                    i.key_pressed(egui::Key::Escape),
                )
            });

        if undo {
            self.undo();
        }
        if redo {
            self.redo();
        }
        if copy {
            self.copy_selection();
        }
        if cut {
            self.cut_selection();
        }
        if paste {
            self.paste_clipboard();
        }
        if select_all {
            let order = self.visible_order.clone();
            self.selection.select_all(&order);
        }
        if delete {
            self.delete_selection();
        }
        if escape {
            self.selection.clear();
        }
        // Ctrl is the clipboard/history modifier; an arrow with it held is not
        // a selection move.
        if (up || down) && !ctrl {
            let order = self.visible_order.clone();
            self.selection.step(&order, if up { -1 } else { 1 }, shift);
        }
    }

    fn show_class_view(&mut self, ui: &mut egui::Ui) {
        if self.selected_class.is_none() {
            ui.centered_and_justified(|ui| {
                ui.label("Select a class from the left panel.");
            });
            return;
        }

        // Field toolbar first: it must work on an empty class too, so the user
        // can "Add 64 bytes" into a class that has no nodes yet.
        self.show_class_toolbar(ui);
        ui.separator();

        if self.process.is_none() {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Not attached — showing demo layout (zeroed buffer).",
            );
            ui.add_space(4.0);
        } else if self.class_base.is_none() {
            // Attached, but nothing told us *where* the class lives. Without
            // this the table silently shows a zero buffer that looks like real
            // (all-zero) target memory.
            ui.colored_label(
                egui::Color32::YELLOW,
                "No base address — set an address formula above, or resolve one \
                 via a script/pointer scan.",
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
        let mut view_rows = build_augmented_rows(
            &self.node_snapshots,
            &self.collapsed,
            #[cfg(target_os = "linux")]
            &self.live_cache,
        );

        // The search box filters rather than jumps: a `TableBuilder` body is
        // virtualized, so "scroll to the next match" would have to drive the
        // scroll offset by row index, while a filter needs nothing but this.
        // Only snapshot rows are matched — live vtable/disassembly children
        // belong to whichever parent survived.
        if !self.class_search.trim().is_empty() {
            let needle = self.class_search.trim().to_lowercase();
            view_rows.retain(|row| match row {
                ViewRow::Snap(i) => {
                    let snap = &self.node_snapshots[*i];
                    snap.name.to_lowercase().contains(&needle)
                        || snap.type_tag.to_lowercase().contains(&needle)
                        || snap.comment.to_lowercase().contains(&needle)
                        || snap.rendered.value.to_lowercase().contains(&needle)
                        || format!("{:x}", snap.offset).contains(&needle)
                }
                _ => false,
            });
        }

        // Record what is on screen, in order: shift-click and the arrow keys
        // range over the *visible* rows, and a selection pointing at a row that
        // is no longer drawn would let a bulk action hit something invisible.
        self.visible_order = view_rows
            .iter()
            .filter_map(|row| match row {
                ViewRow::Snap(i) => {
                    let snap = &self.node_snapshots[*i];
                    Some((snap.owner_class, snap.local_path.clone()))
                }
                _ => None,
            })
            .collect();
        let visible_order = self.visible_order.clone();
        self.selection.retain_visible(&visible_order);

        // Rows are a fixed height, so it must clear the *tallest* widget a row
        // can host — the collapse arrow and the inline text edit are both taller
        // than plain body text, and a short row clipped them.
        let text_height = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = text_height.max(ui.spacing().interact_size.y) + 4.0;

        // Never wrap inside a cell. A wrapped second line overflows the fixed
        // row height and is clipped, which is what turned a 16-digit address
        // into a smear of half-visible rows.
        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);

        // Collect a pending disasm-goto request during the table draw and apply
        // it after the closure exits (avoids the borrow conflict on `self`).
        #[cfg(target_os = "linux")]
        { self.pending_disasm_goto = None; }

        // Row the user clicked this frame, applied after the body closure ends.
        let mut clicked_row: Option<(Uuid, Vec<usize>)> = None;
        let selection = self.selection.clone();
        // Read once: `ctx.input` inside the body closure would be a second
        // borrow of the context the table already holds.
        let (ctrl_held, shift_held) =
            ui.input(|i| (i.modifiers.command, i.modifiers.shift));

        // Column widths matter more than they look: a resizable `TableBuilder`
        // hands each column its width in order and gives the last one whatever
        // is left, so if the fixed widths overflow the pane the trailing
        // columns (Value, Comment — and with them the matrix cells) are pushed
        // off the right edge with no scrollbar to reach them. The five fixed
        // widths below sum to ~475px so all six columns survive a narrow dock
        // pane; every one is still drag-resizable, and Comment absorbs the
        // slack in a wide one.
        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::initial(130.0).at_least(80.0))   // Address
            .column(Column::initial(66.0).at_least(48.0))    // Offset
            .column(Column::initial(68.0).at_least(50.0))    // Type
            .column(Column::initial(85.0).at_least(60.0))    // Name
            .column(Column::initial(128.0).at_least(80.0))   // Value
            .column(Column::remainder().at_least(40.0))      // Comment
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
                            let components     = snap.components.clone();
                            let float_width    = snap.float_width;
                            let hidden         = snap.hidden;

                            // For live-expandable nodes, we treat them as
                            // containers (has_children for collapse toggle) even
                            // if the static model has no children.
                            #[cfg(target_os = "linux")]
                            let is_live_container = matches!(
                                type_tag, "VTable" | "Function" | "FunctionPtr"
                            );
                            #[cfg(not(target_os = "linux"))]
                            let is_live_container = false;

                            // A matrix expands into one child row per matrix row.
                            let is_matrix = matrix_shape(type_tag).is_some();
                            let is_vector = vector_shape(type_tag).is_some();

                            row.set_selected(
                                selection.contains(snap_owner, &snap_local_path),
                            );

                            let (_, r) = row.col(|ui| { mono_cell(ui, format!("0x{address:012X}")); });
                            let mut row_clicked = r.clicked();
                            let (_, r) = row.col(|ui| { mono_cell(ui, format!("+{offset:#06X}")); });
                            row_clicked |= r.clicked();
                            // A hidden field keeps its row rather than
                            // collapsing to a placeholder the way ReClass does:
                            // the row is how you select it to unhide it again.
                            let (_, r) = row.col(|ui| {
                                if hidden {
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(format!("{type_tag} (hidden)"))
                                                .weak()
                                                .italics(),
                                        )
                                        .sense(egui::Sense::click()),
                                    )
                                } else {
                                    text_cell(ui, type_tag)
                                };
                            });
                            row_clicked |= r.clicked();
                            if row_clicked {
                                clicked_row = Some((snap_owner, snap_local_path.clone()));
                            }

                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    let indent = depth as f32 * 12.0;
                                    if indent > 0.0 { ui.add_space(indent); }

                                    if has_children || is_live_container || is_matrix {
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
                                        let resp = text_cell(ui, &name);
                                        if resp.double_clicked() {
                                            self.edit_state = Some(EditState {
                                                node_id: id_path.clone(),
                                                text: name.clone(),
                                                field: EditField::Name,
                                            });
                                        } else if resp.clicked() {
                                            clicked_row =
                                                Some((snap_owner, snap_local_path.clone()));
                                        }
                                    }
                                });
                            });

                            row.col(|ui| {
                                let editing = self
                                    .edit_state
                                    .as_ref()
                                    .is_some_and(|e| e.node_id == id_path && e.field == EditField::Value);

                                if is_vector {
                                    // One editable cell per component, laid out
                                    // inline: `(x, y, z)` is three separate
                                    // values, not one string.
                                    if components.is_empty() {
                                        text_cell(ui, &value);
                                    } else {
                                        let width = float_width.unwrap_or(FloatWidth::F32);
                                        let wsz = width.size();
                                        ui.horizontal(|ui| {
                                            for (i, v) in components.iter().enumerate() {
                                                self.float_component_cell(
                                                    ui,
                                                    &id_path,
                                                    i,
                                                    *v,
                                                    width,
                                                    address.wrapping_add(i * wsz),
                                                );
                                            }
                                        });
                                    }
                                } else if is_matrix {
                                    // Shape summary; the cells live in the
                                    // per-matrix-row children below.
                                    let resp = text_cell(ui, &value);
                                    resp.context_menu(|ui| {
                                        self.build_node_context_menu(
                                            ui, snap_owner, snap_local_path.clone(),
                                            type_tag, &value, pointer_target,
                                        );
                                    });
                                } else if is_editable(type_tag) && self.process.is_some() {
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
                                    let resp = text_cell(ui, &comment);
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

                        // One row of an expanded matrix: `cols` editable cells.
                        ViewRow::MatrixRow { snap_idx, row: mrow } => {
                            let snap = &self.node_snapshots[*snap_idx];
                            let Some((_, cols, width)) = matrix_shape(snap.type_tag) else { return };
                            let cols = cols as usize;
                            let wsz = width.size();
                            let base_index = *mrow * cols;

                            let id_path = snap.id_path.clone();
                            let depth = snap.depth;
                            let base_addr = snap.address;
                            let base_offset = snap.offset;
                            let cells: Vec<f64> = snap
                                .components
                                .get(base_index..base_index + cols)
                                .map(<[f64]>::to_vec)
                                .unwrap_or_default();

                            let row_addr = base_addr.wrapping_add(base_index * wsz);
                            row.col(|ui| { mono_cell(ui, format!("0x{row_addr:012X}")); });
                            row.col(|ui| {
                                mono_cell(ui, format!("+{:#06X}", base_offset + base_index * wsz));
                            });
                            row.col(|ui| { text_cell(ui, ""); });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    ui.add_space((depth as f32 + 1.0) * 12.0 + 16.0);
                                    text_cell(ui, &format!("[{mrow}]"));
                                });
                            });
                            row.col(|ui| {
                                ui.horizontal(|ui| {
                                    for (c, v) in cells.iter().enumerate() {
                                        self.float_component_cell(
                                            ui,
                                            &id_path,
                                            base_index + c,
                                            *v,
                                            width,
                                            row_addr.wrapping_add(c * wsz),
                                        );
                                    }
                                });
                            });
                            row.col(|ui| { text_cell(ui, ""); });
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

        // Clicking a row makes it the toolbar's target; clicking the selected
        // row again clears the selection (so "Add bytes" goes back to appending).
        if let Some(hit) = clicked_row {
            if shift_held {
                self.selection.extend_to(hit, &visible_order);
            } else if ctrl_held {
                self.selection.toggle(hit);
            } else if self.selection.len() == 1 && self.selection.contains(hit.0, &hit.1) {
                // Clicking the only selected row again clears it, so "Add
                // bytes" goes back to appending at the end of the class.
                self.selection.clear();
            } else {
                self.selection.set_single(hit);
            }
        }

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

        // Apply any deferred structural node edits (ChangeType, Delete, …) as a
        // single undo step — a multi-row change is one user action.
        self.flush_pending_node_edits();
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
        // Right-clicking outside the selection acts on the row under the
        // cursor; right-clicking inside it acts on the whole selection, which
        // is what every list-with-multi-select does.
        let in_selection = self.selection.contains(snap_owner, &snap_local_path);
        if !in_selection {
            self.selection.set_single((snap_owner, snap_local_path.clone()));
        }
        let count = self.selection.len().max(1);
        let plural = if count > 1 { format!(" ({count})") } else { String::new() };

        let mut bulk_tag: Option<&'static str> = None;

        ui.menu_button(format!("Change type{plural} ▸"), |ui| {
            for group in TYPE_GROUPS {
                ui.menu_button(format!("{} ▸", group.label), |ui| {
                    for (label, tag) in group.types {
                        if ui.button(*label).clicked() {
                            bulk_tag = Some(tag);
                            ui.close();
                        }
                    }
                });
            }

            ui.separator();
            ui.menu_button("Vector ▸", |ui| {
                for (tag, components, width) in VECTOR_SHAPES {
                    if ui.button(format!("Vec{components} {}", width.rust_ty())).clicked() {
                        bulk_tag = Some(tag);
                        ui.close();
                    }
                }
            });
            ui.menu_button("Matrix ▸", |ui| {
                for (tag, rows, cols, width) in MATRIX_SHAPES {
                    if ui.button(format!("Mat{rows}x{cols} {}", width.rust_ty())).clicked() {
                        bulk_tag = Some(tag);
                        ui.close();
                    }
                }
            });

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
        if ui.button(format!("Copy{plural}\tCtrl+C")).clicked() {
            self.copy_selection();
            ui.close();
        }
        if ui.button(format!("Cut{plural}\tCtrl+X")).clicked() {
            self.cut_selection();
            ui.close();
        }
        if ui
            .add_enabled(
                !self.node_clipboard.is_empty(),
                egui::Button::new("Paste\tCtrl+V"),
            )
            .clicked()
        {
            self.paste_clipboard();
            ui.close();
        }

        ui.separator();
        if ui.button(format!("Hide{plural}")).clicked() {
            self.set_selection_hidden(true);
            ui.close();
        }
        if ui.button(format!("Unhide{plural}")).clicked() {
            self.set_selection_hidden(false);
            ui.close();
        }
        if ui.button(format!("Make class from selection{plural}…")).clicked() {
            self.begin_extract_class();
            ui.close();
        }

        ui.separator();
        if ui.button(format!("Delete{plural}\tDel")).clicked() {
            self.delete_selection();
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
            // The inverse search: the pointer scan asks what *reaches* this
            // address, the spider asks what lives *inside* the object it names.
            if ui.add_enabled(
                enabled,
                egui::Button::new("Spider from this address"),
            ).on_hover_text("Search inside this object for a value").clicked() {
                if let Some(addr) = target_addr {
                    self.spider_panel.set_root(addr);
                    self.pending_focus = Some(TabKind::Spider);
                }
                ui.close();
            }
        }

        if let Some(tag) = bulk_tag {
            self.apply_to_selection(move |owner, path| NodeEditOp::ChangeType {
                owner,
                path,
                new_tag: tag,
            });
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
            if !name.is_empty() {
                self.record_undo();
                if let Some(c) = self.project.get_class_mut(&uuid) {
                    c.name = name;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // ReClass.NET interop
    // -----------------------------------------------------------------------

    /// Import a `.rcnet`, replacing the open project.
    fn pick_import_rcnet(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Import ReClass.NET project")
            .set_directory(self.dialog_start_dir())
            .add_filter("ReClass.NET project", &["rcnet"])
            .pick_file()
        else {
            return;
        };
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                self.last_error = Some(format!("Could not read {}: {e}", path.display()));
                return;
            }
        };
        match nemclass_model::rcnet::import(&bytes, &self.node_registry) {
            Ok((mut project, report)) => {
                // The archive carries no project name, so take the file's.
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    project.name = stem.to_string();
                }
                let class_count = project.classes_in_order().count();
                // No directory: an imported project has not been saved as a
                // nemclass project yet, and pointing `project_dir` at the
                // `.rcnet`'s folder would make the next Save write a
                // `project.nemclass` beside it without being asked.
                self.replace_project(project, None);
                self.project_dirty = true;
                self.status_msg = Some(format!(
                    "Imported {class_count} class(es) from {}",
                    path.display()
                ));
                self.report_interop_notes("Import", &report.notes);
            }
            Err(e) => self.last_error = Some(format!("Import failed: {e}")),
        }
    }

    /// Export the open project as a `.rcnet`.
    fn pick_export_rcnet(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Export ReClass.NET project")
            .set_directory(self.dialog_start_dir())
            .set_file_name(format!("{}.rcnet", self.project.name))
            .add_filter("ReClass.NET project", &["rcnet"])
            .save_file()
        else {
            return;
        };
        match nemclass_model::rcnet::export(&self.project) {
            Ok((bytes, report)) => match std::fs::write(&path, bytes) {
                Ok(()) => {
                    self.status_msg = Some(format!("Exported to {}", path.display()));
                    self.report_interop_notes("Export", &report.notes);
                }
                Err(e) => {
                    self.last_error = Some(format!("Could not write {}: {e}", path.display()))
                }
            },
            Err(e) => self.last_error = Some(format!("Export failed: {e}")),
        }
    }

    /// Surface what an import or export had to approximate.
    ///
    /// These are not errors, but they are not nothing either: a silently
    /// downgraded field is exactly the kind of loss a user finds out about much
    /// later, so they go to the error channel where they persist on screen.
    fn report_interop_notes(&mut self, what: &str, notes: &[String]) {
        if notes.is_empty() {
            return;
        }
        let shown: Vec<&str> = notes.iter().take(8).map(String::as_str).collect();
        let mut msg = format!("{what} was not lossless:\n  {}", shown.join("\n  "));
        if notes.len() > shown.len() {
            msg.push_str(&format!("\n  …and {} more", notes.len() - shown.len()));
        }
        self.last_error = Some(msg);
    }

    // -----------------------------------------------------------------------
    // Unsaved-changes prompt
    // -----------------------------------------------------------------------

    fn show_unsaved_changes_prompt(&mut self, ctx: &egui::Context) {
        let Some(pending) = self.pending_discard else { return };
        let what = match pending {
            PendingDiscard::New => "start a new project",
            PendingDiscard::Open => "open another project",
        };

        #[derive(Clone, Copy)]
        enum Choice {
            Save,
            Discard,
            Cancel,
        }
        let mut choice: Option<Choice> = None;

        egui::Window::new("Unsaved changes")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!("'{}' has unsaved changes.", self.project.name));
                ui.label(format!("Save before you {what}?"));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        choice = Some(Choice::Save);
                    }
                    if ui.button("Discard").clicked() {
                        choice = Some(Choice::Discard);
                    }
                    if ui.button("Cancel").clicked() {
                        choice = Some(Choice::Cancel);
                    }
                });
                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    choice = Some(Choice::Cancel);
                }
            });

        let Some(choice) = choice else { return };
        self.pending_discard = None;
        match choice {
            Choice::Cancel => {}
            Choice::Save => {
                if let Err(e) = self.exec_save() {
                    self.last_error = Some(e);
                    return;
                }
                // `exec_save` routes to Save As when there is no project
                // directory, and the user may have cancelled that — in which
                // case the work is still unsaved and proceeding would lose it.
                if self.project_dirty {
                    return;
                }
                self.run_pending_discard(pending);
            }
            Choice::Discard => self.run_pending_discard(pending),
        }
    }

    fn run_pending_discard(&mut self, pending: PendingDiscard) {
        // Cleared first: the pickers re-check the flag, and a dialog that
        // reopened itself would be unescapable.
        self.project_dirty = false;
        match pending {
            PendingDiscard::New => self.pick_new_project_now(),
            PendingDiscard::Open => self.pick_open_project_now(),
        }
    }

    // -----------------------------------------------------------------------
    // Enum editor
    // -----------------------------------------------------------------------

    /// Edit `project.enums`.
    ///
    /// The descriptions round-tripped through the project file and were reachable
    /// from the scripting API, but had no UI at all — so an `Enum` field could be
    /// placed and never given anything to resolve against.
    fn show_enum_editor(&mut self, ctx: &egui::Context) {
        if !self.enum_editor_open {
            return;
        }
        let mut open = true;
        let mut changed = false;
        let mut remove_enum: Option<usize> = None;
        let mut add_enum = false;

        egui::Window::new("Enums")
            .open(&mut open)
            .default_width(420.0)
            .show(ctx, |ui| {
                if self.project.enums.is_empty() {
                    ui.weak("No enums yet.");
                }
                for (i, desc) in self.project.enums.iter_mut().enumerate() {
                    ui.push_id(i, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Name");
                            if ui.text_edit_singleline(&mut desc.name).changed() {
                                changed = true;
                            }
                            egui::ComboBox::from_label("width")
                                .selected_text(format!("{} byte(s)", desc.size))
                                .show_ui(ui, |ui| {
                                    for size in [1u8, 2, 4, 8] {
                                        if ui
                                            .selectable_value(
                                                &mut desc.size,
                                                size,
                                                format!("{size}"),
                                            )
                                            .clicked()
                                        {
                                            changed = true;
                                        }
                                    }
                                });
                            if ui.checkbox(&mut desc.use_flags, "flags").changed() {
                                changed = true;
                            }
                            if ui.button("🗑").on_hover_text("Remove this enum").clicked() {
                                remove_enum = Some(i);
                            }
                        });

                        let mut remove_value: Option<usize> = None;
                        ui.indent("values", |ui| {
                            for (j, (name, value)) in desc.values.iter_mut().enumerate() {
                                ui.horizontal(|ui| {
                                    if ui
                                        .add(
                                            egui::TextEdit::singleline(name)
                                                .desired_width(160.0),
                                        )
                                        .changed()
                                    {
                                        changed = true;
                                    }
                                    ui.label("=");
                                    let mut text = value.to_string();
                                    if ui
                                        .add(
                                            egui::TextEdit::singleline(&mut text)
                                                .desired_width(90.0),
                                        )
                                        .changed()
                                    {
                                        // Reject rather than clamp: silently
                                        // turning a typo into 0 would give the
                                        // enumerator a value nobody chose.
                                        if let Ok(v) = text.trim().parse::<i64>() {
                                            *value = v;
                                            changed = true;
                                        }
                                    }
                                    if ui.button("✖").clicked() {
                                        remove_value = Some(j);
                                    }
                                });
                            }
                            if ui.button("+ value").clicked() {
                                let next = desc.values.len() as i64;
                                desc.values.push((format!("Value{next}"), next));
                                changed = true;
                            }
                        });
                        if let Some(j) = remove_value {
                            desc.values.remove(j);
                            changed = true;
                        }
                        ui.separator();
                    });
                }
                if ui.button("+ enum").clicked() {
                    add_enum = true;
                }
            });

        if let Some(i) = remove_enum {
            self.record_undo();
            self.project.enums.remove(i);
            changed = true;
        }
        if add_enum {
            self.record_undo();
            let n = self.project.enums.len();
            self.project.enums.push(nemclass_model::EnumDescription::new(format!("Enum{n}")));
            changed = true;
        }
        if changed {
            // Every `Enum` node caches its description's width and value table
            // so it can render without project access; that cache is stale the
            // moment anything here moves.
            self.project.bind_enums();
            self.mark_project_dirty();
            self.invalidate_class_view();
        }
        self.enum_editor_open = open;
    }

}

// ---------------------------------------------------------------------------
// Node-tree structural helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
/// Snapshots the modified-times of every `*.js`/`*.ts` file directly under
/// `dir`. Used by the auto-reload watcher to detect script edits (added, removed,
/// or touched files all change the resulting map). Returns empty on an unreadable
/// directory, which compares equal to a previous empty snapshot (no spurious
/// reload).
#[cfg(feature = "scripting")]
fn scan_script_mtimes(dir: &Path) -> HashMap<PathBuf, std::time::SystemTime> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_script = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("js") || e.eq_ignore_ascii_case("ts"))
            .unwrap_or(false);
        if !is_script {
            continue;
        }
        if let Ok(modified) = entry.metadata().and_then(|m| m.modified()) {
            out.insert(path, modified);
        }
    }
    out
}

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
                        // Was `&mut HashSet::new()`, discarding the guard built
                        // one line above — so a cyclic embed recursed on a fresh
                        // set and this call site disagreed with every other.
                        visited.insert(t_uuid);
                        let sz =
                            nemclass_model::resolved_class_size(tc, project, visited);
                        visited.remove(&t_uuid);
                        sz
                    } else { 0 }
                } else { 0 }
            } else { 0 }
        } else {
            node.memory_size()
        };

        // Vector/matrix nodes carry their components alongside the rendered
        // string so the table can lay out (and edit) each one separately.
        let (components, float_width) = read_float_components(node.as_ref(), buf, cur_offset);

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
            components,
            float_width,
            hidden: node.hidden(),
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

/// Pull the float components out of a vector/matrix node's slice of `buf`.
///
/// The shape is recovered from the node's type tag (see `nemclass_model::node::vector`)
/// rather than by downcasting, so this works through `&dyn Node`. Returns
/// `(components, Some(width))` for vector/matrix tags — with an *empty* vec when
/// the buffer is too short to hold the whole node, so a partial read is never
/// mistaken for real data — and `(vec![], None)` for every other node type.
fn read_float_components(
    node: &dyn Node,
    buf: &[u8],
    offset: usize,
) -> (Vec<f64>, Option<FloatWidth>) {
    let tag = node.type_tag();
    let (count, width) = if let Some((c, w)) = vector_shape(tag) {
        (c as usize, w)
    } else if let Some((r, c, w)) = matrix_shape(tag) {
        (r as usize * c as usize, w)
    } else {
        return (Vec::new(), None);
    };

    let wsz = width.size();
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let Some(start) = offset.checked_add(i * wsz) else { return (Vec::new(), Some(width)) };
        let Some(end) = start.checked_add(wsz) else { return (Vec::new(), Some(width)) };
        if end > buf.len() {
            return (Vec::new(), Some(width));
        }
        match width.read(&buf[start..end]) {
            Some(v) => out.push(v),
            None => return (Vec::new(), Some(width)),
        }
    }
    (out, Some(width))
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

        // An expanded matrix contributes one row per matrix row, laid out from
        // the components already read into the snapshot.
        if let Some((rows, cols, _)) = matrix_shape(snap.type_tag)
            && !collapsed.contains(&snap.id_path)
            && snap.components.len() == rows as usize * cols as usize
        {
            for row in 0..rows as usize {
                out.push(ViewRow::MatrixRow { snap_idx, row });
            }
        }

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

/// Parse a hex address as typed into an address field: an optional `0x`/`0X`
/// prefix, and `_` group separators for readability. Returns `None` on anything
/// that isn't a hex number, including an empty string — a caller that treats a
/// blank field as "unset" must check for that before calling.
pub(crate) fn parse_hex_addr(text: &str) -> Option<usize> {
    let t = text.trim();
    let t = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")).unwrap_or(t);
    if t.is_empty() {
        return None;
    }
    usize::from_str_radix(&t.replace('_', ""), 16).ok()
}

/// The single address parser for the whole UI.
///
/// **Addresses are hexadecimal**, with or without a `0x` prefix, and `_` may be
/// used as a digit separator.
///
/// There used to be five of these with three different conventions in one
/// application: the scanner range and pointer scan treated bare digits as hex,
/// the memory viewer and disassembler treated them as *decimal* (so typing
/// `7fff0000` failed outright while `140000000` silently jumped to decimal
/// 140,000,000 — an address 300 MB away from the one the user meant), and the
/// cheat table and debugger treated them as hex but rejected `_`. Every address
/// box now behaves identically.
pub(crate) fn parse_address(text: &str) -> Result<usize, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("Enter an address".to_string());
    }
    parse_hex_addr(t).ok_or_else(|| format!("Invalid address: '{t}' (expected hex, e.g. 7fff0000)"))
}

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

// ---------------------------------------------------------------------------
// Write-back
// ---------------------------------------------------------------------------

fn write_parsed(proc: &Process, addr: usize, type_tag: &str, text: &str) -> Result<(), String> {
    let bytes = encode_scalar(type_tag, text)?;
    let written = proc.write_buf(addr, &bytes).map_err(|e| e.to_string())?;
    if written != bytes.len() {
        return Err(format!(
            "short write: {written} of {} bytes at {addr:#x}",
            bytes.len()
        ));
    }
    Ok(())
}

/// Encode a user-typed value for `type_tag` into its little-endian bytes.
///
/// Split out from the write so the parsing is unit-testable without a live
/// process — it is the part that was silently wrong.
///
/// Radix rules, matching what a user reasonably expects:
/// - integer types (`Int*`, `UInt*`) are decimal, unless an explicit `0x`
///   prefix says otherwise. `-0x10` is -16.
/// - hex-presented types (`Hex*`, `Pointer`) are hex whether or not the `0x`
///   prefix is written.
///
/// The old implementation stripped `0x` and then parsed the remainder as
/// decimal for every integer type, so `0x10` typed into an `Int32` field wrote
/// **10** to the target — a wrong value, written, with no error shown. It also
/// stripped repeated prefixes (`0x0x10` -> 10) and could never parse `-0x10`,
/// because after stripping, the `-` was no longer leading.
fn encode_scalar(type_tag: &str, text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    let (negative, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, text),
    };
    let has_prefix = body.len() > 2 && (body.starts_with("0x") || body.starts_with("0X"));
    let digits = if has_prefix { &body[2..] } else { body };

    /// Decimal by default; hex on an explicit prefix.
    macro_rules! int {
        ($ty:ty) => {{
            let v: $ty = if has_prefix {
                let mag = <$ty>::from_str_radix(digits, 16).map_err(|e| e.to_string())?;
                if negative {
                    mag.checked_neg()
                        .ok_or_else(|| format!("{text} does not fit in {}", stringify!($ty)))?
                } else {
                    mag
                }
            } else {
                text.parse::<$ty>().map_err(|e| e.to_string())?
            };
            v.to_le_bytes().to_vec()
        }};
    }
    /// Always hex; the `0x` prefix is optional rather than a parse error.
    macro_rules! hex {
        ($ty:ty) => {{
            let v = <$ty>::from_str_radix(digits, 16).map_err(|e| e.to_string())?;
            v.to_le_bytes().to_vec()
        }};
    }
    macro_rules! float {
        ($ty:ty) => {{
            let v = text.parse::<$ty>().map_err(|e| e.to_string())?;
            v.to_le_bytes().to_vec()
        }};
    }

    Ok(match type_tag {
        "Int8" => int!(i8),
        "Int16" => int!(i16),
        "Int32" => int!(i32),
        "Int64" => int!(i64),
        "UInt8" => int!(u8),
        "UInt16" => int!(u16),
        "UInt32" => int!(u32),
        "UInt64" => int!(u64),
        "Hex8" => hex!(u8),
        "Hex16" => hex!(u16),
        "Hex32" => hex!(u32),
        "Hex64" => hex!(u64),
        "Float" => float!(f32),
        "Double" => float!(f64),
        "Bool" => vec![u8::from(matches!(
            text.to_ascii_lowercase().as_str(),
            "true" | "1"
        ))],
        "Pointer" => hex!(u64),
        _ => return Err(format!("'{type_tag}' is not directly writable")),
    })
}

// ---------------------------------------------------------------------------
// Class-view cell helpers
// ---------------------------------------------------------------------------

/// A monospace table cell that truncates rather than wrapping.
///
/// Every class-view cell must go through one of these two helpers: table rows
/// are a fixed height, so a cell that wraps onto a second line has that line
/// clipped, and the column reads as garbage (this is what broke the Address
/// column). The response is click-sensed so a click anywhere in the row can
/// select it.
fn mono_cell(ui: &mut egui::Ui, text: impl Into<String>) -> egui::Response {
    ui.add(
        egui::Label::new(egui::RichText::new(text.into()).monospace())
            .truncate()
            .sense(egui::Sense::click()),
    )
}

/// A proportional table cell that truncates rather than wrapping.
fn text_cell(ui: &mut egui::Ui, text: &str) -> egui::Response {
    ui.add(
        egui::Label::new(text)
            .truncate()
            .sense(egui::Sense::click()),
    )
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

/// Read `size` bytes at `addr`, reporting how much was actually readable.
///
/// Returns `(buffer, readable)`. The buffer is always `size` bytes so callers
/// can index it uniformly; `readable` is how many of them came from the target.
///
/// The caller must not treat a failed read as data. This used to `let _ =` the
/// result and hand back a zero-filled buffer, so a target that had exited — or
/// a class whose address formula resolved somewhere unmapped — rendered as a
/// class full of real-looking zeros rather than as unreadable.
/// `read_float_components` already went out of its way to avoid exactly this,
/// returning no components on a short buffer "so a partial read is never
/// mistaken for real data"; the two policies contradicted each other.
fn read_process_buf(proc: &Process, addr: usize, size: usize) -> (Vec<u8>, usize) {
    if size == 0 {
        return (Vec::new(), 0);
    }
    let mut buf = vec![0u8; size];
    let readable = proc.read_buf(addr, &mut buf).unwrap_or(0);
    (buf, readable)
}

// ---------------------------------------------------------------------------
// Demo project (used as the in-memory default on first launch)
// ---------------------------------------------------------------------------

fn demo_project() -> Project {
    use nemclass_model::node::builtins::{
        ArrayNode, BoolNode, Float32Node, Hex32Node, Hex64Node,
        Int32Node, PointerNode, UInt8Node, Utf8TextNode,
    };
    use nemclass_model::{MatrixNode, VectorNode};

    let mut project = Project::new("Demo Project");
    let mut player = ClassNode::new("PlayerObject");
    player.address_formula = String::new();
    player.comment = "Attach to a process and set a formula to go live.".into();

    { let mut n = Int32Node::new("health");      n.comment = "Current HP".into();           player.children.push(Box::new(n)); }
    { let mut n = Int32Node::new("max_health");  n.comment = "Max HP".into();               player.children.push(Box::new(n)); }
    { let mut n = Float32Node::new("mana");      n.comment = "Mana pool".into();            player.children.push(Box::new(n)); }
    { let mut n = VectorNode::new("position", 3, FloatWidth::F32);
      n.comment = "World position (Vec3 f32)".into();                                       player.children.push(Box::new(n)); }
    { let mut n = VectorNode::new("rotation", 4, FloatWidth::F32);
      n.comment = "Orientation quaternion (Vec4 f32)".into();                                player.children.push(Box::new(n)); }
    { let mut n = MatrixNode::new("view_matrix", 4, 4, FloatWidth::F32);
      n.comment = "View matrix — expand to edit cells".into();                               player.children.push(Box::new(n)); }
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
    use crate::views::node_edit::resolve_parent_vec_mut;
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

    // -----------------------------------------------------------------------
    // Value entry and address parsing
    // -----------------------------------------------------------------------

    /// Typing `0x10` into an Int32 field wrote **10** to the target: the old
    /// parser stripped the prefix and then parsed the remainder as decimal.
    /// A wrong value, written to a live process, with no error shown.
    #[test]
    fn a_hex_prefixed_value_is_written_as_hex() {
        use super::encode_scalar;
        assert_eq!(encode_scalar("Int32", "0x10").unwrap(), 16i32.to_le_bytes());
        assert_eq!(encode_scalar("Int32", "0X10").unwrap(), 16i32.to_le_bytes());
        assert_eq!(encode_scalar("UInt64", "0xFF").unwrap(), 255u64.to_le_bytes());
        // …and a bare decimal stays decimal.
        assert_eq!(encode_scalar("Int32", "10").unwrap(), 10i32.to_le_bytes());
        assert_eq!(encode_scalar("Int32", " 10 ").unwrap(), 10i32.to_le_bytes());
    }

    #[test]
    fn a_negative_hex_value_parses() {
        use super::encode_scalar;
        // Previously impossible: after stripping "0x" the '-' was no longer
        // leading, so the parse failed outright.
        assert_eq!(encode_scalar("Int32", "-0x10").unwrap(), (-16i32).to_le_bytes());
        assert_eq!(encode_scalar("Int32", "-16").unwrap(), (-16i32).to_le_bytes());
    }

    #[test]
    fn a_repeated_prefix_is_rejected_not_silently_accepted() {
        use super::encode_scalar;
        // `trim_start_matches` stripped every leading "0x", so `0x0x10` became
        // the decimal 10 rather than an error.
        assert!(encode_scalar("Int32", "0x0x10").is_err());
        assert!(encode_scalar("Int32", "banana").is_err());
    }

    #[test]
    fn hex_typed_fields_accept_the_prefix_as_well_as_bare_digits() {
        use super::encode_scalar;
        assert_eq!(encode_scalar("Hex32", "ff").unwrap(), 255u32.to_le_bytes());
        assert_eq!(encode_scalar("Hex32", "0xff").unwrap(), 255u32.to_le_bytes());
        assert_eq!(encode_scalar("Pointer", "7fff0000").unwrap(), 0x7fff_0000u64.to_le_bytes());
    }

    #[test]
    fn floats_and_bools_still_parse() {
        use super::encode_scalar;
        assert_eq!(encode_scalar("Float", "1.5").unwrap(), 1.5f32.to_le_bytes());
        assert_eq!(encode_scalar("Double", "-2.25").unwrap(), (-2.25f64).to_le_bytes());
        assert_eq!(encode_scalar("Bool", "true").unwrap(), vec![1u8]);
        assert_eq!(encode_scalar("Bool", "0").unwrap(), vec![0u8]);
        assert!(encode_scalar("VTable", "1").is_err());
    }

    /// Five parsers with three conventions lived in one application. The memory
    /// viewer and disassembler read bare digits as *decimal*, so `7fff0000` was
    /// rejected outright while `140000000` silently jumped to decimal
    /// 140,000,000 — hundreds of megabytes from the intended address.
    #[test]
    fn addresses_are_hex_everywhere() {
        use super::parse_address;
        assert_eq!(parse_address("7fff0000"), Ok(0x7fff_0000));
        assert_eq!(parse_address("0x7fff0000"), Ok(0x7fff_0000));
        assert_eq!(parse_address("0X7FFF0000"), Ok(0x7fff_0000));
        assert_eq!(parse_address("  7fff_0000  "), Ok(0x7fff_0000));
        // The case that used to land somewhere else entirely.
        assert_eq!(parse_address("140000000"), Ok(0x1_4000_0000));
        assert!(parse_address("").is_err());
        assert!(parse_address("nonsense").is_err());
    }

    // -----------------------------------------------------------------------
    // Target liveness
    // -----------------------------------------------------------------------

    /// The UI never noticed a dead target: it kept showing "Attached", rendered
    /// a zeroed buffer that looked like real data, and kept firing freeze writes
    /// at a pid that may since have been recycled.
    #[test]
    #[cfg(unix)]
    fn a_live_process_is_not_reported_as_exited() {
        let me = std::process::id() as libc::pid_t;
        assert!(!super::target_has_exited(me), "this process is plainly alive");
    }

    #[test]
    #[cfg(unix)]
    fn a_reaped_child_is_reported_as_exited() {
        // Spawn, wait for it (so it is reaped, not a zombie), then check.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = child.id() as libc::pid_t;
        child.wait().expect("wait");
        assert!(
            super::target_has_exited(pid),
            "a reaped pid must read as exited"
        );
    }

    // -----------------------------------------------------------------------
    // Vector / matrix rows
    // -----------------------------------------------------------------------

    /// A vector node's components must be carried on the snapshot so the table
    /// can lay out one editable cell per component.
    #[test]
    fn vector_snapshot_carries_its_components() {
        use nemclass_model::{FloatWidth, VectorNode};

        let mut buf = Vec::new();
        for v in [1.0f32, 2.0, 3.0] {
            buf.extend_from_slice(&v.to_ne_bytes());
        }

        let node = VectorNode::new("pos", 3, FloatWidth::F32);
        let (components, width) = read_float_components(&node, &buf, 0);
        assert_eq!(components, vec![1.0, 2.0, 3.0]);
        assert_eq!(width, Some(FloatWidth::F32));
    }

    /// A buffer too short for the whole node yields *no* components rather than
    /// a partial read — half a vector shown as if it were real data would be a
    /// lie about the target's memory.
    #[test]
    fn short_buffer_yields_no_components() {
        use nemclass_model::{FloatWidth, VectorNode};

        let node = VectorNode::new("pos", 3, FloatWidth::F32);
        let (components, width) = read_float_components(&node, &[0u8; 8], 0);
        assert!(components.is_empty());
        assert_eq!(width, Some(FloatWidth::F32));
    }

    /// Non-vector nodes carry nothing, so the table takes the ordinary
    /// single-value path for them.
    #[test]
    fn scalar_nodes_carry_no_components() {
        let node = Int32Node::new("health");
        let (components, width) = read_float_components(&node, &[0u8; 8], 0);
        assert!(components.is_empty());
        assert_eq!(width, None);
    }

    /// An expanded matrix contributes one extra view row per matrix row; a
    /// collapsed one contributes none.
    #[test]
    fn expanded_matrix_injects_one_row_per_matrix_row() {
        use nemclass_model::{FloatWidth, MatrixNode};

        let reg = NodeRegistry::new().with_builtins();
        let mut project = Project::new("P");
        let uuid = Uuid::new_v4();
        let mut cls = ClassNode::with_uuid(uuid, "C");
        cls.children.push(Box::new(MatrixNode::new("view", 3, 4, FloatWidth::F32)));
        project.add_class(cls);
        let _ = &reg;

        // 3x4 f32 = 48 bytes.
        let buf = vec![0u8; 48];
        let mut snapshots = Vec::new();
        let mut visited = HashSet::new();
        flatten_nodes(
            &project.get_class(&uuid).unwrap().children,
            0x1000,
            0,
            0,
            &buf,
            String::new(),
            uuid,
            &[],
            &mut snapshots,
            &project,
            &HashSet::new(),
            &HashSet::new(),
            &HashMap::new(),
            &mut visited,
            8,
        );

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].type_tag, "Matrix3x4");
        assert_eq!(snapshots[0].components.len(), 12);

        // Expanded (nothing in `collapsed`): 1 node row + 3 matrix rows.
        let collapsed = HashSet::new();
        let rows = build_augmented_rows(
            &snapshots,
            &collapsed,
            #[cfg(target_os = "linux")]
            &HashMap::new(),
        );
        assert_eq!(rows.len(), 4);
        assert!(matches!(rows[0], ViewRow::Snap(0)));
        for (i, row) in rows[1..].iter().enumerate() {
            match row {
                ViewRow::MatrixRow { snap_idx, row } => {
                    assert_eq!(*snap_idx, 0);
                    assert_eq!(*row, i);
                }
                _ => panic!("expected a MatrixRow at index {}", i + 1),
            }
        }

        // Collapsed: just the node row.
        let mut collapsed = HashSet::new();
        collapsed.insert(snapshots[0].id_path.clone());
        let rows = build_augmented_rows(
            &snapshots,
            &collapsed,
            #[cfg(target_os = "linux")]
            &HashMap::new(),
        );
        assert_eq!(rows.len(), 1);
    }

    /// "Delete N fields" must clamp to the end of the sibling list rather than
    /// panicking when N runs past it.
    #[test]
    fn delete_range_clamps_to_the_end_of_the_class() {
        let mut project = Project::new("P");
        let uuid = Uuid::new_v4();
        let mut cls = ClassNode::with_uuid(uuid, "C");
        for i in 0..3 {
            cls.children.push(Box::new(Int32Node::new(format!("f{i}"))));
        }
        project.add_class(cls);

        // Delete 1024 starting at index 1 → removes the last two only.
        let (vec, idx) = resolve_parent_vec_mut(&mut project, uuid, &[1]).unwrap();
        let end = idx.saturating_add(1024).min(vec.len());
        vec.drain(idx..end);

        let children = &project.get_class(&uuid).unwrap().children;
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].name(), "f0");
    }
}

// ---------------------------------------------------------------------------
// Class-view editing, against a real app instance
// ---------------------------------------------------------------------------

#[cfg(test)]
mod edit_tests {
    use super::*;
    use nemclass_model::node::builtins::{Float32Node, Int32Node};

    /// An app with one class of four `Int32` fields named a/b/c/d.
    fn app_with_four_fields() -> (NemclassApp, Uuid) {
        let mut app = NemclassApp::new();
        let mut project = Project::new("test");
        let mut class = ClassNode::new("Entity");
        for name in ["a", "b", "c", "d"] {
            class.children.push(Box::new(Int32Node::new(name)));
        }
        let uuid = class.uuid;
        project.add_class(class);
        app.replace_project(project, None);
        app.selected_class = Some(uuid);
        (app, uuid)
    }

    fn field_names(app: &NemclassApp, uuid: Uuid) -> Vec<String> {
        app.project
            .get_class(&uuid)
            .unwrap()
            .children
            .iter()
            .map(|n| n.name().to_string())
            .collect()
    }

    fn field_tags(app: &NemclassApp, uuid: Uuid) -> Vec<&'static str> {
        app.project
            .get_class(&uuid)
            .unwrap()
            .children
            .iter()
            .map(|n| n.type_tag())
            .collect()
    }

    fn select(app: &mut NemclassApp, uuid: Uuid, indices: &[usize]) {
        app.selection.clear();
        for &i in indices {
            app.selection.toggle((uuid, vec![i]));
        }
    }

    #[test]
    fn changing_the_type_of_a_multi_row_selection_changes_every_row() {
        let (mut app, uuid) = app_with_four_fields();
        select(&mut app, uuid, &[0, 2, 3]);
        app.apply_to_selection(|owner, path| NodeEditOp::ChangeType {
            owner,
            path,
            new_tag: "Float",
        });
        app.flush_pending_node_edits();
        assert_eq!(field_tags(&app, uuid), ["Float", "Int32", "Float", "Float"]);
        // Names survive a type change — the field is the same field.
        assert_eq!(field_names(&app, uuid), ["a", "b", "c", "d"]);
    }

    #[test]
    fn deleting_several_rows_removes_exactly_those_rows() {
        let (mut app, uuid) = app_with_four_fields();
        // Non-adjacent, and in an order that would go wrong front-to-back:
        // removing index 0 first shifts 2 to 1 and 3 to 2.
        select(&mut app, uuid, &[0, 2]);
        app.delete_selection();
        app.flush_pending_node_edits();
        assert_eq!(field_names(&app, uuid), ["b", "d"]);
    }

    #[test]
    fn a_multi_row_edit_undoes_as_one_step() {
        let (mut app, uuid) = app_with_four_fields();
        select(&mut app, uuid, &[0, 1, 2, 3]);
        app.apply_to_selection(|owner, path| NodeEditOp::ChangeType {
            owner,
            path,
            new_tag: "Float",
        });
        app.flush_pending_node_edits();
        assert_eq!(field_tags(&app, uuid), ["Float"; 4]);

        app.undo();
        assert_eq!(
            field_tags(&app, uuid),
            ["Int32"; 4],
            "one undo restores all four, not one"
        );
        app.redo();
        assert_eq!(field_tags(&app, uuid), ["Float"; 4]);
    }

    #[test]
    fn deleting_a_whole_class_body_is_undoable() {
        let (mut app, uuid) = app_with_four_fields();
        app.apply_node_edit(NodeEditOp::DeleteRange {
            owner: uuid,
            path: vec![0],
            count: 1024,
        });
        assert!(field_names(&app, uuid).is_empty());
        app.undo();
        assert_eq!(field_names(&app, uuid), ["a", "b", "c", "d"]);
    }

    #[test]
    fn copy_and_paste_duplicates_the_fields_after_the_anchor() {
        let (mut app, uuid) = app_with_four_fields();
        select(&mut app, uuid, &[0, 1]);
        app.copy_selection();
        // Paste lands after the anchor, which `toggle` left on the last click.
        select(&mut app, uuid, &[3]);
        app.paste_clipboard();
        app.flush_pending_node_edits();
        assert_eq!(field_names(&app, uuid), ["a", "b", "c", "d", "a", "b"]);
    }

    #[test]
    fn cut_removes_the_originals_and_keeps_them_for_pasting() {
        let (mut app, uuid) = app_with_four_fields();
        select(&mut app, uuid, &[1]);
        app.cut_selection();
        app.flush_pending_node_edits();
        assert_eq!(field_names(&app, uuid), ["a", "c", "d"]);
        select(&mut app, uuid, &[2]);
        app.paste_clipboard();
        app.flush_pending_node_edits();
        assert_eq!(field_names(&app, uuid), ["a", "c", "d", "b"]);
    }

    #[test]
    fn pasting_with_nothing_selected_appends_to_the_end_of_the_class() {
        let (mut app, uuid) = app_with_four_fields();
        select(&mut app, uuid, &[0]);
        app.copy_selection();
        app.selection.clear();
        app.paste_clipboard();
        app.flush_pending_node_edits();
        assert_eq!(field_names(&app, uuid), ["a", "b", "c", "d", "a"]);
    }

    #[test]
    fn extracting_a_contiguous_run_leaves_one_class_instance_behind() {
        let (mut app, uuid) = app_with_four_fields();
        select(&mut app, uuid, &[1, 2]);
        app.apply_node_edit(NodeEditOp::ExtractClass {
            owner: uuid,
            paths: vec![vec![1], vec![2]],
            name: "Inner".to_string(),
        });

        assert_eq!(field_names(&app, uuid), ["a", "inner", "d"]);
        assert_eq!(field_tags(&app, uuid), ["Int32", "ClassInstance", "Int32"]);

        let inner = app
            .project
            .classes_in_order()
            .find(|c| c.name == "Inner")
            .expect("the new class exists");
        assert_eq!(
            inner.children.iter().map(|n| n.name()).collect::<Vec<_>>(),
            ["b", "c"]
        );
    }

    #[test]
    fn extracting_a_gapped_selection_is_refused_rather_than_silently_reordering() {
        let (mut app, uuid) = app_with_four_fields();
        app.apply_node_edit(NodeEditOp::ExtractClass {
            owner: uuid,
            paths: vec![vec![0], vec![2]],
            name: "Inner".to_string(),
        });
        assert_eq!(
            field_names(&app, uuid),
            ["a", "b", "c", "d"],
            "the class is untouched"
        );
        assert!(
            app.last_error.as_deref().is_some_and(|e| e.contains("contiguous")),
            "the refusal is explained: {:?}",
            app.last_error
        );
    }

    #[test]
    fn hiding_a_field_is_a_model_change_that_survives_a_save() {
        let (mut app, uuid) = app_with_four_fields();
        select(&mut app, uuid, &[1]);
        app.set_selection_hidden(true);
        app.flush_pending_node_edits();
        assert!(app.project.get_class(&uuid).unwrap().children[1].hidden());

        let toml = app.project.to_toml(&app.node_registry).unwrap();
        let reloaded = Project::from_toml(&toml, &app.node_registry).unwrap();
        assert!(reloaded.get_class(&uuid).unwrap().children[1].hidden());
        assert!(!reloaded.get_class(&uuid).unwrap().children[0].hidden());
    }

    #[test]
    fn an_edit_marks_the_project_dirty_and_a_save_clears_it() {
        let (mut app, uuid) = app_with_four_fields();
        assert!(!app.project_dirty, "a freshly loaded project is clean");
        app.apply_node_edit(NodeEditOp::SetName {
            owner: uuid,
            path: vec![0],
            name: "renamed".to_string(),
        });
        assert!(app.project_dirty);

        let dir = std::env::temp_dir().join(format!("nemclass-dirty-{}", uuid.simple()));
        std::fs::create_dir_all(&dir).unwrap();
        app.project_dir = Some(dir.clone());
        app.exec_save().unwrap();
        assert!(!app.project_dirty, "saving clears the marker");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_type_change_carries_the_projects_pointer_width_onto_the_new_node() {
        let (mut app, uuid) = app_with_four_fields();
        app.project.set_pointer_size(4).unwrap();
        select(&mut app, uuid, &[0]);
        app.apply_to_selection(|owner, path| NodeEditOp::ChangeType {
            owner,
            path,
            new_tag: "Pointer",
        });
        app.flush_pending_node_edits();
        // Built by the registry, which has no project — without the explicit
        // hand-off the node would default to 8 and shift every later field.
        assert_eq!(app.project.get_class(&uuid).unwrap().children[0].memory_size(), 4);
    }

    #[test]
    fn pasted_nodes_also_take_the_projects_pointer_width() {
        let mut app = NemclassApp::new();
        let mut project = Project::new("test");
        let mut class = ClassNode::new("Entity");
        class.children.push(Box::new(Float32Node::new("f")));
        let uuid = class.uuid;
        project.add_class(class);
        project.set_pointer_size(4).unwrap();
        app.replace_project(project, None);
        app.selected_class = Some(uuid);

        app.apply_node_edit(NodeEditOp::ChangeType {
            owner: uuid,
            path: vec![0],
            new_tag: "Pointer",
        });
        select(&mut app, uuid, &[0]);
        app.copy_selection();
        app.paste_clipboard();
        app.flush_pending_node_edits();

        let sizes: Vec<usize> = app
            .project
            .get_class(&uuid)
            .unwrap()
            .children
            .iter()
            .map(|n| n.memory_size())
            .collect();
        assert_eq!(sizes, [4, 4]);
    }
}
