//! Dockable-panel layout for the central area, built on `egui_dock`.
//!
//! The top menu bar, address bar, and the left process/class panel stay outside
//! the dock as fixed chrome; everything the user actually *works in* — the class
//! view, raw hex viewer, disassembler, scanner, debugger, and scripts console —
//! becomes a dock tab the user can drag, split, float, and tab together. The
//! resulting [`DockState`] is serialized into the settings file so the layout
//! survives a restart.
//!
//! ## Borrow model
//! [`DockViewer`] holds a single `&mut NemclassApp` and dispatches each tab to
//! the panel `show_*` method that already lives on [`NemclassApp`]. Because
//! `views::dock` is a child module of `views`, it can reach those private
//! methods. The one wrinkle — `DockArea::new(&mut dock_state)` and the viewer
//! both wanting `&mut self` — is resolved in [`super::NemclassApp::show_central_panel`]
//! by `Option::take`-ing the dock state into a local before building the viewer.

use eframe::egui::{self, Ui, WidgetText};
use egui_dock::{DockState, NodeIndex, TabViewer};

use super::NemclassApp;

/// One dockable panel. `Copy`/`Eq` + serde so it round-trips inside a
/// [`DockState`] persisted to `settings.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TabKind {
    /// The ReClass class-structure view (formerly the "Memory View" tab).
    ClassView,
    /// Navigator: strings / functions / calls discovered by a dissect.
    Navigator,
    /// Modules: checkbox list picking which modules the disassembler shows.
    Modules,
    /// Raw hex dump viewer.
    Memory,
    /// Disassembler.
    Disassembly,
    /// Cheat-Engine-style scanner.
    Scanner,
    /// Kernel-module debugger.
    Debugger,
    /// JS scripting console.
    Scripts,
    /// Pointer-chain scanner (ASLR-stable path finder).
    PointerScan,
    /// Structure spider: find a value *inside* a known object.
    Spider,
}

impl TabKind {
    /// Human-readable tab title.
    pub fn title(self) -> &'static str {
        match self {
            TabKind::ClassView => "Classes",
            TabKind::Navigator => "Navigator",
            TabKind::Modules => "Modules",
            TabKind::Memory => "Memory",
            TabKind::Disassembly => "Disassembly",
            TabKind::Scanner => "Scanner",
            TabKind::Debugger => "Debugger",
            TabKind::Scripts => "Scripts",
            TabKind::PointerScan => "Pointer scan",
            TabKind::Spider => "Spider",
        }
    }

    /// Every tab kind, for building the "View" menu that re-opens closed panels.
    pub const ALL: [TabKind; 10] = [
        TabKind::ClassView,
        TabKind::Navigator,
        TabKind::Modules,
        TabKind::Memory,
        TabKind::Disassembly,
        TabKind::Scanner,
        TabKind::Debugger,
        TabKind::Scripts,
        TabKind::PointerScan,
        TabKind::Spider,
    ];
}

/// Builds the default dock layout: the class view fills the centre, the hex
/// viewer + disassembler are tabbed together on the right, and the scanner /
/// debugger / scripts share a panel below the right split. Users rearrange it
/// freely; this is only the first-run / "Reset layout" arrangement.
pub fn default_layout() -> DockState<TabKind> {
    let mut state = DockState::new(vec![TabKind::ClassView, TabKind::Navigator, TabKind::Modules]);
    let surface = state.main_surface_mut();

    // Right ~55%: the Cheat-Engine-style "Memory View" — hex dump on top,
    // disassembler stacked directly below it (a vertical split, not tabs).
    let [_left, right_top] = surface.split_right(NodeIndex::root(), 0.45, vec![TabKind::Memory]);
    let [_mem, disasm] = surface.split_below(right_top, 0.5, vec![TabKind::Disassembly]);

    // Below the disassembler: scanner + pointer scan + debugger + scripts share a
    // tab group. The saved address list has no tab of its own — it docks beneath
    // the scan results inside the Scanner tab, as in Cheat Engine.
    surface.split_below(
        disasm,
        0.6,
        vec![
            TabKind::Scanner,
            TabKind::PointerScan,
            TabKind::Spider,
            TabKind::Debugger,
            TabKind::Scripts,
        ],
    );

    state
}

/// Renders each dock tab by dispatching to the owning [`NemclassApp`]'s existing
/// per-panel `show_*` method.
pub struct DockViewer<'a> {
    pub app: &'a mut NemclassApp,
}

impl TabViewer for DockViewer<'_> {
    type Tab = TabKind;

    fn title(&mut self, tab: &mut TabKind) -> WidgetText {
        tab.title().into()
    }

    fn ui(&mut self, ui: &mut Ui, tab: &mut TabKind) {
        match tab {
            TabKind::ClassView => self.app.show_class_view(ui),
            TabKind::Navigator => self.app.show_navigator_tab(ui),
            TabKind::Modules => self.app.show_modules_tab(ui),
            TabKind::Memory => self.app.show_memory_viewer(ui),
            TabKind::Disassembly => self.app.show_disassembly_tab(ui),
            TabKind::Scanner => self.app.show_scanner_tab(ui),
            TabKind::Debugger => self.app.show_debugger_tab(ui),
            TabKind::Scripts => self.app.show_scripts_tab(ui),
            TabKind::PointerScan => self.app.show_pointer_scan_tab(ui),
            TabKind::Spider => self.app.show_spider_tab(ui),
        }
    }

    /// Stable per-kind id (one instance of each kind, so the kind itself is unique).
    fn id(&mut self, tab: &mut TabKind) -> egui::Id {
        egui::Id::new(("nemclass_dock_tab", *tab))
    }
}
