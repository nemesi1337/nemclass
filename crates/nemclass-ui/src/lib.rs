//! nemclass-ui: egui/eframe views and widgets.
//!
//! Implements the M1 vertical slice:
//! - `NemclassApp` — `eframe::App` impl (the top-level app struct).
//! - Left panel: backend selector, process list, attach, class list.
//! - Central panel: `egui_extras::TableBuilder` memory view (virtualized rows).
//! - Address bar: resolved via `resolve_formula` + `ProcessReader` wrapper.
//! - Live reads throttled via `ctx.request_repaint_after`; graceful error states.
//! - Value editing writes back via `Process::write`.
//! - EventBus integration: publishes `OnAttach`/`OnDetach`.

mod process_reader;
pub mod project_io;
mod views;

pub use views::NemclassApp;
