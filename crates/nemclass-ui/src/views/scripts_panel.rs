//! `ScriptsPanel` — the "Scripts" central tab.
//!
//! Renders the scripting surface: engine status, the list of script files in the
//! project's `src/` directory (with per-file **Reload** and a **Load all**
//! button), the fixed set of host functions scripts can call, and a scrollable,
//! colour-coded view of the shared [`ScriptLog`].
//!
//! The panel is deliberately **stateless about the engine**: it owns no
//! `ScriptHost` and never borrows it.  It reports the user's intent by returning
//! a [`ScriptsPanelAction`], which `mod.rs` applies after the draw closure (the
//! same collect-action / apply-after pattern used elsewhere in this crate). This
//! keeps the panel compiling identically with or without the `scripting` feature.

use std::path::{Path, PathBuf};

use eframe::egui;

use super::script_log::{LogKind, ScriptLog};

/// A user action collected during a `ScriptsPanel::show` draw, applied by the
/// caller after the closure releases its borrows.
pub enum ScriptsPanelAction {
    /// No action this frame.
    None,
    /// Load every script under the project's `src/` directory.
    LoadAll,
    /// Reload a single script file.
    Reload(PathBuf),
    /// Clear the shared log buffer.
    Clear,
}

/// Transient UI state for the Scripts tab.
#[derive(Default)]
pub struct ScriptsPanel {
    /// Case-insensitive substring filter for the script-file list.
    filter: String,
}

impl ScriptsPanel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Draws the panel and returns the collected action.
    ///
    /// - `scripts_dir` — the project's `src/` directory, or `None` when no
    ///   project is open.
    /// - `engine_active` — whether a live JS engine is running.
    /// - `engine_status` — a human-readable status line (spawn error, "disabled",
    ///   etc.) shown under the heading.
    /// - `host_fn_names` — the host functions scripts may call.
    /// - `log` — the shared script log buffer.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        scripts_dir: Option<&Path>,
        engine_active: bool,
        engine_status: &str,
        host_fn_names: &[&str],
        log: &ScriptLog,
    ) -> ScriptsPanelAction {
        let mut action = ScriptsPanelAction::None;

        ui.horizontal(|ui| {
            ui.heading("Scripts");
            ui.separator();
            if engine_active {
                ui.colored_label(egui::Color32::GREEN, "JS engine: active");
            } else {
                ui.colored_label(egui::Color32::GRAY, "JS engine: disabled");
            }
        });
        if !engine_status.is_empty() {
            ui.label(engine_status);
        }

        ui.separator();

        // -- Script files ----------------------------------------------------
        ui.horizontal(|ui| {
            ui.strong("Script files");
            if ui
                .add_enabled(scripts_dir.is_some(), egui::Button::new("Load all"))
                .on_disabled_hover_text("Open or save a project first")
                .clicked()
            {
                action = ScriptsPanelAction::LoadAll;
            }
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(120.0)
                    .hint_text("name…"),
            );
        });

        match scripts_dir {
            None => {
                ui.weak("No project open — scripts live in the project's src/ folder.");
            }
            Some(dir) => {
                let mut files = list_scripts(dir);
                files.sort();
                let filter = self.filter.to_ascii_lowercase();
                let mut any = false;
                egui::ScrollArea::vertical()
                    .max_height(140.0)
                    .id_salt("script_files")
                    .show(ui, |ui| {
                        for path in &files {
                            let name = path
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            if !filter.is_empty() && !name.to_ascii_lowercase().contains(&filter) {
                                continue;
                            }
                            any = true;
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(engine_active, egui::Button::new("Reload").small())
                                    .on_disabled_hover_text("No live engine")
                                    .clicked()
                                {
                                    action = ScriptsPanelAction::Reload(path.clone());
                                }
                                ui.monospace(&name);
                            });
                        }
                    });
                if !any {
                    ui.weak(format!("No .js/.ts files in {}", dir.display()));
                }
            }
        }

        ui.separator();

        // -- Host functions --------------------------------------------------
        ui.collapsing("Host functions", |ui| {
            for name in host_fn_names {
                ui.monospace(*name);
            }
        });

        ui.separator();

        // -- Log -------------------------------------------------------------
        ui.horizontal(|ui| {
            ui.strong("Log");
            if ui.button("Clear").clicked() {
                action = ScriptsPanelAction::Clear;
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("script_log")
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                let buf = log.borrow();
                if buf.is_empty() {
                    ui.weak("(no output)");
                }
                for line in buf.iter() {
                    let color = match line.kind {
                        LogKind::Info => egui::Color32::LIGHT_GRAY,
                        LogKind::Warn => egui::Color32::YELLOW,
                        LogKind::Error => egui::Color32::LIGHT_RED,
                        LogKind::Lifecycle => egui::Color32::LIGHT_BLUE,
                    };
                    ui.colored_label(color, &line.text);
                }
            });

        action
    }
}

/// Returns the `.js` / `.ts` files directly under `dir` (non-recursive).
fn list_scripts(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
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
        if is_script {
            out.push(path);
        }
    }
    out
}
