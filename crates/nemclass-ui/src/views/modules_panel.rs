//! Modules panel — a checkbox list of the attached process's loaded modules.
//!
//! Ticking modules here drives what the disassembler shows: the selected modules'
//! executable regions are unioned into a single concatenated linear disassembly
//! (with a Module column disambiguating each instruction). A **Select all** /
//! **Clear** pair and a live name filter make picking from a large module list
//! (libc + dozens of `.so`s, or a Wine game's DLLs) manageable.
//!
//! The panel owns the selection (`selected`, parallel to the app's base-sorted
//! module list) and returns the new selected-index set whenever it changes; the
//! app forwards that to [`super::DisassemblyPanel::set_selected_modules`].

use eframe::egui;

use nemclass_core::ModuleInfoWithName;

pub struct ModulesPanel {
    filter: String,
    /// Selection state, index-parallel to the app's base-sorted module list.
    selected: Vec<bool>,
}

impl ModulesPanel {
    pub fn new() -> Self {
        Self {
            filter: String::new(),
            selected: Vec::new(),
        }
    }

    /// Reset selection to "nothing selected" for a freshly attached process.
    pub fn on_attach(&mut self, modules: &[ModuleInfoWithName]) {
        self.selected = vec![false; modules.len()];
    }

    pub fn on_detach(&mut self) {
        self.selected.clear();
        self.filter.clear();
    }

    /// Draw the panel. Returns `Some(selected_indices)` (ascending) when the
    /// selection changed this frame, else `None`.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        modules: &[ModuleInfoWithName],
    ) -> Option<Vec<usize>> {
        // Keep the selection vector in step with the module list (first draw after
        // attach, or the list changed under us).
        if self.selected.len() != modules.len() {
            self.selected.resize(modules.len(), false);
        }

        if modules.is_empty() {
            ui.weak("Attach to a process to list its modules.");
            return None;
        }

        let mut changed = false;
        let filter = self.filter.to_ascii_lowercase();
        let is_visible = |m: &ModuleInfoWithName| {
            filter.is_empty() || m.name.to_ascii_lowercase().contains(&filter)
        };

        // ── header: select all / clear / count ────────────────────────────
        ui.horizontal(|ui| {
            // "Select all" acts on the currently-visible (filtered) modules, so it
            // stays useful after narrowing the list.
            let visible: Vec<usize> = (0..modules.len())
                .filter(|&i| is_visible(&modules[i]))
                .collect();
            let all_visible_selected =
                !visible.is_empty() && visible.iter().all(|&i| self.selected[i]);
            let mut check = all_visible_selected;
            if ui.checkbox(&mut check, "Select all").changed() {
                for &i in &visible {
                    self.selected[i] = check;
                }
                changed = true;
            }
            if ui.button("Clear").clicked() {
                for s in self.selected.iter_mut() {
                    *s = false;
                }
                changed = true;
            }
            let n = self.selected.iter().filter(|s| **s).count();
            ui.separator();
            ui.weak(format!("{n} selected / {} modules", modules.len()));
        });

        // ── name filter ───────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("module name…")
                    .desired_width(220.0),
            );
        });

        ui.separator();

        // ── module list (checkbox per module) ─────────────────────────────
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (i, m) in modules.iter().enumerate() {
                    if !is_visible(m) {
                        continue;
                    }
                    let label = format!("{}  {:#x}  ({} KiB)", m.name, m.base, m.size / 1024);
                    if ui.checkbox(&mut self.selected[i], label).changed() {
                        changed = true;
                    }
                }
            });

        changed.then(|| {
            self.selected
                .iter()
                .enumerate()
                .filter_map(|(i, &s)| s.then_some(i))
                .collect()
        })
    }
}
