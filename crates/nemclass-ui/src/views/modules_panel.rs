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
//!
//! ## The selection as an app-wide scope
//!
//! The pointer scanner and the spider also anchor their results in a module
//! image, and both read this selection through [`ModulesPanel::scope`] to decide
//! which images are in play. Those panels source their module lists separately
//! from this one (a TTL'd cache, a fresh enumeration), and in a different order,
//! so the selection is mirrored into [`ModulesPanel::selected_names`] and
//! matched **by name** rather than by index. Two mappings sharing a basename
//! would therefore both match — the same trade-off the scanner's own picker
//! already makes.
//!
//! An empty selection means *no filter*, not *nothing*: someone who never opens
//! this tab gets the old unscoped behaviour.

use std::collections::BTreeSet;

use eframe::egui;

use nemclass_core::ModuleInfoWithName;

pub struct ModulesPanel {
    filter: String,
    /// Selection state, index-parallel to the app's base-sorted module list.
    selected: Vec<bool>,
    /// Names of the ticked modules, refreshed from `selected` on every draw.
    ///
    /// This is what other panels read: it survives the tab being hidden (a
    /// hidden dock tab is not drawn, so `show` stops running) and does not
    /// require the reader to reproduce this panel's module ordering.
    selected_names: BTreeSet<String>,
}

impl ModulesPanel {
    pub fn new() -> Self {
        Self {
            filter: String::new(),
            selected: Vec::new(),
            selected_names: BTreeSet::new(),
        }
    }

    /// Reset selection to "nothing selected" for a freshly attached process.
    pub fn on_attach(&mut self, modules: &[ModuleInfoWithName]) {
        self.selected = vec![false; modules.len()];
        self.selected_names.clear();
    }

    pub fn on_detach(&mut self) {
        self.selected.clear();
        self.selected_names.clear();
        self.filter.clear();
    }

    /// Narrow `modules` to the ticked ones.
    ///
    /// An empty selection is *no filter* rather than *nothing in scope*, so this
    /// returns every module — a user who never opens this tab keeps the
    /// unscoped behaviour. A non-empty selection that matches nothing in
    /// `modules` does return empty: the user asked for specific images and none
    /// of them are here, which is not the same as asking for everything.
    pub fn scope(&self, modules: &[ModuleInfoWithName]) -> Vec<ModuleInfoWithName> {
        if self.selected_names.is_empty() {
            return modules.to_vec();
        }
        modules
            .iter()
            .filter(|m| self.selected_names.contains(&m.name))
            .cloned()
            .collect()
    }

    /// One-line description of the active scope for the panels that honour it,
    /// given the already-narrowed list from [`Self::scope`].
    ///
    /// `None` when no selection is active — a scoped scan that says nothing
    /// about its scope is a trap, but an unscoped one needs no banner.
    pub fn scope_hint(&self, scoped: &[ModuleInfoWithName]) -> Option<String> {
        if self.selected_names.is_empty() {
            return None;
        }
        if scoped.is_empty() {
            return Some(format!(
                "Modules tab: {} module(s) selected, none loaded in this process — nothing in scope.",
                self.selected_names.len()
            ));
        }
        Some(match scoped {
            [only] => format!("Scoped to {} (Modules tab)", only.name),
            _ => format!("Scoped to {} modules (Modules tab)", scoped.len()),
        })
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

        // The selection also scopes the pointer scanner and the spider, so say
        // so here — otherwise ticking a module silently changes what an
        // unrelated tab scans.
        ui.weak("Selected modules drive the disassembler, and scope the pointer scan and spider.");

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

        // Mirror the tick state into the name set every draw, not just when it
        // changed: the module list can be replaced under us (a `.so` loaded or
        // unloaded between frames) without any checkbox being touched.
        self.selected_names = modules
            .iter()
            .zip(&self.selected)
            .filter(|(_, s)| **s)
            .map(|(m, _)| m.name.clone())
            .collect();

        changed.then(|| {
            self.selected
                .iter()
                .enumerate()
                .filter_map(|(i, &s)| s.then_some(i))
                .collect()
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests — the scope logic is pure and needs no egui context
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn module(name: &str, base: usize) -> ModuleInfoWithName {
        ModuleInfoWithName { base, size: 0x1000, name: name.to_owned() }
    }

    fn panel_selecting(names: &[&str]) -> ModulesPanel {
        let mut p = ModulesPanel::new();
        p.selected_names = names.iter().map(|s| (*s).to_owned()).collect();
        p
    }

    /// The common case: a user who never opens the Modules tab must keep the
    /// old unscoped behaviour rather than getting an empty scan.
    #[test]
    fn empty_selection_is_no_filter() {
        let all = vec![module("game.so", 0x1000), module("libc.so.6", 0x2000)];
        let panel = ModulesPanel::new();

        let scoped = panel.scope(&all);
        assert_eq!(scoped.len(), 2);
        assert_eq!(panel.scope_hint(&scoped), None, "unscoped runs need no banner");
    }

    /// Matching is by name, so a reader whose module list is in a different
    /// order (or from a different enumeration) still resolves the selection.
    #[test]
    fn selection_narrows_by_name_regardless_of_order() {
        let panel = panel_selecting(&["game.so"]);
        // Deliberately a different order and base set from the panel's own list.
        let readers_list = vec![
            module("libc.so.6", 0x9000),
            module("game.so", 0x1000),
            module("ld.so", 0x3000),
        ];

        let scoped = panel.scope(&readers_list);
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].name, "game.so");
        assert_eq!(
            panel.scope_hint(&scoped).as_deref(),
            Some("Scoped to game.so (Modules tab)")
        );
    }

    /// Several ticked modules collapse to a count rather than a long name list.
    #[test]
    fn multiple_selected_modules_summarise_as_a_count() {
        let panel = panel_selecting(&["game.so", "libc.so.6"]);
        let all = vec![
            module("game.so", 0x1000),
            module("libc.so.6", 0x2000),
            module("ld.so", 0x3000),
        ];

        let scoped = panel.scope(&all);
        assert_eq!(scoped.len(), 2);
        assert_eq!(
            panel.scope_hint(&scoped).as_deref(),
            Some("Scoped to 2 modules (Modules tab)")
        );
    }

    /// A selection that matches nothing must NOT silently widen back to "all" —
    /// the user named specific images and none are loaded, which is a different
    /// situation from asking for everything. The hint has to say so, since an
    /// empty scope otherwise looks like a broken scan.
    #[test]
    fn selection_matching_nothing_scopes_to_nothing_and_warns() {
        let panel = panel_selecting(&["game.so"]);
        let other_process = vec![module("libc.so.6", 0x2000)];

        let scoped = panel.scope(&other_process);
        assert!(scoped.is_empty());
        let hint = panel.scope_hint(&scoped).expect("an empty scope must be explained");
        assert!(hint.contains("none loaded in this process"), "{hint}");
    }

    /// Detaching drops the scope, so the next process starts unfiltered rather
    /// than inheriting names from the last one.
    #[test]
    fn detach_clears_the_scope() {
        let mut panel = panel_selecting(&["game.so"]);
        panel.on_detach();

        let all = vec![module("libc.so.6", 0x2000)];
        assert_eq!(panel.scope(&all).len(), 1);
        assert_eq!(panel.scope_hint(&all), None);
    }
}
