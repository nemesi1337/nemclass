//! Navigator side panel — an IDA/CE-style browsable index of everything a
//! "Dissect" scan discovered in a module: its **Strings**, **Functions** (call
//! targets), and **Calls** (call sites → targets). Click any row to jump to it
//! in the disassembler (or, for a string, the hex viewer).
//!
//! The lists are cached and only rebuilt when the underlying dissect changes
//! (tracked by an epoch), so browsing a module with thousands of entries stays
//! cheap. Rows are virtualized and filtered by a live search box.

use eframe::egui;

#[cfg(target_os = "linux")]
use egui_extras::{Column, TableBuilder};
#[cfg(target_os = "linux")]
use nemclass_core::{DissectResult, Process};

/// Which index the panel is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NavView {
    Strings,
    Functions,
    Calls,
}

/// What the user asked to do by clicking a row / button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavAction {
    /// Jump the disassembler to this address.
    GotoDisasm(usize),
    /// Jump the hex viewer to this address (used for strings).
    GotoMemory(usize),
    /// Run a dissect over the disassembler's currently-selected module.
    RunDissect,
}

pub struct NavigatorPanel {
    view: NavView,
    filter: String,
    /// The dissect epoch the cached lists were built from.
    built_for: Option<u64>,
    /// `(address, preview, ref_count)` per discovered string, address-sorted.
    #[cfg(target_os = "linux")]
    strings: Vec<(u64, String, usize)>,
    /// `(address, caller_count)` per call target (function), address-sorted.
    #[cfg(target_os = "linux")]
    functions: Vec<(u64, usize)>,
    /// `(call_site, target)` per call instruction, site-sorted.
    #[cfg(target_os = "linux")]
    calls: Vec<(u64, u64)>,
}

impl NavigatorPanel {
    pub fn new() -> Self {
        Self {
            view: NavView::Functions,
            filter: String::new(),
            built_for: None,
            #[cfg(target_os = "linux")]
            strings: Vec::new(),
            #[cfg(target_os = "linux")]
            functions: Vec::new(),
            #[cfg(target_os = "linux")]
            calls: Vec::new(),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn show(&mut self, ui: &mut egui::Ui) -> Option<NavAction> {
        ui.centered_and_justified(|ui| {
            ui.label("The Navigator is Linux-only for now.");
        });
        None
    }

    /// Draw the panel. `dissect` is `(epoch, result)` from the disassembler (or
    /// `None` if nothing has been dissected yet). Returns a navigation request.
    #[cfg(target_os = "linux")]
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        dissect: Option<(u64, &DissectResult)>,
        process: Option<&Process>,
    ) -> Option<NavAction> {
        // Rebuild cached lists when the dissect changes.
        let epoch = dissect.map(|(e, _)| e);
        if self.built_for != epoch {
            self.rebuild(dissect.map(|(_, d)| d));
            self.built_for = epoch;
        }

        let mut action = None;

        // ── header: view selector + scan + filter ─────────────────────────
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.view, NavView::Functions, "Functions");
            ui.selectable_value(&mut self.view, NavView::Strings, "Strings");
            ui.selectable_value(&mut self.view, NavView::Calls, "Calls");
        });
        ui.horizontal(|ui| {
            if ui
                .button("Scan")
                .on_hover_text("Dissect the module selected in the Disassembly panel")
                .clicked()
            {
                action = Some(NavAction::RunDissect);
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(160.0)
                    .hint_text("filter…"),
            );
            let count = match self.view {
                NavView::Strings => self.strings.len(),
                NavView::Functions => self.functions.len(),
                NavView::Calls => self.calls.len(),
            };
            ui.weak(format!("{count}"));
        });
        ui.separator();

        if dissect.is_none() {
            ui.label("No analysis yet.");
            ui.label("Pick a module in the Disassembly panel and press Dissect (or Scan above).");
            return action;
        }

        let inner = match self.view {
            NavView::Strings => self.show_strings(ui, process),
            NavView::Functions => self.show_functions(ui, process),
            NavView::Calls => self.show_calls(ui, process),
        };
        action.or(inner)
    }

    #[cfg(target_os = "linux")]
    fn rebuild(&mut self, dissect: Option<&DissectResult>) {
        self.strings.clear();
        self.functions.clear();
        self.calls.clear();
        let Some(d) = dissect else {
            return;
        };

        for (&addr, refs) in &d.strings {
            let preview = d.string_previews.get(&addr).cloned().unwrap_or_default();
            self.strings.push((addr, preview, refs.len()));
        }
        self.strings.sort_by_key(|(a, _, _)| *a);

        for (&target, callers) in &d.calls {
            self.functions.push((target, callers.len()));
            for &site in callers {
                self.calls.push((site, target));
            }
        }
        self.functions.sort_by_key(|(a, _)| *a);
        self.calls.sort_by_key(|(site, _)| *site);
    }

    /// Case-insensitive filter match on a hex address and an optional label.
    #[cfg(target_os = "linux")]
    fn matches(&self, addr: u64, label: Option<&str>) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        let f = self.filter.to_ascii_lowercase();
        if format!("{addr:x}").contains(&f) {
            return true;
        }
        label.is_some_and(|l| l.to_ascii_lowercase().contains(&f))
    }

    #[cfg(target_os = "linux")]
    fn show_strings(&self, ui: &mut egui::Ui, _process: Option<&Process>) -> Option<NavAction> {
        let rows: Vec<usize> = (0..self.strings.len())
            .filter(|&i| {
                let (a, p, _) = &self.strings[i];
                self.matches(*a, Some(p))
            })
            .collect();

        let mut action = None;
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
        TableBuilder::new(ui)
            .id_salt("nav_strings")
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::initial(150.0).at_least(110.0)) // Address
            .column(Column::remainder().at_least(120.0)) // String
            .column(Column::initial(50.0).at_least(36.0)) // refs
            .header(row_h, |mut h| {
                h.col(|ui| {
                    ui.strong("Address");
                });
                h.col(|ui| {
                    ui.strong("String");
                });
                h.col(|ui| {
                    ui.strong("Refs");
                });
            })
            .body(|body| {
                body.rows(row_h, rows.len(), |mut row| {
                    let Some(&i) = rows.get(row.index()) else {
                        return;
                    };
                    let (addr, preview, refs) = &self.strings[i];
                    row.col(|ui| {
                        ui.monospace(format!("{addr:#x}"));
                    });
                    row.col(|ui| {
                        ui.label(preview);
                    });
                    row.col(|ui| {
                        ui.weak(refs.to_string());
                    });
                    if row.response().clicked() {
                        action = Some(NavAction::GotoMemory(*addr as usize));
                    }
                });
            });
        action
    }

    #[cfg(target_os = "linux")]
    fn show_functions(&self, ui: &mut egui::Ui, process: Option<&Process>) -> Option<NavAction> {
        let mut action = None;
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;

        // Resolve symbols for the filtered set (visible rows resolve lazily via
        // the per-module cache, so this stays cheap even for large modules).
        let rows: Vec<usize> = (0..self.functions.len())
            .filter(|&i| self.matches(self.functions[i].0, None))
            .collect();

        TableBuilder::new(ui)
            .id_salt("nav_functions")
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::initial(150.0).at_least(110.0)) // Address
            .column(Column::remainder().at_least(120.0)) // Symbol
            .column(Column::initial(60.0).at_least(40.0)) // callers
            .header(row_h, |mut h| {
                h.col(|ui| {
                    ui.strong("Address");
                });
                h.col(|ui| {
                    ui.strong("Function");
                });
                h.col(|ui| {
                    ui.strong("Callers");
                });
            })
            .body(|body| {
                body.rows(row_h, rows.len(), |mut row| {
                    let Some(&i) = rows.get(row.index()) else {
                        return;
                    };
                    let (addr, callers) = self.functions[i];
                    let sym = process.and_then(|p| p.resolve_symbol(addr as usize).ok().flatten());
                    row.col(|ui| {
                        ui.monospace(format!("{addr:#x}"));
                    });
                    row.col(|ui| match &sym {
                        Some(name) => {
                            ui.monospace(egui::RichText::new(name).color(egui::Color32::from_rgb(
                                140, 200, 140,
                            )));
                        }
                        None => {
                            ui.weak(format!("sub_{addr:x}"));
                        }
                    });
                    row.col(|ui| {
                        ui.weak(callers.to_string());
                    });
                    if row.response().clicked() {
                        action = Some(NavAction::GotoDisasm(addr as usize));
                    }
                });
            });
        action
    }

    #[cfg(target_os = "linux")]
    fn show_calls(&self, ui: &mut egui::Ui, process: Option<&Process>) -> Option<NavAction> {
        let mut action = None;
        let row_h = ui.text_style_height(&egui::TextStyle::Body) + 4.0;
        let rows: Vec<usize> = (0..self.calls.len())
            .filter(|&i| {
                let (site, target) = self.calls[i];
                self.matches(site, None) || self.matches(target, None)
            })
            .collect();

        TableBuilder::new(ui)
            .id_salt("nav_calls")
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::initial(150.0).at_least(110.0)) // Site
            .column(Column::remainder().at_least(120.0)) // → Target
            .header(row_h, |mut h| {
                h.col(|ui| {
                    ui.strong("Call site");
                });
                h.col(|ui| {
                    ui.strong("→ Target");
                });
            })
            .body(|body| {
                body.rows(row_h, rows.len(), |mut row| {
                    let Some(&i) = rows.get(row.index()) else {
                        return;
                    };
                    let (site, target) = self.calls[i];
                    let sym = process.and_then(|p| p.resolve_symbol(target as usize).ok().flatten());
                    row.col(|ui| {
                        ui.monospace(format!("{site:#x}"));
                    });
                    row.col(|ui| {
                        let label = match &sym {
                            Some(name) => format!("{target:#x}  {name}"),
                            None => format!("{target:#x}"),
                        };
                        ui.monospace(egui::RichText::new(label).color(egui::Color32::from_rgb(
                            120, 170, 255,
                        )));
                    });
                    // Click the site to go to the calling code.
                    if row.response().clicked() {
                        action = Some(NavAction::GotoDisasm(site as usize));
                    }
                });
            });
        action
    }
}

impl Default for NavigatorPanel {
    fn default() -> Self {
        Self::new()
    }
}
