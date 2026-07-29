//! Shared `.ptrmap` file plumbing for the pointer-scan and spider panels.
//!
//! Both panels cap what they render — 500 rows and 1,000 rows — while a scan
//! routinely returns tens of thousands of paths. Everything past the cap used to
//! be unreachable and was thrown away when the target restarted. These dialogs
//! are the way out: export the whole set, bring it back next session rebased onto
//! the relocated process, and intersect two runs down to the paths that are
//! actually stable.
//!
//! The dialogs live here rather than in either panel because the two need them
//! identically, and because the rebase prompt is the one piece of real UI in the
//! feature — a native file picker plus a modal is not worth writing twice.

use std::path::{Path, PathBuf};

use eframe::egui;

use nemclass_core::ModuleInfoWithName;
use nemclass_scan::{Anchor, PathKind, PtrMapFile, ResolvedPath};

/// Extension for a saved path set.
const PTRMAP_EXT: &str = "ptrmap";
/// Extension for a saved raw pointer-map snapshot.
const SNAPSHOT_EXT: &str = "pointermap";

// ---------------------------------------------------------------------------
// Native dialogs
//
// Each returns the status line to show. A cancelled or failed pick is a normal
// outcome the user should just see reported, not an error to propagate — the
// same convention `generator_panel::save_dialog` uses.
// ---------------------------------------------------------------------------

/// Write `file` as a binary `.ptrmap`.
pub fn export(file: &PtrMapFile, default_name: &str, start_dir: &Path) -> String {
    let Some(path) = save_picker(default_name, PTRMAP_EXT, "NemClass path map", start_dir) else {
        return "Export cancelled".to_owned();
    };
    match std::fs::write(&path, file.to_bytes()) {
        Ok(()) => format!(
            "Exported {} path(s) to {}",
            file.entries.len(),
            path.display()
        ),
        Err(e) => format!("Export failed: {e}"),
    }
}

/// Write `file` as a plain-text listing — one formula per line, no display cap.
pub fn export_text(file: &PtrMapFile, default_name: &str, start_dir: &Path) -> String {
    let Some(path) = save_picker(default_name, "txt", "Text", start_dir) else {
        return "Export cancelled".to_owned();
    };
    match std::fs::write(&path, file.to_text()) {
        Ok(()) => format!(
            "Exported {} path(s) as text to {}",
            file.entries.len(),
            path.display()
        ),
        Err(e) => format!("Export failed: {e}"),
    }
}

/// Pick and parse a `.ptrmap`. `Err` carries a status line; `Ok(None)` means the
/// user cancelled and there is nothing to report.
pub fn pick(start_dir: &Path) -> Result<Option<(PtrMapFile, String)>, String> {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Open path map")
        .set_directory(start_dir)
        .add_filter("NemClass path map", &[PTRMAP_EXT])
        .pick_file()
    else {
        return Ok(None);
    };
    let name = file_label(&path);
    let bytes = std::fs::read(&path).map_err(|e| format!("Could not read {name}: {e}"))?;
    let file = PtrMapFile::from_bytes(&bytes).map_err(|e| format!("{name}: {e}"))?;
    Ok(Some((file, name)))
}

/// Write a raw pointer-map snapshot (`PointerMap::to_bytes`).
pub fn export_snapshot(bytes: &[u8], entries: usize, start_dir: &Path) -> String {
    let Some(path) = save_picker("scan", SNAPSHOT_EXT, "NemClass pointer map", start_dir) else {
        return "Export cancelled".to_owned();
    };
    match std::fs::write(&path, bytes) {
        Ok(()) => format!("Exported {entries} pointer(s) to {}", path.display()),
        Err(e) => format!("Export failed: {e}"),
    }
}

/// Pick a raw pointer-map snapshot, returning its bytes.
pub fn pick_snapshot(start_dir: &Path) -> Result<Option<(Vec<u8>, String)>, String> {
    let Some(path) = rfd::FileDialog::new()
        .set_title("Open pointer map")
        .set_directory(start_dir)
        .add_filter("NemClass pointer map", &[SNAPSHOT_EXT])
        .pick_file()
    else {
        return Ok(None);
    };
    let name = file_label(&path);
    let bytes = std::fs::read(&path).map_err(|e| format!("Could not read {name}: {e}"))?;
    Ok(Some((bytes, name)))
}

fn save_picker(
    stem: &str,
    ext: &str,
    filter: &str,
    start_dir: &Path,
) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_file_name(format!("{stem}.{ext}"))
        .set_directory(start_dir)
        .add_filter(filter, &[ext])
        .save_file()
}

fn file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

// ---------------------------------------------------------------------------
// The rebase prompt
// ---------------------------------------------------------------------------

/// What an applied rebase hands back to the panel.
pub struct RebaseOutcome {
    /// The file's paths, re-anchored onto the current process.
    pub paths: Vec<ResolvedPath>,
    /// Whether the scan that produced the file had hit a result cap.
    pub truncated: bool,
    /// The file's name, for the status line.
    pub source: String,
}

/// One editable row: a module the file's anchors refer to.
struct RebaseRow {
    name: String,
    /// The base the paths were discovered against.
    recorded: usize,
    /// Editable replacement, as typed.
    new_text: String,
    /// True when the attached process supplied this base, so the row needs no
    /// attention. False means the module was not found and the recorded base is
    /// almost certainly wrong.
    matched: bool,
    /// How many of the file's paths anchor in this module.
    paths: usize,
}

/// Modal shown after importing a `.ptrmap`, letting the user confirm or correct
/// where each module now lives.
///
/// Module bases are auto-filled from the attached process, which is the whole
/// point of storing anchors module-relative. The hand-editable field matters for
/// the cases auto-resolution cannot cover: a renamed binary, a file imported
/// with nothing attached, and — the common one — spider paths whose root is a
/// heap address in no module at all, which the absolute-delta row shifts.
#[derive(Default)]
pub struct RebaseDialog {
    file: Option<PtrMapFile>,
    source: String,
    rows: Vec<RebaseRow>,
    /// Delta applied to every unanchored path, as typed. Accepts a leading `-`.
    delta_text: String,
    /// How many of the file's paths are unanchored.
    absolute_paths: usize,
}

impl RebaseDialog {
    /// Stage `file` for import, auto-resolving its modules against `modules`.
    ///
    /// Refuses a file holding a different kind of path than `want`: a
    /// `SpiderPath` does not dereference its root and a `PointerPath` does, so
    /// loading one as the other would silently resolve every chain to the wrong
    /// address.
    pub fn open(
        &mut self,
        file: PtrMapFile,
        source: String,
        want: PathKind,
        modules: &[ModuleInfoWithName],
    ) -> Result<(), String> {
        if let Some(&got) = file.kinds().iter().find(|&&k| k != want) {
            return Err(format!(
                "{source} holds {} paths; this is the {} scanner.",
                got.label(),
                want.label()
            ));
        }
        if file.entries.is_empty() {
            return Err(format!("{source} has no paths in it."));
        }

        self.rows = file
            .modules
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let live = modules.iter().find(|l| l.name == m.name).map(|l| l.base);
                let paths = file
                    .entries
                    .iter()
                    .filter(|e| matches!(e.anchor, Anchor::Module { module, .. } if module as usize == i))
                    .count();
                RebaseRow {
                    name: m.name.clone(),
                    recorded: m.base,
                    new_text: format!("{:#x}", live.unwrap_or(m.base)),
                    matched: live.is_some(),
                    paths,
                }
            })
            .collect();
        self.absolute_paths = file
            .entries
            .iter()
            .filter(|e| matches!(e.anchor, Anchor::Absolute(_)))
            .count();
        self.delta_text = "0".to_owned();
        self.source = source;
        self.file = Some(file);
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.file.is_some()
    }

    /// Draw the modal. Returns the resolved paths once the user applies.
    pub fn show(&mut self, ctx: &egui::Context) -> Option<RebaseOutcome> {
        let file = self.file.as_ref()?;
        let mut apply = false;
        let mut cancel = false;

        egui::Window::new("Import path map")
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!(
                    "{} — {} path(s), scanned for {:#x}.",
                    self.source,
                    file.entries.len(),
                    file.goal
                ));
                if file.truncated {
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        "The scan that produced this file hit a result cap, so it is incomplete.",
                    );
                }
                ui.separator();

                if self.rows.is_empty() {
                    ui.weak("No module-anchored paths — nothing to rebase.");
                } else {
                    ui.label("Module bases in the process attached now:");
                    egui::Grid::new("ptrmap_rebase_modules")
                        .num_columns(4)
                        .striped(true)
                        .show(ui, |ui| {
                            ui.strong("Module");
                            ui.strong("Paths");
                            ui.strong("Saved at");
                            ui.strong("Now at");
                            ui.end_row();

                            for row in &mut self.rows {
                                ui.label(&row.name);
                                ui.label(row.paths.to_string());
                                ui.monospace(format!("{:#x}", row.recorded));
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut row.new_text)
                                            .font(egui::TextStyle::Monospace)
                                            .desired_width(140.0),
                                    );
                                    if !row.matched {
                                        ui.colored_label(ui.visuals().warn_fg_color, "not loaded")
                                            .on_hover_text(
                                                "No module of this name is loaded in the \
                                                 attached process. The saved base is kept — \
                                                 type the correct one if you know it.",
                                            );
                                    } else if parse_base(&row.new_text).is_none() {
                                        ui.colored_label(
                                            ui.visuals().error_fg_color,
                                            "not a hex address",
                                        );
                                    }
                                });
                                ui.end_row();
                            }
                        });
                }

                if self.absolute_paths > 0 {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "{} unanchored path(s) — shift by:",
                            self.absolute_paths
                        ));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.delta_text)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(120.0),
                        );
                        if parse_delta(&self.delta_text).is_none() {
                            ui.colored_label(ui.visuals().error_fg_color, "not a hex offset");
                        }
                    });
                    ui.weak(
                        "These paths start at a raw address — a chain that never reached a \
                         module, or a spider root on the heap. A leading '-' walks backwards.",
                    );
                }

                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let ready = self.rows.iter().all(|r| parse_base(&r.new_text).is_some())
                        && parse_delta(&self.delta_text).is_some();
                    if ui
                        .add_enabled(ready, egui::Button::new("Import"))
                        .clicked()
                    {
                        apply = true;
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
                if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                    cancel = true;
                }
            });

        if cancel {
            self.file = None;
            return None;
        }
        if !apply {
            return None;
        }

        let file = self.file.take()?;
        // Resolved from the edited fields, not from the live module list: a
        // hand-typed override has to win over what auto-resolution found.
        let bases: Vec<(String, usize)> = self
            .rows
            .iter()
            .filter_map(|r| Some((r.name.clone(), parse_base(&r.new_text)?)))
            .collect();
        let delta = parse_delta(&self.delta_text).unwrap_or(0);
        let paths = file.rebase(
            &|name| bases.iter().find(|(n, _)| n == name).map(|(_, b)| *b),
            delta,
        );
        Some(RebaseOutcome { paths, truncated: file.truncated, source: std::mem::take(&mut self.source) })
    }
}

/// Parse an edited module base. Shares the UI-wide hex convention.
fn parse_base(text: &str) -> Option<usize> {
    super::parse_hex_addr(text)
}

/// Parse the unanchored-path delta: the same hex convention, plus a sign.
fn parse_delta(text: &str) -> Option<isize> {
    let t = text.trim();
    let (negative, rest) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let magnitude = super::parse_hex_addr(rest)?;
    let signed = isize::try_from(magnitude).ok()?;
    Some(if negative { -signed } else { signed })
}

// ---------------------------------------------------------------------------
// Building a file from what a panel is holding
// ---------------------------------------------------------------------------

/// The module containing `base`, as `(name, base)`.
///
/// Both panels need this to anchor a path when a scan finishes, and both used to
/// inline the containment test. An address inside no module has no owner — that
/// is the normal case for a spider root on the heap, not an error.
pub fn module_at(base: usize, modules: &[ModuleInfoWithName]) -> Option<(String, usize)> {
    modules
        .iter()
        .find(|m| base >= m.base && base < m.base.saturating_add(m.size))
        .map(|m| (m.name.clone(), m.base))
}

/// Build an anchor for a path starting at `base`, interning its module into
/// `file` so the saved anchor is module-relative and survives the next
/// relocation.
///
/// `module` is what [`module_at`] found when the path was discovered, carried on
/// the row rather than recomputed here: after an import the module may no longer
/// be loaded, and re-exporting must not silently downgrade the anchor to an
/// absolute address that will be wrong the next time the target starts.
pub fn anchor_for(
    file: &mut PtrMapFile,
    base: usize,
    module: Option<(&str, usize)>,
) -> Anchor {
    match module {
        Some((name, mod_base)) => Anchor::Module {
            module: file.module_index(name, mod_base),
            offset: base.wrapping_sub(mod_base),
        },
        None => Anchor::Absolute(base),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delta_accepts_a_sign_and_the_ui_hex_convention() {
        assert_eq!(parse_delta("0x1000"), Some(0x1000));
        assert_eq!(parse_delta("1000"), Some(0x1000));
        assert_eq!(parse_delta("-0x1000"), Some(-0x1000));
        assert_eq!(parse_delta("+0x10_00"), Some(0x1000));
        assert_eq!(parse_delta("  -1000  "), Some(-0x1000));
        assert_eq!(parse_delta("0"), Some(0));
        assert_eq!(parse_delta(""), None);
        assert_eq!(parse_delta("-"), None);
        assert_eq!(parse_delta("nonsense"), None);
    }

    fn modules() -> Vec<ModuleInfoWithName> {
        vec![
            ModuleInfoWithName { base: 0x40_0000, size: 0x10_0000, name: "game.exe".into() },
            ModuleInfoWithName { base: 0x7F00_0000, size: 0x1_0000, name: "libfoo.so".into() },
        ]
    }

    fn empty_file() -> PtrMapFile {
        PtrMapFile { goal: 0, modules: vec![], entries: vec![], truncated: false }
    }

    #[test]
    fn module_lookup_covers_a_module_and_stops_at_its_end() {
        let mods = modules();
        assert_eq!(module_at(0x40_1234, &mods), Some(("game.exe".into(), 0x40_0000)));
        assert_eq!(module_at(0x40_0000, &mods), Some(("game.exe".into(), 0x40_0000)));
        assert_eq!(module_at(0x7F00_0008, &mods), Some(("libfoo.so".into(), 0x7F00_0000)));
        // One past the last byte of game.exe belongs to nobody.
        assert_eq!(module_at(0x50_0000, &mods), None);
        assert_eq!(module_at(0x5555_0000, &mods), None);
    }

    #[test]
    fn an_address_inside_a_module_anchors_relative_to_it() {
        let mut file = empty_file();
        let mods = modules();

        let anchor = |file: &mut PtrMapFile, addr: usize| {
            let owner = module_at(addr, &mods);
            anchor_for(file, addr, owner.as_ref().map(|(n, b)| (n.as_str(), *b)))
        };

        assert_eq!(anchor(&mut file, 0x40_1234), Anchor::Module { module: 0, offset: 0x1234 });
        assert_eq!(anchor(&mut file, 0x7F00_0008), Anchor::Module { module: 1, offset: 0x8 });
        // A second path into the first module reuses its slot.
        assert_eq!(anchor(&mut file, 0x40_0000), Anchor::Module { module: 0, offset: 0 });
        assert_eq!(file.modules.len(), 2);
    }

    #[test]
    fn a_path_with_no_module_stays_absolute() {
        let mut file = empty_file();
        assert_eq!(anchor_for(&mut file, 0x5555_0000, None), Anchor::Absolute(0x5555_0000));
        assert!(file.modules.is_empty());
    }

    #[test]
    fn a_module_that_is_no_longer_loaded_still_anchors_relative() {
        // The re-export case: the row remembers the module it was found in even
        // though nothing of that name is loaded now, so the saved anchor stays
        // usable rather than degrading to an address that will move.
        let mut file = empty_file();
        assert_eq!(
            anchor_for(&mut file, 0x140_1234, Some(("gone.so", 0x140_0000))),
            Anchor::Module { module: 0, offset: 0x1234 }
        );
        assert_eq!(file.modules[0].base, 0x140_0000);
    }

    #[test]
    fn a_file_of_the_wrong_kind_is_refused() {
        use nemclass_scan::PtrMapEntry;

        let file = PtrMapFile {
            goal: 0,
            modules: vec![],
            entries: vec![PtrMapEntry {
                kind: PathKind::Spider,
                anchor: Anchor::Absolute(0x1000),
                offsets: vec![0x8],
            }],
            truncated: false,
        };
        let mut dialog = RebaseDialog::default();
        let err = dialog
            .open(file, "run-1.ptrmap".into(), PathKind::Pointer, &[])
            .unwrap_err();
        assert!(err.contains("spider"), "{err}");
        assert!(!dialog.is_open());
    }

    #[test]
    fn opening_prefills_matched_modules_from_the_live_process() {
        use nemclass_scan::{ModuleRef, PtrMapEntry};

        let file = PtrMapFile {
            goal: 0,
            modules: vec![
                ModuleRef { name: "game.exe".into(), base: 0x140_0000 },
                ModuleRef { name: "gone.so".into(), base: 0x200_0000 },
            ],
            entries: vec![
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Module { module: 0, offset: 0x10 },
                    offsets: vec![0x8],
                },
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Module { module: 1, offset: 0x20 },
                    offsets: vec![0x8],
                },
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Absolute(0x5555_0000),
                    offsets: vec![0x8],
                },
            ],
            truncated: false,
        };

        let mut dialog = RebaseDialog::default();
        dialog
            .open(file, "run-1.ptrmap".into(), PathKind::Pointer, &modules())
            .unwrap();

        assert!(dialog.is_open());
        // game.exe is loaded, so its field is prefilled with the live base.
        assert!(dialog.rows[0].matched);
        assert_eq!(dialog.rows[0].new_text, "0x400000");
        assert_eq!(dialog.rows[0].paths, 1);
        // gone.so is not, so the saved base is kept and flagged for the user.
        assert!(!dialog.rows[1].matched);
        assert_eq!(dialog.rows[1].new_text, "0x2000000");
        // The unanchored path is counted separately.
        assert_eq!(dialog.absolute_paths, 1);
    }

    #[test]
    fn an_empty_file_is_refused() {
        let file = PtrMapFile {
            goal: 0,
            modules: vec![],
            entries: vec![],
            truncated: false,
        };
        let mut dialog = RebaseDialog::default();
        assert!(
            dialog
                .open(file, "empty.ptrmap".into(), PathKind::Pointer, &[])
                .is_err()
        );
    }
}
