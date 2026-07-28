//! Code-generator panel: turn the current project's classes into source code.
//!
//! All of the work lives in [`nemclass_model::codegen`] — this panel is the
//! language picker, the "Generate" trigger, and a read-only monospace view of
//! the result with a clipboard/save escape hatch. Output is regenerated only on
//! demand (not every frame) so a large project doesn't re-render source text at
//! the live-update interval.

use eframe::egui;
use nemclass_model::{Language, NodeRegistry, Project, generate_code};

/// Panel state: the chosen target language and the last generated source.
pub struct GeneratorPanel {
    language: Language,
    /// Output of the last `Generate`, or `None` if it hasn't been run yet.
    output: Option<String>,
    /// Transient status line ("Copied to clipboard", a save error, …).
    status: Option<String>,
}

impl Default for GeneratorPanel {
    fn default() -> Self {
        Self { language: Language::Cpp, output: None, status: None }
    }
}

/// The languages offered in the picker, with their display labels and the file
/// extension used by "Save as…".
const LANGUAGES: [(Language, &str, &str); 3] = [
    (Language::Cpp, "C++", "hpp"),
    (Language::CSharp, "C#", "cs"),
    (Language::Rust, "Rust", "rs"),
];

fn label_for(language: Language) -> &'static str {
    LANGUAGES
        .iter()
        .find(|(l, _, _)| *l == language)
        .map(|&(_, label, _)| label)
        .unwrap_or("C++")
}

fn extension_for(language: Language) -> &'static str {
    LANGUAGES
        .iter()
        .find(|(l, _, _)| *l == language)
        .map(|&(_, _, ext)| ext)
        .unwrap_or("txt")
}

impl GeneratorPanel {
    /// Draw the panel. `project`/`registry` are borrowed only for the duration
    /// of a `Generate` click, so this composes with the app's other disjoint
    /// per-frame borrows.
    pub fn ui(&mut self, ui: &mut egui::Ui, project: &Project, registry: &NodeRegistry) {
        ui.horizontal_wrapped(|ui| {
            egui::ComboBox::from_id_salt("generator_language")
                .selected_text(label_for(self.language))
                .show_ui(ui, |ui| {
                    for (lang, label, _) in LANGUAGES {
                        ui.selectable_value(&mut self.language, lang, label);
                    }
                });

            if ui.button("Generate").clicked() {
                self.output = Some(generate_code(self.language, project, registry));
                self.status = None;
            }

            let has_output = self.output.is_some();

            if ui
                .add_enabled(has_output, egui::Button::new("Copy"))
                .clicked()
                && let Some(out) = &self.output
            {
                ui.ctx().copy_text(out.clone());
                self.status = Some("Copied to clipboard".to_owned());
            }

            if ui
                .add_enabled(has_output, egui::Button::new("Save as…"))
                .clicked()
                && let Some(out) = &self.output
            {
                self.status = Some(save_dialog(out, extension_for(self.language)));
            }

            if let Some(msg) = &self.status {
                ui.separator();
                ui.weak(msg);
            }
        });

        ui.separator();

        match &self.output {
            None => {
                ui.weak(
                    "Pick a language and press Generate to emit type definitions \
                     for every class in this project.",
                );
            }
            Some(out) => {
                let class_count = project.classes_in_order().count();
                ui.weak(format!(
                    "{class_count} class(es), {} enum(s), {} lines",
                    project.enums.len(),
                    out.lines().count()
                ));
                ui.add_space(4.0);

                egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
                    // A read-only multiline edit rather than a label: it keeps
                    // selection + copy working for a subset of the output.
                    let mut text = out.as_str();
                    ui.add(
                        egui::TextEdit::multiline(&mut text)
                            .font(egui::TextStyle::Monospace)
                            .code_editor()
                            .desired_width(f32::INFINITY),
                    );
                });
            }
        }
    }
}

/// Run the native save dialog and write `contents`. Returns the status line to
/// show — this never propagates an error, because a failed/cancelled save is a
/// normal outcome the user should just see reported.
fn save_dialog(contents: &str, extension: &str) -> String {
    let Some(path) = rfd::FileDialog::new()
        .set_file_name(format!("generated.{extension}"))
        .add_filter(extension, &[extension])
        .save_file()
    else {
        return "Save cancelled".to_owned();
    };

    match std::fs::write(&path, contents) {
        Ok(()) => format!("Saved to {}", path.display()),
        Err(e) => format!("Save failed: {e}"),
    }
}
