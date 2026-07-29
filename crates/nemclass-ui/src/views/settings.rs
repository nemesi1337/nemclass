//! Persistent user settings, stored as JSON at
//! `~/.local/share/nemclass/settings.json` (via `dirs::data_dir()`).
//!
//! Everything the user would be annoyed to re-set on each launch lives here: the
//! dock layout, window size, the recent-projects list and last-opened project,
//! the selected backend, and the live-read interval. Loading is fully
//! fault-tolerant — a missing, unreadable, or schema-drifted file falls back to
//! [`Settings::default`] and never panics.

use std::path::{Path, PathBuf};

use egui_dock::DockState;
use serde::{Deserialize, Serialize};

use super::dock::TabKind;

/// Current settings schema version. Bump when the shape changes incompatibly so
/// [`Settings::load`] can discard an old file instead of mis-parsing it.
const SCHEMA: u32 = 1;

/// Max entries kept in the recent-projects MRU list.
const RECENT_CAP: usize = 12;

/// Persisted window inner size (logical points). Position is intentionally not
/// stored — Wayland ignores programmatic window positioning, so restoring it is
/// unreliable and often wrong.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WindowGeom {
    pub width: f32,
    pub height: f32,
}

/// The full persisted settings document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Schema version (see [`SCHEMA`]).
    #[serde(default)]
    pub schema: u32,
    /// Last window inner size.
    #[serde(default)]
    pub window: Option<WindowGeom>,
    /// Saved dock layout, stored as raw JSON. Kept as a `Value` (not a typed
    /// `DockState`) on purpose: a freshly-built layout has non-finite
    /// (`Rect::NOTHING`) rects that serde_json writes as `null`, which fails to
    /// deserialize back into `f32`. Storing it raw means a bad layout can never
    /// poison the rest of the settings file — [`Settings::dock_state`] just
    /// returns `None` and the app falls back to the default layout.
    #[serde(default)]
    pub dock: Option<serde_json::Value>,
    /// Recently-opened project directories, most-recent-first.
    #[serde(default)]
    pub recent_projects: Vec<PathBuf>,
    /// The project to auto-reopen on startup (the most recent one that loaded).
    #[serde(default)]
    pub last_project: Option<PathBuf>,
    /// Backend the user last selected (e.g. `linux-native`, `linux-kernel`).
    #[serde(default)]
    pub last_backend: Option<String>,
    /// Live-read snapshot interval, in milliseconds.
    #[serde(default)]
    pub live_interval_ms: Option<u64>,
    /// Colour theme. `None` follows the system preference.
    #[serde(default)]
    pub theme: Option<Theme>,
}

/// The colour theme.
///
/// Several panels hardcode colours chosen against a dark background, so `Light`
/// is offered but the value colours are not re-tuned for it — the theme changes
/// the frame, not the syntax palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Theme {
    Dark,
    Light,
}

impl Theme {
    pub fn label(self) -> &'static str {
        match self {
            Theme::Dark => "Dark",
            Theme::Light => "Light",
        }
    }

    pub fn visuals(self) -> eframe::egui::Visuals {
        match self {
            Theme::Dark => eframe::egui::Visuals::dark(),
            Theme::Light => eframe::egui::Visuals::light(),
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            schema: SCHEMA,
            window: None,
            dock: None,
            recent_projects: Vec::new(),
            last_project: None,
            last_backend: None,
            live_interval_ms: None,
            theme: None,
        }
    }
}

impl Settings {
    /// `~/.local/share/nemclass/settings.json` (respects `$XDG_DATA_HOME`).
    pub fn path() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("nemclass").join("settings.json"))
    }

    /// Loads settings, returning [`Settings::default`] on any error (missing
    /// file, parse failure, or a schema mismatch). Never panics.
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match serde_json::from_str::<Settings>(&text) {
            Ok(s) if s.schema == SCHEMA => s,
            Ok(_) => {
                eprintln!("nemclass: settings schema mismatch; using defaults");
                Self::default()
            }
            Err(e) => {
                eprintln!("nemclass: failed to parse settings ({e}); using defaults");
                Self::default()
            }
        }
    }

    /// Writes settings atomically (temp file + rename), creating the parent
    /// directory as needed. Errors are returned for the caller to log, not
    /// panicked on.
    pub fn save(&self) -> std::io::Result<()> {
        let Some(path) = Self::path() else {
            return Err(std::io::Error::other("no data dir"));
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &path)
    }

    /// Decodes the saved dock layout, or `None` if absent or un-decodable (e.g.
    /// a layout serialized with non-finite rects). Never errors.
    pub fn dock_state(&self) -> Option<DockState<TabKind>> {
        let value = self.dock.clone()?;
        serde_json::from_value(value).ok()
    }

    /// Stores `dock` as raw JSON. A serialization failure just clears the saved
    /// layout rather than propagating.
    pub fn set_dock(&mut self, dock: &DockState<TabKind>) {
        self.dock = serde_json::to_value(dock).ok();
    }

    /// Records `dir` as the most-recently-opened project: moves it to the front
    /// of the MRU list (de-duplicated, capped) and marks it as the last project.
    pub fn note_project(&mut self, dir: &Path) {
        let dir = dir.to_path_buf();
        self.recent_projects.retain(|p| p != &dir);
        self.recent_projects.insert(0, dir.clone());
        self.recent_projects.truncate(RECENT_CAP);
        self.last_project = Some(dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::views::dock;

    /// A full settings document — including a real `DockState<TabKind>` — must
    /// round-trip through JSON under the pinned serde. This is the canary that
    /// the `egui_dock` `serde` feature works with `serde = "=1.0.219"`.
    #[test]
    fn settings_round_trip_with_dock() {
        let mut s = Settings::default();
        s.set_dock(&dock::default_layout());
        s.window = Some(WindowGeom {
            width: 1280.0,
            height: 800.0,
        });
        s.last_backend = Some("linux-native".into());
        s.live_interval_ms = Some(150);
        s.note_project(std::path::Path::new("/tmp/example"));

        let json = serde_json::to_string(&s).expect("serialize");
        let back: Settings = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(back.schema, s.schema);
        assert_eq!(back.last_backend.as_deref(), Some("linux-native"));
        assert_eq!(back.live_interval_ms, Some(150));
        assert_eq!(back.last_project, s.last_project);
        assert!(
            back.dock.is_some(),
            "raw dock JSON survives the settings round trip"
        );
        assert_eq!(
            back.recent_projects,
            vec![std::path::PathBuf::from("/tmp/example")]
        );
    }

    /// A layout whose rects are non-finite (a fresh, never-rendered `DockState`)
    /// must not poison the rest of the settings file: the raw JSON stores fine,
    /// and `dock_state()` simply returns `None` instead of erroring.
    #[test]
    fn nonfinite_layout_does_not_poison_settings() {
        let mut s = Settings::default();
        s.set_dock(&dock::default_layout()); // fresh → NaN/inf rects → JSON nulls
        s.last_backend = Some("linux-kernel".into());

        let json = serde_json::to_string(&s).expect("serialize");
        let back: Settings = serde_json::from_str(&json).expect("deserialize");

        // The other settings survive even though the layout can't be decoded.
        assert_eq!(back.last_backend.as_deref(), Some("linux-kernel"));
        assert!(
            back.dock_state().is_none(),
            "un-decodable layout yields None, not an error"
        );
    }

    /// The MRU list de-duplicates and moves the newest entry to the front.
    #[test]
    fn recent_projects_mru_dedups() {
        let mut s = Settings::default();
        s.note_project(std::path::Path::new("/a"));
        s.note_project(std::path::Path::new("/b"));
        s.note_project(std::path::Path::new("/a")); // touch /a again
        assert_eq!(
            s.recent_projects,
            vec![
                std::path::PathBuf::from("/a"),
                std::path::PathBuf::from("/b")
            ]
        );
        assert_eq!(s.last_project, Some(std::path::PathBuf::from("/a")));
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;

    /// A settings file written before the standalone "Cheat table" tab was
    /// retired names a `TabKind` variant that no longer exists.
    ///
    /// `dock_state` must degrade to `None` so the app falls back to the default
    /// layout, rather than the unknown variant taking the whole settings file
    /// down with it.
    #[test]
    fn a_layout_naming_a_removed_tab_falls_back_to_the_default() {
        let json = r#"{
            "schema": 1,
            "dock": {"surfaces": [{"Main": {"tree": [{"Leaf": {"tabs": ["CheatTable"]}}]}}]}
        }"#;

        let settings: Settings = serde_json::from_str(json).expect("settings still parse");
        assert!(
            settings.dock.is_some(),
            "the raw JSON is kept so the rest of the file is unaffected"
        );
        assert!(
            settings.dock_state().is_none(),
            "a layout naming a removed tab must not decode"
        );
    }
}
