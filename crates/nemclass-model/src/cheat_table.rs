//! Cheat table — a Cheat-Engine-style saved address list.
//!
//! A [`CheatTable`] is a named collection of [`CheatEntry`] rows, each pairing a
//! human description with an address (a hex literal or an [`crate::address`]
//! formula so it survives ASLR), a value type, and an optional freeze. It is the
//! persistent, shareable counterpart to the live scanner: users promote scan
//! hits into a table, annotate them, and reload the table next session.
//!
//! Tables are stored as standalone TOML documents (one per file) under a
//! project's `tables/` directory — separate from `project.nemclass` so a table
//! can be shared independently of a class layout. The UI owns file placement;
//! this module owns the data model and lossless [`CheatTable::to_toml`] /
//! [`CheatTable::from_toml`].

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// One row in a [`CheatTable`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheatEntry {
    /// Human-readable description shown in the table (e.g. "Player HP").
    pub description: String,
    /// The address: either a hex literal (`0x7fff…`) or an address formula
    /// (`[<game.exe> + 0x1000] + 0x40`). Formulas are resolved live by the UI
    /// via [`crate::resolve_formula`], so an entry can outlive ASLR.
    pub address: String,
    /// Value-type tag, matching the scanner's `ScanValueType` tags
    /// (`i8`..`u64`, `f32`, `f64`, `bytes`, `string_utf8`, `string_utf16`).
    pub value_type: String,
    /// Whether the value is frozen (periodically re-written by the UI).
    #[serde(default)]
    pub frozen: bool,
    /// The value to freeze to, as a parse/display string (empty when not frozen).
    #[serde(default)]
    pub frozen_value: String,
    /// Optional group label for organising rows (Cheat Engine "groups"). Empty
    /// means ungrouped.
    #[serde(default)]
    pub group: String,
}

impl CheatEntry {
    /// A new, unfrozen entry.
    pub fn new(
        description: impl Into<String>,
        address: impl Into<String>,
        value_type: impl Into<String>,
    ) -> Self {
        Self {
            description: description.into(),
            address: address.into(),
            value_type: value_type.into(),
            frozen: false,
            frozen_value: String::new(),
            group: String::new(),
        }
    }
}

/// A named list of [`CheatEntry`] rows, serialised as one TOML file.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct CheatTable {
    /// Table name (also the suggested file stem).
    pub name: String,
    /// The rows, in display order.
    #[serde(default)]
    pub entries: Vec<CheatEntry>,
}

impl CheatTable {
    /// An empty table with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), entries: Vec::new() }
    }

    /// Append an entry.
    pub fn push(&mut self, entry: CheatEntry) {
        self.entries.push(entry);
    }

    /// Remove the entry at `index`, returning it, or `None` if out of range.
    pub fn remove(&mut self, index: usize) -> Option<CheatEntry> {
        (index < self.entries.len()).then(|| self.entries.remove(index))
    }

    /// Serialise to a TOML document.
    pub fn to_toml(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| ModelError::SerializeError(e.to_string()))
    }

    /// Parse a TOML document produced by [`Self::to_toml`].
    pub fn from_toml(s: &str) -> Result<Self> {
        toml::from_str(s).map_err(|e| ModelError::DeserializeError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_preserves_all_fields() {
        let mut table = CheatTable::new("MyTrainer");
        table.push(CheatEntry::new("Player HP", "[<game.exe> + 0x1000] + 0x40", "i32"));
        let mut frozen = CheatEntry::new("Ammo", "0x7fff1234", "u32");
        frozen.frozen = true;
        frozen.frozen_value = "999".into();
        frozen.group = "Weapons".into();
        table.push(frozen);

        let toml = table.to_toml().expect("serialize");
        let back = CheatTable::from_toml(&toml).expect("deserialize");
        assert_eq!(table, back);
        assert_eq!(back.entries.len(), 2);
        assert_eq!(back.entries[1].frozen_value, "999");
        assert_eq!(back.entries[1].group, "Weapons");
    }

    #[test]
    fn defaults_fill_missing_optional_fields() {
        // A minimal entry without the optional freeze/group keys still loads.
        let toml = r#"
name = "Minimal"
[[entries]]
description = "Score"
address = "0x1000"
value_type = "i64"
"#;
        let table = CheatTable::from_toml(toml).expect("deserialize");
        assert_eq!(table.entries.len(), 1);
        assert!(!table.entries[0].frozen);
        assert_eq!(table.entries[0].frozen_value, "");
        assert_eq!(table.entries[0].group, "");
    }

    #[test]
    fn remove_out_of_range_is_none() {
        let mut table = CheatTable::new("t");
        table.push(CheatEntry::new("a", "0x1", "i8"));
        assert!(table.remove(5).is_none());
        assert!(table.remove(0).is_some());
        assert!(table.entries.is_empty());
    }
}
