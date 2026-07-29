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

    /// Import a Cheat Engine `.CT` table.
    ///
    /// The community's entire cheat-table corpus is in this format and none of
    /// it could be opened here. A `.CT` is plain XML; the pieces that map are
    /// the description, the address, the pointer offsets and the variable type.
    ///
    /// What does not map is reported rather than dropped silently: CE tables
    /// routinely carry auto-assembler scripts and Lua, which have no equivalent
    /// here at all.
    pub fn from_ce_xml(xml: &str) -> Result<(Self, Vec<String>)> {
        let root = crate::rcnet::xml::parse(xml)?;
        if root.name != "CheatTable" {
            return Err(ModelError::DeserializeError(format!(
                "not a Cheat Engine table (root element is <{}>, expected <CheatTable>)",
                root.name
            )));
        }
        let mut table = CheatTable::new("Imported");
        let mut notes = Vec::new();
        if let Some(entries) = root.child("CheatEntries") {
            collect_ce_entries(entries, "", &mut table, &mut notes);
        }
        Ok((table, notes))
    }
}

/// Walk a `<CheatEntries>` element, flattening CE's nested groups into the
/// `group` field.
fn collect_ce_entries(
    entries: &crate::rcnet::xml::Element,
    group: &str,
    table: &mut CheatTable,
    notes: &mut Vec<String>,
) {
    for entry in entries.children_named("CheatEntry") {
        let description = ce_text(entry, "Description");
        // A group header carries no address of its own; its children inherit
        // its description as their group.
        let is_group = ce_text(entry, "GroupHeader") == "1";
        let child_group = if is_group {
            description.clone()
        } else {
            group.to_string()
        };

        if !is_group {
            let address = ce_text(entry, "Address");
            if address.is_empty() {
                if entry.child("AssemblerScript").is_some() || entry.child("LuaScript").is_some() {
                    notes.push(format!(
                        "'{description}' is a script entry (auto-assembler or Lua), which \
                         nemclass has no equivalent for"
                    ));
                } else if entry.child("CheatEntries").is_none() {
                    notes.push(format!("'{description}' has no address"));
                }
            } else {
                let offsets = ce_offsets(entry);
                let variable = ce_text(entry, "VariableType");
                let Some(value_type) = ce_value_type(&variable) else {
                    notes.push(format!(
                        "'{description}' has variable type '{variable}', which nemclass \
                         cannot scan for"
                    ));
                    continue;
                };
                let mut row = CheatEntry::new(
                    description.clone(),
                    ce_formula(&address, &offsets),
                    value_type,
                );
                row.group = group.to_string();
                table.push(row);
            }
        }

        // Nested entries: a group's children, or a pointer entry that also has
        // sub-entries.
        if let Some(nested) = entry.child("CheatEntries") {
            collect_ce_entries(nested, &child_group, table, notes);
        }
    }
}

/// A child element's text, with CE's surrounding quotes stripped.
fn ce_text(entry: &crate::rcnet::xml::Element, name: &str) -> String {
    let Some(child) = entry.child(name) else {
        return String::new();
    };
    let raw = child.text.trim();
    raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')).unwrap_or(raw).to_string()
}

/// The pointer offsets, in the order CE lists them — outermost last.
fn ce_offsets(entry: &crate::rcnet::xml::Element) -> Vec<i64> {
    let Some(offsets) = entry.child("Offsets") else {
        return Vec::new();
    };
    offsets
        .children_named("Offset")
        .filter_map(|o| parse_ce_number(o.text.trim()))
        .collect()
}

/// CE writes numbers as bare hex, sometimes signed with a leading `-`.
fn parse_ce_number(text: &str) -> Option<i64> {
    let text = text.trim();
    let (neg, body) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let body = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")).unwrap_or(body);
    let magnitude = i64::from_str_radix(body, 16).ok()?;
    Some(if neg { -magnitude } else { magnitude })
}

/// Turn a CE address plus offsets into a nemclass address formula.
///
/// CE lists offsets **innermost first** — the first `<Offset>` is the one added
/// last, immediately before the value. Applying them in file order would build
/// the chain backwards and resolve somewhere else entirely.
fn ce_formula(address: &str, offsets: &[i64]) -> String {
    let base = ce_base_expression(address);
    let mut expr = base;
    for off in offsets.iter().rev() {
        expr = if *off < 0 {
            format!("[{expr}] - {:#x}", off.unsigned_abs())
        } else {
            format!("[{expr}] + {off:#x}")
        };
    }
    expr
}

/// `game.exe+1234` → `<game.exe> + 0x1234`; a bare number stays a hex literal.
fn ce_base_expression(address: &str) -> String {
    let address = address.trim();
    if let Some((module, offset)) = address.split_once('+') {
        let module = module.trim();
        let offset = parse_ce_number(offset).unwrap_or(0);
        // A module name is only a module name if it is not itself a number.
        if parse_ce_number(module).is_none() {
            return if offset == 0 {
                format!("<{module}>")
            } else {
                format!("<{module}> + {offset:#x}")
            };
        }
    }
    if parse_ce_number(address).is_none() && !address.is_empty() {
        // A bare module name with no offset.
        return format!("<{address}>");
    }
    match parse_ce_number(address) {
        Some(v) => format!("{v:#x}"),
        None => address.to_string(),
    }
}

/// CE's `VariableType` names, mapped to the scanner's type tags.
fn ce_value_type(variable: &str) -> Option<&'static str> {
    Some(match variable.trim() {
        "Byte" => "u8",
        "2 Bytes" => "i16",
        "4 Bytes" => "i32",
        "8 Bytes" => "i64",
        "Float" => "f32",
        "Double" => "f64",
        "String" => "string_utf8",
        "Array of byte" | "Array of Bytes" => "bytes",
        // "Binary" is a bitfield within a byte and "Custom" is a plugin type;
        // neither has a scanner tag, so they are reported rather than guessed at.
        _ => return None,
    })
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

    // ── Cheat Engine .CT import ────────────────────────────────────────────

    const SAMPLE_CT: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable CheatEngineTableVersion="42">
  <CheatEntries>
    <CheatEntry>
      <ID>1</ID>
      <Description>"Player"</Description>
      <GroupHeader>1</GroupHeader>
      <CheatEntries>
        <CheatEntry>
          <ID>2</ID>
          <Description>"Health"</Description>
          <VariableType>4 Bytes</VariableType>
          <Address>game.exe+1A2B3C</Address>
          <Offsets>
            <Offset>14</Offset>
            <Offset>40</Offset>
          </Offsets>
        </CheatEntry>
        <CheatEntry>
          <ID>3</ID>
          <Description>"Name"</Description>
          <VariableType>String</VariableType>
          <Address>7FFF00001234</Address>
        </CheatEntry>
      </CheatEntries>
    </CheatEntry>
    <CheatEntry>
      <ID>4</ID>
      <Description>"God mode"</Description>
      <VariableType>Auto Assembler Script</VariableType>
      <AssemblerScript>[ENABLE]
nop
[DISABLE]</AssemblerScript>
    </CheatEntry>
    <CheatEntry>
      <ID>5</ID>
      <Description>"Flags"</Description>
      <VariableType>Binary</VariableType>
      <Address>game.exe+100</Address>
    </CheatEntry>
  </CheatEntries>
</CheatTable>
"#;

    #[test]
    fn a_cheat_engine_table_imports_with_its_pointer_chains_intact() {
        let (table, notes) = CheatTable::from_ce_xml(SAMPLE_CT).expect("imports");

        assert_eq!(table.entries.len(), 2, "two addressable entries: {:?}", table.entries);

        let health = &table.entries[0];
        assert_eq!(health.description, "Health", "the quotes CE writes are stripped");
        assert_eq!(health.value_type, "i32");
        assert_eq!(health.group, "Player", "a group header becomes the group label");
        // CE lists offsets innermost first, so the file order is the reverse of
        // the order they are applied. Reading them in file order would build the
        // chain backwards and resolve somewhere else entirely.
        assert_eq!(health.address, "[[<game.exe> + 0x1a2b3c] + 0x40] + 0x14");

        let name = &table.entries[1];
        assert_eq!(name.value_type, "string_utf8");
        assert_eq!(name.address, "0x7fff00001234", "a bare address is hex, as CE writes it");

        assert!(
            notes.iter().any(|n| n.contains("God mode") && n.contains("auto-assembler")),
            "the script entry is reported: {notes:?}"
        );
        assert!(
            notes.iter().any(|n| n.contains("Flags") && n.contains("Binary")),
            "the unmappable variable type is reported: {notes:?}"
        );
    }

    #[test]
    fn imported_ce_formulas_parse_with_the_address_grammar() {
        let (table, _) = CheatTable::from_ce_xml(SAMPLE_CT).unwrap();
        for entry in &table.entries {
            crate::parse_address(&entry.address)
                .unwrap_or_else(|e| panic!("{:?} failed to parse: {e:?}", entry.address));
        }
    }

    #[test]
    fn a_negative_ce_offset_survives_the_conversion() {
        let xml = r#"<CheatTable><CheatEntries><CheatEntry>
            <Description>"Back"</Description>
            <VariableType>4 Bytes</VariableType>
            <Address>mod.so+10</Address>
            <Offsets><Offset>-8</Offset></Offsets>
        </CheatEntry></CheatEntries></CheatTable>"#;
        let (table, _) = CheatTable::from_ce_xml(xml).unwrap();
        assert_eq!(table.entries[0].address, "[<mod.so> + 0x10] - 0x8");
        crate::parse_address(&table.entries[0].address).expect("parses");
    }

    #[test]
    fn a_document_that_is_not_a_cheat_table_is_rejected() {
        let Err(e) = CheatTable::from_ce_xml("<reclass><classes /></reclass>") else {
            panic!("a foreign document must not import");
        };
        assert!(e.to_string().contains("CheatTable"), "{e}");
    }
}
