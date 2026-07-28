//! Cheat-table panel — Cheat-Engine-style saved address list with live reads and freeze.

use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use nemclass_core::{ModuleInfoWithName, Pid, Process};
use crate::process_reader::ProcessReader;
use nemclass_model::{CheatEntry, CheatTable};
use nemclass_scan::{FreezeSet, ScanValueType};

#[cfg(target_os = "linux")]
use nemclass_scan::ProcessTarget;

const FREEZE_INTERVAL: Duration = Duration::from_millis(200);

/// How long a cached module list is reused before `/proc/<pid>/maps` is parsed
/// again. Module bases only change on `dlopen`/`dlclose`, so a second is ample —
/// and the alternative was a full maps parse *per frame* in `show` plus another
/// on every freeze tick.
const MODULE_CACHE_TTL: Duration = Duration::from_millis(1000);

/// Actions the panel asks the parent app to apply after the draw.
pub enum CheatTablePanelAction {
    None,
    /// Save current table to `<project>/tables/<name>.toml`.
    Save(String),
    /// Load a table by name — constructed only by the JS `table.load` path
    /// (`UiAction::LoadTable`), so it is dead code when `scripting` is off.
    #[cfg_attr(not(feature = "scripting"), allow(dead_code))]
    Load(String),
    /// Jump the memory viewer to this address.
    GotoAddr(usize),
}

pub struct CheatTablePanel {
    table: CheatTable,
    last_freeze: Option<Instant>,
    live_values: Vec<String>,
    pub status_msg: Option<String>,
    /// Module list for address-formula resolution, cached for
    /// [`MODULE_CACHE_TTL`]. Rebuilding it means parsing the whole of
    /// `/proc/<pid>/maps`, which this panel was doing once per drawn frame *and*
    /// again on every 200 ms freeze tick.
    modules: Vec<ModuleInfoWithName>,
    modules_at: Option<Instant>,
    /// The write target for freezing, held across ticks. `ProcessTarget::attach`
    /// was called fresh on every tick, five times a second, forever.
    #[cfg(target_os = "linux")]
    freeze_target: Option<ProcessTarget>,
    #[cfg(target_os = "linux")]
    freeze_target_pid: Option<Pid>,
}

impl CheatTablePanel {
    pub fn new() -> Self {
        Self {
            table: CheatTable::new("default"),
            last_freeze: None,
            live_values: Vec::new(),
            status_msg: None,
            modules: Vec::new(),
            modules_at: None,
            #[cfg(target_os = "linux")]
            freeze_target: None,
            #[cfg(target_os = "linux")]
            freeze_target_pid: None,
        }
    }

    pub fn table_mut(&mut self) -> &mut CheatTable {
        &mut self.table
    }

    /// Replace the active table (e.g. after loading from file).
    pub fn set_table(&mut self, table: CheatTable) {
        self.table = table;
        self.live_values.clear();
    }

    pub fn on_detach(&mut self) {
        self.last_freeze = None;
        self.live_values.clear();
        self.modules.clear();
        self.modules_at = None;
        #[cfg(target_os = "linux")]
        {
            self.freeze_target = None;
            self.freeze_target_pid = None;
        }
    }

    /// The cached module list, refreshed at most once per [`MODULE_CACHE_TTL`].
    fn cached_modules(&mut self, process: Option<&Process>) -> &[ModuleInfoWithName] {
        let Some(p) = process else {
            self.modules.clear();
            self.modules_at = None;
            return &self.modules;
        };
        let stale = self
            .modules_at
            .is_none_or(|t| t.elapsed() >= MODULE_CACHE_TTL);
        if stale {
            self.modules = p.modules().map(|it| it.collect()).unwrap_or_default();
            self.modules_at = Some(Instant::now());
        }
        &self.modules
    }

    /// Toggle the frozen state of every entry in the table at once.
    ///
    /// If *any* entry is currently unfrozen the call freezes all entries
    /// (using the current live value string as the frozen value).  If all
    /// entries are already frozen, the call unfreezes all of them.
    ///
    /// Returns `true` when all entries end up frozen, `false` when all end up
    /// unfrozen (useful for a status message).
    pub fn toggle_freeze_all(&mut self, process: Option<&Process>) -> bool {
        let all_frozen = !self.table.entries.is_empty()
            && self.table.entries.iter().all(|e| e.frozen);

        let target_frozen = !all_frozen;

        // Rebuild the live-values list so we have fresh values to freeze with.
        let n = self.table.entries.len();
        self.live_values.resize(n, String::new());
        // Cached — this used to parse the whole of /proc/<pid>/maps every frame.
        let modules = self.cached_modules(process).to_vec();
        let resolver = process.map(|p| ProcessReader::new(p, modules));
        for (i, entry) in self.table.entries.iter().enumerate() {
            let vt = ScanValueType::from_tag(&entry.value_type);
            self.live_values[i] = read_entry_value(process, resolver.as_ref(), entry, vt);
        }

        // Freeze targets are derived from the model each tick (see `tick_freeze`);
        // here we only flip the flag and capture the value to freeze to.
        for (i, entry) in self.table.entries.iter_mut().enumerate() {
            entry.frozen = target_frozen;
            if target_frozen {
                entry.frozen_value = self.live_values.get(i).cloned().unwrap_or_default();
            } else {
                entry.frozen_value.clear();
            }
        }

        target_frozen
    }

    /// Re-write every frozen entry's value on a throttled interval.
    ///
    /// The freeze set is **derived from the model on every tick** — we resolve
    /// each frozen entry's current address and parse its `frozen_value` with its
    /// current type — so edits to an entry's value, address, or type are always
    /// reflected and no stale byte-cache can revert a change or leak a write to
    /// an old address.
    #[cfg(target_os = "linux")]
    pub fn tick_freeze(&mut self, process: Option<&Process>, pid: Option<Pid>) {
        let should_apply = self
            .last_freeze
            .map(|t| t.elapsed() >= FREEZE_INTERVAL)
            .unwrap_or(true);
        if !should_apply {
            return;
        }
        self.last_freeze = Some(Instant::now());

        let mut freeze_set = FreezeSet::new();
        // Cached — this used to parse the whole of /proc/<pid>/maps every tick.
        let modules = self.cached_modules(process).to_vec();
        let resolver = process.map(|p| ProcessReader::new(p, modules));
        for entry in &self.table.entries {
            if !entry.frozen {
                continue;
            }
            if let (Some(addr), Some(vt)) = (
                resolve_entry_addr(entry, resolver.as_ref()),
                ScanValueType::from_tag(&entry.value_type),
            )
                && let Some(bytes) = value_text_to_bytes(vt, &entry.frozen_value)
            {
                freeze_set.set(addr, bytes);
            }
        }
        if freeze_set.is_empty() {
            return;
        }
        let Some(pid) = pid else { return };
        // Attach once and hold it. This ran `ProcessTarget::attach` fresh on
        // every tick — five times a second, for as long as the app was open.
        if self.freeze_target_pid != Some(pid) {
            self.freeze_target = ProcessTarget::attach(pid).ok();
            self.freeze_target_pid = self.freeze_target.is_some().then_some(pid);
        }
        let Some(target) = self.freeze_target.as_ref() else {
            self.status_msg = Some(format!("Cannot write to pid {pid} — values not frozen."));
            return;
        };
        // Report *why* a value did not stick instead of discarding the result.
        let report = freeze_set.apply(target);
        if let Some(problem) = report.problem() {
            self.status_msg = Some(problem);
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn tick_freeze(&mut self, _process: Option<&Process>, _pid: Option<Pid>) {}

    /// Draw the panel. Returns an action for the parent to apply.
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        process: Option<&Process>,
        _pid: Option<Pid>,
        project_dir: Option<&std::path::Path>,
    ) -> CheatTablePanelAction {
        let mut action = CheatTablePanelAction::None;

        // ── toolbar ─────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            ui.strong("Table:");
            ui.add(
                egui::TextEdit::singleline(&mut self.table.name)
                    .desired_width(140.0)
                    .hint_text("table name"),
            );
            if ui.button("New").clicked() {
                self.set_table(CheatTable::new("default"));
            }
            if ui.button("Add row").clicked() {
                self.table.push(CheatEntry::new("", "0x0", "i32"));
            }
            ui.separator();
            if ui.button("Save").clicked() {
                action = CheatTablePanelAction::Save(self.table.name.clone());
            }
            if ui.button("Load…").clicked() {
                if let Some(dir) = project_dir {
                    let path = dir
                        .join("tables")
                        .join(format!("{}.toml", self.table.name));
                    match std::fs::read_to_string(&path) {
                        Ok(s) => match CheatTable::from_toml(&s) {
                            Ok(t) => {
                                self.set_table(t);
                                self.status_msg = None;
                            }
                            Err(e) => self.status_msg = Some(format!("Load error: {e}")),
                        },
                        Err(e) => {
                            self.status_msg =
                                Some(format!("Read {}: {e}", path.display()))
                        }
                    }
                } else {
                    self.status_msg =
                        Some("No project directory — save the project first.".into());
                }
            }
            ui.separator();
            ui.weak("(Ctrl+F: freeze all)");
        });

        ui.separator();

        // ── refresh live values ──────────────────────────────────────────────
        let n = self.table.entries.len();
        self.live_values.resize(n, String::new());
        // Cached — this used to parse the whole of /proc/<pid>/maps every frame,
        // and again further down for a value write.
        let modules = self.cached_modules(process).to_vec();
        let resolver = process.map(|p| ProcessReader::new(p, modules.clone()));
        for (i, entry) in self.table.entries.iter().enumerate() {
            let vt = ScanValueType::from_tag(&entry.value_type);
            self.live_values[i] = read_entry_value(process, resolver.as_ref(), entry, vt);
        }

        // Collect deferred mutations (can't mutate inside the TableBuilder closure).
        let mut to_remove: Option<usize> = None;
        let mut freeze_toggle: Option<usize> = None;
        let mut write_value: Option<(usize, String)> = None;
        let mut addr_edit_commit: Option<(usize, String)> = None;
        let mut desc_edit_commit: Option<(usize, String)> = None;
        let mut vtype_edit: Option<(usize, ScanValueType)> = None;
        let mut goto_addr: Option<usize> = None;

        if n == 0 {
            ui.label("No entries. Click \"Add row\" to add one.");
        } else {
            let text_height = ui.text_style_height(&egui::TextStyle::Body);
            let row_height = text_height + 4.0;

            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .column(Column::initial(24.0).at_least(24.0))
                .column(Column::initial(140.0).at_least(80.0))
                .column(Column::initial(140.0).at_least(80.0))
                .column(Column::initial(80.0).at_least(60.0))
                .column(Column::initial(100.0).at_least(60.0))
                .column(Column::remainder().at_least(80.0))
                .header(row_height + 2.0, |mut h| {
                    h.col(|ui| {
                        ui.strong("❄");
                    });
                    h.col(|ui| {
                        ui.strong("Description");
                    });
                    h.col(|ui| {
                        ui.strong("Address");
                    });
                    h.col(|ui| {
                        ui.strong("Type");
                    });
                    h.col(|ui| {
                        ui.strong("Value");
                    });
                    h.col(|ui| {
                        ui.strong("Actions");
                    });
                })
                .body(|body| {
                    body.rows(row_height, n, |mut row| {
                        let idx = row.index();
                        let entry = match self.table.entries.get(idx) {
                            Some(e) => e,
                            None => return,
                        };
                        let frozen = entry.frozen;
                        let addr_str = entry.address.clone();
                        let desc_str = entry.description.clone();
                        let vtype_str = entry.value_type.clone();
                        let live_val =
                            self.live_values.get(idx).cloned().unwrap_or_default();

                        row.col(|ui| {
                            let mut f = frozen;
                            if ui.checkbox(&mut f, "").changed() {
                                freeze_toggle = Some(idx);
                            }
                        });
                        row.col(|ui| {
                            let mut desc = desc_str.clone();
                            if ui.text_edit_singleline(&mut desc).changed() {
                                desc_edit_commit = Some((idx, desc));
                            }
                        });
                        row.col(|ui| {
                            let mut addr = addr_str.clone();
                            if ui.text_edit_singleline(&mut addr).changed() {
                                addr_edit_commit = Some((idx, addr));
                            }
                        });
                        row.col(|ui| {
                            let cur_vt = ScanValueType::from_tag(&vtype_str)
                                .unwrap_or(ScanValueType::I32);
                            egui::ComboBox::from_id_salt(egui::Id::new(("ct_vtype", idx)))
                                .selected_text(cur_vt.as_tag())
                                .show_ui(ui, |ui| {
                                    for &vt in ALL_VALUE_TYPES {
                                        if ui
                                            .selectable_label(cur_vt == vt, vt.as_tag())
                                            .clicked()
                                        {
                                            vtype_edit = Some((idx, vt));
                                        }
                                    }
                                });
                        });
                        row.col(|ui| {
                            let mut val = live_val.clone();
                            let resp = ui.text_edit_singleline(&mut val);
                            if resp.lost_focus() && val != live_val {
                                write_value = Some((idx, val));
                            }
                        });
                        row.col(|ui| {
                            ui.horizontal(|ui| {
                                if ui.small_button("Goto").clicked()
                                    && let Some(a) = parse_addr_text(&addr_str) {
                                        goto_addr = Some(a);
                                    }
                                if ui.small_button("Remove").clicked() {
                                    to_remove = Some(idx);
                                }
                            });
                        });
                    });
                });
        }

        // Apply deferred mutations.
        if let Some(idx) = freeze_toggle
            && let Some(entry) = self.table.entries.get_mut(idx) {
                entry.frozen = !entry.frozen;
                if entry.frozen {
                    entry.frozen_value = self.live_values.get(idx).cloned().unwrap_or_default();
                } else {
                    entry.frozen_value.clear();
                }
            }
        if let Some((idx, desc)) = desc_edit_commit
            && let Some(entry) = self.table.entries.get_mut(idx) {
                entry.description = desc;
            }
        if let Some((idx, addr)) = addr_edit_commit
            && let Some(entry) = self.table.entries.get_mut(idx) {
                entry.address = addr;
            }
        if let Some((idx, vt)) = vtype_edit
            && let Some(entry) = self.table.entries.get_mut(idx) {
                entry.value_type = vt.as_tag().to_string();
            }
        if let Some((idx, val_text)) = write_value
            && let Some(entry) = self.table.entries.get_mut(idx) {
                let resolver = process.map(|p| ProcessReader::new(p, modules.clone()));
                let addr = resolve_entry_addr(entry, resolver.as_ref());
                let vt = ScanValueType::from_tag(&entry.value_type);
                if let (Some(addr), Some(vt), Some(proc)) = (addr, vt, process)
                    && write_value_typed(proc, addr, vt, &val_text).is_ok()
                    && entry.frozen
                {
                    // Keep a frozen entry pinned to the value the user just wrote.
                    entry.frozen_value = val_text;
                }
            }
        if let Some(idx) = to_remove
            && idx < self.table.entries.len() {
                self.table.entries.remove(idx);
                self.live_values.truncate(self.table.entries.len());
            }
        if let Some(addr) = goto_addr {
            action = CheatTablePanelAction::GotoAddr(addr);
        }

        if let Some(msg) = &self.status_msg {
            ui.add_space(4.0);
            ui.colored_label(egui::Color32::from_rgb(220, 160, 40), msg);
        }

        action
    }
}

impl Default for CheatTablePanel {
    fn default() -> Self {
        Self::new()
    }
}

// ── helpers ────────────────────────────────────────────────────────────────

fn parse_addr_text(s: &str) -> Option<usize> {
    // Shared with every other address box in the app — see
    // `super::parse_address`. This one additionally accepted no `_` separator.
    super::parse_hex_addr(s)
}

/// Resolves an entry's address, which may be a plain hex literal *or* an
/// address formula like `[<game.exe> + 0x1000] + 0x40`.
///
/// The formula path is what makes a saved entry survive ASLR — the whole point
/// of storing `address` as a string — but it needs a live process to walk the
/// pointer chain and a module list to resolve `<name>`. Hex is tried first so an
/// entry with a literal address still resolves with no process attached.
fn resolve_entry_addr(entry: &CheatEntry, resolver: Option<&ProcessReader<'_>>) -> Option<usize> {
    if let Some(addr) = parse_addr_text(&entry.address) {
        return Some(addr);
    }
    let r = resolver?;
    nemclass_model::resolve_formula(&entry.address, r, r).ok()
}

fn read_entry_bytes(
    process: Option<&Process>,
    resolver: Option<&ProcessReader<'_>>,
    entry: &CheatEntry,
    vt: Option<ScanValueType>,
) -> Option<Vec<u8>> {
    let proc = process?;
    let addr = resolve_entry_addr(entry, resolver)?;
    let width = vt?.fixed_width()?;
    let mut buf = vec![0u8; width];
    let n = proc.read_buf(addr, &mut buf).ok()?;
    (n >= width).then_some(buf)
}

fn read_entry_value(
    process: Option<&Process>,
    resolver: Option<&ProcessReader<'_>>,
    entry: &CheatEntry,
    vt: Option<ScanValueType>,
) -> String {
    if let Some(bytes) = read_entry_bytes(process, resolver, entry, vt) {
        format_value_bytes(&bytes, vt.unwrap())
    } else if !entry.frozen_value.is_empty() {
        entry.frozen_value.clone()
    } else {
        "–".to_string()
    }
}

fn parse_uint_text(t: &str) -> Result<u64, String> {
    let t = t.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("{e}"))
    } else {
        t.parse::<u64>().map_err(|e| format!("{e}"))
    }
}

/// Parse a value string of type `vt` into its little-endian bytes, for pinning a
/// frozen value without a process round-trip. Returns `None` for unparseable
/// text or non-numeric types.
pub(crate) fn value_text_to_bytes(vt: ScanValueType, text: &str) -> Option<Vec<u8>> {
    let t = text.trim();
    Some(match vt {
        ScanValueType::I8 => t.parse::<i8>().ok()?.to_le_bytes().to_vec(),
        ScanValueType::I16 => t.parse::<i16>().ok()?.to_le_bytes().to_vec(),
        ScanValueType::I32 => t.parse::<i32>().ok()?.to_le_bytes().to_vec(),
        ScanValueType::I64 => t.parse::<i64>().ok()?.to_le_bytes().to_vec(),
        ScanValueType::U8 => (parse_uint_text(t).ok()? as u8).to_le_bytes().to_vec(),
        ScanValueType::U16 => (parse_uint_text(t).ok()? as u16).to_le_bytes().to_vec(),
        ScanValueType::U32 => (parse_uint_text(t).ok()? as u32).to_le_bytes().to_vec(),
        ScanValueType::U64 => parse_uint_text(t).ok()?.to_le_bytes().to_vec(),
        ScanValueType::F32 => t.parse::<f32>().ok()?.to_le_bytes().to_vec(),
        ScanValueType::F64 => t.parse::<f64>().ok()?.to_le_bytes().to_vec(),
        _ => return None,
    })
}

fn write_value_typed(
    proc: &Process,
    addr: usize,
    vt: ScanValueType,
    text: &str,
) -> Result<(), String> {
    let t = text.trim();
    macro_rules! parse_write_dec {
        ($T:ty) => {{
            let v: $T = t.parse().map_err(|e| format!("{e}"))?;
            proc.write::<$T>(addr, v).map_err(|e| format!("{e}"))
        }};
    }
    macro_rules! parse_write_uint {
        ($T:ty) => {{
            let v = parse_uint_text(t)? as $T;
            proc.write::<$T>(addr, v).map_err(|e| format!("{e}"))
        }};
    }
    match vt {
        ScanValueType::I8 => parse_write_dec!(i8),
        ScanValueType::I16 => parse_write_dec!(i16),
        ScanValueType::I32 => parse_write_dec!(i32),
        ScanValueType::I64 => parse_write_dec!(i64),
        ScanValueType::U8 => parse_write_uint!(u8),
        ScanValueType::U16 => parse_write_uint!(u16),
        ScanValueType::U32 => parse_write_uint!(u32),
        ScanValueType::U64 => parse_write_uint!(u64),
        ScanValueType::F32 => {
            let v: f32 = t.parse().map_err(|e| format!("{e}"))?;
            proc.write::<f32>(addr, v).map_err(|e| format!("{e}"))
        }
        ScanValueType::F64 => {
            let v: f64 = t.parse().map_err(|e| format!("{e}"))?;
            proc.write::<f64>(addr, v).map_err(|e| format!("{e}"))
        }
        _ => Ok(()),
    }
}

fn format_value_bytes(bytes: &[u8], vt: ScanValueType) -> String {
    match vt {
        ScanValueType::I8 if !bytes.is_empty() => i8::from_le_bytes([bytes[0]]).to_string(),
        ScanValueType::I16 if bytes.len() >= 2 => {
            i16::from_le_bytes(bytes[..2].try_into().unwrap_or_default()).to_string()
        }
        ScanValueType::I32 if bytes.len() >= 4 => {
            i32::from_le_bytes(bytes[..4].try_into().unwrap_or_default()).to_string()
        }
        ScanValueType::I64 if bytes.len() >= 8 => {
            i64::from_le_bytes(bytes[..8].try_into().unwrap_or_default()).to_string()
        }
        ScanValueType::U8 if !bytes.is_empty() => u8::from_le_bytes([bytes[0]]).to_string(),
        ScanValueType::U16 if bytes.len() >= 2 => {
            u16::from_le_bytes(bytes[..2].try_into().unwrap_or_default()).to_string()
        }
        ScanValueType::U32 if bytes.len() >= 4 => {
            u32::from_le_bytes(bytes[..4].try_into().unwrap_or_default()).to_string()
        }
        ScanValueType::U64 if bytes.len() >= 8 => {
            u64::from_le_bytes(bytes[..8].try_into().unwrap_or_default()).to_string()
        }
        ScanValueType::F32 if bytes.len() >= 4 => {
            format!(
                "{:.4}",
                f32::from_le_bytes(bytes[..4].try_into().unwrap_or_default())
            )
        }
        ScanValueType::F64 if bytes.len() >= 8 => {
            format!(
                "{:.6}",
                f64::from_le_bytes(bytes[..8].try_into().unwrap_or_default())
            )
        }
        _ => bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

const ALL_VALUE_TYPES: &[ScanValueType] = &[
    ScanValueType::I8,
    ScanValueType::I16,
    ScanValueType::I32,
    ScanValueType::I64,
    ScanValueType::U8,
    ScanValueType::U16,
    ScanValueType::U32,
    ScanValueType::U64,
    ScanValueType::F32,
    ScanValueType::F64,
    ScanValueType::Bytes,
    ScanValueType::StringUtf8,
    ScanValueType::StringUtf16,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a panel pre-populated with N entries, all unfrozen.
    fn panel_with_entries(n: usize) -> CheatTablePanel {
        let mut p = CheatTablePanel::new();
        for i in 0..n {
            p.table.push(CheatEntry::new(
                format!("entry{i}"),
                "0x0",
                "i32",
            ));
        }
        p
    }

    #[test]
    fn toggle_freeze_all_freezes_when_any_unfrozen() {
        let mut p = panel_with_entries(3);
        // Manually freeze one entry so it's a mixed state.
        p.table.entries[0].frozen = true;

        let now_frozen = p.toggle_freeze_all(None);

        assert!(now_frozen, "should report all-frozen");
        assert!(p.table.entries.iter().all(|e| e.frozen));
    }

    #[test]
    fn toggle_freeze_all_unfreezes_when_all_frozen() {
        let mut p = panel_with_entries(3);
        for e in &mut p.table.entries {
            e.frozen = true;
        }

        let now_frozen = p.toggle_freeze_all(None);

        assert!(!now_frozen, "should report all-unfrozen");
        assert!(p.table.entries.iter().all(|e| !e.frozen));
    }

    #[test]
    fn toggle_freeze_all_empty_table_is_noop() {
        let mut p = CheatTablePanel::new();
        // Empty table: no entries to toggle; result is always "unfrozen" (false).
        let result = p.toggle_freeze_all(None);
        // Whether true or false, the table stays empty — just assert it doesn't panic.
        let _ = result;
        assert!(p.table.entries.is_empty());
    }

    #[test]
    fn toggle_freeze_all_round_trips() {
        let mut p = panel_with_entries(2);
        assert!(p.toggle_freeze_all(None));   // none → all frozen
        assert!(!p.toggle_freeze_all(None));  // all frozen → all unfrozen
    }

    #[test]
    fn value_text_to_bytes_round_trips_types() {
        use super::value_text_to_bytes;
        use nemclass_scan::ScanValueType as T;
        // The derived freeze pins `frozen_value` via this conversion; it must
        // produce the correct little-endian width per type.
        assert_eq!(value_text_to_bytes(T::I32, "1337"), Some(1337i32.to_le_bytes().to_vec()));
        assert_eq!(value_text_to_bytes(T::U8, "0xFF"), Some(vec![0xFF]));
        assert_eq!(value_text_to_bytes(T::U64, "0x1000"), Some(0x1000u64.to_le_bytes().to_vec()));
        assert_eq!(value_text_to_bytes(T::F32, "1.5"), Some(1.5f32.to_le_bytes().to_vec()));
        assert_eq!(value_text_to_bytes(T::I16, " -2 "), Some((-2i16).to_le_bytes().to_vec()));
        // Unparseable / non-numeric → None (won't arm a bogus freeze).
        assert_eq!(value_text_to_bytes(T::I32, "not-a-number"), None);
        assert_eq!(value_text_to_bytes(T::Bytes, "41 42"), None);
    }

    #[test]
    fn toggle_freeze_all_sets_frozen_value_for_derived_freeze() {
        // After freeze-all, every entry must carry a non-empty frozen_value so
        // tick_freeze (which derives writes from the model) has something to pin.
        let mut p = panel_with_entries(2);
        // toggle_freeze_all recomputes live values internally and captures them.
        assert!(p.toggle_freeze_all(None));
        for e in &p.table.entries {
            assert!(e.frozen);
            assert!(!e.frozen_value.is_empty(), "frozen_value must be captured");
        }
    }
}

/// Address resolution for saved entries, which may be hex or a formula.
#[cfg(test)]
mod address_tests {
    use super::*;
    use nemclass_core::MockMemoryBackend;

    const BASE: usize = 0x1_0000;

    fn entry(address: &str) -> CheatEntry {
        CheatEntry::new("e", address, "i32")
    }

    #[test]
    fn a_hex_literal_resolves_without_a_process() {
        assert_eq!(resolve_entry_addr(&entry("0x1234"), None), Some(0x1234));
        assert_eq!(resolve_entry_addr(&entry("1234"), None), Some(0x1234));
    }

    #[test]
    fn a_formula_needs_a_process_but_is_no_longer_dead() {
        // This used to return `None` unconditionally: `resolve_entry_addr` only
        // ever parsed hex, so every formula entry silently never resolved,
        // never read a value and never froze.
        let e = entry("[<game.exe> + 0x10] + 0x4");
        assert_eq!(resolve_entry_addr(&e, None), None, "no process to walk with");

        // 8 bytes at BASE+0x10 point at BASE+0x40; +4 lands on BASE+0x44.
        let mut bytes = vec![0u8; 256];
        bytes[0x10..0x18].copy_from_slice(&(BASE as u64 + 0x40).to_le_bytes());
        let process =
            Process::from_backend_for_test(1, Box::new(MockMemoryBackend::new(BASE, bytes)));
        let modules = vec![nemclass_core::ModuleInfoWithName {
            base: BASE,
            size: 256,
            name: "game.exe".to_string(),
        }];
        let reader = ProcessReader::new(&process, modules);

        assert_eq!(resolve_entry_addr(&e, Some(&reader)), Some(BASE + 0x44));
    }

    #[test]
    fn nonsense_addresses_stay_unresolved() {
        assert_eq!(resolve_entry_addr(&entry("not an address"), None), None);
        assert_eq!(resolve_entry_addr(&entry(""), None), None);
    }
}
