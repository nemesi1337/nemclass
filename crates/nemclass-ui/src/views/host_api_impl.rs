//! `UiHostApi` — main-thread implementation of `nemclass_script::HostApi`.
//!
//! This entire module is gated on `#[cfg(feature = "scripting")]` because
//! `HostApi` itself only exists under that feature.  Every item below is
//! therefore only compiled when the feature is active.
//!
//! # Design
//!
//! `UiHostApi` is built **fresh each frame** in `NemclassApp::logic`, borrowing
//! disjoint fields from `NemclassApp`:
//!
//! - `project: &'a mut Project` — receives `declare_class` / `declare_type` and
//!   the whole `classes.*` editing surface.
//! - `node_registry: &'a NodeRegistry` — constructs nodes for `classes.addNode`.
//! - `process: Option<&'a Process>` — needed for `pattern_scan`, `mem.*`,
//!   `proc.*`, `scan.*`, `disasm.*`; `None` means not attached.
//! - `log: ScriptLog` — an `Rc` **clone** (not a borrow) so it can live in this
//!   struct without conflicting with the other `&mut` borrows above.
//! - `last_error: &'a mut Option<String>` — receives the first host-level error
//!   string, surfaced in the UI status bar.
//! - `ui_actions: &'a mut Vec<UiAction>` — a per-frame queue the `ui.*` methods
//!   push into; the caller drains it after `pump` and applies each action
//!   (which needs app-level panel state `UiHostApi` deliberately does not hold).
//!
//! The `Rc<RefCell<…>>` log is safe here because the UI crate is entirely
//! single-threaded.

/// A deferred UI action requested by a script's `ui.*` call. Applied by the
/// caller after `pump`, since it needs app/panel state (memory/disasm views,
/// selected class) that `UiHostApi` does not borrow.
#[cfg(feature = "scripting")]
#[derive(Debug, Clone)]
pub enum UiAction {
    /// Focus the memory view at an address.
    GotoMemory(usize),
    /// Focus the disassembly view at an address.
    GotoDisasm(usize),
    /// Select a class in the class view.
    SelectClass(uuid::Uuid),
    /// Save the cheat table to `<project>/tables/<name>.toml`.
    SaveTable(String),
    /// Load a cheat table from `<project>/tables/<name>.toml`.
    LoadTable(String),
}

#[cfg(feature = "scripting")]
mod inner {
    use nemclass_core::{Process, RegionIndex};
    use nemclass_model::{ClassNode, EnumDescription, Node, Project};
    use nemclass_script::engine_rusty::serde_json::{self, json, Value};
    use nemclass_script::{scan_module, HostApi, LogLevel};
    use nemclass_model::node::registry::NodeRegistry;
    use uuid::Uuid;

    use super::super::cheat_table_panel::value_text_to_bytes;
    use super::super::script_log::{push, LogKind, ScriptLog};
    use super::super::parse_hotkey;
    use super::UiAction;
    use crate::process_reader::ProcessReader;
    use nemclass_scan::ScanValueType;

    /// Main-thread `HostApi` implementation built fresh each frame.
    pub struct UiHostApi<'a> {
        /// The open project; receives `declare_class` / `declare_type` and the
        /// `classes.*` editing surface.
        pub project: &'a mut Project,
        /// Node factory for `classes.addNode`.
        pub node_registry: &'a NodeRegistry,
        /// Attached process, or `None` when not attached.
        pub process: Option<&'a Process>,
        /// Shared log buffer.  An `Rc` clone rather than a borrow so the struct
        /// can also hold `&mut project` without a lifetime conflict.
        pub log: ScriptLog,
        /// Receives the first error message for display in the UI status bar.
        pub last_error: &'a mut Option<String>,
        /// Queue the `ui.*` methods push deferred actions into.
        pub ui_actions: &'a mut Vec<UiAction>,
        /// The cheat table; mutated by `table.*` calls.
        pub cheat_table: &'a mut nemclass_model::CheatTable,
        /// Script-registered hotkeys; mutated by `hotkeys.register`/`unregister`.
        pub script_hotkeys: &'a mut Vec<super::super::HotkeyReg>,
        /// Monotonic id source for `hotkeys.register`.
        pub next_hotkey_id: &'a mut u32,
        /// Direct script freezes (`(addr, type, value text)`); mutated by
        /// `mem.freeze`/`mem.unfreeze`.
        pub script_freezes: &'a mut Vec<(usize, nemclass_scan::ScanValueType, String)>,
        /// Cheat-Engine-style iterative scan session, held across calls so
        /// `scan.first`/`scan.next`/`scan.results`/`scan.reset` can narrow a
        /// result set over time. Linux only.
        #[cfg(target_os = "linux")]
        pub script_scanner:
            &'a mut Option<nemclass_scan::Scanner<nemclass_scan::ProcessTarget>>,
    }

    // ---- small arg-parsing helpers -----------------------------------------

    /// Accepts an address as a JS number (`f64`/`u64`) or a `"0x.."`/decimal
    /// string, returning a `usize`.
    fn as_addr(v: &Value) -> Result<usize, String> {
        match v {
            Value::Number(n) => {
                if let Some(u) = n.as_u64() {
                    Ok(u as usize)
                } else if let Some(f) = n.as_f64() {
                    if f < 0.0 {
                        Err("negative address".to_string())
                    } else {
                        Ok(f as usize)
                    }
                } else {
                    Err("bad numeric address".to_string())
                }
            }
            Value::String(s) => parse_addr_str(s),
            _ => Err(format!("expected an address, got {v}")),
        }
    }

    /// Parses a hex (`0x..`) or decimal string into a `usize`.
    fn parse_addr_str(s: &str) -> Result<usize, String> {
        let t = s.trim();
        let r = if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            usize::from_str_radix(hex, 16)
        } else {
            t.parse::<usize>()
        };
        r.map_err(|_| format!("bad address string: {s:?}"))
    }

    /// Upper bound on the number of bytes a single script call may request to
    /// read, so an untrusted length can't drive a process-aborting allocation.
    const MAX_SCRIPT_READ: usize = 64 * 1024 * 1024;

    /// Parse exactly-`width` little-endian `bytes` as `vt` into a JSON number.
    /// 64-bit ints go through `f64` (lossy, like the scalar reads); non-numeric
    /// types yield `null`.
    fn bytes_to_json_num(vt: nemclass_scan::ScanValueType, b: &[u8]) -> Value {
        use nemclass_scan::ScanValueType as T;
        macro_rules! le {
            ($ty:ty) => {{
                const W: usize = std::mem::size_of::<$ty>();
                let mut a = [0u8; W];
                a.copy_from_slice(&b[..W]);
                json!(<$ty>::from_le_bytes(a) as f64)
            }};
        }
        match vt {
            T::I8 => json!(b[0] as i8 as f64),
            T::U8 => json!(b[0] as f64),
            T::I16 => le!(i16),
            T::U16 => le!(u16),
            T::I32 => le!(i32),
            T::U32 => le!(u32),
            T::I64 => le!(i64),
            T::U64 => le!(u64),
            T::F32 => le!(f32),
            T::F64 => le!(f64),
            _ => Value::Null,
        }
    }

    /// Write one JSON number `v` as `vt` at `addr` in `proc`.
    fn write_typed_value(
        proc: &Process,
        addr: usize,
        vt: nemclass_scan::ScanValueType,
        v: &Value,
    ) -> Result<(), String> {
        use nemclass_scan::ScanValueType as T;
        macro_rules! wi {
            ($ty:ty) => {{
                proc.write::<$ty>(addr, as_i64(v)? as $ty).map_err(|e| format!("write: {e}"))
            }};
        }
        macro_rules! wu {
            ($ty:ty) => {{
                proc.write::<$ty>(addr, as_u64_flex(v)? as $ty).map_err(|e| format!("write: {e}"))
            }};
        }
        match vt {
            T::I8 => wi!(i8),
            T::I16 => wi!(i16),
            T::I32 => wi!(i32),
            T::I64 => wi!(i64),
            T::U8 => wu!(u8),
            T::U16 => wu!(u16),
            T::U32 => wu!(u32),
            T::U64 => wu!(u64),
            T::F32 => proc.write::<f32>(addr, as_f64(v)? as f32).map_err(|e| format!("write: {e}")),
            T::F64 => proc.write::<f64>(addr, as_f64(v)?).map_err(|e| format!("write: {e}")),
            _ => Err(format!("writeValues: unsupported type {}", vt.as_tag())),
        }
    }

    /// Greedy Hex64/32/16/8 padding nodes summing to `gap` bytes, for filling a
    /// gap before a field placed at an explicit offset.
    fn hex_fill(registry: &NodeRegistry, mut gap: usize) -> Vec<Box<dyn Node>> {
        let mut out: Vec<Box<dyn Node>> = Vec::new();
        for (tag, sz) in [("Hex64", 8usize), ("Hex32", 4), ("Hex16", 2), ("Hex8", 1)] {
            while gap >= sz {
                match registry.construct(tag) {
                    Some(n) => {
                        out.push(n);
                        gap -= sz;
                    }
                    None => return out,
                }
            }
        }
        out
    }

    /// The `idx`-th element of a JSON array argument list.
    fn arg(args: &Value, idx: usize) -> Result<&Value, String> {
        args.as_array()
            .ok_or_else(|| "args must be an array".to_string())?
            .get(idx)
            .ok_or_else(|| format!("missing argument #{idx}"))
    }

    /// An optional argument (returns `None` past the end or for JS `null`).
    fn opt_arg(args: &Value, idx: usize) -> Option<&Value> {
        args.as_array()
            .and_then(|a| a.get(idx))
            .filter(|v| !v.is_null())
    }

    fn as_str(v: &Value) -> Result<String, String> {
        match v {
            Value::String(s) => Ok(s.clone()),
            other => Ok(other.to_string()),
        }
    }

    fn as_f64(v: &Value) -> Result<f64, String> {
        v.as_f64().ok_or_else(|| format!("expected a number, got {v}"))
    }

    fn as_i64(v: &Value) -> Result<i64, String> {
        match v {
            Value::Number(n) => n
                .as_i64()
                .or_else(|| n.as_f64().map(|f| f as i64))
                .ok_or_else(|| "bad integer".to_string()),
            Value::String(s) => s.trim().parse::<i64>().map_err(|_| format!("bad int: {s:?}")),
            _ => Err(format!("expected an integer, got {v}")),
        }
    }

    fn as_u64_flex(v: &Value) -> Result<u64, String> {
        match v {
            Value::Number(n) => n
                .as_u64()
                .or_else(|| n.as_f64().map(|f| f as u64))
                .ok_or_else(|| "bad unsigned".to_string()),
            Value::String(s) => s.trim().parse::<u64>().map_err(|_| format!("bad u64: {s:?}")),
            _ => Err(format!("expected an unsigned integer, got {v}")),
        }
    }

    /// Marshals a JS scan value argument (a number or string) into an optional
    /// [`Needle`] of `vt` for the given `compare`, mirroring the scanner panel's
    /// needle handling. Change-relative compares (`Unknown`/`Increased`/…) need
    /// no needle and yield `None`; needle-requiring compares error if the value
    /// arg is missing. Single-needle only — `Between` upper bounds are not
    /// accepted here (use the UI Scanner for two-sided ranges).
    #[cfg(target_os = "linux")]
    fn parse_scan_needle(
        vt: ScanValueType,
        value: Option<&Value>,
        compare: nemclass_scan::ScanCompareType,
    ) -> Result<Option<nemclass_scan::Needle>, String> {
        if !compare.needs_needle() {
            return Ok(None);
        }
        let raw = value.ok_or_else(|| {
            format!("compare {compare:?} needs a value")
        })?;
        let text = as_str(raw)?;
        let needle = vt
            .parse_needle(&text)
            .map_err(|e| format!("bad value {text:?} for type {}: {e:?}", vt.as_tag()))?;
        Ok(Some(needle))
    }

    /// Serialize a project [`EnumDescription`] into the JS `EnumInfo` shape:
    /// `{ name, size, flags, values: { variant: number } }`.
    fn enum_to_json(e: &EnumDescription) -> Value {
        let values: serde_json::Map<String, Value> = e
            .values
            .iter()
            .map(|(k, v)| (k.clone(), json!(v)))
            .collect();
        json!({
            "name": e.name,
            "size": e.size,
            "flags": e.use_flags,
            "values": values,
        })
    }

    impl<'a> UiHostApi<'a> {
        /// The attached process or a `"not attached"` error.
        fn proc(&self) -> Result<&Process, String> {
            self.process.ok_or_else(|| "not attached".to_string())
        }

        /// Reads the module list once (case-insensitive lookups build on this).
        fn modules(&self) -> Result<Vec<nemclass_core::ModuleInfoWithName>, String> {
            Ok(self
                .proc()?
                .modules()
                .map_err(|e| format!("enumerate modules: {e}"))?
                .collect())
        }

        /// Reads a full module image by name (the main module if `name` is None).
        fn module_bytes(&self, name: Option<&str>) -> Result<(usize, Vec<u8>), String> {
            let mods = self.modules()?;
            let info = match name {
                Some(n) => mods
                    .iter()
                    .find(|m| m.name.eq_ignore_ascii_case(n))
                    .ok_or_else(|| format!("module not found: {n}"))?,
                None => mods.first().ok_or_else(|| "no modules".to_string())?,
            };
            let mut bytes = vec![0u8; info.size];
            let _ = self.proc()?.read_buf(info.base, &mut bytes);
            Ok((info.base, bytes))
        }

        /// Reads the image of the module that *contains* `addr`, returning its
        /// base, its bytes, and the offset of `addr` within it.
        fn module_bytes_at(&self, addr: usize) -> Result<(usize, Vec<u8>, usize), String> {
            let mods = self.modules()?;
            let info = mods
                .iter()
                .find(|m| addr >= m.base && addr < m.base.saturating_add(m.size))
                .ok_or_else(|| format!("0x{addr:x} is not inside any module"))?;
            let mut bytes = vec![0u8; info.size];
            let _ = self.proc()?.read_buf(info.base, &mut bytes);
            Ok((info.base, bytes, addr - info.base))
        }

        /// Typed read helper returning JSON, tolerating `read` errors as a host
        /// error string.
        fn read_num<T>(&self, addr: usize, to_json: impl Fn(T) -> Value) -> Result<Value, String>
        where
            T: bytemuck::Pod,
        {
            let v = self
                .proc()?
                .read::<T>(addr)
                .map_err(|e| format!("read: {e}"))?;
            Ok(to_json(v))
        }

        /// Typed write helper returning `true` on success.
        fn write_num<T>(&self, addr: usize, value: T) -> Result<Value, String>
        where
            T: bytemuck::Pod,
        {
            self.proc()?
                .write::<T>(addr, value)
                .map_err(|e| format!("write: {e}"))?;
            Ok(json!(true))
        }

        /// Resolves a class by uuid or (case-insensitive) name.
        fn find_class_uuid(&self, key: &str) -> Option<Uuid> {
            if let Ok(u) = key.parse::<Uuid>()
                && self.project.get_class(&u).is_some()
            {
                return Some(u);
            }
            self.project
                .classes_in_order()
                .find(|c| c.name.eq_ignore_ascii_case(key))
                .map(|c| c.uuid)
        }
    }

    impl<'a> HostApi for UiHostApi<'a> {
        fn pattern_scan(&mut self, module: &str, pattern: &str) -> Result<Vec<usize>, String> {
            let (base, bytes) = self.module_bytes(Some(module))?;
            let hits = scan_module(base, &bytes, pattern);
            push(
                &self.log,
                LogKind::Info,
                format!("pattern_scan({module:?}, {pattern:?}): {} hit(s)", hits.len()),
            );
            Ok(hits)
        }

        fn declare_type(&mut self, ty: EnumDescription) -> Result<(), String> {
            let name = ty.name.clone();
            if let Some(existing) = self.project.enums.iter_mut().find(|e| e.name == name) {
                *existing = ty;
                push(&self.log, LogKind::Info, format!("declare_type: updated enum {name:?}"));
            } else {
                self.project.enums.push(ty);
                push(&self.log, LogKind::Info, format!("declare_type: added enum {name:?}"));
            }
            Ok(())
        }

        fn declare_class(&mut self, name: &str, address_formula: &str) -> Result<(), String> {
            let existing_uuid = self
                .project
                .classes_in_order()
                .find(|c| c.name == name)
                .map(|c| c.uuid);

            if let Some(uuid) = existing_uuid {
                if let Some(class) = self.project.get_class_mut(&uuid) {
                    class.address_formula = address_formula.to_string();
                    push(&self.log, LogKind::Info, format!("declare_class: updated formula for {name:?}"));
                }
            } else {
                let mut class = ClassNode::new(name);
                class.address_formula = address_formula.to_string();
                self.project.add_class(class);
                push(&self.log, LogKind::Info, format!("declare_class: added class {name:?}"));
            }
            Ok(())
        }

        fn log(&mut self, level: LogLevel, msg: &str) {
            let kind = match level {
                LogLevel::Info => LogKind::Info,
                LogLevel::Warn => LogKind::Warn,
                LogLevel::Error => LogKind::Error,
            };
            push(&self.log, kind, msg);
            if kind == LogKind::Error && self.last_error.is_none() {
                *self.last_error = Some(msg.to_string());
            }
        }

        /// The generic catalog dispatcher. One big `match` on the dotted method
        /// name; each arm parses the JSON args array and reuses core/model.
        fn call(&mut self, method: &str, args: &Value) -> Result<Value, String> {
            match method {
                // ---- mem.* --------------------------------------------------
                "mem.readBytes" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let len = as_f64(arg(args, 1)?)? as usize;
                    if len > MAX_SCRIPT_READ {
                        return Err(format!(
                            "readBytes length {len} exceeds cap of {MAX_SCRIPT_READ} bytes"
                        ));
                    }
                    let mut buf = vec![0u8; len];
                    let n = self.proc()?.read_buf(addr, &mut buf).map_err(|e| format!("read: {e}"))?;
                    buf.truncate(n);
                    Ok(json!(buf))
                }
                "mem.writeBytes" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let bytes: Vec<u8> = arg(args, 1)?
                        .as_array()
                        .ok_or("writeBytes: expected byte array")?
                        .iter()
                        .map(|v| v.as_u64().unwrap_or(0) as u8)
                        .collect();
                    let proc = self.proc()?;
                    for (i, b) in bytes.iter().enumerate() {
                        proc.write::<u8>(addr + i, *b).map_err(|e| format!("write: {e}"))?;
                    }
                    Ok(json!(true))
                }
                "mem.readValues" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let ty = as_str(arg(args, 1)?)?;
                    let count = as_f64(arg(args, 2)?)? as usize;
                    let vt = nemclass_scan::ScanValueType::from_tag(&ty)
                        .ok_or_else(|| format!("unknown type: {ty}"))?;
                    let width = vt
                        .fixed_width()
                        .ok_or_else(|| format!("type {ty} has no fixed width"))?;
                    let total = count
                        .checked_mul(width)
                        .ok_or_else(|| "readValues: size overflow".to_string())?;
                    if total > MAX_SCRIPT_READ {
                        return Err(format!("readValues span {total} exceeds cap of {MAX_SCRIPT_READ}"));
                    }
                    let mut buf = vec![0u8; total];
                    let n = self.proc()?.read_buf(addr, &mut buf).map_err(|e| format!("read: {e}"))?;
                    let avail = n / width;
                    let vals: Vec<Value> = (0..avail)
                        .map(|i| bytes_to_json_num(vt, &buf[i * width..i * width + width]))
                        .collect();
                    Ok(json!(vals))
                }
                "mem.writeValues" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let ty = as_str(arg(args, 1)?)?;
                    let vals = arg(args, 2)?
                        .as_array()
                        .ok_or_else(|| "writeValues: expected an array".to_string())?;
                    let vt = nemclass_scan::ScanValueType::from_tag(&ty)
                        .ok_or_else(|| format!("unknown type: {ty}"))?;
                    let width = vt
                        .fixed_width()
                        .ok_or_else(|| format!("type {ty} has no fixed width"))?;
                    let proc = self.proc()?;
                    for (i, v) in vals.iter().enumerate() {
                        write_typed_value(proc, addr + i * width, vt, v)?;
                    }
                    Ok(json!(vals.len() as f64))
                }
                "mem.resolveRip" => {
                    // x64 RIP-relative resolve: read the rel32 displacement at
                    // `insn + dispOffset`, return `insn + instrLen + disp`.
                    let insn = as_addr(arg(args, 0)?)?;
                    let disp_off = as_f64(arg(args, 1)?)? as usize;
                    let instr_len = as_f64(arg(args, 2)?)? as usize;
                    let disp = self
                        .proc()?
                        .read::<i32>(insn.wrapping_add(disp_off))
                        .map_err(|e| format!("read: {e}"))? as i64;
                    let target = (insn as i64)
                        .wrapping_add(instr_len as i64)
                        .wrapping_add(disp) as usize;
                    Ok(json!(target as f64))
                }
                "mem.readStruct" => {
                    // Read a struct given a layout: [{ name, type, offset? }].
                    // Missing offsets pack sequentially. One call reads it all.
                    let addr = as_addr(arg(args, 0)?)?;
                    let fields = arg(args, 1)?
                        .as_array()
                        .ok_or_else(|| "readStruct: layout must be an array".to_string())?;
                    let proc = self.proc()?;
                    let mut obj = serde_json::Map::new();
                    let mut cursor = 0usize;
                    for f in fields {
                        let name = f
                            .get("name")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| "readStruct: field needs a name".to_string())?
                            .to_string();
                        let ty = f
                            .get("type")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| "readStruct: field needs a type".to_string())?;
                        let vt = nemclass_scan::ScanValueType::from_tag(ty)
                            .ok_or_else(|| format!("unknown type: {ty}"))?;
                        let width = vt
                            .fixed_width()
                            .ok_or_else(|| format!("type {ty} has no fixed width"))?;
                        let field_off = f
                            .get("offset")
                            .and_then(|v| v.as_f64())
                            .map(|x| x as usize)
                            .unwrap_or(cursor);
                        let mut buf = vec![0u8; width];
                        let n = proc
                            .read_buf(addr.wrapping_add(field_off), &mut buf)
                            .map_err(|e| format!("read: {e}"))?;
                        let value = if n >= width { bytes_to_json_num(vt, &buf) } else { Value::Null };
                        obj.insert(name, value);
                        cursor = field_off + width;
                    }
                    Ok(Value::Object(obj))
                }
                "mem.readStructArray" => {
                    // Read `count` structs of the given `layout` starting at `addr`
                    // in ONE syscall. `opts.stride` overrides the packed struct
                    // size. Returns an array of objects.
                    let addr = as_addr(arg(args, 0)?)?;
                    let fields = arg(args, 1)?
                        .as_array()
                        .ok_or_else(|| "readStructArray: layout must be an array".to_string())?;
                    let count = as_f64(arg(args, 2)?)? as usize;
                    // Parse the layout once: (name, type, width, offset).
                    let mut parsed: Vec<(String, nemclass_scan::ScanValueType, usize, usize)> = Vec::new();
                    let mut cursor = 0usize;
                    for f in fields {
                        let name = f
                            .get("name")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| "field needs a name".to_string())?
                            .to_string();
                        let ty = f
                            .get("type")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| "field needs a type".to_string())?;
                        let vt = nemclass_scan::ScanValueType::from_tag(ty)
                            .ok_or_else(|| format!("unknown type: {ty}"))?;
                        let width = vt.fixed_width().ok_or_else(|| format!("type {ty} has no fixed width"))?;
                        let off = f
                            .get("offset")
                            .and_then(|v| v.as_f64())
                            .map(|x| x as usize)
                            .unwrap_or(cursor);
                        parsed.push((name, vt, width, off));
                        cursor = off + width;
                    }
                    let stride = opt_arg(args, 3)
                        .and_then(|o| o.get("stride"))
                        .and_then(|v| v.as_f64())
                        .map(|x| x as usize)
                        .unwrap_or(cursor);
                    if stride == 0 {
                        return Err("readStructArray: struct stride is 0".to_string());
                    }
                    let total = count
                        .checked_mul(stride)
                        .ok_or_else(|| "readStructArray: size overflow".to_string())?;
                    if total > MAX_SCRIPT_READ {
                        return Err(format!("readStructArray span {total} exceeds cap"));
                    }
                    let mut buf = vec![0u8; total];
                    let n = self.proc()?.read_buf(addr, &mut buf).map_err(|e| format!("read: {e}"))?;
                    let avail = n / stride;
                    let arr: Vec<Value> = (0..avail)
                        .map(|i| {
                            let base = i * stride;
                            let mut obj = serde_json::Map::new();
                            for (name, vt, width, off) in &parsed {
                                let s = base + off;
                                let value = if s + width <= n {
                                    bytes_to_json_num(*vt, &buf[s..s + width])
                                } else {
                                    Value::Null
                                };
                                obj.insert(name.clone(), value);
                            }
                            Value::Object(obj)
                        })
                        .collect();
                    Ok(json!(arr))
                }
                "mem.writeStruct" => {
                    // Write the fields present in `values` back to a struct using
                    // the same `layout` shape as `readStruct`. Returns the count
                    // written.
                    let addr = as_addr(arg(args, 0)?)?;
                    let fields = arg(args, 1)?
                        .as_array()
                        .ok_or_else(|| "writeStruct: layout must be an array".to_string())?;
                    let values = arg(args, 2)?
                        .as_object()
                        .ok_or_else(|| "writeStruct: values must be an object".to_string())?;
                    let proc = self.proc()?;
                    let mut cursor = 0usize;
                    let mut written = 0usize;
                    for f in fields {
                        let name = f
                            .get("name")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| "writeStruct: field needs a name".to_string())?;
                        let ty = f
                            .get("type")
                            .and_then(|v| v.as_str())
                            .ok_or_else(|| "writeStruct: field needs a type".to_string())?;
                        let vt = nemclass_scan::ScanValueType::from_tag(ty)
                            .ok_or_else(|| format!("unknown type: {ty}"))?;
                        let width = vt
                            .fixed_width()
                            .ok_or_else(|| format!("type {ty} has no fixed width"))?;
                        let field_off = f
                            .get("offset")
                            .and_then(|v| v.as_f64())
                            .map(|x| x as usize)
                            .unwrap_or(cursor);
                        if let Some(v) = values.get(name) {
                            write_typed_value(proc, addr.wrapping_add(field_off), vt, v)?;
                            written += 1;
                        }
                        cursor = field_off + width;
                    }
                    Ok(json!(written as f64))
                }
                "mem.readI8" => self.read_num::<i8>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.readI16" => self.read_num::<i16>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.readI32" => self.read_num::<i32>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.readI64" => self.read_num::<i64>(as_addr(arg(args, 0)?)?, |v| json!(v as f64)),
                "mem.readU8" => self.read_num::<u8>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.readU16" => self.read_num::<u16>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.readU32" => self.read_num::<u32>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.readU64" => self.read_num::<u64>(as_addr(arg(args, 0)?)?, |v| json!(v as f64)),
                "mem.readU64Str" => self.read_num::<u64>(as_addr(arg(args, 0)?)?, |v| json!(v.to_string())),
                "mem.readF32" => self.read_num::<f32>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.readF64" => self.read_num::<f64>(as_addr(arg(args, 0)?)?, |v| json!(v)),
                "mem.writeI8" => self.write_num::<i8>(as_addr(arg(args, 0)?)?, as_i64(arg(args, 1)?)? as i8),
                "mem.writeI16" => self.write_num::<i16>(as_addr(arg(args, 0)?)?, as_i64(arg(args, 1)?)? as i16),
                "mem.writeI32" => self.write_num::<i32>(as_addr(arg(args, 0)?)?, as_i64(arg(args, 1)?)? as i32),
                "mem.writeI64" => self.write_num::<i64>(as_addr(arg(args, 0)?)?, as_i64(arg(args, 1)?)?),
                "mem.writeU8" => self.write_num::<u8>(as_addr(arg(args, 0)?)?, as_u64_flex(arg(args, 1)?)? as u8),
                "mem.writeU16" => self.write_num::<u16>(as_addr(arg(args, 0)?)?, as_u64_flex(arg(args, 1)?)? as u16),
                "mem.writeU32" => self.write_num::<u32>(as_addr(arg(args, 0)?)?, as_u64_flex(arg(args, 1)?)? as u32),
                "mem.writeU64" => self.write_num::<u64>(as_addr(arg(args, 0)?)?, as_u64_flex(arg(args, 1)?)?),
                "mem.writeF32" => self.write_num::<f32>(as_addr(arg(args, 0)?)?, as_f64(arg(args, 1)?)? as f32),
                "mem.writeF64" => self.write_num::<f64>(as_addr(arg(args, 0)?)?, as_f64(arg(args, 1)?)?),
                "mem.readPointer" => self.read_num::<usize>(as_addr(arg(args, 0)?)?, |v| json!(v as f64)),
                "mem.readString" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let max = as_f64(arg(args, 1)?)? as usize;
                    let enc = opt_arg(args, 2).map(as_str).transpose()?.unwrap_or_else(|| "utf8".into());
                    Ok(json!(self.read_string(addr, max, &enc)?))
                }
                "mem.writeString" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let s = as_str(arg(args, 1)?)?;
                    let enc = opt_arg(args, 2).map(as_str).transpose()?.unwrap_or_else(|| "utf8".into());
                    self.write_string(addr, &s, &enc)?;
                    Ok(json!(true))
                }
                "mem.readChain" => {
                    let base = as_addr(arg(args, 0)?)?;
                    let offsets: Vec<i64> = arg(args, 1)?
                        .as_array()
                        .ok_or("readChain: expected offsets array")?
                        .iter()
                        .map(as_i64)
                        .collect::<Result<_, _>>()?;
                    let proc = self.proc()?;
                    let mut addr = base;
                    for off in offsets {
                        let p = proc.read::<usize>(addr).map_err(|e| format!("chain read: {e}"))?;
                        // Reinterpret the (possibly negative) offset's bits and
                        // wrap, so high-half-canonical pointers don't corrupt via
                        // an i64 round-trip.
                        addr = p.wrapping_add(off as usize);
                    }
                    Ok(json!(addr as f64))
                }
                "mem.isValid" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let pid = self.proc()?.pid();
                    let idx = RegionIndex::from_pid(pid).map_err(|e| format!("regions: {e}"))?;
                    Ok(json!(idx.is_mapped(addr)))
                }
                "mem.freeze" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let ty = as_str(arg(args, 1)?)?;
                    let vt = ScanValueType::from_tag(&ty)
                        .ok_or_else(|| format!("mem.freeze: unknown type {ty:?}"))?;
                    let value = as_str(arg(args, 2)?)?;
                    // Validate the value parses for this type before pinning it.
                    if value_text_to_bytes(vt, &value).is_none() {
                        return Err(format!("mem.freeze: value {value:?} not valid for type {ty}"));
                    }
                    if let Some(slot) = self.script_freezes.iter_mut().find(|(a, ..)| *a == addr) {
                        *slot = (addr, vt, value);
                    } else {
                        self.script_freezes.push((addr, vt, value));
                    }
                    Ok(json!(true))
                }
                "mem.unfreeze" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let before = self.script_freezes.len();
                    self.script_freezes.retain(|(a, ..)| *a != addr);
                    Ok(json!(self.script_freezes.len() != before))
                }

                // ---- proc.* -------------------------------------------------
                "proc.attached" => Ok(json!(self.process.is_some())),
                "proc.pid" => Ok(json!(self.process.map(|p| p.pid()).unwrap_or(0))),
                "proc.name" => Ok(json!(self.proc()?.name().unwrap_or_default())),
                "proc.modules" => {
                    let mods: Vec<Value> = self
                        .modules()?
                        .iter()
                        .map(|m| json!({ "name": m.name, "base": m.base as f64, "size": m.size as f64 }))
                        .collect();
                    Ok(json!(mods))
                }
                "proc.module" => {
                    let name = as_str(arg(args, 0)?)?;
                    let hit = self
                        .modules()?
                        .into_iter()
                        .find(|m| m.name.eq_ignore_ascii_case(&name))
                        .map(|m| json!({ "name": m.name, "base": m.base as f64, "size": m.size as f64 }));
                    Ok(hit.unwrap_or(Value::Null))
                }
                "proc.moduleAt" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let hit = self
                        .modules()?
                        .into_iter()
                        .find(|m| addr >= m.base && addr < m.base.saturating_add(m.size))
                        .map(|m| json!({ "name": m.name, "base": m.base as f64, "size": m.size as f64 }));
                    Ok(hit.unwrap_or(Value::Null))
                }
                "proc.baseAddress" => {
                    let name = opt_arg(args, 0).map(as_str).transpose()?;
                    let (base, _) = self.module_bytes(name.as_deref())?;
                    Ok(json!(base as f64))
                }
                "proc.regions" => Ok(json!(self.regions())),
                "proc.regionAt" => {
                    let addr = as_addr(arg(args, 0)?)? as f64;
                    let region = self.regions().into_iter().find(|r| {
                        let start = r.get("start").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let end = r.get("end").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        addr >= start && addr < end
                    });
                    Ok(region.unwrap_or(Value::Null))
                }
                "proc.resolveSymbol" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let sym = self.proc()?.resolve_symbol(addr).map_err(|e| format!("resolve: {e}"))?;
                    Ok(sym.map(Value::String).unwrap_or(Value::Null))
                }
                "proc.exports" => self.proc_exports(args),
                "proc.resolveExport" => self.proc_resolve_export(args),

                // ---- scan.* -------------------------------------------------
                "scan.aob" => {
                    let pattern = as_str(arg(args, 0)?)?;
                    let module = opt_arg(args, 1).and_then(|o| o.get("module")).map(as_str).transpose()?;
                    let (base, bytes) = self.module_bytes(module.as_deref())?;
                    Ok(json!(scan_module(base, &bytes, &pattern).iter().map(|a| *a as f64).collect::<Vec<_>>()))
                }
                "scan.aobResolveRip" => {
                    // Fused: AOB scan (first hit) -> resolve the x64 RIP-relative
                    // target -> optionally deref. Returns the address, or null if
                    // the pattern isn't found. `opts = { module?, deref? }`.
                    let pattern = as_str(arg(args, 0)?)?;
                    let disp_off = as_f64(arg(args, 1)?)? as usize;
                    let instr_len = as_f64(arg(args, 2)?)? as usize;
                    let opts = opt_arg(args, 3);
                    let module = opts.and_then(|o| o.get("module")).map(as_str).transpose()?;
                    let deref = opts
                        .and_then(|o| o.get("deref"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let (base, bytes) = self.module_bytes(module.as_deref())?;
                    let Some(&insn) = scan_module(base, &bytes, &pattern).first() else {
                        return Ok(Value::Null);
                    };
                    let proc = self.proc()?;
                    let disp = proc
                        .read::<i32>(insn.wrapping_add(disp_off))
                        .map_err(|e| format!("read rel32: {e}"))? as i64;
                    let target = (insn as i64)
                        .wrapping_add(instr_len as i64)
                        .wrapping_add(disp) as usize;
                    let result = if deref {
                        proc.read::<usize>(target).map_err(|e| format!("deref: {e}"))?
                    } else {
                        target
                    };
                    Ok(json!(result as f64))
                }
                "scan.value" => {
                    let ty = as_str(arg(args, 0)?)?;
                    let value = as_str(arg(args, 1)?)?;
                    let module = opt_arg(args, 2).and_then(|o| o.get("module")).map(as_str).transpose()?;
                    let (base, bytes) = self.module_bytes(module.as_deref())?;
                    Ok(json!(self.value_scan(base, &bytes, &ty, &value)?))
                }
                "scan.range" => {
                    let start = as_addr(arg(args, 0)?)?;
                    let size = as_f64(arg(args, 1)?)? as usize;
                    let ty = as_str(arg(args, 2)?)?;
                    let value = as_str(arg(args, 3)?)?;
                    if size > MAX_SCRIPT_READ {
                        return Err(format!("scan.range size {size} exceeds cap of {MAX_SCRIPT_READ}"));
                    }
                    let mut bytes = vec![0u8; size];
                    let n = self.proc()?.read_buf(start, &mut bytes).map_err(|e| format!("read: {e}"))?;
                    bytes.truncate(n);
                    Ok(json!(self.value_scan(start, &bytes, &ty, &value)?))
                }
                "scan.pointer" => self.scan_pointer(args),
                "scan.rescan" => self.scan_rescan(args),
                "scan.makeSignature" => {
                    let addr = as_addr(arg(args, 0)?)?;
                    let (_base, bytes, off) = self.module_bytes_at(addr)?;
                    // Operand-masked signature (wildcards displacements/immediates)
                    // so it survives a rebased image.
                    let sig = nemclass_core::make_masked_signature(&bytes, off, 8, 128);
                    Ok(sig.map(Value::String).unwrap_or(Value::Null))
                }
                "scan.first" => self.scan_session_first(args),
                "scan.next" => self.scan_session_next(args),
                "scan.results" => self.scan_session_results(args),
                "scan.resultsWithValues" => self.scan_session_values(args),
                "scan.reset" => self.scan_session_reset(),
                "classes.fromPointer" => self.classes_from_pointer(args),

                // ---- classes.* ---------------------------------------------
                "classes.list" => {
                    let list: Vec<Value> = self
                        .project
                        .classes_in_order()
                        .map(|c| (c.uuid, c.name.clone(), c.address_formula.clone()))
                        .collect::<Vec<_>>()
                        .into_iter()
                        .map(|(uuid, name, formula)| {
                            let size = self.project.resolved_class_size(&uuid);
                            json!({ "uuid": uuid.to_string(), "name": name, "size": size as f64, "formula": formula })
                        })
                        .collect();
                    Ok(json!(list))
                }
                "classes.create" => {
                    let name = opt_arg(args, 0).map(as_str).transpose()?;
                    let name = name.unwrap_or_else(|| self.next_class_name());
                    let class = ClassNode::new(name.clone());
                    let uuid = class.uuid;
                    self.project.add_class(class);
                    push(&self.log, LogKind::Info, format!("classes.create: {name:?}"));
                    Ok(json!(uuid.to_string()))
                }
                "classes.get" => {
                    let key = as_str(arg(args, 0)?)?;
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(Value::Null) };
                    let class = self.project.get_class(&uuid).unwrap();
                    let nodes: Vec<Value> = class
                        .children
                        .iter()
                        .map(|n| json!({ "type": n.type_tag(), "name": n.name(), "comment": n.comment() }))
                        .collect();
                    Ok(json!({
                        "uuid": uuid.to_string(),
                        "name": class.name,
                        "formula": class.address_formula,
                        "nodes": nodes,
                    }))
                }
                "classes.setFormula" => {
                    let key = as_str(arg(args, 0)?)?;
                    let formula = as_str(arg(args, 1)?)?;
                    // Validate before storing. Without this an unparseable formula
                    // (e.g. a stray `0x0x1234` from double-prefixing) is silently
                    // accepted and the class simply never resolves — a confusing,
                    // silent failure for script authors. Empty is the valid
                    // "unresolved" default a freshly-created class carries.
                    if !formula.trim().is_empty()
                        && let Err(e) = nemclass_model::parse_address(&formula)
                    {
                        return Err(format!("invalid address formula {formula:?}: {e}"));
                    }
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(json!(false)) };
                    self.project.get_class_mut(&uuid).unwrap().address_formula = formula;
                    Ok(json!(true))
                }
                "classes.addNode" => {
                    let key = as_str(arg(args, 0)?)?;
                    let ty = as_str(arg(args, 1)?)?;
                    let opts = opt_arg(args, 2);
                    let name = opts.and_then(|o| o.get("name")).and_then(|v| v.as_str()).map(str::to_string);
                    let comment = opts.and_then(|o| o.get("comment")).and_then(|v| v.as_str()).map(str::to_string);
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(json!(false)) };
                    let Some(mut node) = self.node_registry.construct(&ty) else {
                        return Err(format!("unknown node type: {ty}"));
                    };
                    if let Some(n) = name { node.set_name(n); }
                    if let Some(c) = comment { node.set_comment(c); }
                    self.project.get_class_mut(&uuid).unwrap().children.push(node);
                    Ok(json!(true))
                }
                "classes.addNodeAt" => {
                    // Place a field so it STARTS at byte `offset`, padding any gap
                    // before it with Hex bytes. Errors if `offset` lands inside an
                    // existing field. Fields after the insertion shift down.
                    let key = as_str(arg(args, 0)?)?;
                    let offset = as_f64(arg(args, 1)?)? as usize;
                    let ty = as_str(arg(args, 2)?)?;
                    let opts = opt_arg(args, 3);
                    let name = opts.and_then(|o| o.get("name")).and_then(|v| v.as_str()).map(str::to_string);
                    let comment = opts.and_then(|o| o.get("comment")).and_then(|v| v.as_str()).map(str::to_string);
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(json!(false)) };
                    let Some(mut node) = self.node_registry.construct(&ty) else {
                        return Err(format!("unknown node type: {ty}"));
                    };
                    if let Some(n) = name { node.set_name(n); }
                    if let Some(c) = comment { node.set_comment(c); }

                    let registry = self.node_registry;
                    // Resolve each child's real byte width *before* taking the
                    // mutable borrow. `Node::memory_size()` reports 0 for a
                    // `ClassInstance` — it has no project context to look the
                    // target class up in — so walking the cursor with it placed
                    // every field after an embedded class at the wrong offset,
                    // and made the "falls inside an existing field" check fire
                    // on offsets that were in fact correct.
                    let child_sizes: Vec<usize> = {
                        let class = self.project.get_class(&uuid).unwrap();
                        class
                            .children
                            .iter()
                            .map(|child| {
                                let mut visited = std::collections::HashSet::from([uuid]);
                                nemclass_model::resolved_node_size(
                                    child.as_ref(),
                                    self.project,
                                    &mut visited,
                                )
                            })
                            .collect()
                    };
                    let class = self.project.get_class_mut(&uuid).unwrap();
                    // Walk children; `cursor` is the start offset of each child.
                    let mut cursor = 0usize;
                    let mut insert_at: Option<usize> = None;
                    for (i, size) in child_sizes.iter().enumerate() {
                        if cursor == offset {
                            insert_at = Some(i);
                            break;
                        }
                        if cursor > offset {
                            return Err(format!("offset {offset:#x} falls inside an existing field"));
                        }
                        cursor = cursor.saturating_add(*size);
                    }
                    match insert_at {
                        Some(i) => class.children.insert(i, node),
                        None => {
                            // `cursor` is now the total size; offset is at/after the end.
                            if offset < cursor {
                                return Err(format!("offset {offset:#x} falls inside an existing field"));
                            }
                            for pad in hex_fill(registry, offset - cursor) {
                                class.children.push(pad);
                            }
                            class.children.push(node);
                        }
                    }
                    Ok(json!(true))
                }
                "classes.setPointerTarget" => {
                    let key = as_str(arg(args, 0)?)?;
                    let path: Vec<usize> = arg(args, 1)?
                        .as_array()
                        .ok_or("path must be an array")?
                        .iter()
                        .map(|v| as_f64(v).map(|f| f as usize))
                        .collect::<Result<_, _>>()?;
                    let target_key = as_str(arg(args, 2)?)?;
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(json!(false)) };
                    let Some(target) = self.find_class_uuid(&target_key) else { return Ok(json!(false)) };
                    let class = self.project.get_class_mut(&uuid).unwrap();
                    match walk_node_mut(&mut class.children, &path) {
                        Some(node) => Ok(json!(node.set_pointer_target(target))),
                        None => Ok(json!(false)),
                    }
                }
                "classes.removeNode" => {
                    let key = as_str(arg(args, 0)?)?;
                    let path: Vec<usize> = arg(args, 1)?
                        .as_array()
                        .ok_or("path must be an array")?
                        .iter()
                        .map(|v| as_f64(v).map(|f| f as usize))
                        .collect::<Result<_, _>>()?;
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(json!(false)) };
                    let class = self.project.get_class_mut(&uuid).unwrap();
                    Ok(json!(remove_node(&mut class.children, &path)))
                }
                "classes.setNodeName" | "classes.setNodeComment" => {
                    let key = as_str(arg(args, 0)?)?;
                    let path: Vec<usize> = arg(args, 1)?
                        .as_array()
                        .ok_or("path must be an array")?
                        .iter()
                        .map(|v| as_f64(v).map(|f| f as usize))
                        .collect::<Result<_, _>>()?;
                    let text = as_str(arg(args, 2)?)?;
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(json!(false)) };
                    let class = self.project.get_class_mut(&uuid).unwrap();
                    match walk_node_mut(&mut class.children, &path) {
                        Some(node) => {
                            if method == "classes.setNodeName" {
                                node.set_name(text);
                            } else {
                                node.set_comment(text);
                            }
                            Ok(json!(true))
                        }
                        None => Ok(json!(false)),
                    }
                }
                "classes.resolveBase" => {
                    let key = as_str(arg(args, 0)?)?;
                    let Some(uuid) = self.find_class_uuid(&key) else { return Ok(Value::Null) };
                    let formula = self.project.get_class(&uuid).unwrap().address_formula.clone();
                    let proc = self.proc()?;
                    let mods = proc.modules().map_err(|e| format!("modules: {e}"))?.collect();
                    let reader = ProcessReader::new(proc, mods);
                    match nemclass_model::resolve_formula(&formula, &reader, &reader) {
                        Ok(addr) => Ok(json!(addr as f64)),
                        Err(_) => Ok(Value::Null),
                    }
                }
                "classes.dissect" => self.classes_dissect(args),

                // ---- disasm.* ----------------------------------------------
                "disasm.at" => {
                    let addr = as_addr(arg(args, 0)?)? as u64;
                    let count = opt_arg(args, 1).map(as_f64).transpose()?.map(|f| f as usize).unwrap_or(16);
                    self.disasm_at(addr, count)
                }
                "disasm.func" => {
                    let addr = as_addr(arg(args, 0)?)? as u64;
                    self.disasm_func(addr)
                }
                // Decode a raw byte array (e.g. a dumped snippet / shellcode) —
                // no process needed, works on any platform.
                "disasm.decodeBytes" => {
                    let bytes: Vec<u8> = arg(args, 0)?
                        .as_array()
                        .ok_or("decodeBytes: expected a byte array")?
                        .iter()
                        .map(|v| as_f64(v).map(|f| f as u8))
                        .collect::<Result<_, _>>()?;
                    let base = opt_arg(args, 1).map(as_addr).transpose()?.unwrap_or(0) as u64;
                    let mut out: Vec<Value> = Vec::new();
                    nemclass_core::disassemble_instructions(&bytes, base, false, |ins| {
                        out.push(insn_json(&ins));
                        true
                    });
                    Ok(json!(out))
                }
                "disasm.xrefsTo" => self.disasm_xrefs_to(args),

                // ---- ui.* ---------------------------------------------------
                "ui.notify" => {
                    let msg = as_str(arg(args, 0)?)?;
                    push(&self.log, LogKind::Info, msg.clone());
                    *self.last_error = Some(msg);
                    Ok(Value::Null)
                }
                "ui.gotoMemory" => {
                    self.ui_actions.push(UiAction::GotoMemory(as_addr(arg(args, 0)?)?));
                    Ok(Value::Null)
                }
                "ui.gotoDisasm" => {
                    self.ui_actions.push(UiAction::GotoDisasm(as_addr(arg(args, 0)?)?));
                    Ok(Value::Null)
                }
                "ui.selectClass" => {
                    let key = as_str(arg(args, 0)?)?;
                    match self.find_class_uuid(&key) {
                        Some(uuid) => {
                            self.ui_actions.push(UiAction::SelectClass(uuid));
                            Ok(Value::Null)
                        }
                        None => Err(format!("class not found: {key}")),
                    }
                }

                // ---- table.* ------------------------------------------------
                "table.add" => {
                    let obj = arg(args, 0)?
                        .as_object()
                        .ok_or("table.add: expected object argument")?;
                    let description = obj.get("description")
                        .and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    let address = obj.get("address")
                        .and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    let value_type = obj.get("type")
                        .and_then(|v| v.as_str()).unwrap_or("i32").to_owned();
                    let frozen = obj.get("frozen")
                        .and_then(|v| v.as_bool()).unwrap_or(false);
                    let frozen_value = obj.get("value")
                        .and_then(|v| v.as_str()).unwrap_or("").to_owned();
                    let idx = self.cheat_table.entries.len();
                    self.cheat_table.push(nemclass_model::CheatEntry {
                        description, address, value_type, frozen,
                        frozen_value, group: String::new(),
                    });
                    Ok(json!(idx))
                }
                "table.list" => {
                    let entries: Vec<Value> = self.cheat_table.entries.iter().enumerate().map(|(i, e)| {
                        json!({
                            "index": i,
                            "description": e.description,
                            "address": e.address,
                            "type": e.value_type,
                            "frozen": e.frozen,
                        })
                    }).collect();
                    Ok(json!(entries))
                }
                "table.remove" => {
                    let idx = as_u64_flex(arg(args, 0)?)? as usize;
                    Ok(json!(self.cheat_table.remove(idx).is_some()))
                }
                "table.freeze" => {
                    let idx = as_u64_flex(arg(args, 0)?)? as usize;
                    // Optional value to pin to; the freeze is applied from the
                    // model each tick, so `frozen_value` must be set here.
                    let value = opt_arg(args, 1).map(as_str).transpose()?;
                    let ok = if let Some(e) = self.cheat_table.entries.get_mut(idx) {
                        e.frozen = true;
                        if let Some(v) = value {
                            e.frozen_value = v;
                        }
                        true
                    } else {
                        false
                    };
                    Ok(json!(ok))
                }
                "table.unfreeze" => {
                    let idx = as_u64_flex(arg(args, 0)?)? as usize;
                    let ok = if let Some(e) = self.cheat_table.entries.get_mut(idx) {
                        e.frozen = false; true
                    } else { false };
                    Ok(json!(ok))
                }
                "table.save" => {
                    let name = as_str(arg(args, 0)?)?;
                    self.ui_actions.push(UiAction::SaveTable(name));
                    Ok(Value::Null)
                }
                "table.load" => {
                    let name = as_str(arg(args, 0)?)?;
                    self.ui_actions.push(UiAction::LoadTable(name));
                    Ok(Value::Null)
                }

                // ---- enums.* ------------------------------------------------
                "enums.define" => {
                    let name = as_str(arg(args, 0)?)?;
                    let values_obj = arg(args, 1)?
                        .as_object()
                        .ok_or("enums.define: `values` must be an object")?;
                    let mut values: Vec<(String, i64)> = Vec::with_capacity(values_obj.len());
                    for (k, v) in values_obj {
                        let n = v
                            .as_i64()
                            .or_else(|| v.as_f64().map(|f| f as i64))
                            .ok_or_else(|| format!("enums.define: value for {k:?} must be an integer"))?;
                        values.push((k.clone(), n));
                    }
                    let mut size: u8 = 4;
                    let mut use_flags = false;
                    if let Some(opts) = opt_arg(args, 2).and_then(|v| v.as_object()) {
                        if let Some(s) = opts.get("size").and_then(|v| v.as_u64()) {
                            size = match s {
                                1 | 2 | 4 | 8 => s as u8,
                                _ => return Err(format!("enums.define: size must be 1/2/4/8, got {s}")),
                            };
                        }
                        if let Some(f) = opts.get("flags").and_then(|v| v.as_bool()) {
                            use_flags = f;
                        }
                    }
                    let mut desc = EnumDescription::new(name.clone());
                    desc.size = size;
                    desc.use_flags = use_flags;
                    desc.values = values;
                    self.declare_type(desc)?;
                    Ok(json!(true))
                }
                "enums.list" => {
                    let out: Vec<Value> =
                        self.project.enums.iter().map(enum_to_json).collect();
                    Ok(json!(out))
                }
                "enums.get" => {
                    let name = as_str(arg(args, 0)?)?;
                    Ok(match self.project.enums.iter().find(|e| e.name == name) {
                        Some(e) => enum_to_json(e),
                        None => Value::Null,
                    })
                }

                // ---- hotkeys.* ----------------------------------------------
                "hotkeys.register" => {
                    let combo = as_str(arg(args, 0)?)?;
                    let (ctrl, shift, alt, key) = parse_hotkey(&combo)
                        .ok_or_else(|| format!("hotkeys.register: bad combo {combo:?}"))?;
                    let id = *self.next_hotkey_id;
                    *self.next_hotkey_id = self.next_hotkey_id.wrapping_add(1);
                    self.script_hotkeys.push(super::super::HotkeyReg {
                        id, ctrl, shift, alt, key,
                    });
                    Ok(json!(id))
                }
                "hotkeys.unregister" => {
                    let id = as_u64_flex(arg(args, 0)?)? as u32;
                    let before = self.script_hotkeys.len();
                    self.script_hotkeys.retain(|h| h.id != id);
                    Ok(json!(self.script_hotkeys.len() != before))
                }

                other => Err(format!("unknown host method: {other}")),
            }
        }
    }

    // ---- longer helpers kept off the giant match ---------------------------

    impl<'a> UiHostApi<'a> {
        /// `scan.pointer(goal, opts?)` — pointer-chain scan (Linux only).
        fn scan_pointer(&self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                use nemclass_scan::{PointerScanConfig, ProcessTarget, Region};
                let goal = as_addr(arg(args, 0)?)?;
                let opts = opt_arg(args, 1);
                let max_depth = opts
                    .and_then(|o| o.get("maxDepth"))
                    .map(as_f64)
                    .transpose()?
                    .map(|f| f as usize)
                    .unwrap_or(5)
                    .clamp(1, 12);
                let max_offset = opts
                    .and_then(|o| o.get("maxOffset"))
                    .map(as_f64)
                    .transpose()?
                    .map(|f| f as usize)
                    .unwrap_or(0x1000);

                let pid = self.proc()?.pid();
                let mods = self.modules()?;
                let static_ranges: Vec<Region> =
                    mods.iter().map(|m| Region::new(m.base, m.size)).collect();
                if static_ranges.is_empty() {
                    return Err("no modules to anchor pointer scan".to_string());
                }
                let target = ProcessTarget::attach(pid)
                    .map_err(|e| format!("ProcessTarget: {e}"))?;
                let cfg = PointerScanConfig {
                    max_depth,
                    max_offset,
                    static_ranges,
                    ..Default::default()
                };
                let result = nemclass_scan::pointer_scan(&target, goal, &cfg)
                    .map_err(|e| format!("pointer_scan: {e}"))?;

                let paths: Vec<Value> = result
                    .paths
                    .iter()
                    .map(|p| {
                        let module = mods.iter().find(|m| {
                            p.base >= m.base && p.base < m.base.saturating_add(m.size)
                        });
                        let formula = match module {
                            Some(m) => p.to_formula(&m.name, m.base),
                            None => p.to_formula("unknown", 0),
                        };
                        json!({
                            "formula": formula,
                            "base": p.base as f64,
                            "depth": p.offsets.len() as f64,
                            "offsets": p.offsets.iter().map(|o| *o as f64).collect::<Vec<_>>(),
                        })
                    })
                    .collect();
                Ok(json!(paths))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("pointer scan is Linux-only".to_string())
            }
        }

        /// `scan.first(type, value?, compare?)` — start a Cheat-Engine-style
        /// iterative scan session over the whole target. Builds a fresh
        /// `Scanner<ProcessTarget>`, runs the first scan, stores it, and returns
        /// the match count (Linux only).
        #[allow(unused_variables)]
        fn scan_session_first(&mut self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                use nemclass_scan::{ProcessTarget, ScanCompareType, Scanner};

                let ty = as_str(arg(args, 0)?)?;
                let vt = ScanValueType::from_tag(&ty)
                    .ok_or_else(|| format!("scan.first: unknown type {ty:?}"))?;
                // Default compare is `exact`; `unknown` seeds a change-relative
                // baseline with no needle.
                let compare = match opt_arg(args, 2) {
                    Some(v) => {
                        let tag = as_str(v)?;
                        ScanCompareType::from_tag(&tag)
                            .ok_or_else(|| format!("scan.first: unknown compare {tag:?}"))?
                    }
                    None => ScanCompareType::Exact,
                };
                if compare.needs_previous() {
                    return Err(format!(
                        "scan.first: compare {compare:?} needs a previous scan; use it in scan.next"
                    ));
                }
                let needle = parse_scan_needle(vt, opt_arg(args, 1), compare)?;

                let pid = self.proc()?.pid();
                let target = ProcessTarget::attach(pid)
                    .map_err(|e| format!("ProcessTarget: {e}"))?;
                let mut scanner = Scanner::new(target, vt);
                let count = scanner
                    .first_scan(compare, needle)
                    .map_err(|e| format!("scan.first: {e}"))?
                    .len();
                *self.script_scanner = Some(scanner);
                Ok(json!(count as f64))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("scan.first is Linux-only".to_string())
            }
        }

        /// `scan.next(compare, value?)` — refine the active scan session and
        /// return the new match count (Linux only).
        #[allow(unused_variables)]
        fn scan_session_next(&mut self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                use nemclass_scan::ScanCompareType;

                let tag = as_str(arg(args, 0)?)?;
                let compare = ScanCompareType::from_tag(&tag)
                    .ok_or_else(|| format!("scan.next: unknown compare {tag:?}"))?;
                // The engine rejects this too, but naming the API here makes the
                // script error actionable rather than generic.
                if compare.is_baseline() {
                    return Err(format!(
                        "scan.next: {tag:?} is a first-scan baseline — pass it to scan.first, \
                         then narrow with \"changed\"/\"increased\"/\"decreased\" or a value"
                    ));
                }
                let scanner = self
                    .script_scanner
                    .as_mut()
                    .ok_or("scan.next: no active scan session — call scan.first first")?;
                let needle = parse_scan_needle(scanner.value_type(), opt_arg(args, 1), compare)?;
                let count = scanner
                    .next_scan(compare, needle)
                    .map_err(|e| format!("scan.next: {e}"))?
                    .len();
                Ok(json!(count as f64))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("scan.next is Linux-only".to_string())
            }
        }

        /// `scan.results(max?)` — up to `max` (default 1000, cap 100000) result
        /// addresses from the active session (Linux only).
        #[allow(unused_variables)]
        fn scan_session_results(&self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                const DEFAULT_MAX: usize = 1_000;
                const HARD_CAP: usize = 100_000;
                let max = opt_arg(args, 0)
                    .map(as_f64)
                    .transpose()?
                    .map(|f| (f as usize).min(HARD_CAP))
                    .unwrap_or(DEFAULT_MAX);
                let scanner = self
                    .script_scanner
                    .as_ref()
                    .ok_or("scan.results: no active scan session")?;
                let addrs: Vec<f64> = scanner
                    .results()
                    .iter()
                    .take(max)
                    .map(|r| r.address as f64)
                    .collect();
                Ok(json!(addrs))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("scan.results is Linux-only".to_string())
            }
        }

        /// `scan.resultsWithValues(max?)` — like `scan.results` but returns
        /// `{address, value, previous}` triples: `value` is read live from the
        /// target right now, `previous` is what the address held as of the scan
        /// generation before the current one.
        fn scan_session_values(&self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                use nemclass_scan::ScanTarget;
                const DEFAULT_MAX: usize = 1_000;
                const HARD_CAP: usize = 100_000;
                let max = opt_arg(args, 0)
                    .map(as_f64)
                    .transpose()?
                    .map(|f| (f as usize).min(HARD_CAP))
                    .unwrap_or(DEFAULT_MAX);
                let scanner = self
                    .script_scanner
                    .as_ref()
                    .ok_or("scan.resultsWithValues: no active scan session")?;
                let vt = scanner.value_type();
                let width = vt.fixed_width().unwrap_or(0);
                let target = scanner.target();
                let out: Vec<Value> = scanner
                    .results()
                    .iter()
                    .take(max)
                    .map(|r| {
                        let value = if width > 0 {
                            let mut buf = vec![0u8; width];
                            match target.read(r.address, &mut buf) {
                                Ok(n) if n >= width => bytes_to_json_num(vt, &buf),
                                _ => Value::Null,
                            }
                        } else {
                            Value::Null
                        };
                        json!({
                            "address": r.address as f64,
                            "value": value,
                            "previous": bytes_to_json_num(vt, r.previous),
                        })
                    })
                    .collect();
                Ok(json!(out))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("scan.resultsWithValues is Linux-only".to_string())
            }
        }

        /// `scan.reset()` — drop the active scan session; returns whether one
        /// existed (Linux only).
        fn scan_session_reset(&mut self) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                Ok(json!(self.script_scanner.take().is_some()))
            }
            #[cfg(not(target_os = "linux"))]
            {
                Err("scan.reset is Linux-only".to_string())
            }
        }

        /// `scan.rescan(paths, goal)` — keep only the given pointer paths that
        /// still resolve to `goal` in current memory (Linux only). Each path is a
        /// `{ base, offsets }` object as returned by `scan.pointer`.
        fn scan_rescan(&self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                let paths = arg(args, 0)?
                    .as_array()
                    .ok_or("paths must be an array")?;
                let goal = as_addr(arg(args, 1)?)?;
                let proc = self.proc()?;
                let read_ptr = |a: usize| proc.read::<u64>(a).ok().map(|v| v as usize);
                let kept: Vec<Value> = paths
                    .iter()
                    .filter(|p| {
                        let Some(base) = p.get("base").and_then(|v| v.as_f64()) else {
                            return false;
                        };
                        // Signed: a chain may step backwards from a pointer
                        // stored in the middle of a structure.
                        let offsets: Vec<isize> = p
                            .get("offsets")
                            .and_then(|o| o.as_array())
                            .map(|a| a.iter().filter_map(|v| v.as_f64().map(|x| x as isize)).collect())
                            .unwrap_or_default();
                        let path = nemclass_scan::PointerPath { base: base as usize, offsets };
                        path.resolve(read_ptr) == Some(goal)
                    })
                    .cloned()
                    .collect();
                Ok(json!(kept))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("scan.rescan is Linux-only".to_string())
            }
        }

        /// `classes.dissect(key, opts?)` — auto-generate the class body by
        /// dissecting `size` bytes at the class's resolved base (Linux only).
        /// Returns the number of fields generated. Replaces the class children.
        fn classes_dissect(&mut self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                use nemclass_core::{classify_in_process, RegionIndex};
                let key = as_str(arg(args, 0)?)?;
                let size = opt_arg(args, 1)
                    .and_then(|o| o.get("size"))
                    .and_then(|v| v.as_f64())
                    .map(|f| f as usize)
                    .unwrap_or(0x200)
                    .min(MAX_SCRIPT_READ);
                let Some(uuid) = self.find_class_uuid(&key) else {
                    return Ok(json!(false));
                };

                // Resolve the class base via its address formula.
                let formula = self.project.get_class(&uuid).unwrap().address_formula.clone();
                let proc = self.proc()?;
                let mods: Vec<_> = proc.modules().map_err(|e| format!("modules: {e}"))?.collect();
                let reader = ProcessReader::new(proc, mods);
                let base = nemclass_model::resolve_formula(&formula, &reader, &reader)
                    .map_err(|e| format!("resolve base: {e}"))?;

                // Read the region and dissect it into node definitions.
                let mut buf = vec![0u8; size];
                let n = proc.read_buf(base, &mut buf).map_err(|e| format!("read: {e}"))?;
                buf.truncate(n);
                let index = RegionIndex::from_pid(proc.pid()).map_err(|e| format!("regions: {e}"))?;
                let defs = nemclass_model::dissect::dissect_buffer(base, &buf, |w| {
                    classify_in_process(w, &index, proc)
                });
                let count = defs.len();

                // Materialise nodes, then replace the class body.
                let mut nodes = Vec::with_capacity(count);
                for def in defs {
                    nodes.push(
                        self.node_registry
                            .deserialize_node(def)
                            .map_err(|e| format!("node: {e}"))?,
                    );
                }
                if let Some(class) = self.project.get_class_mut(&uuid) {
                    class.children = nodes;
                }
                Ok(json!(count as f64))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("classes.dissect is Linux-only".to_string())
            }
        }

        /// `disasm.xrefsTo(addr)` — code sites referencing `addr` (call/jump/
        /// RIP-relative) within its module's executable regions (Linux only).
        fn disasm_xrefs_to(&self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                const CAP: usize = 10_000;
                let target = as_addr(arg(args, 0)?)? as u64;
                let mods = self.modules()?;
                let m = mods
                    .iter()
                    .find(|m| {
                        (target as usize) >= m.base
                            && (target as usize) < m.base.saturating_add(m.size)
                    })
                    .ok_or_else(|| format!("0x{target:x} is not inside any module"))?;
                let proc = self.proc()?;
                let regions = nemclass_core::module_exec_regions(proc.pid(), m.base, m.size)
                    .map_err(|e| format!("exec regions: {e}"))?;
                // Read/scan each exec region in bounded chunks (a large `.text`
                // must not drive one huge allocation). An `OVERLAP` re-reads the
                // trailing bytes so an instruction straddling a chunk edge is
                // still decoded; refs in that overlap are attributed to the next
                // chunk to avoid double-counting.
                const CHUNK: usize = 1 << 20; // 1 MiB
                const OVERLAP: usize = 16; // max x86 instruction length
                let mut refs: Vec<f64> = Vec::new();
                let mut buf = vec![0u8; CHUNK + OVERLAP];
                'outer: for (start, end) in regions {
                    let region_len = end.saturating_sub(start) as usize;
                    let mut pos = 0usize;
                    while pos < region_len {
                        let want = (region_len - pos).min(CHUNK + OVERLAP);
                        let chunk_base = start + pos as u64;
                        let n = proc.read_buf(chunk_base as usize, &mut buf[..want]).unwrap_or(0);
                        let last = pos + want >= region_len;
                        for a in nemclass_core::find_code_refs(&buf[..n], chunk_base, target) {
                            // Skip the trailing-overlap refs (re-scanned as the
                            // head of the next chunk), except on the final chunk.
                            if !last && (a - chunk_base) as usize >= CHUNK {
                                continue;
                            }
                            refs.push(a as f64);
                            if refs.len() >= CAP {
                                break 'outer;
                            }
                        }
                        if want <= OVERLAP {
                            break;
                        }
                        pos += want - OVERLAP;
                    }
                }
                Ok(json!(refs))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("disasm.xrefsTo is Linux-only".to_string())
            }
        }

        /// `proc.exports(module?)` — exported symbols of a module (Linux only).
        fn proc_exports(&self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                let name = opt_arg(args, 0).map(as_str).transpose()?;
                let mods = self.modules()?;
                let info = match name {
                    Some(n) => mods
                        .iter()
                        .find(|m| m.name.eq_ignore_ascii_case(&n))
                        .ok_or_else(|| format!("module not found: {n}"))?,
                    None => mods.first().ok_or_else(|| "no modules".to_string())?,
                };
                let syms = self
                    .proc()?
                    .exports(info.base)
                    .map_err(|e| format!("exports: {e}"))?;
                Ok(json!(syms
                    .iter()
                    .map(|s| json!({ "name": s.name, "address": s.address as f64 }))
                    .collect::<Vec<_>>()))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("proc.exports is Linux-only".to_string())
            }
        }

        /// `proc.resolveExport(module, name)` — address of an exported symbol (Linux only).
        fn proc_resolve_export(&self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                let module = as_str(arg(args, 0)?)?;
                let sym = as_str(arg(args, 1)?)?;
                let info = self
                    .modules()?
                    .into_iter()
                    .find(|m| m.name.eq_ignore_ascii_case(&module))
                    .ok_or_else(|| format!("module not found: {module}"))?;
                let addr = self
                    .proc()?
                    .resolve(info.base, &sym)
                    .map_err(|e| format!("resolve: {e}"))?;
                Ok(addr.map(|a| json!(a as f64)).unwrap_or(Value::Null))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("proc.resolveExport is Linux-only".to_string())
            }
        }

        /// `classes.fromPointer(goal, name?, opts?)` — scan + create a class (Linux only).
        fn classes_from_pointer(&mut self, args: &Value) -> Result<Value, String> {
            #[cfg(target_os = "linux")]
            {
                use nemclass_scan::{PointerScanConfig, ProcessTarget, Region};
                let goal = as_addr(arg(args, 0)?)?;
                let name = opt_arg(args, 1).map(as_str).transpose()?;
                let opts = opt_arg(args, 2);
                let max_depth = opts
                    .and_then(|o| o.get("maxDepth"))
                    .map(as_f64)
                    .transpose()?
                    .map(|f| f as usize)
                    .unwrap_or(5)
                    .clamp(1, 12);
                let max_offset = opts
                    .and_then(|o| o.get("maxOffset"))
                    .map(as_f64)
                    .transpose()?
                    .map(|f| f as usize)
                    .unwrap_or(0x1000);

                let pid = self.proc()?.pid();
                let mods = self.modules()?;
                let static_ranges: Vec<Region> =
                    mods.iter().map(|m| Region::new(m.base, m.size)).collect();
                if static_ranges.is_empty() {
                    return Err("no modules to anchor pointer scan".to_string());
                }
                let target = ProcessTarget::attach(pid)
                    .map_err(|e| format!("ProcessTarget: {e}"))?;
                let cfg = PointerScanConfig {
                    max_depth,
                    max_offset,
                    static_ranges,
                    ..Default::default()
                };
                let result = nemclass_scan::pointer_scan(&target, goal, &cfg)
                    .map_err(|e| format!("pointer_scan: {e}"))?;

                let first = match result.paths.first() {
                    Some(p) => p,
                    None => return Ok(Value::Null),
                };
                let module = mods.iter().find(|m| {
                    first.base >= m.base && first.base < m.base.saturating_add(m.size)
                });
                let formula = match module {
                    Some(m) => first.to_formula(&m.name, m.base),
                    None => first.to_formula("unknown", 0),
                };

                // Determine class name: provided, else auto-generated.
                let class_name = name.unwrap_or_else(|| {
                    let existing: std::collections::HashSet<String> =
                        self.project.classes_in_order().map(|c| c.name.clone()).collect();
                    (1..).find_map(|n| {
                        let c = format!("Class {n}");
                        if !existing.contains(&c) { Some(c) } else { None }
                    }).unwrap_or_else(|| "Class".to_string())
                });

                let mut class = nemclass_model::ClassNode::new(class_name.clone());
                class.address_formula = formula;
                let uuid = class.uuid;
                self.project.add_class(class);
                push(&self.log, LogKind::Info, format!("classes.fromPointer: created {class_name:?}"));
                Ok(json!(uuid.to_string()))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                Err("pointer scan is Linux-only".to_string())
            }
        }

        fn read_string(&self, addr: usize, max: usize, enc: &str) -> Result<String, String> {
            let proc = self.proc()?;
            // Cap the length a script can request so a huge value can't drive a
            // process-aborting allocation / unbounded loop.
            let max = max.min(MAX_SCRIPT_READ);
            if enc.eq_ignore_ascii_case("utf16") {
                let mut units = Vec::new();
                for i in 0..max {
                    let u = proc.read::<u16>(addr + i * 2).map_err(|e| format!("read: {e}"))?;
                    if u == 0 { break; }
                    units.push(u);
                }
                Ok(String::from_utf16_lossy(&units))
            } else {
                let mut bytes = vec![0u8; max];
                let n = proc.read_buf(addr, &mut bytes).map_err(|e| format!("read: {e}"))?;
                bytes.truncate(n);
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                Ok(String::from_utf8_lossy(&bytes[..end]).to_string())
            }
        }

        fn write_string(&self, addr: usize, s: &str, enc: &str) -> Result<(), String> {
            let proc = self.proc()?;
            if enc.eq_ignore_ascii_case("utf16") {
                let mut units: Vec<u16> = s.encode_utf16().collect();
                units.push(0);
                for (i, u) in units.iter().enumerate() {
                    proc.write::<u16>(addr + i * 2, *u).map_err(|e| format!("write: {e}"))?;
                }
            } else {
                let mut bytes = s.as_bytes().to_vec();
                bytes.push(0);
                for (i, b) in bytes.iter().enumerate() {
                    proc.write::<u8>(addr + i, *b).map_err(|e| format!("write: {e}"))?;
                }
            }
            Ok(())
        }

        /// Linux memory regions (reads `/proc/<pid>/maps`). Empty on other OSes.
        #[cfg(target_os = "linux")]
        fn regions(&self) -> Vec<Value> {
            let Ok(proc) = self.proc() else { return Vec::new() };
            let path = format!("/proc/{}/maps", proc.pid());
            let Ok(maps) = std::fs::read_to_string(path) else { return Vec::new() };
            let mut out = Vec::new();
            for line in maps.lines() {
                let mut fields = line.split_whitespace();
                let Some(range) = fields.next() else { continue };
                let perms = fields.next().unwrap_or("----");
                let Some((from, to)) = range.split_once('-') else { continue };
                let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(from, 16),
                    usize::from_str_radix(to, 16),
                ) else {
                    continue;
                };
                out.push(json!({
                    "start": start as f64,
                    "size": (end - start) as f64,
                    "end": end as f64,
                    "perms": perms,
                }));
            }
            out
        }

        #[cfg(not(target_os = "linux"))]
        fn regions(&self) -> Vec<Value> {
            Vec::new()
        }

        /// Exact value scan over a module image buffer.
        fn value_scan(&self, base: usize, bytes: &[u8], ty: &str, value: &str) -> Result<Vec<f64>, String> {
            use nemclass_scan::{ScanCompareType, ScanValueType};
            let vt = match ty.to_ascii_lowercase().as_str() {
                "i8" => ScanValueType::I8,
                "i16" => ScanValueType::I16,
                "i32" => ScanValueType::I32,
                "i64" => ScanValueType::I64,
                "u8" => ScanValueType::U8,
                "u16" => ScanValueType::U16,
                "u32" => ScanValueType::U32,
                "u64" => ScanValueType::U64,
                "f32" => ScanValueType::F32,
                "f64" => ScanValueType::F64,
                other => return Err(format!("unknown scan type: {other}")),
            };
            let needle = vt.parse_needle(value).map_err(|e| format!("bad value: {e}"))?;
            let stride = needle.stride().max(1);
            const CAP: usize = 10_000;
            let mut hits = Vec::new();
            let mut off = 0;
            while off + stride <= bytes.len() {
                if needle.compare_first(bytes, off, ScanCompareType::Exact) {
                    hits.push((base + off) as f64);
                    if hits.len() >= CAP {
                        push(
                            &self.log,
                            LogKind::Warn,
                            format!("scan.value: truncated at {CAP} hits"),
                        );
                        break;
                    }
                }
                off += 1;
            }
            Ok(hits)
        }

        #[cfg(target_os = "linux")]
        fn disasm_at(&self, addr: u64, count: usize) -> Result<Value, String> {
            let proc = self.proc()?;
            let insns = nemclass_core::disassemble_range(proc, addr, count.saturating_mul(15))
                .map_err(|e| format!("disasm: {e}"))?;
            Ok(json!(insns.iter().take(count).map(insn_json).collect::<Vec<_>>()))
        }

        #[cfg(target_os = "linux")]
        fn disasm_func(&self, addr: u64) -> Result<Value, String> {
            let proc = self.proc()?;
            let f = nemclass_core::disassemble_function(proc, addr, 4096)
                .map_err(|e| format!("disasm: {e}"))?;
            Ok(json!(f.instructions.iter().map(insn_json).collect::<Vec<_>>()))
        }

        #[cfg(not(target_os = "linux"))]
        fn disasm_at(&self, _addr: u64, _count: usize) -> Result<Value, String> {
            Err("disassembly is Linux-only".to_string())
        }

        #[cfg(not(target_os = "linux"))]
        fn disasm_func(&self, _addr: u64) -> Result<Value, String> {
            Err("disassembly is Linux-only".to_string())
        }

        /// Next auto class name (`Class N`), deduped against existing names.
        fn next_class_name(&self) -> String {
            let existing: std::collections::HashSet<String> =
                self.project.classes_in_order().map(|c| c.name.clone()).collect();
            for n in 1.. {
                let candidate = format!("Class {n}");
                if !existing.contains(&candidate) {
                    return candidate;
                }
            }
            "Class".to_string()
        }
    }

    /// JSON for one disassembled instruction.
    #[cfg(target_os = "linux")]
    fn insn_json(i: &nemclass_core::InstructionData) -> Value {
        let bytes: String = i.data.iter().map(|b| format!("{b:02X}")).collect();
        let mut obj = json!({
            "address": i.address as f64,
            "bytes": bytes,
            "text": i.instruction,
        });
        if let (Some(t), Some(map)) = (i.target, obj.as_object_mut()) {
            map.insert("target".to_string(), json!(t as f64));
        }
        obj
    }

    /// Walks a `children` tree by a child-index `path`, returning the addressed
    /// node mutably. An empty path is invalid (`None`).
    fn walk_node_mut<'n>(
        children: &'n mut [Box<dyn Node>],
        path: &[usize],
    ) -> Option<&'n mut Box<dyn Node>> {
        let (&first, rest) = path.split_first()?;
        let node = children.get_mut(first)?;
        if rest.is_empty() {
            return Some(node);
        }
        let kids = node.children_mut()?;
        walk_node_mut(kids, rest)
    }

    /// Removes the node addressed by `path`. Returns whether a node was removed.
    fn remove_node(children: &mut Vec<Box<dyn Node>>, path: &[usize]) -> bool {
        match path.split_first() {
            Some((&idx, [])) => {
                if idx < children.len() {
                    children.remove(idx);
                    true
                } else {
                    false
                }
            }
            Some((&idx, rest)) => match children.get_mut(idx).and_then(|n| n.children_mut()) {
                Some(kids) => remove_node(kids, rest),
                None => false,
            },
            None => false,
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{bytes_to_json_num, hex_fill};
        use nemclass_model::NodeRegistry;
        use nemclass_scan::ScanValueType as T;
        use serde_json::json;

        #[test]
        fn hex_fill_sums_to_gap_greedily() {
            let reg = NodeRegistry::new().with_builtins();
            for gap in [0usize, 1, 2, 4, 7, 8, 13, 32, 100] {
                let total: usize = hex_fill(&reg, gap).iter().map(|n| n.memory_size()).sum();
                assert_eq!(total, gap, "hex_fill({gap}) must sum to {gap}");
            }
            // 13 = Hex64 + Hex32 + Hex8 (greedy).
            assert_eq!(hex_fill(&reg, 13).len(), 3);
        }

        #[test]
        fn bytes_to_json_num_parses_each_type() {
            // Little-endian parse per type, used by `mem.readValues`.
            assert_eq!(bytes_to_json_num(T::I32, &1337i32.to_le_bytes()), json!(1337.0));
            assert_eq!(bytes_to_json_num(T::U8, &[0xFF]), json!(255.0));
            assert_eq!(bytes_to_json_num(T::I8, &[0xFF]), json!(-1.0));
            assert_eq!(bytes_to_json_num(T::I16, &(-2i16).to_le_bytes()), json!(-2.0));
            assert_eq!(bytes_to_json_num(T::U32, &0xDEADBEEFu32.to_le_bytes()), json!(0xDEADBEEFu32 as f64));
            assert_eq!(bytes_to_json_num(T::F32, &1.5f32.to_le_bytes()), json!(1.5));
            assert_eq!(bytes_to_json_num(T::F64, &2.25f64.to_le_bytes()), json!(2.25));
            // Non-numeric type → null.
            assert_eq!(bytes_to_json_num(T::Bytes, &[1, 2, 3, 4]), serde_json::Value::Null);
        }
    }
}

// Re-export the struct at module level so callers can write
// `use crate::views::host_api_impl::UiHostApi;` regardless of the inner mod.
#[cfg(feature = "scripting")]
pub use inner::UiHostApi;
