//! The method catalog: the **single source of truth** for the namespaced host
//! API exposed to scripts as `nemclass.<ns>.<fn>(...)`.
//!
//! This module is intentionally **not** feature-gated: it is pure `&'static str`
//! data with no v8 dependency, so it always compiles and drives three
//! consumers off one table:
//!
//! 1. the generated JS `nemclass` shim (grouped by the `ns` prefix before the
//!    dot) — see [`crate::engine_rusty`] (behind `scripting`);
//! 2. the generated `nemclass.d.ts` typings — see [`crate::scaffold`];
//! 3. the UI Scripts-panel reference list — via [`host_method_names`].
//!
//! Every entry routes through the generic `__host_call(method, args)` bridge, so
//! adding a method is a single line here plus a `match` arm in the host
//! dispatcher (`UiHostApi::call`). The legacy four functions (`pattern_scan`,
//! `declare_type`, `declare_class`, `log`) and `on` are **not** in this catalog —
//! they keep their existing named ops for back-compat.

/// One namespaced host method: its dotted `name` (`"mem.readU32"`), the
/// TypeScript signature fragment `ts_sig` used to generate the `.d.ts` method
/// declaration, and a one-line `doc` comment.
///
/// `ts_sig` is the text between the method name and the trailing `;` in the
/// generated declaration — i.e. `(addr: Address): number` for
/// `mem.readU32`. The `.d.ts` generator splits `name` on the dot to group
/// methods into per-namespace interfaces.
pub struct HostMethod {
    /// Dotted method name, `"<ns>.<fn>"`. The catalog key and the string passed
    /// to `__host_call`.
    pub name: &'static str,
    /// TypeScript signature fragment: `(args...): ret`.
    pub ts_sig: &'static str,
    /// Human-readable one-line doc for the `.d.ts` and the panel reference.
    pub doc: &'static str,
}

/// Every namespaced host method exposed to scripts. Grouped by namespace for
/// readability; the `.d.ts` generator re-groups by the `ns` prefix.
pub const HOST_METHODS: &[HostMethod] = &[
    // --- mem.* : typed memory read/write on the attached process ------------
    HostMethod { name: "mem.readBytes", ts_sig: "(addr: Address, len: number): number[]", doc: "Read `len` bytes at `addr`." },
    HostMethod { name: "mem.readValues", ts_sig: "(addr: Address, type: string, count: number): number[]", doc: "Read an array of `count` typed values at `addr` in one call." },
    HostMethod { name: "mem.readStruct", ts_sig: "(addr: Address, layout: { name: string, type: string, offset?: number }[]): Record<string, number>", doc: "Read a whole struct (typed fields at offsets) into an object in one call." },
    HostMethod { name: "mem.writeStruct", ts_sig: "(addr: Address, layout: { name: string, type: string, offset?: number }[], values: Record<string, number>): number", doc: "Write the given struct fields back (same layout as readStruct); returns count written." },
    HostMethod { name: "mem.readStructArray", ts_sig: "(addr: Address, layout: { name: string, type: string, offset?: number }[], count: number, opts?: { stride?: number }): Record<string, number>[]", doc: "Read `count` structs (an entity list) in one syscall; stride defaults to the packed size." },
    HostMethod { name: "mem.writeValues", ts_sig: "(addr: Address, type: string, values: number[]): number", doc: "Write an array of typed values at `addr`; returns the count written." },
    HostMethod { name: "mem.writeBytes", ts_sig: "(addr: Address, bytes: number[]): boolean", doc: "Write a byte array at `addr`." },
    HostMethod { name: "mem.readI8", ts_sig: "(addr: Address): number", doc: "Read a signed 8-bit int." },
    HostMethod { name: "mem.readI16", ts_sig: "(addr: Address): number", doc: "Read a signed 16-bit int." },
    HostMethod { name: "mem.readI32", ts_sig: "(addr: Address): number", doc: "Read a signed 32-bit int." },
    HostMethod { name: "mem.readI64", ts_sig: "(addr: Address): number", doc: "Read a signed 64-bit int (may lose precision)." },
    HostMethod { name: "mem.readU8", ts_sig: "(addr: Address): number", doc: "Read an unsigned 8-bit int." },
    HostMethod { name: "mem.readU16", ts_sig: "(addr: Address): number", doc: "Read an unsigned 16-bit int." },
    HostMethod { name: "mem.readU32", ts_sig: "(addr: Address): number", doc: "Read an unsigned 32-bit int." },
    HostMethod { name: "mem.readU64", ts_sig: "(addr: Address): number", doc: "Read an unsigned 64-bit int (may lose precision)." },
    HostMethod { name: "mem.readU64Str", ts_sig: "(addr: Address): string", doc: "Read an unsigned 64-bit int as an exact decimal string." },
    HostMethod { name: "mem.readF32", ts_sig: "(addr: Address): number", doc: "Read a 32-bit float." },
    HostMethod { name: "mem.readF64", ts_sig: "(addr: Address): number", doc: "Read a 64-bit float." },
    HostMethod { name: "mem.writeI8", ts_sig: "(addr: Address, value: number): boolean", doc: "Write a signed 8-bit int." },
    HostMethod { name: "mem.writeI16", ts_sig: "(addr: Address, value: number): boolean", doc: "Write a signed 16-bit int." },
    HostMethod { name: "mem.writeI32", ts_sig: "(addr: Address, value: number): boolean", doc: "Write a signed 32-bit int." },
    HostMethod { name: "mem.writeI64", ts_sig: "(addr: Address, value: number | string): boolean", doc: "Write a signed 64-bit int (number or decimal string)." },
    HostMethod { name: "mem.writeU8", ts_sig: "(addr: Address, value: number): boolean", doc: "Write an unsigned 8-bit int." },
    HostMethod { name: "mem.writeU16", ts_sig: "(addr: Address, value: number): boolean", doc: "Write an unsigned 16-bit int." },
    HostMethod { name: "mem.writeU32", ts_sig: "(addr: Address, value: number): boolean", doc: "Write an unsigned 32-bit int." },
    HostMethod { name: "mem.writeU64", ts_sig: "(addr: Address, value: number | string): boolean", doc: "Write an unsigned 64-bit int (number or decimal string)." },
    HostMethod { name: "mem.writeF32", ts_sig: "(addr: Address, value: number): boolean", doc: "Write a 32-bit float." },
    HostMethod { name: "mem.writeF64", ts_sig: "(addr: Address, value: number): boolean", doc: "Write a 64-bit float." },
    HostMethod { name: "mem.readPointer", ts_sig: "(addr: Address): Address", doc: "Read a native-width pointer." },
    HostMethod { name: "mem.readString", ts_sig: "(addr: Address, maxLen: number, enc?: \"utf8\" | \"utf16\"): string", doc: "Read a NUL-terminated string (utf8 default)." },
    HostMethod { name: "mem.writeString", ts_sig: "(addr: Address, str: string, enc?: \"utf8\" | \"utf16\"): boolean", doc: "Write a string (utf8 default), NUL-terminated." },
    HostMethod { name: "mem.readChain", ts_sig: "(base: Address, offsets: number[]): Address", doc: "Walk a CE pointer chain: deref then add each offset." },
    HostMethod { name: "mem.resolveRip", ts_sig: "(insn: Address, dispOffset: number, instrLen: number): Address", doc: "Resolve an x64 RIP-relative target: insn + instrLen + (rel32 read at insn+dispOffset)." },
    HostMethod { name: "mem.isValid", ts_sig: "(addr: Address): boolean", doc: "Whether `addr` is currently mapped in the target." },
    HostMethod { name: "mem.freeze", ts_sig: "(addr: Address, type: string, value: number | string): boolean", doc: "Freeze `addr` to `value` (typed) via the throttled freeze tick, independent of the cheat table (Linux only)." },
    HostMethod { name: "mem.unfreeze", ts_sig: "(addr: Address): boolean", doc: "Stop freezing `addr`; returns whether a freeze was active." },

    // --- proc.* : process / module / region info ----------------------------
    HostMethod { name: "proc.attached", ts_sig: "(): boolean", doc: "Whether a process is attached." },
    HostMethod { name: "proc.pid", ts_sig: "(): number", doc: "The attached pid (0 if not attached)." },
    HostMethod { name: "proc.name", ts_sig: "(): string", doc: "The attached process name." },
    HostMethod { name: "proc.modules", ts_sig: "(): ModuleInfo[]", doc: "Enumerate loaded modules." },
    HostMethod { name: "proc.module", ts_sig: "(name: string): ModuleInfo | null", doc: "Look up a module by name." },
    HostMethod { name: "proc.moduleAt", ts_sig: "(addr: Address): ModuleInfo | null", doc: "The module whose image contains `addr`, or null." },
    HostMethod { name: "proc.baseAddress", ts_sig: "(name?: string): Address", doc: "Base of a named module (or the main module)." },
    HostMethod { name: "proc.regions", ts_sig: "(): RegionInfo[]", doc: "Enumerate memory regions (Linux)." },
    HostMethod { name: "proc.regionAt", ts_sig: "(addr: Address): RegionInfo | null", doc: "The memory region containing `addr` (with perms), or null (Linux)." },
    HostMethod { name: "proc.resolveSymbol", ts_sig: "(addr: Address): string | null", doc: "Resolve `addr` to a symbol name." },
    HostMethod { name: "proc.exports", ts_sig: "(module?: string): { name: string, address: Address }[]", doc: "Exported symbols of a module (main module if omitted; Linux only)." },
    HostMethod { name: "proc.resolveExport", ts_sig: "(module: string, name: string): Address | null", doc: "Address of an exported symbol by name (Linux only)." },

    // --- scan.* : AOB + value scanning + pointer chains ----------------------
    HostMethod { name: "scan.aob", ts_sig: "(pattern: string, opts?: { module?: string }): Address[]", doc: "IDA-style AOB scan over a module." },
    HostMethod { name: "scan.aobResolveRip", ts_sig: "(pattern: string, dispOffset: number, instrLen: number, opts?: { module?: string, deref?: boolean }): Address | null", doc: "AOB scan (first hit) then resolve the x64 RIP-relative target, optionally deref. Null if not found." },
    HostMethod { name: "scan.value", ts_sig: "(type: string, value: number | string, opts?: { module?: string }): Address[]", doc: "Exact value scan over a module image." },
    HostMethod { name: "scan.pointer", ts_sig: "(goal: Address, opts?: { maxDepth?: number, maxOffset?: number }): PointerPath[]", doc: "Find ASLR-stable pointer chains leading to `goal` (Linux only)." },
    HostMethod { name: "scan.rescan", ts_sig: "(paths: PointerPath[], goal: Address): PointerPath[]", doc: "Keep only the given pointer paths that still resolve to `goal` (Linux only)." },
    HostMethod { name: "scan.range", ts_sig: "(start: Address, size: number, type: string, value: number | string): Address[]", doc: "Exact value scan over an arbitrary `[start, start+size)` range (e.g. heap)." },
    HostMethod { name: "scan.makeSignature", ts_sig: "(addr: Address): string | null", doc: "Generate a unique AOB signature for the code/data at `addr` in its module (Linux only)." },
    HostMethod { name: "scan.first", ts_sig: "(type: string, value?: number | string, compare?: string): number", doc: "Start a stateful scan session over the whole target: first scan for `value` (default compare \"exact\", or \"unknown\" for no needle). Returns the match count (Linux only)." },
    HostMethod { name: "scan.next", ts_sig: "(compare: string, value?: number | string): number", doc: "Refine the current scan session (e.g. \"decreased\", \"exact\"). Returns the new match count; errors with no active session (Linux only)." },
    HostMethod { name: "scan.results", ts_sig: "(max?: number): Address[]", doc: "Addresses of the current scan session's results, up to `max` (default 1000, cap 100000) (Linux only)." },
    HostMethod { name: "scan.resultsWithValues", ts_sig: "(max?: number): { address: Address, value: number }[]", doc: "Current scan session results paired with their live values (Linux only)." },
    HostMethod { name: "scan.reset", ts_sig: "(): boolean", doc: "Drop the current scan session; returns whether one existed (Linux only)." },

    // --- classes.* : project class editing ----------------------------------
    HostMethod { name: "classes.list", ts_sig: "(): ClassInfo[]", doc: "List classes in the project." },
    HostMethod { name: "classes.create", ts_sig: "(name?: string): string", doc: "Create a class, returning its uuid." },
    HostMethod { name: "classes.get", ts_sig: "(uuidOrName: string): ClassDetail | null", doc: "Fetch a class by uuid or name." },
    HostMethod { name: "classes.setFormula", ts_sig: "(uuidOrName: string, formula: string): boolean", doc: "Set a class's address formula." },
    HostMethod { name: "classes.addNode", ts_sig: "(uuidOrName: string, type: string, opts?: { name?: string, comment?: string }): boolean", doc: "Append a node of `type` to a class." },
    HostMethod { name: "classes.setPointerTarget", ts_sig: "(uuidOrName: string, path: number[], targetUuidOrName: string): boolean", doc: "Point a Pointer node at a target class." },
    HostMethod { name: "classes.removeNode", ts_sig: "(uuidOrName: string, path: number[]): boolean", doc: "Remove a node by child-index path." },
    HostMethod { name: "classes.resolveBase", ts_sig: "(uuidOrName: string): Address | null", doc: "Evaluate a class's address formula live." },
    HostMethod { name: "classes.fromPointer", ts_sig: "(goal: Address, name?: string, opts?: { maxDepth?: number, maxOffset?: number }): string | null", doc: "Run a pointer scan to `goal`, create a class with the best formula, and return its uuid (Linux only)." },

    // --- enums.* : project enum (custom type) editing -----------------------
    HostMethod { name: "enums.define", ts_sig: "(name: string, values: Record<string, number>, opts?: { size?: number, flags?: boolean }): boolean", doc: "Upsert an enum by name into the project (`values` maps variant name to integer)." },
    HostMethod { name: "enums.list", ts_sig: "(): EnumInfo[]", doc: "List all project enums." },
    HostMethod { name: "enums.get", ts_sig: "(name: string): EnumInfo | null", doc: "Fetch a project enum by name." },

    // --- hotkeys.* : script-registered global hotkeys -----------------------
    HostMethod { name: "hotkeys.register", ts_sig: "(combo: string): number", doc: "Register a global hotkey (e.g. \"Ctrl+Shift+H\", \"F6\"); returns an id fired as `OnHotkey`." },
    HostMethod { name: "hotkeys.unregister", ts_sig: "(id: number): boolean", doc: "Unregister a hotkey by id; returns whether it existed." },

    // --- disasm.* : disassembly ---------------------------------------------
    HostMethod { name: "disasm.at", ts_sig: "(addr: Address, count?: number): Instruction[]", doc: "Disassemble `count` instructions at `addr`." },
    HostMethod { name: "disasm.func", ts_sig: "(addr: Address): Instruction[]", doc: "Disassemble the function at `addr`." },
    HostMethod { name: "disasm.decodeBytes", ts_sig: "(bytes: number[], base?: Address): Instruction[]", doc: "Disassemble a raw byte array (no process needed)." },
    HostMethod { name: "disasm.xrefsTo", ts_sig: "(addr: Address): Address[]", doc: "Find code sites (call/jump/RIP-relative) that reference `addr` in its module (Linux only)." },
    HostMethod { name: "classes.dissect", ts_sig: "(key: string, opts?: { size?: number }): number", doc: "Auto-generate a class body by dissecting memory at its resolved base; returns field count (Linux only)." },
    HostMethod { name: "classes.addNodeAt", ts_sig: "(key: string, offset: number, type: string, opts?: { name?: string, comment?: string }): boolean", doc: "Add a field that starts at byte `offset`, padding any gap with hex bytes (errors if the offset is inside an existing field)." },
    HostMethod { name: "classes.setNodeName", ts_sig: "(key: string, path: number[], name: string): boolean", doc: "Rename a node (field) at the given child-index path in a class." },
    HostMethod { name: "classes.setNodeComment", ts_sig: "(key: string, path: number[], comment: string): boolean", doc: "Set a node's comment at the given child-index path in a class." },

    // --- ui.* : UI actions ---------------------------------------------------
    HostMethod { name: "ui.notify", ts_sig: "(msg: string): void", doc: "Show a status message + log line." },
    HostMethod { name: "ui.gotoMemory", ts_sig: "(addr: Address): void", doc: "Focus the memory view at `addr`." },
    HostMethod { name: "ui.gotoDisasm", ts_sig: "(addr: Address): void", doc: "Focus the disassembly view at `addr`." },
    HostMethod { name: "ui.selectClass", ts_sig: "(uuidOrName: string): void", doc: "Select a class in the class view." },

    // --- table.* : cheat table management -----------------------------------
    HostMethod { name: "table.add", ts_sig: "(entry: { description?: string, address: string, type: string, frozen?: boolean, value?: string }): number", doc: "Append an entry to the cheat table; returns its index." },
    HostMethod { name: "table.list", ts_sig: "(): TableEntry[]", doc: "Return all cheat-table entries." },
    HostMethod { name: "table.remove", ts_sig: "(index: number): boolean", doc: "Remove the entry at `index`." },
    HostMethod { name: "table.freeze", ts_sig: "(index: number): boolean", doc: "Freeze the entry at `index`." },
    HostMethod { name: "table.unfreeze", ts_sig: "(index: number): boolean", doc: "Unfreeze the entry at `index`." },
    HostMethod { name: "table.save", ts_sig: "(name: string): void", doc: "Save the cheat table to `<project>/tables/<name>.toml`." },
    HostMethod { name: "table.load", ts_sig: "(name: string): void", doc: "Load a cheat table from `<project>/tables/<name>.toml`." },
];

/// The dotted names of every namespaced host method, in catalog order. Used by
/// the UI Scripts-panel reference (replacing the hardcoded list) alongside the
/// legacy `pattern_scan`/`declare_class`/`declare_type`/`log` names.
pub fn host_method_names() -> Vec<&'static str> {
    HOST_METHODS.iter().map(|m| m.name).collect()
}

/// The distinct namespace prefixes (`mem`, `proc`, ...) in first-seen order.
/// Used by the JS shim + `.d.ts` generators to build one object/interface per
/// namespace.
pub fn namespaces() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for m in HOST_METHODS {
        let ns = m.name.split('.').next().unwrap_or(m.name);
        if !out.contains(&ns) {
            out.push(ns);
        }
    }
    out
}

/// Splits a dotted method name into `(namespace, function)`.
pub fn split_name(name: &str) -> (&str, &str) {
    match name.split_once('.') {
        Some((ns, f)) => (ns, f),
        None => (name, name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_method_is_dotted_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for m in HOST_METHODS {
            assert!(m.name.contains('.'), "method `{}` must be namespaced", m.name);
            assert!(seen.insert(m.name), "duplicate method `{}`", m.name);
            assert!(m.ts_sig.starts_with('('), "ts_sig for `{}` must start with (", m.name);
        }
    }

    #[test]
    fn namespaces_cover_the_expected_groups() {
        let ns = namespaces();
        for expected in ["mem", "proc", "scan", "classes", "disasm", "ui", "table", "enums", "hotkeys"] {
            assert!(ns.contains(&expected), "namespace `{expected}` present");
        }
    }

    #[test]
    fn host_method_names_matches_catalog_len() {
        assert_eq!(host_method_names().len(), HOST_METHODS.len());
    }
}
