//! Project-directory scaffolding + TypeScript type generation.
//!
//! [`write_script_scaffold`] writes the three files a `project.nemclass`
//! directory needs so `src/*.ts` scripts get editor autocomplete against the
//! host API and the event payloads:
//!
//! - `package.json`   — declares the project's script package + `nemclass.d.ts`.
//! - `tsconfig.json`  — points the compiler at `src/` and the ambient types.
//! - `nemclass.d.ts`  — ambient declarations for the `nemclass` global (host
//!   functions + `on(...)` event registration) and the six lifecycle event
//!   payload shapes.
//!
//! **This module is intentionally *not* feature-gated.** It is pure string/file
//! I/O with no v8 dependency, so it always compiles and is unit-tested in the
//! default build. The generated `.d.ts` is derived from a single in-crate source
//! of truth — [`EVENT_KINDS`] and the host-fn list mirrored from
//! [`crate::events::Event`] / [`crate::host_api`] — so the declarations cannot
//! silently drift from the Rust event enum. A guard test
//! (`event_kinds_match_the_event_enum`) fails if a new [`crate::events::Event`]
//! variant is added without updating [`EVENT_KINDS`].

use std::fs;
use std::path::Path;

/// The six lifecycle events plus the user-raised `Custom` event, as the JS-facing
/// handler names scripts register with `nemclass.on(<name>, fn)`.
///
/// This is the single source of truth the `.d.ts` `EventName` union and the
/// per-event handler typings are generated from. Kept in lock-step with
/// [`crate::events::Event::kind`] by `event_kinds_match_the_event_enum`.
pub const EVENT_KINDS: &[&str] = &[
    "OnProjectLoad",
    "OnAttach",
    "OnDetach",
    "ClassAddressUpdated",
    "GlobalVariableUpdated",
    "OnTick",
    "OnHotkey",
    "Custom",
];

/// Writes `package.json`, `tsconfig.json`, and `nemclass.d.ts` into
/// `project_dir` (a `project.nemclass` directory), creating the directory (and
/// its `src/`) if needed.
///
/// Overwrites the three generated files if they already exist — they are derived
/// artifacts, so regenerating on project open keeps the type surface current. It
/// does **not** touch anything under `src/`.
pub fn write_script_scaffold(project_dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(project_dir.join("src"))?;

    fs::write(project_dir.join("package.json"), PACKAGE_JSON)?;
    fs::write(project_dir.join("tsconfig.json"), TSCONFIG_JSON)?;
    fs::write(project_dir.join("nemclass.d.ts"), generate_dts())?;

    // Seed example scripts, but only if absent — never clobber user edits under
    // `src/`. Each demonstrates a distinct slice of the API and type-checks
    // against the generated `nemclass.d.ts`.
    let src = project_dir.join("src");
    for (name, body) in EXAMPLE_SCRIPTS {
        let path = src.join(name);
        if !path.exists() {
            fs::write(path, body)?;
        }
    }

    Ok(())
}

/// Regenerate **only** `nemclass.d.ts` in `project_dir` from the current host-API
/// catalog + event kinds. Called when a project is opened so the type surface
/// tracks the running build, without re-seeding example scripts or touching
/// `package.json`/`tsconfig.json`. A no-op-ish overwrite of a derived artifact.
pub fn write_dts(project_dir: &Path) -> std::io::Result<()> {
    fs::write(project_dir.join("nemclass.d.ts"), generate_dts())
}

/// The example scripts seeded into `src/` on project creation (only if the file
/// does not already exist). TypeScript, type-checked against `nemclass.d.ts`.
pub const EXAMPLE_SCRIPTS: &[(&str, &str)] = &[
    (
        "example_aob_class.ts",
        r#"// Example: find a signature with an AOB scan, then declare a class at it.
// Runs on attach. Adjust the pattern + module for your target.
nemclass.on("OnAttach", () => {
  const hits = nemclass.scan.aob("48 8B ?? ?? ?? ?? ?? 48 89");
  if (hits.length === 0) {
    nemclass.log("aob: no matches");
    return;
  }
  const addr = hits[0];
  nemclass.log("aob: first hit at 0x" + addr.toString(16));
  // Declare a class whose base is the found address (as an absolute formula).
  nemclass.declare_class("FoundStruct", "0x" + addr.toString(16));
});
"#,
    ),
    (
        "example_pointer_watch.ts",
        r#"// Example: a CE-style pointer-chain health watch. Every tick, resolve
// base -> [+0x10] -> [+0x28] and read a float health value, notifying the UI.
const MODULE = "game.exe";
const CHAIN = [0x10, 0x28, 0x0]; // deref then add, per hop (CE semantics)

nemclass.on("OnTick", (e) => {
  if (e.kind !== "OnTick" || e.pid === null) return;
  const base = nemclass.proc.baseAddress(MODULE);
  if (base === 0) return;
  const healthPtr = nemclass.mem.readChain(base, CHAIN);
  if (!nemclass.mem.isValid(healthPtr)) return;
  const health = nemclass.mem.readF32(healthPtr);
  if (health < 25) {
    nemclass.ui.notify("Low health: " + health.toFixed(1));
  }
});
"#,
    ),
    (
        "example_autofill_class.ts",
        r#"// Example: auto-fill a class with fields and wire a pointer to a sub-class.
nemclass.on("OnProjectLoad", () => {
  const enemy = nemclass.classes.create("Enemy");
  nemclass.classes.addNode(enemy, "Int32", { name: "id" });
  nemclass.classes.addNode(enemy, "Float", { name: "health" });

  const player = nemclass.classes.create("Player");
  nemclass.classes.addNode(player, "Int32", { name: "score" });
  // Append a pointer, then aim it at the Enemy class (path = [child index]).
  nemclass.classes.addNode(player, "Pointer", { name: "target" });
  const ok = nemclass.classes.setPointerTarget(player, [1], enemy);
  nemclass.log("player.target -> Enemy: " + ok);
});
"#,
    ),
    (
        "example_full_trainer.ts",
        r#"// Example: a complete trainer tying the API together —
//   attach -> AOB-locate a struct -> dissect it into a class ->
//   bind hotkeys -> freeze/heal on keypress, and watch a value each tick.
// Edit MODULE / PATTERN / offsets for your target.
const MODULE = "game.bin";
const PATTERN = "48 8B 05 ?? ?? ?? ?? 48 8B 88"; // -> mov rax, [rip+X]; ...
const HP_OFFSET = 0x40;   // Player+0x40 = health (i32)
const AMMO_OFFSET = 0x80; // Player+0x80 = ammo (i32)

let playerAddr = 0;
let godMode = 0, refill = 0;

nemclass.on("OnAttach", (e) => {
  nemclass.log(`attached to ${e.name} (pid ${e.pid})`);

  // 1. Locate the player struct via an AOB, resolving the rip-relative operand.
  const [hit] = nemclass.scan.aob(PATTERN, { module: MODULE });
  if (!hit) { nemclass.log("pattern not found"); return; }
  // The mov's disp32 lives 3 bytes in; read it and compute the target.
  const disp = nemclass.mem.readI32(hit + 3);
  playerAddr = hit + 7 + disp;                 // rip-relative: next-insn + disp
  playerAddr = nemclass.mem.readPointer(playerAddr); // deref the global -> instance
  nemclass.log(`player @ 0x${playerAddr.toString(16)}`);

  // 2. Build + auto-dissect a class at the instance so it shows in the UI.
  const cls = nemclass.classes.create("Player");
  nemclass.classes.setFormula(cls, `0x${playerAddr.toString(16)}`);
  nemclass.classes.dissect(cls, { size: 0x100 });
  nemclass.ui.selectClass(cls);

  // 3. Bind hotkeys.
  godMode = nemclass.hotkeys.register("F1");
  refill  = nemclass.hotkeys.register("F2");
  nemclass.ui.notify("F1 = god mode, F2 = refill ammo");
});

nemclass.on("OnHotkey", (e) => {
  if (e.kind !== "OnHotkey" || playerAddr === 0) return;
  if (e.id === godMode) {
    nemclass.mem.freeze(playerAddr + HP_OFFSET, "i32", "9999");
    nemclass.ui.notify("God mode ON (HP frozen)");
  } else if (e.id === refill) {
    nemclass.mem.writeI32(playerAddr + AMMO_OFFSET, 999);
    nemclass.ui.notify("Ammo refilled");
  }
});

nemclass.on("OnTick", () => {
  if (playerAddr === 0) return;
  const hp = nemclass.mem.readI32(playerAddr + HP_OFFSET);
  if (hp < 25) nemclass.ui.notify(`Low HP: ${hp}`);
});
"#,
    ),
];

/// `package.json` scaffolded on project creation. Static: it only names the
/// package and points editors at the generated ambient declarations.
const PACKAGE_JSON: &str = r#"{
  "name": "nemclass-project",
  "version": "0.1.0",
  "private": true,
  "description": "nemclass scripting project — host-API types in nemclass.d.ts",
  "types": "./nemclass.d.ts"
}
"#;

/// `tsconfig.json` scaffolded on project creation. Includes `src/` and the
/// ambient `nemclass.d.ts` so scripts type-check against the host API.
const TSCONFIG_JSON: &str = r#"{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ES2020",
    "moduleResolution": "node",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "noEmit": true,
    "types": []
  },
  "include": ["src/**/*.ts", "nemclass.d.ts"]
}
"#;

/// Builds the ambient `nemclass.d.ts` from [`EVENT_KINDS`] and the host-API
/// surface, so the declarations track the Rust event enum / host fns.
fn generate_dts() -> String {
    // The `EventName` union, derived from EVENT_KINDS (single source of truth).
    let event_union = EVENT_KINDS
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(" | ");

    // The namespaced API, generated from the catalog: one interface per
    // namespace (`mem`, `proc`, ...), plus the fields on `NemclassHost` that
    // expose them. Grouped in catalog order.
    let mut ns_interfaces = String::new();
    let mut ns_fields = String::new();
    for ns in crate::api_catalog::namespaces() {
        let iface = format!("NemclassApi_{ns}");
        ns_interfaces.push_str(&format!("interface {iface} {{\n"));
        for m in crate::api_catalog::HOST_METHODS {
            let (mns, func) = crate::api_catalog::split_name(m.name);
            if mns != ns {
                continue;
            }
            ns_interfaces.push_str(&format!("  /** {} */\n  {}{};\n", m.doc, func, m.ts_sig));
        }
        ns_interfaces.push_str("}\n\n");
        ns_fields.push_str(&format!("  /** The `{ns}.*` API namespace. */\n  {ns}: {iface};\n"));
    }

    format!(
        r#"// GENERATED by nemclass write_script_scaffold — do not edit by hand.
// Ambient declarations for the `nemclass` scripting host API and lifecycle
// events. Regenerated whenever a project is (re)opened.

/** A resolved absolute address in the target process. */
type Address = number;

/** The lifecycle/custom events a script can subscribe to via `nemclass.on`. */
type EventName = {event_union};

/** Payload for `OnProjectLoad`: the loaded project directory path. */
interface OnProjectLoadEvent {{ kind: "OnProjectLoad"; path: string; }}

/** Payload for `OnAttach`: the attached process id and (best-effort) name. */
interface OnAttachEvent {{ kind: "OnAttach"; pid: number; name: string | null; }}

/** Payload for `OnDetach`: no data — the target is gone. */
interface OnDetachEvent {{ kind: "OnDetach"; }}

/** Payload for `ClassAddressUpdated`: the class UUID and its new base address. */
interface ClassAddressUpdatedEvent {{ kind: "ClassAddressUpdated"; class: string; address: Address; }}

/** A named pointer into the target (name + resolved address). */
interface GlobalVariable {{ name: string; address: Address; }}

/** Payload for `GlobalVariableUpdated`: the changed global variable. */
interface GlobalVariableUpdatedEvent {{ kind: "GlobalVariableUpdated"; variable: GlobalVariable; }}

/** Payload for `OnTick`: a periodic snapshot-interval tick. */
interface OnTickEvent {{ kind: "OnTick"; pid: number | null; }}

/** Payload for `OnHotkey`: the id of the script-registered hotkey that fired. */
interface OnHotkeyEvent {{ kind: "OnHotkey"; id: number; }}

/** Payload for a user-raised `Custom` event. */
interface CustomEvent {{ kind: "Custom"; name: string; payload: {{ text: string; attrs: Record<string, string>; }}; }}

/** Discriminated union of every event payload dispatched to handlers. */
type NemclassEvent =
  | OnProjectLoadEvent
  | OnAttachEvent
  | OnDetachEvent
  | ClassAddressUpdatedEvent
  | GlobalVariableUpdatedEvent
  | OnTickEvent
  | OnHotkeyEvent
  | CustomEvent;

/** A loaded module image in the target. */
interface ModuleInfo {{ name: string; base: Address; size: number; }}

/** One ASLR-stable pointer chain returned by `scan.pointer`. */
interface PointerPath {{ formula: string; base: Address; depth: number; offsets: number[]; }}

/** One contiguous memory region (Linux). */
interface RegionInfo {{ start: Address; size: number; end: Address; perms: string; }}

/** A class summary from `classes.list`. */
interface ClassInfo {{ uuid: string; name: string; size: number; formula: string; }}

/** A node summary within a class. */
interface NodeInfo {{ type: string; name: string; comment: string; }}

/** A class with its nodes from `classes.get`. */
interface ClassDetail {{ uuid: string; name: string; formula: string; nodes: NodeInfo[]; }}

/** One disassembled instruction. */
interface Instruction {{ address: Address; bytes: string; text: string; target?: Address; }}

/** One row in the cheat table. */
interface TableEntry {{ index: number; description: string; address: string; type: string; frozen: boolean; }}

/** A project enum (custom type) from `enums.list` / `enums.get`. */
interface EnumInfo {{ name: string; size: number; flags: boolean; values: Record<string, number>; }}

{ns_interfaces}

/** A description of a custom (enum) type declared via `declare_type`. */
interface EnumDescription {{
  name: string;
  /** Underlying size in bytes: 1, 2, 4, or 8 (default 4). */
  size?: number;
  /** Whether the values are bit-flags (default false). */
  use_flags?: boolean;
  /** Ordered `[variantName, value]` members. */
  values: [string, number][];
}}

/** The host API exposed to scripts as the global `nemclass` object. */
interface NemclassHost {{
  /**
   * IDA-style byte-pattern scan over a loaded module. Tokens are hex bytes
   * (`4A`), full wildcards (`??`/`?`), or nibble wildcards (`4?`/`?8`).
   * Returns every absolute match address. Not available during
   * `tryResolveClassAddress` (throws if called from a resolver).
   */
  pattern_scan(module: string, pattern: string): Address[];

  /** Declare a custom (enum) type into the host's model. */
  declare_type(descriptor: EnumDescription): void;

  /**
   * Declare a class by name with an address formula (e.g. `"game.exe"+0x10`).
   * The host creates the class in the open project.
   */
  declare_class(name: string, addressFormula: string): void;

  /** Log a message through the host (appears in the app's log). */
  log(msg: string): void;

{ns_fields}
  /**
   * Register a handler for a lifecycle/custom event. The handler receives the
   * matching event payload. As an alternative, a module may `export` a function
   * named `onAttach` / `onDetach` / `onProjectLoad` / `classAddressUpdated` /
   * `globalVariableUpdated` / `tryResolveClassAddress` and it is dispatched
   * automatically.
   */
  on(event: EventName, handler: (e: NemclassEvent) => void): void;

  /**
   * Register the `TryResolveClassAddress` resolver: given a query it returns an
   * address to claim the class, or `null`/`undefined` to defer. Host functions
   * are unavailable inside this resolver.
   */
  tryResolveClassAddress?: (q: {{ pid: number; class: string; }}) => Address | null | undefined;
}}

declare global {{
  const nemclass: NemclassHost;
}}

export {{}};
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Event;

    #[test]
    fn writes_the_three_scaffold_files() {
        let dir = tempfile::tempdir().unwrap();
        let proj = dir.path().join("project.nemclass");
        write_script_scaffold(&proj).unwrap();

        assert!(proj.join("package.json").is_file(), "package.json written");
        assert!(proj.join("tsconfig.json").is_file(), "tsconfig.json written");
        assert!(proj.join("nemclass.d.ts").is_file(), "nemclass.d.ts written");
        assert!(proj.join("src").is_dir(), "src/ created");
    }

    #[test]
    fn dts_contains_host_api_and_event_symbols() {
        let dts = generate_dts();
        // Legacy host functions.
        for sym in ["pattern_scan", "declare_type", "declare_class", "log", "on"] {
            assert!(dts.contains(sym), "d.ts declares host fn `{sym}`");
        }
        // Generated namespaces from the catalog appear as fields + interfaces.
        for ns in ["mem", "proc", "scan", "classes", "disasm", "ui", "table"] {
            assert!(
                dts.contains(&format!("NemclassApi_{ns}")),
                "d.ts declares interface for namespace `{ns}`"
            );
        }
        // A couple of specific catalog methods land in the d.ts.
        assert!(dts.contains("readU32"), "d.ts has mem.readU32");
        assert!(dts.contains("readChain"), "d.ts has mem.readChain");
        assert!(dts.contains("setPointerTarget"), "d.ts has classes.setPointerTarget");
        assert!(dts.contains("pointer"), "d.ts has scan.pointer");
        assert!(dts.contains("first"), "d.ts has scan.first (stateful session)");
        assert!(dts.contains("results"), "d.ts has scan.results (stateful session)");
        assert!(dts.contains("fromPointer"), "d.ts has classes.fromPointer");
        assert!(dts.contains("PointerPath"), "d.ts has PointerPath interface");
        assert!(dts.contains("NemclassApi_table"), "d.ts declares interface for namespace `table`");
        assert!(dts.contains("TableEntry"), "d.ts has TableEntry interface");
        assert!(dts.contains("add"), "d.ts has table.add");
        assert!(dts.contains("OnTickEvent"), "d.ts has OnTickEvent");
        // The three new namespaces + event.
        assert!(dts.contains("NemclassApi_enums"), "d.ts declares interface for namespace `enums`");
        assert!(dts.contains("NemclassApi_hotkeys"), "d.ts declares interface for namespace `hotkeys`");
        assert!(dts.contains("EnumInfo"), "d.ts has EnumInfo interface");
        assert!(dts.contains("define"), "d.ts has enums.define");
        assert!(dts.contains("register"), "d.ts has hotkeys.register");
        assert!(dts.contains("freeze"), "d.ts has mem.freeze");
        assert!(dts.contains("OnHotkeyEvent"), "d.ts has OnHotkeyEvent");
        // The six event payload interfaces + the union.
        for sym in [
            "NemclassEvent",
            "OnProjectLoadEvent",
            "OnAttachEvent",
            "OnDetachEvent",
            "ClassAddressUpdatedEvent",
            "GlobalVariableUpdatedEvent",
            "CustomEvent",
            "tryResolveClassAddress",
            "declare const",
        ] {
            // (`declare const` guards the ambient `nemclass` global.)
            let needle = if sym == "declare const" { "const nemclass" } else { sym };
            assert!(dts.contains(needle), "d.ts declares `{sym}`");
        }
        // Every EVENT_KIND appears in the EventName union.
        for k in EVENT_KINDS {
            assert!(dts.contains(&format!("\"{k}\"")), "EventName union has `{k}`");
        }
    }

    #[test]
    fn package_and_tsconfig_point_at_the_dts() {
        assert!(PACKAGE_JSON.contains("nemclass.d.ts"));
        assert!(TSCONFIG_JSON.contains("nemclass.d.ts"));
        assert!(TSCONFIG_JSON.contains("src/**/*.ts"));
    }

    /// Guard: [`EVENT_KINDS`] must stay in lock-step with the [`Event`] enum, so
    /// the generated `.d.ts` can never silently omit a new event variant.
    #[test]
    fn event_kinds_match_the_event_enum() {
        // One representative value per variant; `Event::kind()` is the authority.
        let samples = [
            Event::OnProjectLoad { path: String::new() },
            Event::OnAttach { pid: 0, name: None },
            Event::OnDetach,
            Event::ClassAddressUpdated {
                class: uuid::Uuid::nil(),
                address: 0,
            },
            Event::GlobalVariableUpdated {
                variable: crate::events::GlobalVariable::new("x", 0),
            },
            Event::OnTick { pid: None },
            Event::OnHotkey { id: 0 },
            Event::Custom {
                name: String::new(),
                payload: crate::events::CustomPayload::empty(),
            },
        ];
        let from_enum: Vec<&str> = samples.iter().map(|e| e.kind()).collect();
        assert_eq!(
            from_enum, EVENT_KINDS,
            "EVENT_KINDS drifted from Event::kind(); update scaffold::EVENT_KINDS"
        );
    }
}
