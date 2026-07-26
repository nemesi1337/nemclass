# nemclass scripting cookbook

nemclass embeds a V8 JavaScript/TypeScript engine. Scripts live in your project's
`src/` directory (every `*.ts`/`*.js` is loaded); a generated `nemclass.d.ts` gives
full autocomplete. The global object is `nemclass` (also destructurable).

Everything a script calls runs on the UI thread against the live process/project,
so calls are synchronous: `const hp = nemclass.mem.readI32(addr)` returns a number.

## Namespaces at a glance

| Namespace | What it does |
|-----------|--------------|
| `mem`     | typed read/write (`readI32`, `writeF32`, `readBytes`, `readValues`/`writeValues` (arrays), `readString`, `readChain`, `readPointer`, `isValid`, `freeze`, …) |
| `proc`    | `pid`, `name`, `modules`, `module`/`moduleAt`, `baseAddress`, `regions`/`regionAt`, `resolveSymbol`, `exports`/`resolveExport`, `attached` |
| `scan`    | `aob`, `value`, `range`, `pointer`/`rescan`, `makeSignature`, `first`/`next`/`results`/`reset` (sessions) |
| `classes` | `list`, `create`, `get`, `addNode`, `removeNode`, `setNodeName`/`setNodeComment`, `setPointerTarget`, `setFormula`, `resolveBase`, `fromPointer`, `dissect` |
| `disasm`  | `at`, `func`, `decodeBytes`, `xrefsTo` |
| `enums` / `hotkeys` / `table` | `define`/`list`/`get`; `register`/`unregister` (+`OnHotkey`); cheat table `add`/`freeze`/`save`/… |
| `ui`      | `notify`, `gotoMemory`, `gotoDisasm`, `selectClass` |
| —         | `on(event, handler)`, `log/warn/error`, `pattern_scan/declare_class/declare_type` (legacy) |

Events: `on("OnAttach", e => …)`, `OnDetach`, `OnProjectLoad`, `OnTick` (fires each
snapshot — use for polling/freezing), `ClassAddressUpdated`.

## Recipes

### Find a value and watch it
```ts
const hits = nemclass.scan.value("i32", 100);        // exact I32 == 100
nemclass.log(`found ${hits.length} matches`);
const addr = hits[0];
nemclass.on("OnTick", () => nemclass.ui.notify(`HP = ${nemclass.mem.readI32(addr)}`));
```

### AOB scan → declare a class at the hit
```ts
const [hit] = nemclass.scan.aob("48 8B 05 ?? ?? ?? ?? 48 89", { module: "game.bin" });
if (hit) {
  const uuid = nemclass.classes.create("PlayerFromAob");
  nemclass.classes.setFormula(uuid, `0x${hit.toString(16)}`);
  nemclass.classes.addNode(uuid, "Int32", { name: "health" });
}
```

### Pointer-chain watch (ASLR-stable)
```ts
const base = nemclass.proc.baseAddress("game.bin");
// [[base+0x1000]+0x40]+0x14
const addr = nemclass.mem.readChain(base + 0x1000, [0x40, 0x14]);
nemclass.on("OnTick", () => {
  const a = nemclass.mem.readChain(nemclass.proc.baseAddress("game.bin") + 0x1000, [0x40, 0x14]);
  if (nemclass.mem.isValid(a)) nemclass.mem.writeI32(a, 9999); // freeze HP
});
```

### Turn a pointer scan into a class
```ts
// scan for chains that resolve to `goal`, then build a class from the best one.
const goal = 0x7fff12340000;
const uuid = nemclass.classes.fromPointer(goal, "TargetStruct", { maxDepth: 5 });
if (uuid) nemclass.ui.selectClass(uuid);
```

### Auto-fill a class with typed fields
```ts
const uuid = nemclass.classes.create("Entity");
nemclass.classes.setFormula(uuid, "<game.bin> + 0x4C0000");
for (const [name, type] of [["health","Int32"],["mana","Float"],["pos","Float"]]) {
  nemclass.classes.addNode(uuid, type, { name });
}
```

### Read → modify → write a whole struct
```ts
const LAYOUT = [
  { name: "health", type: "i32", offset: 0x40 },
  { name: "mana",   type: "f32", offset: 0x44 },
  { name: "ammo",   type: "i32", offset: 0x80 },
];
const p = nemclass.mem.readStruct(playerAddr, LAYOUT); // { health, mana, ammo }
nemclass.log(`HP=${p.health} MP=${p.mana}`);
nemclass.mem.writeStruct(playerAddr, LAYOUT, { health: 9999, ammo: 999 }); // partial update
```

### Read an entire entity list in one syscall
```ts
// 64 entities, each 0x100 bytes; pull name-offset fields for all of them at once.
const ENT = [
  { name: "id",     type: "i32", offset: 0x00 },
  { name: "health", type: "i32", offset: 0x40 },
  { name: "posX",   type: "f32", offset: 0x80 },
];
const ents = nemclass.mem.readStructArray(entArrayAddr, ENT, 64, { stride: 0x100 });
const alive = ents.filter(e => e.health > 0);
nemclass.log(`${alive.length} live entities`);
```

### Read/write an array in one call
```ts
// Read 16 i32s (a stats block) in a single host round-trip, then write some back.
const stats = nemclass.mem.readValues(base + 0x100, "i32", 16);
nemclass.log("stats: " + stats.join(", "));
nemclass.mem.writeValues(base + 0x100, "i32", [100, 100, 999]); // maxed first three
```
(A new project ships `src/example_full_trainer.ts` — a complete attach→AOB→dissect→hotkeys→freeze trainer to learn from.)

### React to attach
```ts
nemclass.on("OnAttach", e => nemclass.log(`attached to ${e.name} (pid ${e.pid})`));
```

### Resolve a game function by name and hook-scan around it
```ts
const addr = nemclass.proc.resolveExport("game.bin", "UpdatePlayer");
if (addr) {
  nemclass.log(`UpdatePlayer @ 0x${addr.toString(16)}`);
  const sig = nemclass.scan.makeSignature(addr);   // AOB to re-find it after an update
  nemclass.log(`signature: ${sig}`);
}
// List all exports:
for (const e of nemclass.proc.exports("game.bin")) nemclass.log(`${e.name} @ ${e.address}`);
```

### Full pointer-scan workflow (find → restart → rescan → class)
```ts
let paths = nemclass.scan.pointer(0x7fff12340000, { maxDepth: 5 });
nemclass.log(`${paths.length} candidate chains`);
// ... restart / relocate the target, then narrow to the ones that still hold:
paths = nemclass.scan.rescan(paths, /* new goal */ 0x7fff56780000);
if (paths.length) {
  const uuid = nemclass.classes.create("Player");
  nemclass.classes.setFormula(uuid, paths[0].formula);
}
```

### Build a cheat table from a scan and freeze it
```ts
for (const addr of nemclass.scan.value("i32", 100)) {
  const i = nemclass.table.add({ description: "hp?", address: `0x${addr.toString(16)}`, type: "i32" });
  nemclass.table.freeze(i, 100);   // pin the value
}
nemclass.table.save("trainer");    // → tables/trainer.toml
```
(In the UI, Ctrl+F freezes/unfreezes every cheat-table row at once.)

### Iterative (stateful) scan session — the classic "find health" hunt
Unlike the one-shot `scan.value`/`scan.range`/`scan.aob`, a **session** keeps a
live result set on the host that you narrow over time — exactly like the UI
Scanner (`scan.first` → change the value in-game → `scan.next` → repeat). Linux
only; each call returns the current match count. Compare tags are
case-insensitive: `exact`/`eq`, `notEqual`/`ne`, `greater`/`gt`, `less`/`lt`,
`between`, `unknown`, `increased`/`inc`, `increasedBy`, `decreased`/`dec`,
`decreasedBy`, `changed`, `unchanged`.

```ts
// 1. You know your health is 100 right now.
let n = nemclass.scan.first("i32", 100);        // exact scan, e.g. 5000 hits
nemclass.log(`first: ${n} candidates`);

// 2. Take some damage in-game, then narrow to values that dropped.
n = nemclass.scan.next("decreased");            // e.g. 40 hits
// 3. Take more damage, narrow again — repeat until one address survives.
n = nemclass.scan.next("decreased");            // e.g. 1 hit

if (n === 1) {
  const [hp] = nemclass.scan.results();         // the survivor address
  nemclass.log(`health @ 0x${hp.toString(16)} = ${nemclass.mem.readI32(hp)}`);
  nemclass.mem.freeze(hp, "i32", "9999");       // pin it
}
nemclass.scan.reset();                          // drop the session when done
```

Don't know the starting value? Seed with `unknown` (no needle), then hunt by
change:
```ts
nemclass.scan.first("f32", undefined, "unknown"); // baseline: every candidate
nemclass.scan.next("increased");                  // mana went up
nemclass.scan.next("unchanged");                  // ...then held steady
const addrs = nemclass.scan.results(50);          // up to 50 addresses
```
`scan.results(max?)` returns up to `max` addresses (default 1000, hard cap
100000). The session is dropped automatically on detach or project change.

### Global hotkeys (`hotkeys.*` + `OnHotkey`)
Register a combo like `"Ctrl+Shift+H"`, `"F6"`, or `"Alt+K"`. `register` returns
an id; the app fires an `OnHotkey` event carrying that id whenever the combo is
pressed (matched against the current Ctrl/Shift/Alt state). Hotkeys are cleared
when a different project is opened.
```ts
const godMode = nemclass.hotkeys.register("Ctrl+Shift+H");
const heal    = nemclass.hotkeys.register("F6");

nemclass.on("OnHotkey", (e) => {
  if (e.kind !== "OnHotkey") return;
  if (e.id === godMode) {
    nemclass.mem.freeze(0x140000000, "i32", 9999); // pin health
    nemclass.ui.notify("God mode ON");
  } else if (e.id === heal) {
    nemclass.mem.writeI32(0x140000000, 100);
  }
});

// Later: nemclass.hotkeys.unregister(godMode);
```

### Direct memory freeze (`mem.freeze` / `mem.unfreeze`)
Freeze an address to a typed value without touching the cheat table. The freeze
is re-applied on a throttled tick (~200 ms) from the current registration, so a
later `mem.freeze` on the same address just updates the pinned value. Linux only.
```ts
nemclass.mem.freeze(0x7fff1234, "f32", 100.0);   // pin a float
nemclass.mem.freeze(0x7fff1234, "f32", 250.0);   // update the same address
nemclass.mem.unfreeze(0x7fff1234);               // stop freezing
```

### Enums (`enums.define` / `enums.list` / `enums.get`)
Upsert a project enum (custom type) by name. `values` maps each variant name to
its integer; `opts.size` (1/2/4/8, default 4) and `opts.flags` (bit-flags,
default false) are optional.
```ts
nemclass.enums.define("Team", { Red: 0, Blue: 1, Spectator: 2 });
nemclass.enums.define("Buffs", { Poison: 1, Haste: 2, Shield: 4 }, { size: 1, flags: true });

for (const en of nemclass.enums.list()) {
  nemclass.log(`${en.name} (size ${en.size}, flags ${en.flags})`);
}
const team = nemclass.enums.get("Team"); // { name, size, flags, values } | null
```

### Auto-dissect a struct from memory (ReClass auto-dissect)
```ts
const uuid = nemclass.classes.create("AutoStruct");
nemclass.classes.setFormula(uuid, "<game.bin> + 0x4C0000");
const fields = nemclass.classes.dissect(uuid, { size: 0x100 }); // guesses ints/floats/pointers/strings
nemclass.log(`dissected ${fields} fields`);
nemclass.ui.selectClass(uuid);
```

### Resolve a global via AOB + RIP-relative (one call)
The classic "find a global (e.g. UE `GWorld`/`SystemGlobalEnvironment`)" idiom —
AOB-scan a `mov reg, [rip+disp32]` site, resolve the RIP-relative target, deref:
```ts
// 48 8B 05 <disp32> lives at +10; disp is at +13, next instruction at +17.
const sge = nemclass.scan.aobResolveRip(
  "48 89 7C 24 ? E8 ? ? ? ? 48 8B 05 ? ? ? ? 45 33 C0",
  13, 17, { module: "test.dll", deref: true },
);
if (sge === null) throw new Error("pattern not found");
nemclass.log(`SGE @ 0x${sge.toString(16)}`);
```
Prefer the pieces? `mem.resolveRip(insn, 13, 17)` does just the RIP math; add
`mem.readPointer(...)` to deref. Both `?` and `??` are full-byte wildcards.

### Find who calls a function (xrefs)
```ts
const fn = nemclass.proc.resolveExport("game.bin", "TakeDamage");
if (fn) {
  const callers = nemclass.disasm.xrefsTo(fn); // call/jump/rip-relative sites in the module
  nemclass.log(`${callers.length} references to TakeDamage`);
  for (const site of callers) nemclass.log("  ref @ 0x" + site.toString(16));
}
```

## Notes & limits
- I64/U64 reads may lose precision in JS numbers; use `mem.readU64Str(addr)` for the exact value.
- Addresses are plain numbers; hex strings (`"0x1234"`) are also accepted where an address is expected.
- Pointer scan and disassembly are Linux-only (they need `/proc` + a live target); they return an error/empty off-Linux.
- Host calls are unavailable inside a `tryResolveClassAddress` resolver (it blocks the main thread); do scanning in normal handlers/`OnTick`.
