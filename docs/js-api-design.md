# nemclass JS API — target surface (design)

Goal: give scripts the full power of the tool, in the spirit of Cheat Engine's Lua
API, PINCE's Python API, and ReClass automation. Namespaced globals, typed, with a
generated `nemclass.d.ts` so users get autocomplete.

Marshalling: host functions take/return JSON (serde_json::Value). Engine runs on a
dedicated thread; each call is a synchronous request → UI pump executes against the
live `Process`/`Project` via the per-frame `UiHostApi` (disjoint borrows) → response.

## Namespaces

### `mem` — memory access (requires attached process)
- `mem.readBytes(addr, len): number[]`
- `mem.writeBytes(addr, bytes: number[]): boolean`
- `mem.readI8/readI16/readI32/readI64(addr): number` (I64 as number; may lose precision — also `readI64Str` returns string)
- `mem.readU8/readU16/readU32/readU64(addr): number`
- `mem.readF32/readF64(addr): number`
- `mem.readPointer(addr): number` (pointer-width read)
- `mem.writeI8..writeU64/writeF32/writeF64(addr, value): boolean`
- `mem.readString(addr, maxLen, enc?: "utf8"|"utf16"): string`
- `mem.writeString(addr, str, enc?): boolean`
- `mem.readChain(base, offsets: number[]): number` — CE-style pointer chain (deref each hop, add offset)
- `mem.isValid(addr): boolean` — address falls in a readable region

### `proc` — process & modules
- `proc.attached(): boolean`
- `proc.pid(): number`
- `proc.name(): string`
- `proc.modules(): {name, base, size, path}[]`
- `proc.module(name): {name, base, size, path} | null`
- `proc.baseAddress(module?): number` — module base (main module if omitted)
- `proc.regions(): {start, end, size, perms}[]`

### `scan` — searching
- `scan.aob(pattern: string, opts?: {module?, start?, end?, max?}): number[]`
  IDA-style masked pattern: `"48 8B ?? ?? 89"` (`??`/`?` = wildcard).
- `scan.value(type, value, opts?): number[]` — first exact scan (type: i8..u64,f32,f64,bytes,string)
- `scan.next(prev: number[], op, value?): number[]` — comparison (eq/ne/gt/lt/inc/dec/changed/unchanged)
- returns addresses; large result sets truncated with a logged notice (no silent cap)

### `classes` — ReClass project automation
- `classes.list(): {uuid, name, size, formula}[]`
- `classes.create(name?): string /*uuid*/`
- `classes.get(uuidOrName): {uuid, name, formula, nodes: {...}[]} | null`
- `classes.setFormula(uuid, formula): boolean`
- `classes.addNode(uuid, type, opts?: {name?, comment?, count?, length?}): boolean`
- `classes.setPointerTarget(uuid, path: number[], targetUuid): boolean`
- `classes.setClassInstance(uuid, path, targetUuid): boolean`
- `classes.removeNode(uuid, path): boolean`
- `classes.resolveBase(uuid): number | null` — evaluate the class formula against the live process

### `disasm`
- `disasm.at(addr, count?): {address, bytes, text, target?}[]`
- `disasm.func(addr): {address, bytes, text, target?}[]`

### `table` — CE-style address list / freeze (backed by scanner freeze list)
- `table.add({desc?, address, type, value?}): id`
- `table.freeze(address, type, value): id`
- `table.unfreeze(id): boolean`
- `table.list(): {id, desc, address, type, value, frozen}[]`
- `table.remove(id): boolean`

### events / hooks / timing
- `on(event, handler)` — lifecycle (`attach`,`detach`,`frame`,`projectLoad`,…) + custom
- `emit(event, data?)`
- `interval(ms, handler): id` / `clearInterval(id)` — periodic tick driven by the UI pump (for freeze/poll loops)
- `hotkey(combo, handler): id` — e.g. `"Ctrl+Shift+H"`; fires while app focused

### `ui` / `log`
- `log(...args)`, `log.warn(...)`, `log.error(...)`
- `ui.notify(msg)` — status line
- `ui.gotoMemory(addr)`, `ui.gotoDisasm(addr)`, `ui.selectClass(uuid)`

## Rollout
1. Wire the request/response op for the new functions (extend the existing dispatch).
2. Implement handlers in `UiHostApi` reusing core (read/write/scan/disasm/formula) and the model (class CRUD).
3. Extend `write_script_scaffold`'s `nemclass.d.ts` to declare every namespace/function.
4. Ship `src/` example scripts: pointer-chain watch, AOB→class, freeze table, auto-dissect helper.
5. Surface the function list in the Scripts panel "Host functions" reference (single source of truth).

Backward compatibility: keep any existing global (e.g. current host object) working; add the
namespaces alongside, or alias old names.
