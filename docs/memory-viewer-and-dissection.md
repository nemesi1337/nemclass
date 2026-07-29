# Memory viewer & dissection

This is nemclass's reverse-engineering surface: a raw hex viewer, an automatic
*dissector* that guesses field types, reconstruction of vtables and functions,
and a navigable disassembler. The analysis primitives live in
`nemclass-core::analysis` and the disassembler; the guessing pass lives in
`nemclass-model::dissect`; the UI ties them together. Most of this is **Linux-only**
and function naming needs the `symbols` feature.

## Analysis primitives (`nemclass-core`)

- **`RegionIndex` / `AddrClass`** — build an index of the target's mapped regions
  (`RegionIndex::from_pid`) and classify any address as `Unmapped`, `Data`, or
  `Executable` (with the owning module). This answers "is this a valid pointer?
  does it point to code?".
- **String detection** — `detect_strings(buf, min_len)` and `string_at(...)` find
  printable ASCII/UTF-8 and UTF-16LE runs in a byte buffer.
- **Pointer classification** — `classify_value(value, &region_index, read)`
  returns `PointerClass`: `Null`, `NotPointer`, `DataPtr`, `CodePtr`, or
  `VTablePtr { method_count }` (a data slot whose target is an aligned array of
  ≥2 code pointers).
- **Disassembly** — the iced-x86 wrapper (`disassemble_instructions`) annotates
  each `InstructionData` with a `FlowKind` (`Seq`/`Call`/`Jump`/`CondJump`/`Ret`/
  `Int3`) and a direct branch `target`. `disassemble_function(process, addr, max)`
  walks linearly to `ret`/`int3` and collects call targets.

## Symbol resolution (`symbols` feature)

`SymbolResolver` maps a runtime code address to a function name from on-disk
debug info: **DWARF** (via `addr2line`/`object`) on Linux and **PDB** (via
`pdb-addr2line`) on Windows, falling back to the ELF/PE export tables. It reads
the module's backing file (found from `/proc/<pid>/maps`) and applies the correct
PIE/ET_EXEC load bias so probe addresses land in the object's address space.
`Process::resolve_symbol(addr)` is the convenience entry point (Linux + `symbols`).

## The auto-dissector (`nemclass-model::dissect`)

`auto_dissect(process, base, len)` reads a region and walks it in pointer-sized
steps, emitting a `Vec<NodeDef>` of guessed fields:

- inline strings → `Utf8Text` / `Utf16Text` (sized to the run),
- vtable pointers → `VTable` with N `VMethod` children,
- code pointers → `FunctionPtr`, data pointers → `Pointer`,
- otherwise a small integer → `Int64`, else `Hex64`.

The pure core, `dissect_buffer(base, buf, classify)`, takes an injected classifier
so it is fully unit-testable without a live process. The emitted `NodeDef`s use
only registered type tags, so they deserialize straight back into live nodes.

## UI: the four surfaces

1. **Memory View (class table) ▸ Auto-dissect.** Runs `auto_dissect` at the
   selected class's base, previews the guessed nodes (a type-count summary), and
   on *Accept* fills the class.
2. **Memory View ▸ live node expansion.** Expanding a `VTable` node walks the
   pointer array live and lists each method (resolved name + a *disasm* link);
   expanding a `Function`/`FunctionPtr` node shows its disassembly inline.
3. **Memory tab (raw hex editor).** `address | hex bytes | ascii` grid with a
   go-to box, follow-pointer (a qword classified as a pointer becomes a clickable
   link tagged data/code/vtable), display-type toggle (byte/word/dword/qword/
   float), configurable row width (8/16/32), string-run highlighting, and
   changed-byte tinting between snapshots.

   It edits: double-click a byte to type over it, click and shift-click to
   select a span, then Copy, Paste, Fill, or *Copy as AOB* to hand the pattern
   to the scanner. Paging is a whole window at a time (buttons or
   PageUp/PageDown), navigation is back **and** forward, and addresses can be
   bookmarked by name. Context actions: *Dissect as class here* and
   *Disassemble here*.
4. **Disassembly tab.** `address | bytes | instruction`, with the entry function
   named via `resolve_symbol`, call/jmp/jcc targets rendered as clickable links
   (annotated with the target's symbol name when known), and a back/forward
   navigation stack.

   Patching lives here: *NOP out* and *Patch bytes…* write through a recorded
   [`PatchSet`], so every change keeps the bytes it replaced and the patch list
   reverts or re-applies it. *Set breakpoint here* arms an execute breakpoint in
   the debugger without retyping the address.

Together these cover **strings, vtables, functions, and function calls** —
discoverable automatically or by hand, and cross-linked so a vtable method jumps
straight into the disassembler.

Auto-dissect runs on the background pool: it reads and classifies every word in
the span, and running that inline froze the window until it finished.
