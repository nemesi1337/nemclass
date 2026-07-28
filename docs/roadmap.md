# Roadmap

Where nemclass stands against the three tools it draws from — **ReClass.NET**
(class reconstruction), **Cheat Engine** (scanning, patching, cheat tables) and
**PINCE** (Linux debugging workflows) — and what closes the gap.

This came out of a full review of all six crates in July 2026, cross-read
against the ReClass.NET sources. The architecture held up well: the layered
`MemoryBackend` / `ProcessProvider` seam, the mockable `ScanTarget`, the dock UI
and the ~70-method JS host API are all ahead of the references in places. What
was weak was correctness underneath and *workflow* on top.

**Phase 0 (stabilization) is complete.** The milestones below are not.

---

## Phase 0 — stabilization ✅

Seven commits fixing correctness and data-loss defects. Summarised because the
detail is in the commit messages:

| Area | What was wrong |
|------|----------------|
| Scan engine | One `EFAULT` aborted an entire first scan; a hole mid-region silently abandoned the rest of it with no diagnostic. Pointer-map entries were sorted by value alone and then `dedup`ed, so every 1 MiB chunk boundary leaked a duplicate and `find_paths` emitted the same path repeatedly. |
| Memory layer | Both symbol resolvers `Box::leak`ed the module file they index — one full module image leaked per attach, forever. The Windows backend returned `Err` for `ERROR_PARTIAL_COPY` while the trait documents a byte count, so the first range crossing a mapping boundary aborted every scan/disassembly on Windows. `write_buf` flipped pages to RWX on every write and raced itself into leaving them that way. |
| Model / codegen | The Rust generator put the opening brace inside a line comment, so any class with a comment produced unparseable output. No generator escaped comments. C++ emitted `wchar_t` for UTF-16 (4 bytes on Linux), failing its own `static_assert`. An unknown node type made the whole project file unopenable. Duplicate class UUIDs silently destroyed a class. |
| Script engine | Dropping the engine hung the application whenever the worker was mid-host-call. An unbounded pump let `for(;;) nemclass.log()` freeze the UI and exhaust memory. |
| Session lifecycle | Attaching to a second process without detaching first left five panels on the old one — including the cheat table, which then wrote process A's frozen values into process B. Nothing detected a dead target. |
| Input | Typing `0x10` into an Int32 field wrote **10**. Five address parsers with three conventions: `140000000` meant two different addresses depending on which box you typed it in. Ctrl+F fired while typing. |

Verification: `cargo make ci` green (fmt, clippy `-D warnings`, tests), ~420
tests, the C++/Rust generators' output now compiled by `g++`/`rustc` in-test, and
an end-to-end `--screenshot` run that attaches to a live process.

---

## Where nemclass already leads

Worth stating, because the gap list below is long and one-sided:

- **Backend abstraction.** `ProviderRegistry` with a real `dyn ProcessProvider`
  beats ReClass.NET's flat `CoreFunctions` C table; the kernel-module backend has
  no equivalent in any of the three.
- **Scripting.** The ~70-method JS host API (`mem`, `proc`, `scan`, `classes`,
  `disasm`, `table`, `ui`, `hotkeys`) exceeds anything ReClass.NET exposes and is
  comparable to CE's Lua.
- **Disassembler.** Virtualized linear listing across selected modules, xrefs,
  back-synced navigation, operand-masked signature generation — ReClass.NET has
  none of this.
- **Scanner scoping.** Module-scoped scans and full protection/memory-type
  tri-state filters, ahead of both references.
- **UI shell.** Dockable persisted layout, background job pool with progress and
  cancel, auto-dissect with preview.

---

## M1 — Class-view workflow

*The core ReClass identity, and the biggest single gap.*

Prerequisite: split `views/mod.rs` (5300 lines, ~60 fields on `NemclassApp`)
into `class_view`, `snapshot`, `node_edit`, `session`, `scripting`, `project`.
Replace the eight ad-hoc `pending_*` options with one `AppCommand` queue.

- **Multi-select / shift+arrow range selection.** `selected_node` is a single
  `Option`; every ReClass "…Node(s)" menu item is plural. Not being able to
  select eight rows and change them all to `Int32` is the workflow.
- Copy/paste nodes; **undo/redo** over `NodeEditOp` (today "Delete 1024 fields"
  and "Accept auto-dissect" are irreversible); keyboard shortcuts (Delete,
  arrows, Ctrl+C/V/S/O/N); create-class-from-nodes; hide/unhide; search in class.
- Expose node types that exist in the model but not in the type menu: `Array`,
  `Utf8Text`, `Utf16Text`, `VTable`, `Function`, `FunctionPtr`.
- Class comment editing (the field exists, no UI writes it); an enum editor
  (`project.enums` round-trips, no UI at all).
- A dirty flag and an unsaved-changes prompt; confirmation on destructive
  actions.

## M2 — Model completeness and ReClass.NET interop

- Missing node types: `Union`, `BitField`, `Enum` (bind a field to the existing
  `EnumDescription`), typed `Array` elements, `ClassInstanceArray`, `Utf32Text`,
  `Utf16TextPtr`/`Utf32TextPtr`, `NInt`/`NUInt`.
- **Pointer width.** `Pointer`/`VTable`/`Function` hardcode 8 bytes, so a 32-bit
  target's layout is unrepresentable. Same for the vtable probe.
- **`.rcnet` import/export** — there is currently *no* interop with ReClass.NET
  projects at all. Needs the `IsHidden` node flag the format persists.
- Plugin extensibility: `NodeRegistry::register` takes bare `fn` pointers, so a
  plugin cannot capture configuration and a dynamic tag must be leaked. Move to
  `Box<dyn Fn>` + owned keys (this also collapses the `VECTOR_SHAPES` /
  `MATRIX_SHAPES` duplication). Add a code-generator extension point — today a
  plugin node type emits an anonymous byte blob.
- C# `Utf8Text` marshals as a `string` reference field inside an explicit-layout
  struct; should use a fixed byte array as the UTF-16 path already does.

## M3 — Scanner to Cheat Engine parity

- **Batching.** `next_scan` issues one syscall per surviving result — 5 M at the
  default cap. `MemoryBackend::read_buf_batch` and an `IOV_MAX`-chunked iovec
  implementation already exist; `ScanTarget` just does not expose them. Biggest
  available speedup. Also `mem::take` the previous generation instead of cloning
  ~80 MB per pass.
- Multi-threaded first scan; a `memchr`-style prefilter for AOB/string scans.
- Coalesce abutting regions: a value straddling two adjacent `rw-p` mappings is
  currently never found.
- Missing CE settings: grouped/struct scan, hex result display, float rounding
  modes (one absolute tolerance today), percentage increase/decrease, "same as
  first scan", user-supplied fast-scan alignment (boolean today),
  case-insensitive and UTF-32 strings, save/load result sets, multi-select
  results with bulk add, pause-target-while-scanning.
- `parse_int::<i32>("0xFFFFFFFF")` fails where CE reads it as `-1`; `Between`
  with no upper bound silently degrades to `GreaterThan`.

## M4 — Pointer scan maturity

Replace the exponential unmemoized DFS with CE's level-by-level reverse BFS with
per-level dedup. Add pointermap save/load (the map is rebuilt from scratch every
scan), rescan against a new goal after a restart, negative offsets,
offset/alignment filters, "must end in a static", result scoring, and progress +
cancel — this is the longest operation in the app and shows only a spinner.

## M5 — Memory viewer editing

In-place hex editing, a byte-selection model, copy/paste/fill, AOB-from-
selection, scrolling past the fixed 4 KiB window (today you must retype an
address to advance a page), forward navigation, configurable bytes-per-row,
bookmarks. Also clamp qword classification to the viewport — Phase 0 moved it off
the frame loop, but it still classifies the whole page.

## M6 — Debugger workflows

The kernel module already provides hardware breakpoints/watchpoints and register
capture. What is missing is the layer on top.

- **"Find what accesses / writes this address"** — arm a watchpoint, aggregate
  hits by RIP with counts, symbols, decoded instruction and register snapshots.
  The most-used feature in both CE and ReClass.NET, and mostly assembly of parts
  that already exist.
- Thread list (`/proc/<pid>/task`; the kernel ABI already reports `tid`),
  per-thread registers, execution control, call stack, register editing (the ABI
  is read-only), breakpoint enable/disable, conditions, hit counts.
- "Set breakpoint here" in the disassembler context menu; today the debugger's
  address must be hand-typed.
- Unify debugger attach with the main attach (they open separate authed fds, so
  they are in different kernel sessions), run it off the UI thread, and add a
  `ptrace` fallback when the module is not loaded.

## M7 — Assembler, patching, CE ecosystem

`iced-x86` is already a dependency and ships `code_asm`; there is no assembler
anywhere today, and NOP-out is the only patch — irreversible, with no record.

- Assemble-in-place, then a patch list with revert and persistence.
- User comments and labels in the disassembler (the Comment column is derived
  only), rename-function, byte/instruction search, basic-block reconstruction.
- **`.CT` import** — the community's entire cheat-table corpus is unusable.
- Cheat-table UX: groups (the field serializes, no UI), per-entry hotkeys, a
  pointer-offset editor, freeze modes (allow increase/decrease), multi-select.
- Code injection (alloc + detour) on top of the assembler.

## M8 — Platform, polish, docs

- One toast/status surface replacing the eight independent never-expiring
  message channels; progress and cancel on the four long operations that lack
  them (pointer scan, rescan, module dissect, auto-dissect — the last still runs
  synchronously on the UI thread).
- **Freeze on its own thread.** It runs from `App::logic`, so freezing silently
  stops when the window is minimised.
- A settings dialog (settings persist but have no UI), theme support, Escape on
  modals, disabled-control hover text.
- Split `ProcessProvider::enumerate_sections_and_modules`: every scan and
  pointer-map build pays for a module list it discards, including remote
  PE-header reads.
- Windows honestly: there is no Windows `ScanTarget` at all, the Windows symbol
  resolver is reachable from nothing, and `Error::last` uses `__errno_location`
  under `#[cfg(unix)]` (wrong on macOS/BSD).

---

## Known documentation drift

- `getting-started.md` shows a pre-dock three-tab layout and calls the Classes
  tab "Memory View".
- `memory-viewer-and-dissection.md` marks shipped features "(TODO)".
- `code-generation.md` and `project-format.md` show an API signature and a
  project file that do not match the code.
