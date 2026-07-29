# Roadmap

Where nemclass stands against the three tools it draws from — **ReClass.NET**
(class reconstruction), **Cheat Engine** (scanning, patching, cheat tables) and
**PINCE** (Linux debugging workflows) — and what closed the gap.

This came out of a full review of all six crates in July 2026, cross-read
against the ReClass.NET sources. The architecture held up well: the layered
`MemoryBackend` / `ProcessProvider` seam, the mockable `ScanTarget`, the dock UI
and the ~70-method JS host API are all ahead of the references in places. What
was weak was correctness underneath and *workflow* on top.

**Phase 0 and M1–M8 are implemented**, including the items that were left open
in the first pass. What remains is listed under [Still open](#still-open) at the
end, honestly and specifically — it is now a short list of things that need a
Windows machine or a running target to finish, not features.

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

---

## Where nemclass leads

Worth stating, because the gap list below was long and one-sided:

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

## M1 — Class-view workflow ✅

*The core ReClass identity, and the biggest single gap.*

`selected_node` was a single `Option`, and every ReClass "…Node(s)" menu item is
plural for a reason: selecting eight rows and making them all `Int32` *is* the
workflow. Selection is now a set plus an anchor, with shift-click ranging over
the **visible** rows rather than sibling indices.

- Undo/redo over whole-project snapshots. Nodes are `Box<dyn Node>` and not
  `Clone`, so an inverse-operation scheme would need every op to reconstruct
  what it replaced — which is the serialization this does once, generically.
  A multi-row change is one undo step, because it was one action.
- Multi-row edits queue back-to-front: applying a delete or an insert
  front-to-back shifts every later index.
- Copy/cut/paste; Delete, arrows, shift+arrow, Ctrl+C/X/V/A/Z/Y, Escape — all
  guarded on text focus; hide/unhide; make-a-class-from-a-contiguous-run (a
  gapped selection is refused, not silently reordered); a search filter.
- The type menu covers every registered type. It offered scalars, vectors and
  matrices only, so `Array`, the text types, `VTable` and `Function` existed in
  the model and in saved projects but were unreachable from the UI.
- Class comments and project enums both round-tripped into generated source with
  no UI to write them. Both have editors; editing an enum re-binds the nodes
  that render through it.
- A dirty marker in the title bar, and New/Open ask before discarding.
- The editing model, selection and history live in `views/node_edit.rs`.

## M2 — Model completeness and ReClass.NET interop ✅

- Every pointer-shaped node hardcoded eight bytes, so a 32-bit target's layout
  was not merely wrong but **unrepresentable**. Pointer width lives on the
  `Project` and is pushed into the nodes, because `Node::memory_size` takes only
  `&self` — the class view lays out fields with no project in scope.
- New types: `Union`, `BitField`, `Enum`, `ClassInstanceArray`, `Utf32Text`, the
  three text pointers, `NInt`/`NUInt`, typed `Array` elements. Nodes carry the
  `hidden` flag `.rcnet` persists.
- **`.rcnet` import/export.** There was no interop at all. The two models differ
  — ReClass *wraps* (its pointers and arrays hold an inner node where we hold a
  UUID and an element tag), and we have double-precision vectors it has no type
  for — so every approximation is reported rather than absorbed.
- `NodeRegistry` keys on owned strings and stores `Box<dyn Fn>`: a plugin that
  computes its tag had to `Box::leak` it, and a bare `fn` cannot capture.
  `register_codegen` lets a type spell itself in generated source.
- Two codegen bugs the compile-the-output test caught: Rust emitted `#[repr(C)]`,
  which pads, where the layout being described is packed; C# marshalled
  `Utf8Text` as a `string` **reference** inside an explicit-layout struct, which
  throws `TypeLoadException` the moment it overlaps.

## M3 — Scanner to Cheat Engine parity ✅

- **Batching.** `next_scan` issued one syscall per surviving result — five
  million at the default cap — because `ScanTarget` had no batch read, while
  `read_buf_batch` and its IOV_MAX-chunked iovec implementation had been there
  the whole time. Batches of 1024. A short batch falls back to per-span reads so
  one freed address still drops one result.
- The previous generation is `mem::take`n, not cloned — about 100 MB per pass.
- A first scan shards across threads, cutting on the alignment lattice and
  reading `stride - 1` past the cut so a straddling value is found exactly once.
- Adjacent `rw-p` mappings are coalesced: the walk stopped at each region's end,
  so a value with two bytes either side of the seam could not be found at all.
- `Between` with no upper bound quietly became `value > lower`; refused now.
  `0xFFFFFFFF` for an `i32` was rejected as out of range where CE reads it as -1.
- Float rounding modes, percentage increase/decrease, same-as-first-scan (which
  needed a first-scan column carried through every narrowing), case-insensitive
  and UTF-32 strings, user-supplied alignment, hex display, save/load result sets.
- AOB and string scans prefilter with `memchr`; a leading wildcard disables it.

## M4 — Pointer scan maturity ✅

- The reverse search was an unmemoized DFS: every route reaching an intermediate
  address re-expanded it, so a depth-6 scan did not finish. Level-by-level BFS
  with a visit set. Collapsed alternative routes are **counted and reported**,
  not silently dropped.
- Signed offsets, `max_negative_offset`, `offset_alignment`,
  `must_end_in_static`, result scoring (shortest chains through smallest offsets
  first), progress and cancellation for both phases.
- The map serializes: harvesting it is most of the cost, and it was rebuilt from
  scratch for every goal. `rescan_paths` re-bases a chain's anchor against a
  moved module.
- Overlapping static ranges are coalesced — `is_mapped` consults only the last
  range whose base is below the address, so an anchor inside an overlap could be
  missed depending on sort order.

## M5 — Memory viewer editing ✅

Double-click a byte to type over it; select a span and Copy, Paste, Fill, or
*Copy as AOB* (in the spelling the scanner's own pattern parser accepts, checked
by a test). A short write is reported rather than swallowed. Paging is a whole
window at a time by button or PageUp/PageDown, saturating at both ends;
navigation gained a forward stack; bytes-per-row is selectable; addresses can be
bookmarked by name. The qword classification follows the viewport rather than
classifying the whole page for the sixteen rows anyone can see.

## M6 — Debugger workflows ✅

**Find what accesses / writes this address.** Every primitive existed —
hardware watchpoints, register capture, an event queue — and none of it was
assembled into the thing anyone opens a debugger for. `AccessTally` aggregates
hits by RIP, busiest first, with the most recent registers and a bounded site
table that reports its drops.

The captured RIP is the instruction *after* the access — a data watchpoint on
x86 traps once the access retires — and the UI says so rather than presenting it
as the accessing instruction. `preceding_instruction` does the walk-back by
finding the decode that ends exactly at the reported RIP, and returns nothing
when it cannot rather than guessing.

Also: the event poll drains the queue instead of taking one hit per tick; "Find
what writes this" on a class field; "Set breakpoint here" in the disassembler; a
clicked access site opens in the disassembler; a thread list, because every hit
reports a tid and nothing turned that number into a named thread.

## M7 — Assembler, patching, CE ecosystem ✅

`PatchSet` keeps the bytes that were there alongside the ones written.
Re-patching an address keeps the *first* patch's originals: the second patch
reads already-patched bytes, and storing those would make a revert restore the
first patch's output. A patch whose two sides disagree in length is refused —
it could not be reverted cleanly. Patches anchor to their module so a set can be
re-applied after a restart; an unanchored one refuses to rebase.

NOP-out is a recorded patch, "Patch bytes…" writes an arbitrary sequence, and
the patch list reverts and re-applies. Each write invalidates the decoded
listing — a plain re-focus only scrolled the stale one.

**A text assembler.** `iced-x86` decodes and builds instructions
programmatically but has no text assembler, and neither does anything else in the
Rust x86 ecosystem — so this parses the subset patching uses: flow control,
register and memory moves, arithmetic, comparisons, stack ops. It is deliberately
incomplete, and an unrecognised mnemonic is an error naming itself rather than a
wrong encoding. Branch targets are absolute and resolve against the address being
assembled at. The tests round-trip through the decoder rather than comparing
against hand-written bytes, which would only prove the test author and the code
agree.

**Code injection** is a detour into a code cave. Allocating in the target needs
`mmap` executed *in* the target, which is not wired up — and a detour works
without it, because every real binary has runs of alignment padding already
mapped executable. Displaced instructions are taken whole (a partial one decodes
as garbage and executes) and re-encoded at their new address so their branches
still point where they meant to. A payload that does not fit is refused rather
than run off the end of the padding, and the cave is written before the hook: the
other order leaves a jump into whatever the padding was.

**Disassembler annotations**: user comments and labels (the Comment column was
derived only, and a label replaces the address, which is the point of naming
one), an instruction/byte-pattern search, and basic-block reconstruction — the
listing decoded linearly and said nothing about shape. A branch out of the
decoded listing produces no edge, because claiming one to an address nothing is
known about would be a lie.

**`.CT` import.** Pointer chains convert correctly: CE lists offsets
innermost-first, so reading them in file order builds the chain backwards.
Imported formulas are checked against the real address grammar by a test. Nested
group headers become the `group` field. Auto-assembler scripts, Lua and bitfield
entries are reported by name rather than dropped.

**Cheat-table UX**: freeze modes, group collapsing, multi-select with bulk
actions, per-entry hotkeys, and a pointer-offset button. "Allow increase" is a
*ratchet*, not a weaker freeze: the new high becomes the floor, and the
comparison goes through the value type rather than the bytes — -1 has a larger
unsigned byte pattern than 1, so a bytewise ratchet is backwards for anything
signed.

## M8 — Platform, polish, docs ✅

- **Freeze on its own thread.** It ran from `App::logic`, which egui calls only
  when it repaints, so freezing silently stopped when the window was minimised —
  exactly when a trainer is supposed to be working.
- `ProcessProvider::enumerate_sections` splits the section walk from the module
  walk. Every scan and pointer-map build called the combined form and threw the
  modules away, having paid for a second handle and a remote PE-header read per
  Wine module.
- `Error::last` called `libc::__errno_location` under a bare `cfg(unix)`. That is
  the glibc/musl spelling; the BSDs and Apple export `__error`, so it did not
  link there at all.
- Auto-dissect runs on the background pool; it froze the window, including the
  button that started it.
- A settings dialog and theme support: the settings file had persisted the
  window size, dock layout, recent projects and live interval since it existed,
  with no way to see or change any of it, and no `set_visuals` call existed at
  all.
- **One notification surface.** Messages went to eight independent
  `status_msg`/`last_error` fields, each drawn in its own tab, so a scan error
  raised while the user was looking at the class view never appeared — and none
  of them expired. Panels keep their field as an outbox and it is drained into
  one stack per frame; a repeating message counts up rather than stacking.
- Progress and cancellation now also cover the pointer-scan rescan and the module
  dissect. A stopped rescan hands back what survived rather than an empty list,
  which would read as "every chain is dead".
- **Windows has a `ScanTarget`**, so the scanner, pointer scan and spider run
  there — every layer beneath them already could. `Process::resolve_symbol` and
  the PDB resolver are reachable: the resolver existed and nothing called it,
  because its entry point was `cfg(target_os = "linux")`.
- Docs: the getting-started layout showed the pre-dock arrangement, the
  code-generation example had the wrong signature and a `?` on an infallible
  call, and the project-format sample showed a shape the serializer does not
  write.

---

## Still open

Named specifically rather than left implied by the ticks above.

**The Windows UI.** `nemclass-core`, `-model` and `-scan` cross-compile to
`x86_64-pc-windows-gnu` — including the scan target and the PDB resolver — but
the egui shell is not Windows-clean and nothing here has been *run* on Windows.
This was the user's explicit scoping decision: fix the contract, stay
Linux-first. The Windows paths are compile-checked on every change and honest
about what they do; they are not validated behaviour.

**The PDB resolver's runtime behaviour.** It compiles and is now reachable, but
matching a module to its PDB is done by looking for a sibling `.pdb` rather than
reading the RSDS entry from the PE debug directory and consulting a symbol
server. That is written down in the module's own docs, not hidden.

**The CI gate.** `cargo make ci` fails at `fmt-check` on repo-wide pre-existing
rustfmt drift (~757 hunks) unrelated to any of this work. Clippy `-D warnings`
and the full test suite are green. A repo-wide reformat belongs in its own commit
with nothing else in it — that call is the user's, not a side effect of feature
work.
