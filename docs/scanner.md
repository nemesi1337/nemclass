# Value scanner

`nemclass-scan` is a Cheat-Engine-style memory scanner — a port of ReClass.NET's
`MemoryScanner`, restructured around a single **`ScanTarget`** trait so the scan
engine is platform-neutral and mock-testable. The live Linux target is backed by
`nemclass-core`; the engine itself works against an in-memory `MockTarget`.

## Core types

- **`ScanValueType`** — the searchable value kinds: `I8..I64`, `U8..U64`,
  `F32`/`F64`, `Bytes` (array-of-bytes / AOB with `??` wildcards), and UTF-8 /
  UTF-16 strings. Each knows its stride and how to `parse_needle`.
- **`ScanCompareType`** — `Exact`, `NotEqual`, `GreaterThan`, `LessThan`,
  `Between` (with an upper bound), the change-relative kinds for next-scans
  (`Increased`, `IncreasedBy`, `Decreased`, `DecreasedBy`, `Changed`,
  `Unchanged`), and `Unknown`, which is a **first-scan baseline only** — it
  accepts every candidate, so a next scan rejects it (`is_baseline`).
- **`Needle`** — a parsed search value; `Needle::with_upper_bound` supplies the
  second operand for `Between`.
- **`ScanTarget` / `WriteTarget`** — the read/write seams. Implementors:
  `MockTarget` (in-memory, for tests/headless), and (Linux) `ProcessTarget`
  backed by `process_vm_readv`/`writev` region enumeration.
- **`Scanner<T>`** — generic over `ScanTarget`.
- **`ScanError`** — why a scan could not run: `NeedsFirstScan`,
  `CompareNeedsPrevious`, `CompareIsFirstScanOnly`, `MissingNeedle`,
  `NeedleTypeMismatch`, `NoStride`, `TargetUnreadable`, `Cancelled`. `Display`
  gives a message fit for a status line.
- **`ScanObserver`** — progress callback; returning `false` aborts the pass.
  Any `FnMut(ScanProgress) -> bool` implements it; `NoObserver` is the no-op.
- **`ScanStats`** — `scanned` / `matched` / `unreadable` for the last pass.
- **`FreezeSet`** — periodically re-writes pinned values through a `WriteTarget`.

## First scan / next scan

```rust,ignore
use nemclass_scan::{MockTarget, Scanner, ScanValueType, ScanCompareType};

let mut buf = vec![0u8; 32];
buf[8..12].copy_from_slice(&1337i32.to_le_bytes());
let target = MockTarget::new(0x1000, buf);

let mut scanner = Scanner::new(target, ScanValueType::I32);
let needle = ScanValueType::I32.parse_needle("1337").unwrap();
let results = scanner.first_scan(ScanCompareType::Exact, Some(needle)).unwrap();
assert_eq!(results.iter().next().unwrap().address, 0x1008);
```

- **`first_scan`** walks the target's readable regions in chunks (region-safe,
  short-read tolerant), collecting every address matching the compare.
- **`next_scan`** re-reads only the *previous* match addresses and re-applies a
  compare — including the change-relative kinds (e.g. `Increased` vs the value
  captured last scan). This is how you narrow "unknown initial value" hunts.
  - An address that can no longer be read (freed, unmapped) drops **that one
    result**; the count lands in `Scanner::last_scan_stats().unreadable`. Only
    an all-unreadable pass errors, with `TargetUnreadable`, and it deliberately
    leaves the current generation intact so a dead process is never mistaken
    for a narrowing to zero.
  - `Unknown` is rejected here, before any generation is pushed.
  - Needle-less `Increased`/`Decreased`/`Changed`/`Unchanged` interpret both
    values **as the scan's value type**, so signedness and float ordering are
    respected (`-1 → 1` increases; `-1.5 → -0.5` increases). Float
    `Changed`/`Unchanged` use the same `DEFAULT_FLOAT_TOLERANCE` the needle-ful
    path does, so a 1-ULP wobble is not a change.
- **`undo`** restores the previous result set from a bounded history.
- **`first_scan_with` / `next_scan_with`** take a `ScanObserver` for progress and
  cooperative cancellation. An aborted pass returns `ScanError::Cancelled` and
  leaves the current generation untouched.

### Alignment and the result cap

By default a first scan only tests addresses aligned to the value's width —
Cheat Engine's **Fast Scan**, and the reason compilers align scalars.
`Scanner::with_alignment(1)` tests every byte offset instead, at roughly the type
width in extra results and memory. Variable-width types (`Bytes`, strings) are
always byte-granular: a pattern or an embedded string has no natural alignment.

`Scanner::with_result_limit` caps a first scan (5M by default) and
`results_truncated()` reports that the set is a prefix. This matters for
`Unknown`, which matches *every* candidate: even aligned, a large working set
produces tens of millions of results.

> **Known limitation.** An `Unknown` baseline is stored as one result per
> candidate address. Cheat Engine instead snapshots each region's bytes and
> compares region-to-region, which is dramatically cheaper for exactly this case.
> Until that lands, scope an unknown-value hunt with the scan range.

### Result columns

`ScanResults` is a column store — addresses, `current`, `previous` — so a result
costs `8 + 2 * stride` bytes with no per-result allocation. `ScanResult` is a
borrowed view (`address`, `current`, `previous`).

`previous` is the value as of the generation *before* this one, which is what a
Cheat Engine "Previous" column shows. On a first scan it equals `current`.

## AOB (array-of-bytes) patterns

`ScanValueType::Bytes` parses patterns with wildcards, e.g. `48 8B ?? ?? 89`.
The pattern engine (`BytePattern` / `PatternByte`) matches known bytes and skips
wildcard positions. This is the scanner-side analog of the IDA-style
`find_pattern` host API in `nemclass-script`.

## Freezing values

Add an address to a `FreezeSet` with a value; on each tick the set re-writes it
through the `WriteTarget`, holding the value constant against the target's own
writes. Removing it stops the re-write.

## In the UI

The **Scanner** tab drives all of this: choose a value type + compare, run a
first scan, iteratively next-scan to narrow, then freeze or edit results. For the
`Between` compare an upper-bound field appears so both operands are captured.

Once a session is active:

- the **value type is locked** (the stored previous values are that type's
  width) — press *New Scan* to change it;
- the **compare list switches** to the next-scan vocabulary: the change-relative
  kinds appear and `Unknown` disappears;
- **Value** re-reads from the target on the `live_interval_ms` throttle, for the
  rows actually on screen. It is tinted when it differs from what the scan
  matched, and shows a red `??` for an address that could not be read — never
  the stale scan-time bytes, which would look identical to a value that simply
  is not changing;
- **Previous** shows the prior generation's value;
- a long first scan shows a progress bar and a **Stop** button.

The saved **address list** (persisted under `tables/`, see
[project format](project-format.md)) is docked
beneath the results, Cheat Engine style, and is where freezing lives — the
Freeze button on a result row adds a frozen entry there. Double-clicking a
result's address, or the right-click menu, sends it to the same list. Entries
resolve either a hex literal or an address formula
(`[<game.exe> + 0x10] + 0x4`), so a saved entry survives ASLR.
