# nemclass-scan

A Cheat-Engine-style value scanner — a port of ReClass.NET's `MemoryScanner`,
built around a single `ScanTarget` seam so the engine is platform-neutral and
mock-testable. The live Linux target is backed by `nemclass-core`; the engine
works equally against an in-memory `MockTarget`.

## What's in here

- **`ScanValueType`** — searchable kinds: `I8..I64`, `U8..U64`, `F32`/`F64`,
  `Bytes` (AOB with `??` wildcards), and UTF-8/UTF-16 strings. Each knows its
  stride and `parse_needle`.
- **`ScanCompareType`** — `Exact`/`NotEqual`/`GreaterThan`/`LessThan`/`Between`,
  the change-relative kinds (`Increased`, `IncreasedBy`, `Decreased`,
  `DecreasedBy`, `Changed`, `Unchanged`), and `Unknown` — a first-scan baseline
  only, since it accepts every candidate.
- **`Needle`** — a parsed search value; `with_upper_bound` supplies the second
  operand for `Between`.
- **`ScanTarget` / `WriteTarget`** — the read/write seams. `MockTarget`
  (in-memory) and (Linux) `ProcessTarget`.
- **`Scanner<T>`** — `first_scan` (chunked region walk, alignment-stepped and
  result-capped) and `next_scan` (re-reads only previous matches, dropping any
  that became unreadable), with a bounded `undo` history. The `*_with` variants
  take a `ScanObserver` for progress and cancellation.
- **`ScanResults`** — a column store of `(address, current, previous)`.
- **`ScanError` / `ScanStats`** — typed failure reasons and per-pass counters.
- **`FreezeSet`** — periodically re-writes pinned values through a `WriteTarget`.
- **`BytePattern` / `PatternByte`** — the AOB matcher.

## Example

```rust,ignore
use nemclass_scan::{MockTarget, Scanner, ScanValueType, ScanCompareType};

let mut buf = vec![0u8; 32];
buf[8..12].copy_from_slice(&1337i32.to_le_bytes());
let target = MockTarget::new(0x1000, buf);

let mut scanner = Scanner::new(target, ScanValueType::I32);
let needle = ScanValueType::I32.parse_needle("1337").unwrap();
let results = scanner.first_scan(ScanCompareType::Exact, Some(needle)).unwrap();
```

The engine depends only on the `ScanTarget` trait, so the full scan/next-scan/
freeze flow is unit-tested headlessly against `MockTarget`.

See `../../../docs/scanner.md`.
