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
  `Between` (with an upper bound), plus the change-relative kinds for next-scans:
  `Unknown`, `Increased`, `IncreasedBy`, `Decreased`, `DecreasedBy`, `Changed`,
  `Unchanged`.
- **`Needle`** — a parsed search value; `Needle::with_upper_bound` supplies the
  second operand for `Between`.
- **`ScanTarget` / `WriteTarget`** — the read/write seams. Implementors:
  `MockTarget` (in-memory, for tests/headless), and (Linux) `ProcessTarget`
  backed by `process_vm_readv`/`writev` region enumeration.
- **`Scanner<T>`** — generic over `ScanTarget`.
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
- **`undo`** restores the previous result set from a bounded history.

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
