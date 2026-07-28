# nemclass-core

The process/memory foundation of nemclass. Everything the model, scanner, and UI
build on lives here, with all OS-specific code isolated behind `#[cfg(...)]`.

## What's in here

- **Backend seams.** `MemoryBackend` (raw `read_buf`/`write_buf` + batched
  variants) and `ProcessProvider` (`enumerate_processes`, `open`,
  `enumerate_sections_and_modules`), plus a `ProviderRegistry` that maps a name
  to a boxed provider.
- **`Process`.** A handle wrapping a boxed `MemoryBackend` with typed access —
  `read::<T>` / `read_batch::<T>` / `write::<T>` via `bytemuck::Pod`, plus
  `read_buf` and `modules()`.
- **Backends.** Linux iovec (`process_vm_readv`/`writev`) + `LinuxProvider`; the
  privileged `KernelBackend`/`KernelProvider` + `Debugger` over the `nemclass_mod`
  char device (Linux); the `windows-sys` backend (`#[cfg(windows)]`).
- **Disassembly.** An iced-x86 wrapper: `disassemble_instructions` /
  `InstructionData` with a `FlowKind` and direct branch `target`.
- **Symbols** (`symbols` feature). `SymbolResolver` — DWARF (`addr2line`/`object`)
  and PDB (`pdb-addr2line`) address→name resolution, plus PE/ELF export parsers.
- **Analysis.** `RegionIndex`/`AddrClass`, `detect_strings`/`string_at`,
  `classify_value`/`PointerClass`, and `disassemble_function`/`FunctionDisasm` —
  the primitives behind the memory dissector.

## Typed reads at a glance

```rust,ignore
let registry = ProviderRegistry::default();
let provider = registry.get("linux-native").unwrap();
let process = provider.open(pid)?;

let hp: i32 = process.read::<i32>(base + 0x10)?;
process.write::<i32>(base + 0x10, hp + 25)?;
```

## Features & platform

- `symbols` — opt-in DWARF/PDB resolution. Off by default; the base build
  compiles none of `addr2line`/`object`/`pdb-addr2line`.
- Linux is the primary platform; the crate cross-compiles to
  `x86_64-pc-windows-gnu`. The kernel backend/debugger and the analysis/disasm
  helpers are Linux-only.

See the workspace guides: `../../../docs/memory-backends.md`,
`../../../docs/kernel-module.md`, and
`../../../docs/memory-viewer-and-dissection.md`.
