# Architecture

nemclass is a Cargo **workspace** (Rust edition 2024) of six crates with a
one-directional dependency graph. Keeping the dependencies acyclic keeps the
low-level memory code free of any UI or domain concerns and makes each layer
independently testable.

```text
        nemclass-app        (eframe binary — the launcher)
             │
        nemclass-ui         (egui views: pickers, class view, scanner, hex, disasm)
          │      │
          │      └────────────► nemclass-scan   (value scanner)
          │
     ┌────┴────┐
     ▼         ▼
nemclass-model  nemclass-script   (domain model)   (events + plugins/JS)
     │
     ▼
nemclass-core   (process/memory layer: backends, Process, disasm, symbols, analysis)
```

- `nemclass-model` depends on `nemclass-core` (the address-formula parser and
  the dissector resolve against a live `Process` / module list).
- `nemclass-scan` depends on `nemclass-core` (its live target reads process
  memory) but the scan engine itself is generic over a `ScanTarget` trait.
- `nemclass-ui` depends on model, script, scan, and core.
- `nemclass-app` depends only on `nemclass-ui`.

## The layered backend design

The heart of `nemclass-core` is two composable traits so the *raw-IO* seam and
the *platform-lifecycle* seam can evolve independently:

- **`MemoryBackend`** — raw read/write on an already-opened target:
  `read_buf` / `read_buf_batch` / `write_buf` / `write_buf_batch`.
  Implementors: the Linux iovec backend (`process_vm_readv`/`writev`), the
  `KernelBackend` (routes IO through the `nemclass_mod` char device), and the
  Windows backend (`ReadProcessMemory`/`WriteProcessMemory`).
- **`ProcessProvider`** — the lifecycle above raw IO: `enumerate_processes`,
  `open(pid) -> Process`, and `enumerate_sections_and_modules`. Implementors:
  `LinuxProvider`, `KernelProvider`, `WindowsProvider`.
- **`ProviderRegistry`** — maps a backend name to a boxed provider so the UI can
  offer a backend picker. Default entries: `"linux-native"` and `"linux-kernel"`
  on Linux, `"windows-native"` on Windows.

`Process` wraps a boxed `MemoryBackend` and adds typed access —
`read::<T>` / `read_batch::<T>` / `write::<T>` — implemented on top of `read_buf`
using `bytemuck::Pod` (no hand-rolled `unsafe` transmutes). See
[memory-backends.md](memory-backends.md).

## Platform isolation

All OS-specific code lives behind `#[cfg(...)]`:

- Linux `/proc`, `libc` iovec, ptrace-free kernel IO → `#[cfg(target_os = "linux")]`.
- Windows `windows-sys` backend → `#[cfg(windows)]`.
- Platform-neutral value types (`ProcessEntry`, `MemoryRegion`, `Protection`,
  `Section`, `Module`, `Pid`) live in `nemclass-core::internal::process::types`
  and compile everywhere.

The `Pid` type alias (`libc::pid_t` on unix, `i32` elsewhere) keeps the trait
signatures platform-neutral so a Windows build never depends on `libc`.

## Feature flags

Two optional Cargo features keep the base build lean:

- **`symbols`** (on `nemclass-core`) — DWARF (`addr2line`/`object`) on Unix and
  PDB (`pdb-addr2line`) on Windows for resolving a code address to a function
  name. Enabled transitively by `nemclass-ui`. Off by default the crate compiles
  zero of these dependencies.
- **`scripting`** (on `nemclass-script`) — the rustyscript/v8 JS engine. Heavy
  to build (prebuilt v8 download + a long compile), and **on by default for
  `nemclass-app`**. It builds only because `serde` is pinned below 1.0.220 —
  the deno/swc tree still references the `serde::__private` facade that
  1.0.220 removed. See the pin comments in the workspace `Cargo.toml` before
  bumping `serde`, `toml` or `deno_media_type`.

See [building-and-testing.md](building-and-testing.md) for the full matrix.
