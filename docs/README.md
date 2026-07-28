# nemclass documentation

**nemclass** is a native, Linux-first (Windows-ready) reverse-engineering tool
written in Rust. It combines two capabilities:

- **ReClass.NET-style class reconstruction** — build up `struct`/`class`
  definitions over a live process's memory and watch fields update in real time.
- **Cheat-Engine-style tooling** — a value scanner, a raw hex memory viewer, a
  memory *dissector* (auto-guess field types), a disassembler, and (on Linux) a
  privileged kernel-module backend with a non-ptrace debugger.

> The on-disk repository directory is `reclass-rs`, but the product and all
> crates are named **nemclass**.

## Documentation map

| Guide | What it covers |
|-------|----------------|
| [architecture.md](architecture.md) | The Cargo workspace, crate graph, and the layered backend design. |
| [getting-started.md](getting-started.md) | Build, run, attach to a process, and define your first class. |
| [memory-backends.md](memory-backends.md) | `MemoryBackend`/`ProcessProvider`/`ProviderRegistry` and the native / kernel / Windows backends. |
| [kernel-module.md](kernel-module.md) | The `nemclass_mod` Linux kernel module: loading, auth, and how the client talks to it. |
| [domain-model.md](domain-model.md) | The `Node` hierarchy, `ClassNode`, `Project`, and the address-formula language. |
| [project-format.md](project-format.md) | The `project.nemclass` (TOML) format and the project directory layout. |
| [scanner.md](scanner.md) | The value scanner: value/compare types, first/next scans, AOB patterns, freeze. |
| [memory-viewer-and-dissection.md](memory-viewer-and-dissection.md) | The hex viewer, auto-dissect, vtable/function reconstruction, and the disassembly view. |
| [scripting-and-plugins.md](scripting-and-plugins.md) | The event bus, host APIs, compile-time plugins, and the (experimental) JS engine. |
| [code-generation.md](code-generation.md) | Exporting classes to C++ / C# / Rust. |
| [building-and-testing.md](building-and-testing.md) | Cargo features, the test/clippy gates, and cross-compilation status. |

## Crate map

| Crate | Role |
|-------|------|
| `nemclass-core` | Process/memory layer: backend traits, `Process`, typed read/write, backends (iovec / kernel / Windows), disassembler, symbols, and the memory-dissection analysis module. |
| `nemclass-model` | Domain model: the `Node` hierarchy, `ClassNode`, `Project`, the address-formula parser, `project.nemclass` (TOML) (de)serialization, code generators, and the auto-dissector. |
| `nemclass-script` | Event bus + lifecycle events, the `ScriptEngine` trait, host APIs, compile-time plugins, and the feature-gated JS engine. |
| `nemclass-scan` | Cheat-Engine-style value scanner over a mockable `ScanTarget` seam. |
| `nemclass-ui` | The egui/eframe desktop UI (process picker, class view, scanner, debugger, hex viewer, disassembly). |
| `nemclass-app` | The `eframe` binary that launches the UI. |

## Platform status

nemclass is developed **Linux-first**. `nemclass-core` cross-compiles to
`x86_64-pc-windows-gnu` (a native `ReadProcessMemory` backend exists), but the
desktop UI is not yet Windows-clean — Linux is the supported platform today.
Several features (the kernel backend/debugger, the disassembler-backed views,
and DWARF/PDB symbol resolution) are Linux-only or opt-in; each guide notes its
platform requirements.
