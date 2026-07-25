# Building & testing

## Build

```text
cargo build --workspace                         # base build (lean, no v8/DWARF)
cargo build -p nemclass-core --features symbols # DWARF/PDB symbol resolution
```

`nemclass-ui` enables `nemclass-core/symbols`, so `cargo build -p nemclass-app`
(or `--workspace`) compiles the symbol backends. A standalone
`cargo build -p nemclass-core` stays lean.

## Cargo features

| Feature | Crate | Effect | Status |
|---------|-------|--------|--------|
| `symbols` | `nemclass-core` | DWARF (`addr2line`/`object`, unix) + PDB (`pdb-addr2line`, windows) address→name resolution. | Working; opt-in; enabled by `nemclass-ui`. |
| `scripting` | `nemclass-script` | rustyscript/v8 JS engine on a worker thread. | **Currently unbuildable** (upstream deno `swc_config`-vs-`serde` conflict); deferred. Do not use `--all-features`. |

## Tests

```text
cargo test --workspace                          # all non-feature tests
cargo test -p nemclass-core --features symbols  # includes the DWARF resolver test
```

Test coverage highlights:

- **core** — flow-control/branch-target decoding, `RegionIndex` classification,
  string/pointer/vtable detection, and (with `symbols`) a DWARF resolver test
  that compiles a `-g` fixture with `cc` at test time.
- **model** — node `memory_size`, value rendering, the address-formula parser,
  lossless `project.nemclass` TOML round-trips, and `dissect_buffer`.
- **scan** — the scan engine against an in-memory `MockTarget`.
- **script** — event bus, `find_pattern`, and the plugin registry.

## Lint gate

```text
cargo clippy --workspace --all-targets -- -D warnings
```

The workspace is expected to be clippy-clean with warnings denied.

## Cross-compilation

```text
cargo check -p nemclass-core --target x86_64-pc-windows-gnu             # clean
cargo check -p nemclass-core --target x86_64-pc-windows-gnu --features symbols  # clean
```

- **`nemclass-core` cross-compiles to Windows** — it has a native
  `ReadProcessMemory`/`WriteProcessMemory` backend under `#[cfg(windows)]`.
- **`nemclass-ui` does not yet cross-compile to Windows** — a couple of UI call
  sites still use `libc::pid_t` / a Linux-only `Process::modules` path that need
  abstracting to the neutral `Pid`. Linux is the supported UI platform today.

## Keeping the knowledge graph current

This repo ships a `graphify-out/` knowledge graph. After code changes, run
`graphify update .` to keep it fresh (AST-only, no API cost).
