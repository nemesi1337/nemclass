# Getting started

## Prerequisites

- A recent stable Rust toolchain (edition 2024).
- Linux is the supported development/runtime platform today.
- For the graphical app: a working display / windowing environment (the app is
  an `eframe`/`egui` native window).

## Build

```text
# whole workspace
cargo build --workspace

# just the app
cargo build -p nemclass-app
```

The base build pulls in no heavy optional dependencies. To include DWARF/PDB
symbol resolution (used by the disassembly/function views), build with the
`symbols` feature — note that `nemclass-ui` already enables it, so building the
app gets it automatically.

## Run

```text
cargo run -p nemclass-app
```

This opens the **NemClass** window. The layout:

```text
┌─ menu bar (New / Open / Save) ───────────────────────────────────┐
├─ address bar (selected class base + formula) ────────────────────┤
├─ left panel ────────────┬─ central panel ─────────────────────────┤
│ Backend: [combo]        │ [Memory View][Scanner][Debugger]         │
│ (auth key, if kernel)   │ [Memory][Disassembly]                    │
│ Filter: [___]  Refresh  │                                          │
│  process list           │  active tab content …                    │
│ Classes:  ▶ MyClass     │                                          │
└─────────────────────────┴──────────────────────────────────────────┘
```

## First class (the vertical slice)

1. **Pick a backend.** In the left panel choose `linux-native` (the default,
   ptrace-free `process_vm_readv`). Use `linux-kernel` only if you have the
   kernel module loaded — see [kernel-module.md](kernel-module.md).
2. **Enumerate & attach.** Click *Refresh* to list processes (type in *Filter*
   to narrow by name or pid), select one, and *Attach*.
3. **Create a class.** In the *Classes* list click *+ Add class*. Set its
   **address formula** in the address bar, e.g. `"target"+0x4C0A10` or a pointer
   chain like `["libfoo.so"+0x2E80]+0x18` — see the formula language in
   [domain-model.md](domain-model.md).
4. **Add nodes** (fields) — integers, floats, pointers, text, arrays, nested
   classes — in the *Memory View* table. Values update live (throttled snapshot).
5. **Edit a value.** Double-click a value cell, type a new value, and it is
   written back to the target via the backend.

## Faster starts with dissection

Instead of adding fields by hand, click **Auto-dissect** in the Memory View (or
*Dissect as class here* in the **Memory** hex viewer) to have nemclass guess the
field types at the class base — pointers, strings, vtables, functions, integers —
and fill the class for you. See
[memory-viewer-and-dissection.md](memory-viewer-and-dissection.md).

## Projects

*File ▸ New* creates a project **directory** containing `project.nemclass`
(TOML) plus scaffolding. *Open* / *Save* round-trip it losslessly. See
[project-format.md](project-format.md).
