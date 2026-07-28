# nemclass-ui

The egui/eframe desktop UI. Exposes `NemclassApp` (the `eframe::App`
implementation) and the `project_io` helpers; the `nemclass-app` binary just
launches it. Enables `nemclass-core`'s `symbols` feature so the disassembly and
function views can name code.

## Layout

- **Left panel** — the backend picker (`ProviderRegistry`; a hex auth-key field
  appears for the `linux-kernel` backend), a filterable/sorted process list
  (Wine processes are shown by their Windows `.exe`), attach/detach, and the
  class list.
- **Central tabs:**
  - **Memory View** — the class table (`egui_extras::TableBuilder`) with throttled
    live snapshots, edit-to-write-back, an **Auto-dissect** button, and live
    expansion of `VTable`/`Function` nodes.
  - **Scanner** — the `nemclass-scan` value scanner UI.
  - **Debugger** — attach + hardware/uprobe breakpoints via the kernel module.
  - **Memory** — a raw hex viewer (follow-pointer, string highlight, changed-byte
    tint, display types).
  - **Disassembly** — navigable disassembly with clickable call/jmp targets and
    symbol names.
- **Address bar** — the selected class's base, resolved from its formula.

## Projects

`project_io` provides `create_project_at` / `load_project_from` /
`save_project_to` for the on-disk project directory (see
`../../../docs/project-format.md`).

## Platform note

Linux is the supported UI platform today. A few call sites still use
`libc::pid_t` / a Linux-only module-enumeration path, so this crate does not yet
cross-compile to Windows even though `nemclass-core` does.

See `../../../docs/getting-started.md` and
`../../../docs/memory-viewer-and-dissection.md`.
