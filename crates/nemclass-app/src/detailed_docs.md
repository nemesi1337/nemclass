# nemclass-app

The `eframe` binary — the thin launcher for the NemClass RE tool. It sets up
`NativeOptions` (window title/size), calls `eframe::run_native`, and hands off to
`nemclass_ui::NemclassApp`. All UI and application logic lives in `nemclass-ui`.

## Run

```text
cargo run -p nemclass-app
```

On non-debug builds the Windows console window is suppressed via
`windows_subsystem = "windows"` (ignored on other platforms). If `RUST_LOG` is
set, `env_logger` surfaces egui's internal logs on stderr.

See `../../../docs/getting-started.md` for the end-to-end workflow.
