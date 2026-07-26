#![doc = include_str!("detailed_docs.md")]
//! `nemclass-app` — `eframe` entry point for the NemClass RE tool.
//!
//! This binary is the thin launcher: it sets up `NativeOptions`, calls
//! `eframe::run_native`, and returns.  All UI logic lives in `nemclass-ui`.
//!
//! ## Screenshot smoke mode
//! `nemclass-app --screenshot <PATH.ppm> [--frames N]` boots the UI, renders a
//! few frames, captures the framebuffer to a binary PPM, and exits. It doubles
//! as a render verification (proves the dock layout builds and draws without
//! panicking) and a way to produce a visual of the current UI.

// On Windows release builds, suppress the console window that would otherwise
// flash when the app starts.  On non-Windows this attribute is silently ignored.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;
use nemclass_ui::NemclassApp;

fn main() -> eframe::Result {
    // Optional: initialise env_logger so egui's internal logs appear on stderr
    // when RUST_LOG is set.  Ignore if the logger was already installed.
    let _ = env_logger_try_init();

    // Restore the last window size from settings (position is not persisted —
    // Wayland ignores programmatic positioning).
    let inner_size = nemclass_ui::saved_window_size().unwrap_or([1400.0, 880.0]);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NemClass – Memory RE Tool")
            .with_inner_size(inner_size)
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    // `--screenshot <path> [--frames N]` runs the capture harness instead of the
    // interactive app.
    if let Some(shot) = ScreenshotConfig::from_args() {
        return eframe::run_native(
            "NemClass",
            native_options,
            Box::new(move |_cc| Ok(Box::new(ScreenshotHarness::new(NemclassApp::new(), shot)))),
        );
    }

    eframe::run_native(
        "NemClass",
        native_options,
        Box::new(|_cc| Ok(Box::new(NemclassApp::new()))),
    )
}

/// Parsed `--screenshot` invocation.
struct ScreenshotConfig {
    path: PathBuf,
    /// Frame at which to request the screenshot (lets the layout settle).
    shot_frame: u32,
    /// Optional pid to attach to (`self` = this process) for a live capture.
    attach_pid: Option<i32>,
    /// Backend for the attach (default `linux-native`).
    backend: String,
    /// Module name substring to disassemble after attaching.
    module: Option<String>,
    /// Run a dissect and show the Navigator (rather than the disassembler).
    dissect: bool,
}

impl ScreenshotConfig {
    fn from_args() -> Option<Self> {
        let args: Vec<String> = std::env::args().collect();
        let flag = |name: &str| -> Option<String> {
            args.iter()
                .position(|a| a == name)
                .and_then(|i| args.get(i + 1))
                .cloned()
        };
        let idx = args.iter().position(|a| a == "--screenshot")?;
        let path = PathBuf::from(args.get(idx + 1)?);
        let shot_frame = flag("--frames").and_then(|s| s.parse().ok()).unwrap_or(6);
        let attach_pid = flag("--attach").and_then(|s| {
            if s == "self" {
                Some(std::process::id() as i32)
            } else {
                s.parse().ok()
            }
        });
        let backend = flag("--backend").unwrap_or_else(|| "linux-native".to_string());
        let module = flag("--module");
        let dissect = args.iter().any(|a| a == "--dissect");
        Some(Self {
            path,
            shot_frame,
            attach_pid,
            backend,
            module,
            dissect,
        })
    }
}

/// Wraps [`NemclassApp`], driving it for a few frames, then capturing the
/// framebuffer to a PPM and closing the window.
struct ScreenshotHarness {
    inner: NemclassApp,
    cfg: ScreenshotConfig,
    frame_count: u32,
}

impl ScreenshotHarness {
    fn new(inner: NemclassApp, cfg: ScreenshotConfig) -> Self {
        Self {
            inner,
            cfg,
            frame_count: 0,
        }
    }
}

impl eframe::App for ScreenshotHarness {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // On the first frame, optionally attach + drive the disassembler so the
        // capture shows a live view rather than the "attach first" placeholder.
        if self.frame_count == 0
            && let Some(pid) = self.cfg.attach_pid
        {
            if let Err(e) = self.inner.debug_attach_disasm(
                &self.cfg.backend,
                pid,
                self.cfg.module.as_deref(),
            ) {
                eprintln!("screenshot: attach failed: {e}");
            } else {
                println!("screenshot: attached to pid {pid}");
                if self.cfg.dissect {
                    self.inner.debug_dissect();
                    self.inner.debug_solo_navigator();
                } else {
                    self.inner.debug_solo_disasm();
                }
            }
        }

        self.inner.logic(ctx, frame);
        self.frame_count += 1;

        // Save a screenshot event delivered from a prior request, then quit.
        let shot: Option<Arc<egui::ColorImage>> = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = shot {
            if let Err(e) = save_ppm(&self.cfg.path, &image) {
                eprintln!(
                    "screenshot: failed to write {}: {e}",
                    self.cfg.path.display()
                );
            } else {
                println!("screenshot: wrote {}", self.cfg.path.display());
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Request the capture once the layout has settled.
        if self.frame_count == self.cfg.shot_frame {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
        // Keep frames flowing so the request/response round-trips promptly.
        ctx.request_repaint();
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.inner.ui(ui, frame);
    }
}

/// Writes a `ColorImage` as a binary PPM (P6, RGB — alpha dropped). No external
/// image crate needed; convert to PNG with `magick out.ppm out.png` if desired.
fn save_ppm(path: &std::path::Path, image: &egui::ColorImage) -> std::io::Result<()> {
    let [w, h] = image.size;
    let mut out = format!("P6\n{w} {h}\n255\n").into_bytes();
    out.reserve(w * h * 3);
    for px in &image.pixels {
        out.extend_from_slice(&[px.r(), px.g(), px.b()]);
    }
    std::fs::write(path, out)
}

/// Try to initialise `env_logger`; silently ignore `SetLoggerError` if another
/// logger was already installed (common in test harnesses).
fn env_logger_try_init() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::try_init().map_err(Into::into)
}
