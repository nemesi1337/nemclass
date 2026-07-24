//! `nemclass-app` — `eframe` entry point for the NemClass RE tool.
//!
//! This binary is the thin launcher: it sets up `NativeOptions`, calls
//! `eframe::run_native`, and returns.  All UI logic lives in `nemclass-ui`.

// On Windows release builds, suppress the console window that would otherwise
// flash when the app starts.  On non-Windows this attribute is silently ignored.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use nemclass_ui::NemclassApp;

fn main() -> eframe::Result {
    // Optional: initialise env_logger so egui's internal logs appear on stderr
    // when RUST_LOG is set.  Ignore if the logger was already installed.
    let _ = env_logger_try_init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("NemClass – Memory RE Tool")
            .with_inner_size([1280.0, 800.0])
            .with_min_inner_size([800.0, 500.0]),
        ..Default::default()
    };

    eframe::run_native(
        "NemClass",
        native_options,
        Box::new(|_cc| Ok(Box::new(NemclassApp::new()))),
    )
}

/// Try to initialise `env_logger`; silently ignore `SetLoggerError` if another
/// logger was already installed (common in test harnesses).
fn env_logger_try_init() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::try_init().map_err(Into::into)
}
