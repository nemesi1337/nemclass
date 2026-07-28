//! Shared in-memory log buffer for script output, surfaced in the Scripts panel.
//!
//! All scripting-layer log traffic (from `HostApi::log`, engine lifecycle events,
//! and UI-side status messages) flows through a `ScriptLog` — an
//! `Rc<RefCell<Vec<LogLine>>>`. Using `Rc<RefCell>` rather than a channel is
//! correct here because both the writer (`UiHostApi`, built each frame on the UI
//! thread) and the reader (`ScriptsPanel`) run on the **same thread**: there is
//! no cross-thread sharing. The `Rc` clone is cheap and keeps the borrow set in
//! `UiHostApi` small (no lifetime on the log field).

use std::{cell::RefCell, rc::Rc};

/// Severity / category of a log line.
///
/// `Info` is only constructed by the feature-gated `UiHostApi`, so allow it to be
/// "unused" in the default (no-`scripting`) build.
#[cfg_attr(not(feature = "scripting"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogKind {
    /// Informational message from a script or the engine.
    Info,
    /// A warning worth surfacing but not fatal.
    Warn,
    /// An error from a script host-API call or the engine itself.
    Error,
    /// Engine/project lifecycle event (spawn, load, detach, …).
    Lifecycle,
}

/// A single line in the script log.
pub struct LogLine {
    /// Severity / category.
    pub kind: LogKind,
    /// Human-readable message text.
    pub text: String,
}

/// Maximum number of lines kept in the buffer.  Oldest lines are evicted first.
const MAX_LOG_LINES: usize = 1_000;

/// A shared, cheaply-cloneable handle to the script log buffer.
///
/// Clone this to pass the same buffer into `UiHostApi` each frame without
/// borrowing the surrounding struct — the clone is an `Rc` bump, not a copy of
/// the data.
pub type ScriptLog = Rc<RefCell<Vec<LogLine>>>;

/// Creates a new, empty `ScriptLog`.
pub fn new_script_log() -> ScriptLog {
    Rc::new(RefCell::new(Vec::new()))
}

/// Appends a line to `log`, evicting the oldest entries once the buffer exceeds
/// [`MAX_LOG_LINES`].
pub fn push(log: &ScriptLog, kind: LogKind, text: impl Into<String>) {
    let mut buf = log.borrow_mut();
    if buf.len() >= MAX_LOG_LINES {
        // Drain the oldest quarter to amortise the cost of repeated draining.
        let drain_count = MAX_LOG_LINES / 4;
        buf.drain(..drain_count);
    }
    buf.push(LogLine { kind, text: text.into() });
}
