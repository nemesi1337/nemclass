//! Off-thread execution for the UI's discrete, long-running operations.
//!
//! eframe drives the whole app on one thread, so any expensive call made inline
//! from a click handler or per-frame `logic()` freezes the window until it
//! returns — a value scan (seconds), a pointer scan (tens of seconds), a module
//! dissect, project disk I/O, or the blocking script-resolve round-trip. This
//! module moves those onto a shared background thread pool.
//!
//! The model is deliberately small:
//!
//! - [`Runtime`] owns a single multi-threaded tokio runtime. Heavy work runs via
//!   `spawn_blocking` (the memory backends are synchronous libc/ioctl/Win32
//!   calls, not `async`), so tokio here is really just a managed blocking pool.
//! - [`BackgroundJob<T>`] is a per-operation handle: one in flight at a time,
//!   result delivered over a `std::sync::mpsc` channel the UI drains with a
//!   non-blocking [`BackgroundJob::poll`] each frame — no `block_on` ever touches
//!   the UI thread. The worker calls `ctx.request_repaint()` on completion so the
//!   frame wakes to ingest the result even when the app is otherwise idle.

use std::sync::mpsc::{self, Receiver, TryRecvError};

use eframe::egui;

/// The app-wide background runtime. Held by `NemclassApp` as `Option<Runtime>` so
/// it can be shut down without blocking on exit (see [`Runtime::shutdown`]).
pub struct Runtime {
    rt: tokio::runtime::Runtime,
}

impl Runtime {
    /// Builds the shared runtime. Two worker threads is plenty: the actual work
    /// runs on the (separate, on-demand) `spawn_blocking` pool.
    pub fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("nemclass-bg")
            .build()
            .expect("build background tokio runtime");
        Runtime { rt }
    }

    /// A cloneable handle for spawning onto this runtime.
    pub fn handle(&self) -> tokio::runtime::Handle {
        self.rt.handle().clone()
    }

    /// Non-blocking shutdown: drops the runtime without waiting for in-flight
    /// `spawn_blocking` tasks, so app exit never hangs on a running scan. Call
    /// from `Drop for NemclassApp`.
    pub fn shutdown(self) {
        self.rt.shutdown_background();
    }
}

/// The state of a [`BackgroundJob`] observed by a single [`BackgroundJob::poll`].
pub enum Poll<T> {
    /// No job has been spawned, or the last result was already taken.
    Idle,
    /// A job is running and has not produced a result yet.
    Running,
    /// The job finished; the payload is handed back exactly once.
    Done(T),
}

/// A handle to at most one in-flight background operation producing a `T`.
///
/// Spawn with [`BackgroundJob::spawn`], gate the triggering button on
/// [`BackgroundJob::is_running`], and drain the result with
/// [`BackgroundJob::poll`] once per frame. Spawning again while a job is running
/// supersedes it: the previous worker keeps running to completion (a
/// `spawn_blocking` task can't be cancelled mid-call) but its result is dropped
/// silently because its sender half is gone.
pub struct BackgroundJob<T> {
    rx: Option<Receiver<T>>,
}

impl<T> Default for BackgroundJob<T> {
    fn default() -> Self {
        BackgroundJob { rx: None }
    }
}

impl<T: Send + 'static> BackgroundJob<T> {
    /// True while a spawned job has not yet been drained by [`poll`](Self::poll).
    pub fn is_running(&self) -> bool {
        self.rx.is_some()
    }

    /// Runs `f` on the runtime's blocking pool and arranges for its return value
    /// to be picked up by the next [`poll`](Self::poll). `ctx` is used only to
    /// `request_repaint()` once the work finishes, waking the frame to ingest it.
    ///
    /// Replaces any previous in-flight job (see the type docs on supersession).
    pub fn spawn<F>(&mut self, rt: &tokio::runtime::Handle, ctx: egui::Context, f: F)
    where
        F: FnOnce() -> T + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        self.rx = Some(rx);
        rt.spawn_blocking(move || {
            // If the UI dropped the receiver (superseded / app shutting down) the
            // send fails harmlessly and the result is discarded.
            let _ = tx.send(f());
            ctx.request_repaint();
        });
    }

    /// Drains the job's result if it is ready. Call once per frame. Returns
    /// [`Poll::Done`] exactly once per completed job.
    pub fn poll(&mut self) -> Poll<T> {
        match &self.rx {
            None => Poll::Idle,
            Some(rx) => match rx.try_recv() {
                Ok(value) => {
                    self.rx = None;
                    Poll::Done(value)
                }
                Err(TryRecvError::Empty) => Poll::Running,
                // Worker panicked / dropped the sender without sending: treat as
                // idle so the UI is not stuck showing a spinner forever.
                Err(TryRecvError::Disconnected) => {
                    self.rx = None;
                    Poll::Idle
                }
            },
        }
    }
}
