//! M2: the real `rustyscript` (v8) [`ScriptEngine`], behind the `scripting`
//! feature.
//!
//! # Threading model
//!
//! A v8 isolate — and therefore `rustyscript::Runtime` — is **single-threaded and
//! `!Send`**. So [`RustyScriptEngine`] owns a **dedicated OS thread** that
//! constructs and drives the `Runtime` for its whole lifetime. The public handle
//! is `Send + Sync`: it holds only a [`std::sync::mpsc::Sender`] of [`Command`]s
//! plus the worker's [`JoinHandle`]. Every [`ScriptEngine`] method turns into a
//! command on that channel; [`Drop`] sends [`Command::Shutdown`] and joins.
//!
//! Event payloads are already `serde`-serializable ([`crate::events`]), so they
//! cross into JS as `serde_json::Value` via `json_args!`.
//!
//! # Host-callback bridge (the delicate part)
//!
//! Scripts call host functions (`pattern_scan`, `declare_type`, `declare_class`,
//! `log`) that need **live host state** — the attached [`nemclass_core::Process`]
//! and the open project — which lives on the **main thread**, not the worker. So
//! each JS-callable host function (registered with `register_function`) runs on
//! the worker thread, marshals a [`HostRequest`] onto a channel back to the main
//! thread, and **blocks on a per-request reply channel** for the answer.
//!
//! The main thread services those requests by calling
//! [`RustyScriptEngine::pump_host_requests`] every UI frame with its live
//! [`HostApi`]. This is the seam that lets worker-thread JS reach main-thread
//! state without sharing `!Send` handles.
//!
//! ## Deadlock avoidance (documented choice)
//!
//! [`RustyScriptEngine::resolve_class_address`] **blocks the main thread** on a
//! worker reply (the resolver hook must return a value). If, while the main
//! thread is blocked there, the JS resolver called a host function, the worker
//! would block on the main thread which is itself blocked on the worker →
//! **deadlock**.
//!
//! We resolve this by the **document-and-error** strategy (rather than a
//! re-entrant select on the main thread): the worker sets a *resolving* flag for
//! the duration of a `tryResolveClassAddress` call, and any host-function request
//! raised while that flag is set returns an **error to JS immediately** instead
//! of round-tripping to the (blocked) main thread. Host functions are therefore
//! *unavailable inside the resolver* — a resolver that calls one gets a clear
//! JS exception, never a hang. This keeps the main-thread wait a simple blocking
//! `recv()` with no re-entrancy, which is trivially deadlock-free. The `.d.ts`
//! documents the restriction (`tryResolveClassAddress` note).

use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, SyncSender};
use std::thread::JoinHandle;

use rustyscript::{json_args, serde_json, Module, Runtime, RuntimeOptions};
use serde_json::Value;

use crate::engine::ScriptEngine;
use crate::events::{ClassAddressQuery, Event};

/// The severity of a script [`HostApi::log`] line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Informational message.
    Info,
    /// Warning.
    Warn,
    /// Error.
    Error,
}

/// A JS-shaped, serde-deserializable mirror of
/// [`nemclass_model::EnumDescription`] (which itself does not derive serde, and
/// which this crate must not modify). Fields mirror the model exactly so the
/// `.d.ts` `EnumDescription` shape is faithful.
#[derive(serde::Deserialize)]
struct EnumDescriptor {
    /// Type name.
    name: String,
    /// Underlying size in bytes (1/2/4/8). Defaults to 4 if omitted.
    #[serde(default = "default_enum_size")]
    size: u8,
    /// Whether values are bit-flags. Defaults to `false`.
    #[serde(default)]
    use_flags: bool,
    /// Ordered `[name, value]` members.
    #[serde(default)]
    values: Vec<(String, i64)>,
}

fn default_enum_size() -> u8 {
    4
}

impl EnumDescriptor {
    /// Converts the JS mirror into the model's `EnumDescription`.
    fn into_model(self) -> nemclass_model::EnumDescription {
        let mut ty = nemclass_model::EnumDescription::new(self.name);
        ty.size = self.size;
        ty.use_flags = self.use_flags;
        ty.values = self.values;
        ty
    }
}

/// Live host state the embedder implements **on the main thread**, where the
/// attached [`nemclass_core::Process`] and the open project live.
///
/// The worker thread never holds these `!Send` handles; instead JS host calls are
/// marshalled as [`HostRequest`]s and answered here via
/// [`RustyScriptEngine::pump_host_requests`].
pub trait HostApi {
    /// IDA-style byte-pattern scan over `module`, returning absolute match
    /// addresses. Backed by reading the module's bytes from the live process and
    /// running [`crate::scan_module`] / [`crate::find_pattern`].
    fn pattern_scan(&mut self, module: &str, pattern: &str) -> Result<Vec<usize>, String>;

    /// Declare a custom type into the host's model.
    fn declare_type(
        &mut self,
        ty: nemclass_model::EnumDescription,
    ) -> Result<(), String>;

    /// Declare a class by `name` with an `address_formula` into the open project.
    fn declare_class(&mut self, name: &str, address_formula: &str) -> Result<(), String>;

    /// Emit a log line from a script.
    fn log(&mut self, level: LogLevel, msg: &str);
}

/// A host-API call marshalled from the worker (JS) thread to the main thread.
///
/// Each variant carries a one-shot reply channel the main thread answers on. The
/// worker blocks on the paired [`Receiver`] until [`RustyScriptEngine::pump_host_requests`]
/// services it. `pattern_scan` / `declare_*` reply with a `Result`; `log` is
/// fire-and-forget (no reply).
pub enum HostRequest {
    /// `nemclass.pattern_scan(module, pattern)`.
    PatternScan {
        /// Target module name.
        module: String,
        /// IDA-style pattern string.
        pattern: String,
        /// Reply: absolute match addresses, or an error string.
        reply: SyncSender<Result<Vec<usize>, String>>,
    },
    /// `nemclass.declare_type(descriptor)`.
    DeclareType {
        /// The custom type to declare.
        ty: nemclass_model::EnumDescription,
        /// Reply: unit, or an error string.
        reply: SyncSender<Result<(), String>>,
    },
    /// `nemclass.declare_class(name, addressFormula)`.
    DeclareClass {
        /// Class name.
        name: String,
        /// Address-formula expression.
        address_formula: String,
        /// Reply: unit, or an error string.
        reply: SyncSender<Result<(), String>>,
    },
    /// `nemclass.log(msg)` — fire-and-forget.
    Log {
        /// Severity.
        level: LogLevel,
        /// Message body.
        msg: String,
    },
}

/// Commands sent from the public handle (main thread) to the worker (v8) thread.
enum Command {
    /// Load a single script module from disk.
    LoadScript(PathBuf),
    /// Load every `*.js`/`*.ts` under a directory (the project's `src/`).
    LoadScriptsDir(PathBuf),
    /// Fire-and-forget: dispatch an event to the registered JS handlers.
    Dispatch(Event),
    /// Query: run the JS `tryResolveClassAddress` resolver; reply with the
    /// first address (or `None`).
    ResolveClassAddress {
        /// The query (pid + class UUID).
        query: ClassAddressQuery,
        /// Reply channel for the resolved address.
        reply: Sender<Option<usize>>,
    },
    /// Stop the worker; it drops the `Runtime` and exits.
    Shutdown,
}

/// The `RustyScriptEngine` public handle: `Send + Sync`, lives on the UI/bus
/// thread, and proxies to a dedicated v8 worker thread.
pub struct RustyScriptEngine {
    /// Command channel to the worker.
    tx: Sender<Command>,
    /// Drains host-API requests raised by worker-thread JS. The main thread
    /// services this via [`RustyScriptEngine::pump_host_requests`].
    host_rx: Receiver<HostRequest>,
    /// Worker join handle (taken on drop to join cleanly).
    worker: Option<JoinHandle<()>>,
}

// The handle only holds channel ends + a JoinHandle, all `Send`. v8 stays on the
// worker thread and never crosses this boundary.
impl RustyScriptEngine {
    /// Spawns the worker thread and its v8 `Runtime`, returning the public
    /// handle. The host functions are registered on the worker at startup.
    pub fn spawn() -> Result<Self, String> {
        let (tx, cmd_rx) = std::sync::mpsc::channel::<Command>();
        let (host_tx, host_rx) = std::sync::mpsc::channel::<HostRequest>();

        // Startup handshake: the worker reports whether Runtime construction and
        // host-fn registration succeeded before `spawn` returns.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();

        let worker = std::thread::Builder::new()
            .name("nemclass-v8".into())
            .spawn(move || worker_main(cmd_rx, host_tx, ready_tx))
            .map_err(|e| format!("failed to spawn v8 worker thread: {e}"))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx,
                host_rx,
                worker: Some(worker),
            }),
            Ok(Err(e)) => {
                let _ = worker.join();
                Err(e)
            }
            Err(_) => {
                let _ = worker.join();
                Err("v8 worker exited before signalling readiness".to_string())
            }
        }
    }

    /// Drains all pending host-API requests and answers them against `host`.
    /// **Call this every UI frame** — it is how worker-thread JS reaches the live
    /// main-thread [`HostApi`]. Non-blocking: returns once the queue is empty.
    pub fn pump_host_requests(&mut self, host: &mut dyn HostApi) {
        while let Ok(req) = self.host_rx.try_recv() {
            service_host_request(req, host);
        }
    }
}

/// Answers one [`HostRequest`] using the live [`HostApi`]. Shared by the frame
/// pump and (potentially) a blocking drain.
fn service_host_request(req: HostRequest, host: &mut dyn HostApi) {
    match req {
        HostRequest::PatternScan {
            module,
            pattern,
            reply,
        } => {
            let _ = reply.send(host.pattern_scan(&module, &pattern));
        }
        HostRequest::DeclareType { ty, reply } => {
            let _ = reply.send(host.declare_type(ty));
        }
        HostRequest::DeclareClass {
            name,
            address_formula,
            reply,
        } => {
            let _ = reply.send(host.declare_class(&name, &address_formula));
        }
        HostRequest::Log { level, msg } => {
            host.log(level, &msg);
        }
    }
}

impl Drop for RustyScriptEngine {
    fn drop(&mut self) {
        // Best-effort clean shutdown: tell the worker to stop and join it.
        let _ = self.tx.send(Command::Shutdown);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl ScriptEngine for RustyScriptEngine {
    fn load_scripts(&mut self, dir: &Path) -> Result<(), String> {
        self.tx
            .send(Command::LoadScriptsDir(dir.to_path_buf()))
            .map_err(|_| "v8 worker is gone".to_string())
    }

    fn register_host_fn(&mut self, _name: &str, _func: crate::engine::HostFn) {
        // The M2 engine registers its fixed host-API surface (pattern_scan,
        // declare_type, declare_class, log) on the worker at startup and routes
        // them through the `HostApi` trait / `HostRequest` bridge. Arbitrary
        // per-call Rust closures cannot cross to the `!Send` v8 thread, so this
        // trait method is intentionally a no-op here; the M1 `NoopEngine` keeps
        // the generic seam for tests.
    }

    fn on_event(&mut self, event: &Event) {
        // Fire-and-forget across the channel.
        let _ = self.tx.send(Command::Dispatch(event.clone()));
    }

    fn resolve_class_address(&mut self, query: &ClassAddressQuery) -> Option<usize> {
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        if self
            .tx
            .send(Command::ResolveClassAddress {
                query: query.clone(),
                reply: reply_tx,
            })
            .is_err()
        {
            return None;
        }
        // Block for the worker's answer. Host functions are unavailable inside
        // the resolver (see the module docs), so the worker never depends on the
        // main thread here — this simple blocking wait cannot deadlock.
        reply_rx.recv().ok().flatten()
    }
}

/// Shared JS shim installed into every runtime: defines the `nemclass` global
/// that wraps the raw registered host functions and provides `on(...)` handler
/// registration + the auto-dispatch of exported handler names.
const NEMCLASS_SHIM: &str = r#"
globalThis.__nemclass_handlers = globalThis.__nemclass_handlers || {};
globalThis.nemclass = {
    pattern_scan: (module, pattern) => rustyscript.functions.__host_pattern_scan(module, pattern),
    declare_type: (descriptor) => rustyscript.functions.__host_declare_type(descriptor),
    declare_class: (name, addressFormula) => rustyscript.functions.__host_declare_class(name, addressFormula),
    log: (msg) => rustyscript.functions.__host_log(String(msg)),
    on: (event, handler) => {
        (globalThis.__nemclass_handlers[event] ||= []).push(handler);
    },
};
"#;

/// The runtime-side entrypoint script rustyscript dispatches events into. It
/// walks handlers registered via `nemclass.on(...)` and, as a convenience, any
/// matching function `export`ed from a loaded module (recorded by the shim's
/// module scan is out of scope; we support `nemclass.on` + a global fallback).
const NEMCLASS_DISPATCH: &str = r#"
export function __nemclass_dispatch(kind, payload) {
    const handlers = (globalThis.__nemclass_handlers || {})[kind] || [];
    for (const h of handlers) {
        try { h(payload); } catch (e) { nemclass.log("handler error: " + e); }
    }
    // Global-function fallback: onAttach / onDetach / onProjectLoad / etc.
    const fallback = {
        OnAttach: "onAttach",
        OnDetach: "onDetach",
        OnProjectLoad: "onProjectLoad",
        ClassAddressUpdated: "classAddressUpdated",
        GlobalVariableUpdated: "globalVariableUpdated",
        Custom: "onCustom",
    }[kind];
    if (fallback && typeof globalThis[fallback] === "function") {
        try { globalThis[fallback](payload); } catch (e) { nemclass.log("handler error: " + e); }
    }
}

export function __nemclass_resolve(query) {
    const handlers = (globalThis.__nemclass_handlers || {})["tryResolveClassAddress"] || [];
    for (const h of handlers) {
        const r = h(query);
        if (typeof r === "number") return r;
    }
    if (typeof globalThis.tryResolveClassAddress === "function") {
        const r = globalThis.tryResolveClassAddress(query);
        if (typeof r === "number") return r;
    }
    return null;
}
"#;

/// State a JS host-fn callback needs to reach the main thread: the request
/// channel plus the *resolving* flag that makes host fns error out during
/// `tryResolveClassAddress` (deadlock avoidance).
#[derive(Clone)]
struct HostBridge {
    host_tx: Sender<HostRequest>,
    resolving: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl HostBridge {
    /// Sends a request that expects a reply and blocks for it — unless we are
    /// mid-resolve, in which case it errors immediately (no round-trip to the
    /// blocked main thread).
    fn call<T, F>(&self, make: F) -> Result<T, String>
    where
        F: FnOnce(SyncSender<Result<T, String>>) -> HostRequest,
    {
        if self.resolving.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(
                "host functions are unavailable inside tryResolveClassAddress".to_string(),
            );
        }
        let (reply_tx, reply_rx) = std::sync::mpsc::sync_channel(1);
        self.host_tx
            .send(make(reply_tx))
            .map_err(|_| "host bridge closed".to_string())?;
        reply_rx
            .recv()
            .map_err(|_| "host bridge dropped the reply".to_string())?
    }
}

/// The worker thread body: builds the `Runtime`, registers host functions, loads
/// the shim, then serves commands until `Shutdown`.
fn worker_main(
    cmd_rx: Receiver<Command>,
    host_tx: Sender<HostRequest>,
    ready_tx: Sender<Result<(), String>>,
) {
    let resolving = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bridge = HostBridge {
        host_tx,
        resolving: resolving.clone(),
    };

    let mut runtime = match Runtime::new(RuntimeOptions::default()) {
        Ok(r) => r,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("failed to create v8 runtime: {e}")));
            return;
        }
    };

    if let Err(e) = register_host_fns(&mut runtime, &bridge) {
        let _ = ready_tx.send(Err(e));
        return;
    }

    // Load the shim (defines the `nemclass` global) and the dispatch module.
    let shim = Module::new("__nemclass_shim.js", NEMCLASS_SHIM);
    if let Err(e) = runtime.load_module(&shim) {
        let _ = ready_tx.send(Err(format!("failed to load nemclass shim: {e}")));
        return;
    }
    let dispatch = Module::new("__nemclass_dispatch.js", NEMCLASS_DISPATCH);
    let dispatch_handle = match runtime.load_module(&dispatch) {
        Ok(h) => h,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("failed to load nemclass dispatch: {e}")));
            return;
        }
    };

    let _ = ready_tx.send(Ok(()));

    // Command loop.
    for cmd in cmd_rx {
        match cmd {
            Command::LoadScript(path) => {
                if let Ok(module) = Module::load(&path) {
                    if let Err(e) = runtime.load_module(&module) {
                        bridge_log(&bridge, LogLevel::Error, &format!("load {path:?}: {e}"));
                    }
                } else {
                    bridge_log(&bridge, LogLevel::Error, &format!("cannot read {path:?}"));
                }
            }
            Command::LoadScriptsDir(dir) => match Module::load_dir(&dir) {
                Ok(modules) => {
                    for module in modules {
                        if let Err(e) = runtime.load_module(&module) {
                            bridge_log(
                                &bridge,
                                LogLevel::Error,
                                &format!("load {:?}: {e}", module.filename()),
                            );
                        }
                    }
                }
                Err(e) => bridge_log(&bridge, LogLevel::Error, &format!("load dir {dir:?}: {e}")),
            },
            Command::Dispatch(event) => {
                let payload = serde_json::to_value(&event).unwrap_or(Value::Null);
                let kind = event.kind();
                let _res: Result<(), _> = runtime.call_function(
                    Some(&dispatch_handle),
                    "__nemclass_dispatch",
                    json_args!(kind, payload),
                );
                if let Err(e) = _res {
                    bridge_log(&bridge, LogLevel::Error, &format!("dispatch {kind}: {e}"));
                }
            }
            Command::ResolveClassAddress { query, reply } => {
                let q = serde_json::to_value(&query).unwrap_or(Value::Null);
                // Guard host fns for the duration of the resolver call.
                resolving.store(true, std::sync::atomic::Ordering::SeqCst);
                let out: Option<usize> = match runtime.call_function::<Option<i64>>(
                    Some(&dispatch_handle),
                    "__nemclass_resolve",
                    json_args!(q),
                ) {
                    Ok(Some(addr)) if addr >= 0 => Some(addr as usize),
                    Ok(_) => None,
                    Err(e) => {
                        bridge_log(&bridge, LogLevel::Error, &format!("resolve: {e}"));
                        None
                    }
                };
                resolving.store(false, std::sync::atomic::Ordering::SeqCst);
                let _ = reply.send(out);
            }
            Command::Shutdown => break,
        }
    }
    // `runtime` drops here on the worker thread — the only place v8 is dropped.
}

/// Registers the fixed host-API surface on the runtime, each closure marshalling
/// to the main thread via the [`HostBridge`].
fn register_host_fns(runtime: &mut Runtime, bridge: &HostBridge) -> Result<(), String> {
    let b = bridge.clone();
    runtime
        .register_function("__host_pattern_scan", move |args: &[Value]| {
            let module = json_str(args, 0)?;
            let pattern = json_str(args, 1)?;
            let hits = b
                .call(|reply| HostRequest::PatternScan {
                    module,
                    pattern,
                    reply,
                })
                .map_err(rustyscript::Error::Runtime)?;
            let arr: Vec<Value> = hits.into_iter().map(|a| Value::from(a as u64)).collect();
            Ok(Value::Array(arr))
        })
        .map_err(|e| format!("register pattern_scan: {e}"))?;

    let b = bridge.clone();
    runtime
        .register_function("__host_declare_type", move |args: &[Value]| {
            let descriptor = args.first().cloned().unwrap_or(Value::Null);
            // `nemclass_model::EnumDescription` does not derive serde, so we
            // deserialize into a local JS-shaped mirror and convert. This keeps
            // the model crate untouched while giving JS a stable descriptor.
            let mirror: EnumDescriptor = serde_json::from_value(descriptor)
                .map_err(|e| rustyscript::Error::Runtime(format!("bad EnumDescription: {e}")))?;
            let ty = mirror.into_model();
            b.call(|reply| HostRequest::DeclareType { ty, reply })
                .map_err(rustyscript::Error::Runtime)?;
            Ok(Value::Null)
        })
        .map_err(|e| format!("register declare_type: {e}"))?;

    let b = bridge.clone();
    runtime
        .register_function("__host_declare_class", move |args: &[Value]| {
            let name = json_str(args, 0)?;
            let address_formula = json_str(args, 1)?;
            b.call(|reply| HostRequest::DeclareClass {
                name,
                address_formula,
                reply,
            })
            .map_err(rustyscript::Error::Runtime)?;
            Ok(Value::Null)
        })
        .map_err(|e| format!("register declare_class: {e}"))?;

    let b = bridge.clone();
    runtime
        .register_function("__host_log", move |args: &[Value]| {
            let msg = json_str(args, 0).unwrap_or_default();
            // Fire-and-forget; never blocks, so it works even mid-resolve.
            let _ = b.host_tx.send(HostRequest::Log {
                level: LogLevel::Info,
                msg,
            });
            Ok(Value::Null)
        })
        .map_err(|e| format!("register log: {e}"))?;

    Ok(())
}

/// Extracts a string argument at `idx` from JS-supplied JSON args.
fn json_str(args: &[Value], idx: usize) -> Result<String, rustyscript::Error> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Ok(other.to_string()),
        None => Err(rustyscript::Error::Runtime(format!(
            "missing string argument #{idx}"
        ))),
    }
}

/// Sends a log line through the bridge (fire-and-forget).
fn bridge_log(bridge: &HostBridge, level: LogLevel, msg: &str) {
    let _ = bridge.host_tx.send(HostRequest::Log {
        level,
        msg: msg.to_string(),
    });
}
