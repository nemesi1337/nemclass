//! `ScriptHost` — a feature-gated wrapper enum that unifies the real
//! `RustyScriptEngine` (behind `--features scripting`) and a `Disabled` no-op,
//! so `mod.rs` holds exactly one `script_host: ScriptHost` field regardless of
//! whether the scripting feature is compiled in.
//!
//! All `cfg` noise lives here; callers only see `ScriptHost` methods.

use std::path::Path;

use nemclass_script::Event;

/// The active scripting back-end held by `NemclassApp`.
///
/// - With `--features scripting`: `Rusty(RustyScriptEngine)` is the live v8
///   engine; `Disabled` is still reachable when `spawn()` fails.
/// - Without the feature: only `Disabled` compiles; the `Rusty` variant and all
///   v8 code are removed from the binary entirely.
pub enum ScriptHost {
    /// The live rustyscript / v8 engine.  Only compiled with the feature.
    #[cfg(feature = "scripting")]
    Rusty(nemclass_script::RustyScriptEngine),
    /// No scripting: either the feature is absent or `spawn()` returned an error.
    Disabled,
}

impl ScriptHost {
    /// Attempts to spawn the real engine (feature-gated) and returns the host
    /// together with an optional human-readable error message.
    ///
    /// - **With feature, spawn succeeds** → `(Rusty(engine), None)`.
    /// - **With feature, spawn fails** → `(Disabled, Some(error_string))`.
    /// - **Without feature** → `(Disabled, None)` — no error, just no engine.
    pub fn spawn() -> (Self, Option<String>) {
        #[cfg(feature = "scripting")]
        {
            match nemclass_script::RustyScriptEngine::spawn() {
                Ok(engine) => (ScriptHost::Rusty(engine), None),
                Err(msg) => (ScriptHost::Disabled, Some(msg)),
            }
        }
        #[cfg(not(feature = "scripting"))]
        {
            (ScriptHost::Disabled, None)
        }
    }

    /// Loads every `*.js` / `*.ts` file under `dir` into the engine.
    ///
    /// Returns `Err(String)` if the engine is live and rejects the directory.
    /// Always returns `Ok(())` for `Disabled`.
    #[cfg_attr(not(feature = "scripting"), allow(unused_variables))]
    pub fn load_scripts(&mut self, dir: &Path) -> Result<(), String> {
        match self {
            #[cfg(feature = "scripting")]
            ScriptHost::Rusty(engine) => {
                use nemclass_script::ScriptEngine as _;
                engine.load_scripts(dir)
            }
            ScriptHost::Disabled => Ok(()),
        }
    }

    /// Dispatches a fire-and-forget lifecycle/notification event to the engine.
    ///
    /// No-op for `Disabled`.
    #[cfg_attr(not(feature = "scripting"), allow(unused_variables))]
    pub fn on_event(&mut self, ev: &Event) {
        match self {
            #[cfg(feature = "scripting")]
            ScriptHost::Rusty(engine) => {
                use nemclass_script::ScriptEngine as _;
                engine.on_event(ev);
            }
            ScriptHost::Disabled => {}
        }
    }

    /// A detached, `Send` resolver handle for running `tryResolveClassAddress`
    /// off the UI thread (so the window keeps repainting), or `None` when no live
    /// engine is running. Only compiled under the `scripting` feature.
    #[cfg(feature = "scripting")]
    pub fn resolver(&self) -> Option<nemclass_script::ScriptResolver> {
        match self {
            ScriptHost::Rusty(engine) => Some(engine.resolver()),
            ScriptHost::Disabled => None,
        }
    }

    /// Returns `true` when a live engine is running (the v8 worker thread is up).
    ///
    /// Use this to decide whether to keep requesting repaints even while not
    /// attached, so pending host-API requests drain.
    pub fn is_active(&self) -> bool {
        match self {
            #[cfg(feature = "scripting")]
            ScriptHost::Rusty(_) => true,
            ScriptHost::Disabled => false,
        }
    }

    /// Drains all pending host-API requests raised by worker-thread JS and
    /// services them against `host`.  Call this **every UI frame** (in `logic`).
    ///
    /// Only compiled when `scripting` is enabled because `HostApi` itself only
    /// exists under that feature.
    #[cfg(feature = "scripting")]
    pub fn pump(&mut self, host: &mut dyn nemclass_script::HostApi) {
        if let ScriptHost::Rusty(engine) = self {
            engine.pump_host_requests(host);
        }
    }
}
