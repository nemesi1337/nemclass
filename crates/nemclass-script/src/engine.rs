//! The scripting engine seam.
//!
//! [`ScriptEngine`] is the trait the M2 rustyscript (v8) engine implements; M1
//! ships only the trait and a [`NoopEngine`]. The engine is *also* a
//! [`crate::Subscriber`] adapter target — see [`EngineSubscriber`] — so it plugs
//! into the [`crate::EventBus`] like any other subscriber.

use std::path::Path;

use crate::events::{ClassAddressQuery, Event};

/// A registered host function: a name and a Rust callback the scripts can call.
///
/// In M1 this is a plain boxed closure over serializable JSON-shaped arguments,
/// modelled here without a `serde_json` dependency as `Vec<String>` in / `String`
/// out. In M2 this maps directly onto rustyscript's
/// `register_function(name, |args: &[serde_json::Value]| -> Result<Value, _>)`
/// (and the `sync_callback!` macro), so the *signature shape* — "named callback,
/// serializable args, serializable/erroring return" — is already correct and the
/// M2 change is only the concrete value type.
pub type HostFn = Box<dyn FnMut(&[String]) -> Result<String, String> + Send>;

/// The engine that runs user scripts and dispatches events into them.
///
/// # M2: how `RustyScriptEngine` implements this
///
/// rustyscript wraps `deno_core`/v8. A v8 **isolate is single-threaded and
/// `!Send`**, so `RustyScriptEngine` will:
///
/// 1. **Own a dedicated thread.** On construction it spawns a worker thread that
///    creates `rustyscript::Runtime::new(...)` and owns it for its lifetime. The
///    public `RustyScriptEngine` handle holds only a `Sender<EngineCommand>`
///    (+ result channels) to that thread — the handle itself is `Send`/`Sync`
///    and lives on the UI/bus thread. This is why every payload in
///    [`crate::events`] is `Serialize`: commands and events cross this channel.
///
/// 2. **Implement [`ScriptEngine::load_scripts`]** by sending a `LoadDir(path)`
///    command; the worker walks `dir` and `runtime.load_module(&Module::load(f))`
///    for each `src/*.js|*.ts`, keeping the returned `ModuleHandle`s so events
///    can be dispatched to the right module.
///
/// 3. **Implement [`ScriptEngine::register_host_fn`]** by sending a
///    `RegisterFn(name, fn)` command; the worker calls
///    `runtime.register_function(name, sync_callback!(...))`, exposing it to JS
///    as `rustyscript.functions.<name>(...)`. The pattern-scan / declare-type /
///    declare-class host APIs (see [`crate::host_api`]) are registered this way.
///
/// 4. **Implement [`ScriptEngine::on_event`]** by serializing the [`Event`] and
///    sending a `Dispatch(event)` command; the worker invokes the matching JS
///    handler with `runtime.call_function(Some(&handle), event.kind(),
///    json_args!(payload))` (e.g. `onAttach`, `classAddressUpdated`). Because
///    notifications don't need a reply, this is fire-and-forget across the
///    channel.
///
/// 5. **Implement [`ScriptEngine::resolve_class_address`]** by sending a
///    `Resolve(query)` command *and blocking on a reply channel* (this hook must
///    return a value): the worker calls the JS `tryResolveClassAddress`
///    resolver via `call_function` and sends back the `Option<usize>`.
///
/// The whole engine is gated behind the `scripting` Cargo feature so the heavy
/// v8 build is opt-in. None of the above changes [`ScriptEngine`],
/// [`crate::EventBus`], or the [`crate::host_api`] traits — that is the point of
/// defining them now.
pub trait ScriptEngine {
    /// Loads all scripts under `dir` (the project's `src/`).
    fn load_scripts(&mut self, dir: &Path) -> Result<(), String>;

    /// Registers a host function callable from scripts by `name`.
    fn register_host_fn(&mut self, name: &str, func: HostFn);

    /// Dispatches a fire-and-forget [`Event`] notification into the scripts.
    fn on_event(&mut self, event: &Event);

    /// Runs the scripts' `TryResolveClassAddress` resolver, returning the first
    /// address a script supplies (or `None`).
    fn resolve_class_address(&mut self, query: &ClassAddressQuery) -> Option<usize>;
}

/// The M1 no-op engine: satisfies [`ScriptEngine`] while doing nothing.
///
/// Lets the app wire an engine unconditionally (and the bus treat it as a
/// [`crate::Subscriber`] via [`EngineSubscriber`]) before M2's real engine
/// exists. It records host-fn registrations and load calls so tests and the UI
/// can observe that wiring happened, but never runs anything.
#[derive(Default)]
pub struct NoopEngine {
    /// Names of host functions "registered" (kept for observability).
    registered: Vec<String>,
    /// Script directories "loaded".
    loaded_dirs: Vec<std::path::PathBuf>,
}

impl NoopEngine {
    /// A fresh no-op engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Names of host functions registered so far.
    pub fn registered_fns(&self) -> &[String] {
        &self.registered
    }

    /// Script directories passed to [`ScriptEngine::load_scripts`] so far.
    pub fn loaded_dirs(&self) -> &[std::path::PathBuf] {
        &self.loaded_dirs
    }
}

impl ScriptEngine for NoopEngine {
    fn load_scripts(&mut self, dir: &Path) -> Result<(), String> {
        self.loaded_dirs.push(dir.to_path_buf());
        Ok(())
    }

    fn register_host_fn(&mut self, name: &str, _func: HostFn) {
        self.registered.push(name.to_owned());
    }

    fn on_event(&mut self, _event: &Event) {
        // No scripts to notify.
    }

    fn resolve_class_address(&mut self, _query: &ClassAddressQuery) -> Option<usize> {
        // A no-op engine never resolves an address — always defers.
        None
    }
}

/// Adapts any [`ScriptEngine`] into a [`crate::Subscriber`] so it can be
/// registered on the [`crate::EventBus`] alongside compile-time plugins.
///
/// This is exactly how M2's `RustyScriptEngine` joins the bus: wrap it in an
/// `EngineSubscriber` and `bus.register(Box::new(...))`. Notifications flow
/// through [`ScriptEngine::on_event`]; the `TryResolveClassAddress` chain flows
/// through [`ScriptEngine::resolve_class_address`].
pub struct EngineSubscriber<E: ScriptEngine> {
    engine: E,
}

impl<E: ScriptEngine> EngineSubscriber<E> {
    /// Wraps `engine` as a bus subscriber.
    pub fn new(engine: E) -> Self {
        Self { engine }
    }

    /// Borrows the wrapped engine.
    pub fn engine(&self) -> &E {
        &self.engine
    }

    /// Mutably borrows the wrapped engine (e.g. to load scripts / register host
    /// functions before registering on the bus).
    pub fn engine_mut(&mut self) -> &mut E {
        &mut self.engine
    }
}

impl<E: ScriptEngine> crate::Subscriber for EngineSubscriber<E> {
    fn name(&self) -> &str {
        "script-engine"
    }

    fn on_event(&mut self, event: &Event) {
        self.engine.on_event(event);
    }

    fn try_resolve_class_address(&mut self, query: &ClassAddressQuery) -> Option<usize> {
        self.engine.resolve_class_address(query)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bus::{EventBus, Subscriber};
    use uuid::Uuid;

    #[test]
    fn noop_engine_records_wiring_and_resolves_none() {
        let mut engine = NoopEngine::new();
        engine.load_scripts(Path::new("/tmp/project/src")).unwrap();
        engine.register_host_fn("pattern_scan", Box::new(|_args| Ok(String::new())));
        engine.register_host_fn("declare_type", Box::new(|_args| Ok(String::new())));

        assert_eq!(engine.loaded_dirs().len(), 1);
        assert_eq!(engine.registered_fns(), &["pattern_scan", "declare_type"]);

        // A no-op engine defers on the resolver chain and ignores events.
        engine.on_event(&Event::OnDetach);
        assert_eq!(
            engine.resolve_class_address(&ClassAddressQuery::new(1, Uuid::new_v4())),
            None
        );
    }

    #[test]
    fn engine_plugs_into_bus_as_a_subscriber() {
        // Proves the M2 wiring path: an engine becomes a bus Subscriber.
        let mut sub = EngineSubscriber::new(NoopEngine::new());
        // Reachable through the Subscriber trait.
        sub.on_event(&Event::OnDetach);
        assert_eq!(
            sub.try_resolve_class_address(&ClassAddressQuery::new(1, Uuid::new_v4())),
            None
        );

        let mut bus = EventBus::new();
        bus.register(Box::new(EngineSubscriber::new(NoopEngine::new())));
        assert_eq!(bus.subscriber_count(), 1);
        bus.publish(&Event::OnDetach);
    }
}
