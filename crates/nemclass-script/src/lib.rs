//! nemclass-script: event bus + scripting/plugin layer.
//!
//! M1 ships **traits + scaffolding only**: the [`Event`] model, the
//! [`EventBus`], the [`ScriptEngine`] trait (+ [`NoopEngine`]), the host-API
//! traits (+ a real, tested [`find_pattern`] matcher), and the compile-time
//! [`Plugin`] trait (+ registry and a feature-gated example).
//!
//! The rustyscript (v8) engine lands in **M2** behind the `scripting` feature.
//! Every seam here is designed so that engine slots in without changing any bus,
//! engine, host-API, or plugin contract:
//!
//! - Event payloads are identity-based and `serde`-serializable, so they cross
//!   the M2 v8-thread / JS boundary unchanged (see [`events`]).
//! - The JS engine is just another [`Subscriber`] (via [`EngineSubscriber`]),
//!   registered on the same [`EventBus`] as compile-time plugins (see [`bus`]).
//! - [`ScriptEngine`]'s methods map 1:1 onto rustyscript's `load_module`,
//!   `register_function` / `sync_callback!`, and `call_function` (see
//!   [`engine`]).
//!
//! ## M2 wiring at a glance
//!
//! ```ignore
//! // (M2, behind the `scripting` feature)
//! let mut engine = RustyScriptEngine::spawn();          // owns a v8 thread
//! engine.register_host_fn("pattern_scan", scan_hostfn); // -> register_function
//! engine.load_scripts(project.join("src").as_path())?;  // -> load_module per file
//! bus.register(Box::new(EngineSubscriber::new(engine))); // joins the bus
//! ```

pub mod bus;
pub mod engine;
pub mod events;
pub mod host_api;
pub mod plugin;

pub use bus::{EventBus, Subscriber};
pub use engine::{EngineSubscriber, HostFn, NoopEngine, ScriptEngine};
pub use events::{ClassAddressQuery, CustomPayload, Event, GlobalVariable};
pub use host_api::{
    PatternError, PatternScan, TypeDeclare, find_pattern, scan_module, try_find_pattern,
};
pub use plugin::{Plugin, PluginHost, PluginRegistry, register_builtin_plugins};
