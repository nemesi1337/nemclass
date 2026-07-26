#![doc = include_str!("detailed_docs.md")]
//! nemclass-script: event bus + scripting/plugin layer.
//!
//! **M1** shipped traits + scaffolding: the [`Event`] model, the [`EventBus`],
//! the [`ScriptEngine`] trait (+ [`NoopEngine`]), the host-API traits (+ a real,
//! tested [`find_pattern`] matcher), and the compile-time [`Plugin`] trait.
//!
//! **M2** (behind the `scripting` Cargo feature) adds the real rustyscript (v8)
//! engine — [`RustyScriptEngine`] — plus its main-thread [`HostApi`] bridge, and
//! (always compiled) [`write_script_scaffold`] for TypeScript type generation.
//! None of it changes any bus / engine / host-API / plugin contract from M1.
//!
//! ## Design invariants that make M2 additive
//!
//! - Event payloads are identity-based and `serde`-serializable, so they cross
//!   the v8-thread / JS boundary unchanged (see [`events`]).
//! - The JS engine is just another [`Subscriber`] (via [`EngineSubscriber`]),
//!   registered on the same [`EventBus`] as compile-time plugins (see [`bus`]).
//! - [`ScriptEngine`]'s methods map onto rustyscript's `load_module`,
//!   `register_function`, and `call_function` — dispatched to a dedicated v8
//!   worker thread over a command channel (see [`engine_rusty`]).
//!
//! ## Building the `scripting` feature (v8 is heavy)
//!
//! `--features scripting` pulls in `rustyscript` → `deno_core`/v8: a large,
//! slow build (a ~20 MB prebuilt v8 download plus a long compile). The default
//! build has **no** v8 dependency. See [`engine_rusty`] for the threading model.
//!
//! ## M2 wiring at a glance
//!
//! ```ignore
//! // (behind the `scripting` feature)
//! let mut engine = RustyScriptEngine::spawn()?;         // owns a v8 thread
//! engine.load_scripts(project.join("src").as_path())?;  // -> load_module per file
//! // ...each UI frame, service host-API calls from worker-thread JS:
//! engine.pump_host_requests(&mut host);                 // host: &mut dyn HostApi
//! bus.register(Box::new(EngineSubscriber::new(engine))); // joins the bus
//! ```

pub mod api_catalog;
pub mod bus;
pub mod engine;
pub mod events;
pub mod host_api;
pub mod plugin;
pub mod scaffold;

#[cfg(feature = "scripting")]
pub mod engine_rusty;

pub use api_catalog::{host_method_names, HostMethod, HOST_METHODS};
pub use bus::{EventBus, Subscriber};
pub use engine::{EngineSubscriber, HostFn, NoopEngine, ScriptEngine};
pub use events::{ClassAddressQuery, CustomPayload, Event, GlobalVariable};
pub use host_api::{
    PatternError, PatternScan, TypeDeclare, find_pattern, scan_module, try_find_pattern,
};
pub use plugin::{Plugin, PluginHost, PluginRegistry, register_builtin_plugins};
pub use scaffold::{write_dts, write_script_scaffold, EVENT_KINDS};

#[cfg(feature = "scripting")]
pub use engine_rusty::{HostApi, HostRequest, LogLevel, RustyScriptEngine};
