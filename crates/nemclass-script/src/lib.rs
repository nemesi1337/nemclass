//! nemclass-script: event bus + scripting/plugin layer.
//!
//! M1 ships traits only: event types, the `EventBus`, the `ScriptEngine` trait
//! (+ `NoopEngine`), host-API traits, and the compile-time `Plugin` trait.
//! The rustyscript (v8) engine lands in M2 behind the `scripting` feature.
//!
//! WIP — implemented by the `scripting-plugin-engineer` agent.
