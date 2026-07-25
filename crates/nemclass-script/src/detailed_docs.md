# nemclass-script

The extension layer: a lifecycle event bus, host-side APIs, compile-time plugins,
and an optional (experimental) embedded JavaScript engine.

## What's in here

- **Events** (`events`). The `Event` model — `OnProjectLoad`, `OnAttach`,
  `OnDetach`, `TryResolveClassAddress` (`ClassAddressQuery`), `ClassAddressUpdated`,
  `GlobalVariableUpdated` (`GlobalVariable`), and `Custom` (`CustomPayload`).
- **Bus** (`bus`). `EventBus` + `Subscriber`: register subscribers, publish
  events. Plugins and the JS engine are subscribers of the same bus.
- **Engine** (`engine`). The `ScriptEngine` trait, the always-available
  `NoopEngine`, and `EngineSubscriber` (adapts an engine into a bus subscriber).
- **Host APIs** (`host_api`). IDA-style pattern scanning (`find_pattern` /
  `try_find_pattern` / `scan_module`, with `??` wildcards) and the
  `TypeDeclare`/`PatternScan` traits.
- **Plugins** (`plugin`). The compile-time `Plugin` trait with `PluginHost`,
  `PluginRegistry`, and `register_builtin_plugins`.
- **Scaffolding** (`scaffold`). `write_script_scaffold` + `EVENT_KINDS` generate
  a project's TypeScript type declarations.
- **JS engine** (`engine_rusty`, `scripting` feature). `RustyScriptEngine` runs
  rustyscript/v8 on a worker thread with a `HostApi` bridge.

## Status of the `scripting` feature

The M1 traits/scaffolding above are always compiled and tested. The rustyscript
(v8) engine behind `--features scripting` is **currently unbuildable** due to an
upstream deno dependency conflict (`swc_config` vs the required `serde` version).
It is deferred; the default build has no v8 dependency and uses `NoopEngine`.
Avoid `--all-features`.

```rust,ignore
// Always available:
let mut bus = EventBus::new();
bus.register(/* a Subscriber */);
```

See `../../../docs/scripting-and-plugins.md`.
