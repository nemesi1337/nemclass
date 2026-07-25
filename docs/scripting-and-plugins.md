# Scripting & plugins

`nemclass-script` is the extension layer: a lifecycle **event bus**, host-side
**APIs** scripts/plugins can call, a compile-time **plugin** system, and an
optional embedded **JavaScript engine**.

## Events & the bus

`Event` models the app lifecycle:

- `OnProjectLoad`, `OnAttach`, `OnDetach`
- `TryResolveClassAddress` — a query (`ClassAddressQuery`) a subscriber can
  answer to override how a class base is resolved
- `ClassAddressUpdated`, `GlobalVariableUpdated` (`GlobalVariable`)
- `Custom` (`CustomPayload`) — user-raised events

`EventBus` lets `Subscriber`s register and the app `publish` events. Both
compile-time plugins and the JS engine are subscribers of the *same* bus.

## Host APIs

Host-side capabilities exposed to scripts/plugins (`host_api`):

- **Pattern scanning** — IDA-style `find_pattern` / `try_find_pattern` /
  `scan_module` (a tested matcher with `??` wildcards).
- **Type / class declaration** — `TypeDeclare` / `PatternScan` traits for
  declaring custom types and classes programmatically.

## Compile-time plugins

The `Plugin` trait (with `PluginHost`, `PluginRegistry`,
`register_builtin_plugins`) is the ReClass `IPlugin`-style seam: a plugin can
`initialize(host)`, provide node types / providers, and subscribe to events.
Plugins are discovered at build time via Cargo features.

## The JavaScript engine (`scripting` feature — experimental)

Behind the `scripting` Cargo feature, `RustyScriptEngine` embeds
rustyscript/deno_core/v8 on a dedicated worker thread, bridged to the UI over a
command channel. Design invariants keep it purely additive over the M1 traits:

- event payloads are `serde`-serializable, so they cross the v8-thread boundary;
- the JS engine is just another `Subscriber` (via `EngineSubscriber`);
- `ScriptEngine`'s `load_scripts` / `register_host_fn` / `dispatch` map onto
  rustyscript's `load_module` / `register_function` / `call_function`.

`ScriptEngine` + `NoopEngine` are always available; the real engine is opt-in.

> **Status:** the `scripting` feature currently **does not compile** due to an
> upstream dependency conflict in the deno/v8 tree (`swc_config` requires a
> `serde` private module layout that conflicts with the `serde` version the rest
> of the tree needs). It is deferred; the default build has no v8 dependency and
> uses `NoopEngine`. Do not build with `--all-features`.

## TypeScript scaffolding

`write_script_scaffold` (always compiled) generates the `package.json` /
`tsconfig.json` and `.d.ts` type declarations for a project's `src/` directory,
derived from the host-API surface (`EVENT_KINDS` etc.), so user scripts get
editor autocomplete even before the engine is enabled.
