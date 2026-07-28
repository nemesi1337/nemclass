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
- `OnTick` — emitted once per snapshot interval (carries the attached `pid`),
  so trainers can poll / re-apply values without their own timer
- `OnHotkey` — a script-registered global hotkey fired (carries its `id`)
- `Custom` (`CustomPayload`) — user-raised events

`EventBus` lets `Subscriber`s register and the app `publish` events. Both
compile-time plugins and the JS engine are subscribers of the *same* bus.

## Host APIs

Host-side capabilities exposed to scripts/plugins (`host_api`):

- **Pattern scanning** — IDA-style `find_pattern` / `try_find_pattern` /
  `scan_module` (a tested matcher with `??` wildcards).
- **Type / class declaration** — `TypeDeclare` / `PatternScan` traits for
  declaring custom types and classes programmatically.

For the JS engine, the full script-facing surface is **catalog-driven**:
`api_catalog::HOST_METHODS` is the single source of truth (one entry per method:
name, TypeScript signature, doc) and generates the JS namespace shim, the
`nemclass.d.ts` type declarations, and the in-app reference panel. It spans
`mem.*` (typed/struct/array reads & writes, `resolveRip`, `freeze`), `scan.*`
(aob/value/range/pointer/rescan/signature, `aobResolveRip`), `classes.*`
(add/dissect/set-name/comment, `addNodeAt`), `disasm.*`, `proc.*`, `enums.*`,
`hotkeys.*`, and `table.*`. Adding a method is one catalog line plus one
`UiHostApi::call` match arm.

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

### Multi-file scripts (`import "./helpers"`)

Scripts in a project's `src/` can be split across files and use ordinary
relative ES imports — `import { addressToFormula } from "./helpers"` — with or
without a file extension. A custom `RelativeImportResolver`
(`rustyscript::module_loader::ImportProvider`, wired via
`RuntimeOptions.import_provider`) resolves each specifier against the real file
on disk, probing `.ts`/`.tsx`/`.mts`/`.cts`/`.mjs`/`.cjs`/`.js`/`.json` and
`index.*` when the extension is omitted. This bypasses rustyscript's default
whitelist, so imports resolve regardless of the order files are loaded in.

> **Build note:** the `scripting` feature has strict dependency pins (see the
> [scripting build constraint](../CLAUDE.md) / project memory): it compiles only
> with `serde = 1.0.219`, `toml 0.8`, and `deno_media_type 0.2.1`. Build with
> `--features scripting`, not `--all-features`.

## TypeScript scaffolding

`write_script_scaffold` (always compiled) generates the `package.json` /
`tsconfig.json` and `.d.ts` type declarations for a project's `src/` directory,
derived from the host-API surface (`EVENT_KINDS` etc.), so user scripts get
editor autocomplete even before the engine is enabled.
