# nemclass-model

The domain model — a Rust port of ReClass.NET's node system, plus the project
format, address-formula evaluator, code generators, and the auto-dissector.
Depends on `nemclass-core` (formula evaluation and dissection resolve against a
live `Process`).

## What's in here

- **Nodes.** The object-safe `Node` trait (`type_tag`, `memory_size`, `children`,
  and a pure `render(buf, base) -> RenderedValue`) and the `NodeRegistry` that
  maps a type tag to its constructor + deserializer. Built-ins cover integers,
  floats, bool, hex views, pointers, text, containers (`Class`/`ClassInstance`/
  `Array`), and the RE nodes `VTable`/`VMethod`/`Function`/`FunctionPtr`.
- **Classes & project.** `ClassNode` (UUID, address formula, ordered children)
  and `Project` (classes + enums + metadata).
- **Address formulas.** `parse_address` / `resolve_formula` (with `ModuleResolver`
  + `MemoryReader`) evaluate `"module"+0x10` and pointer chains `[base+0x10]+0x20`.
- **Serialization.** `serialize` lowers nodes to the tagged `NodeDef` intermediate
  for lossless `project.nemclass` (TOML) round-trips.
- **Code generation.** `codegen` — `generate_code(&project, Language::{Cpp,CSharp,
  Rust})`.
- **Dissection.** `dissect` — `auto_dissect(process, base, len)` and the pure,
  testable `dissect_buffer(base, buf, classify)` that guess field types.

## Round-trip is the invariant

`Project → TOML → Project` must be lossless; it is the crate's primary test. The
`NodeDef.attrs` map (a flattened `HashMap<String, toml::Value>`) lets new node
types persist their extra fields with no format changes.

```rust,ignore
let registry = NodeRegistry::new().with_builtins();
// ...build a Project, serialize to project.nemclass, read it back via `registry`.
```

## Notes

- `render` is pure (formats from a byte buffer) — no live process access — which
  keeps value formatting fully unit-testable. The *live* parts of the RE nodes
  (walking a vtable array, disassembling a function) are driven by the UI.

See `../../../docs/domain-model.md`, `../../../docs/project-format.md`,
`../../../docs/code-generation.md`, and
`../../../docs/memory-viewer-and-dissection.md`.
