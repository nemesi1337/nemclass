# Domain model

`nemclass-model` ports ReClass.NET's node system to idiomatic Rust. A project is
a set of **classes**; each class is an ordered tree of **nodes** (fields) laid
out over a base address in the target.

## The `Node` trait

Every field type implements the object-safe `Node` trait. Key methods:

- `type_tag() -> &'static str` — the stable type id (e.g. `"Int32"`, `"Pointer"`,
  `"VTable"`), also the serialization key and the plugin extension point.
- `name` / `comment` (+ setters) — metadata.
- `memory_size() -> usize` — the node's byte footprint.
- `children()` / `children_mut()` — for container nodes.
- `render(&self, buf: &[u8], base_offset: usize) -> RenderedValue` — formats the
  value from a **read-back byte buffer**. This is pure: no live process access,
  which keeps value formatting fully testable.
- `to_node_def()` — lower to the serialization intermediate (see
  [project-format.md](project-format.md)).

`RenderedValue { value: String, type_tag, memory_size }` is what the UI table
renders per row.

## `NodeRegistry`

`NodeRegistry` maps a `type_tag` to a `(constructor, deserializer)` pair.
`NodeRegistry::new().with_builtins()` registers every built-in type. It is also
the extension point for plugin-declared node types.

## Built-in node types

| Group | Types |
|-------|-------|
| Integers | `Int8/16/32/64`, `UInt8/16/32/64` |
| Floating point | `Float` (f32), `Double` (f64) |
| Boolean | `Bool` |
| Hex views | `Hex8/16/32/64` |
| Pointers | `Pointer` (may reference another class by UUID) |
| Text | `Utf8Text`, `Utf16Text` (fixed-length, NUL-aware) |
| Containers | `Class` (nested), `ClassInstance` (inline reference), `Array` (count × element) |
| Reverse-engineering | `VTable`, `VMethod`, `Function`, `FunctionPtr` |

The RE nodes are the payoff of the dissection feature:

- **`VTable`** — a pointer to a virtual method table; a container whose children
  are `VMethod`s. In the UI, expanding it *live-reads* the pointer array.
- **`VMethod`** — one virtual-method slot (index + resolved name).
- **`Function`** — a function member (stores an editable signature).
- **`FunctionPtr`** — a code pointer.

Their `render` is static (shows the stored pointer); the *live* vtable-array
walk and inline disassembly are driven by the UI with process access. See
[memory-viewer-and-dissection.md](memory-viewer-and-dissection.md).

## `ClassNode` and `Project`

- **`ClassNode`** — `uuid`, `name`, `comment`, an `address_formula: String`, and
  ordered `children`. Classes reference each other by UUID (via `Pointer` /
  `ClassInstance`).
- **`Project`** — classes indexed by UUID, plus enums (`EnumDescription`) and
  metadata; `get_class_mut`, `classes_in_order`, etc.

## The address-formula language

A class's base is computed by evaluating its `address_formula` against the
target's module list and live memory. The parser (`nemclass-model::address`) is
a tokenizer → AST → interpreter, exposed as `parse_address` and `resolve_formula`
(the latter takes a `ModuleResolver` and a `MemoryReader`).

Supported expressions:

- Module base + offset: `"libfoo.so"+0x2E80` or `"target"+0x4C0A10`
- Arithmetic: `+`, `-`, and hex/decimal literals
- **Pointer dereference / chains**: `[base+0x10]+0x20`,
  `["libfoo.so"+0x2E80]+0x18` — each `[...]` reads a pointer from the target.

This backs the `TryResolveClassAddress` lifecycle event and the address bar in
the UI.
