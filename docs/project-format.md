# Project format

A nemclass **project is a directory**, not a single file. Creating or opening one
manages several files; the authoritative data lives in `project.nemclass` (TOML).

## Directory layout

```text
MyProject/
├── project.nemclass     # the project (TOML): metadata, enums, classes + nodes
├── package.json         # scaffolded — scripting API type info
├── tsconfig.json        # scaffolded — TypeScript config for src/
├── src/                 # user scripts (JS/TS)
└── tables/              # saved address lists (cheat tables), one TOML each
```

## `project.nemclass` (TOML)

The file holds a `[project]` metadata section, zero or more `[[enums]]`, and
`[[classes]]`. Each class carries an ordered list of nodes. Nodes serialize
through a tagged intermediate, **`NodeDef`**:

```rust,ignore
pub struct NodeDef {
    pub type_tag: String,                  // serialized as `type`
    pub name: String,
    pub comment: String,
    pub attrs: HashMap<String, toml::Value>, // type-specific (flattened)
    pub nodes: Vec<NodeDef>,               // children, for containers
}
```

- `type` selects the node type via the `NodeRegistry`.
- `attrs` carries type-specific fields (e.g. an `Array`'s `count`/`element_size`,
  a text node's `length`, a `Function`'s `signature`). Because it is a flattened
  `HashMap<String, toml::Value>`, new node types serialize their extra data with
  no schema changes.
- `nodes` nests children for container types (`Class`, `Array`, `VTable`, …).

A small illustrative shape:

```toml
[project]
name = "MyProject"
version = "1"
# Only written for a 32-bit target; absent means 8-byte pointers.
# pointer_size = 4

[[classes]]
uuid = "6f1d0b9e-6a1a-4a2f-9a3c-2a0a1d5e7b31"
name = "Player"
comment = ""
address_formula = "<game> + 0x4C0A10"

  [[classes.nodes]]
  type = "Int32"
  name = "health"
  comment = "current HP"

  [[classes.nodes]]
  type = "Pointer"
  name = "inventory"
  target_class_uuid = "9c2f5a80-0b41-4c26-8e77-1f3a55d2c904"

  [[classes.nodes]]
  type = "Utf8Text"
  name = "display_name"
  length = 32
  hidden = true
```

A class is a `[[classes]]` table with its own `uuid`, not a node with
`type = "Class"`; the `type` key appears on the *nodes*. Type-specific
attributes (`length`, `count`, `element_type`, `bits`, `enum_name`,
`target_class_uuid`, `class_uuid`) sit alongside `name`/`comment`, and `hidden`
is written only when set.

## Round-trip guarantee

`Project → TOML → Project` is **lossless** — a primary unit test builds a project
with nested classes, pointers, arrays, and the RE node types, serializes it,
deserializes it via the registry, and asserts structural equality. Deserialization
is depth-bounded to reject maliciously deep documents.

A node type this build does not recognise — written by a newer version, or by a
build with a plugin this one lacks — is **not** an error and is **not** dropped.
It is kept verbatim as an `Unknown` placeholder and written back byte-for-byte,
so opening and re-saving a project in an older build does not strip the fields it
did not understand.

The `version` field is checked on load: a file from a newer schema is refused
rather than half-read. A 64-bit project is written as version `1`, which older
builds still read correctly; a 32-bit one is version `2`, because an older build
would ignore `pointer_size`, lay every pointer out as eight bytes, and silently
shift every field after the first.

## Scaffolding

On project creation, `package.json` / `tsconfig.json` are written with the
scripting API's TypeScript declarations so `src/*.ts` gets autocomplete, `src/`
and `tables/` are created, and the whole thing round-trips through the
`nemclass-ui::project_io` module (`create_project_at` / `load_project_from` /
`save_project_to`).
