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
└── tables/              # cheat tables (reserved for future use)
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

```text
[project]
name = "MyProject"

[[classes]]
type = "Class"
name = "Player"
comment = ""
address_formula = "\"game\"+0x4C0A10"

  [[classes.nodes]]
  type = "Int32"
  name = "health"
  comment = "current HP"

  [[classes.nodes]]
  type = "Pointer"
  name = "inventory"
  comment = ""
```

## Round-trip guarantee

`Project → TOML → Project` is **lossless** — a primary unit test builds a project
with nested classes, pointers, arrays, and the RE node types, serializes it,
deserializes it via the registry, and asserts structural equality. Deserialization
is depth-bounded to reject maliciously deep documents.

## Scaffolding

On project creation, `package.json` / `tsconfig.json` are written with the
scripting API's TypeScript declarations so `src/*.ts` gets autocomplete, `src/`
and `tables/` are created, and the whole thing round-trips through the
`nemclass-ui::project_io` module (`create_project_at` / `load_project_from` /
`save_project_to`).
