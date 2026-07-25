# Code generation

`nemclass-model::codegen` turns a project's classes into source code in a target
language, so a reconstructed layout can be pasted straight into a real codebase.

## API

```rust,ignore
use nemclass_model::{generate_code, CodeGenerator, Language};

let src = generate_code(&project, Language::Cpp)?;
```

- **`Language`** — the supported outputs: C++, C#, and Rust.
- **`CodeGenerator`** — the trait each language backend implements.
- **`generate_code` (aka `codegen::generate`)** — the entry point; walks the
  project's classes and emits a source string.

## What it emits

For each class the generator emits a `struct`/`class` with:

- one field per node, using the language's natural type for each node type
  (integers, floats, bool, pointers, fixed arrays, nested classes, text buffers),
- **offset correctness** — padding/placement so field offsets match the target
  layout, computed from resolved node sizes (container nodes contribute their
  real inline size, not zero),
- references between classes resolved by UUID, with a cycle guard and a fallback
  when a referenced class is missing.

## Notes

- Offsets are derived from each node's resolved size; nested/inline classes are
  sized recursively so generated `static_assert`s / offset comments line up with
  the live layout.
- The generators are pure functions over the `Project`, so they are unit-tested
  against fixtures with nested classes and pointers.
