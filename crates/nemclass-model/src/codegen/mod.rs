//! Code generation: turn a `Project` into source-code type definitions.
//!
//! Three built-in generators:
//! - [`CppCodeGenerator`]   → C++ `class` with `#pragma pack(push, 1)`
//! - [`CSharpCodeGenerator`] → C# `struct` with `[StructLayout(LayoutKind.Explicit)]`
//! - [`RustCodeGenerator`]  → Rust `#[repr(C)] struct`
//!
//! All three implement [`CodeGenerator`]. Use the free [`generate`] helper to
//! dispatch by [`Language`].
//!
//! ## ClassInstance size resolution
//!
//! `ClassInstanceNode::memory_size()` deliberately returns 0 in the model layer
//! (the real size is only known when a `Project` is available). All size
//! computations in this module — offset accumulation, class totals, and size
//! assertions — use [`resolved_class_size`] instead, which walks the target
//! `ClassNode`'s children recursively and accumulates their sizes. A visited-set
//! guards against self/mutual inline-embed cycles.

mod cpp;
mod csharp;
mod rust_gen;

#[cfg(test)]
mod tests;

pub use cpp::CppCodeGenerator;
pub use csharp::CSharpCodeGenerator;
pub use rust_gen::RustCodeGenerator;

/// Test helper re-exports (only compiled in test builds).
#[cfg(test)]
pub(crate) mod mod_test_helpers {
    pub(crate) use super::sanitize_ident;
}

use std::collections::HashSet;

use crate::node::registry::NodeRegistry;
use crate::node::vector::{FloatWidth, matrix_shape, vector_shape};
use crate::project::Project;

/// Target language for code generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    Cpp,
    CSharp,
    Rust,
}

/// Object-safe code generator trait.
///
/// Implementors receive the full `Project` (classes + enums) and a `NodeRegistry`
/// (needed to read node attrs via `to_node_def`). They return a self-contained
/// source string with no external dependencies beyond `std`.
pub trait CodeGenerator {
    fn language(&self) -> Language;
    fn generate(&self, project: &Project, registry: &NodeRegistry) -> String;
}

/// Dispatch helper: select a built-in generator and run it.
pub fn generate(language: Language, project: &Project, registry: &NodeRegistry) -> String {
    match language {
        Language::Cpp => CppCodeGenerator.generate(project, registry),
        Language::CSharp => CSharpCodeGenerator.generate(project, registry),
        Language::Rust => RustCodeGenerator.generate(project, registry),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers used by all three generators
// ---------------------------------------------------------------------------

/// The array length a field kind would emit, for the kinds that emit an array.
///
/// A length of `0` must not reach the output: `uint8_t x[0]` is a GCC extension
/// and ill-formed ISO C++, and `fixed byte x[0]` is a hard C# error (CS0842).
/// Zero-length fields arise routinely — an `ArrayNode` defaults to `count = 0`,
/// a `Utf8Text` to `length = 0`, and an unresolved `ClassInstance` becomes
/// `RawBytes(0)` — so every generator checks this and emits a comment instead of
/// a member. The field contributes no bytes either way, so the layout is
/// unchanged.
pub(crate) fn emitted_array_len(kind: &FieldKind) -> Option<usize> {
    match kind {
        FieldKind::RawBytes(n) | FieldKind::Array { count: n } => Some(*n),
        FieldKind::Utf8Text(n) => Some(*n),
        FieldKind::Utf16Text(n) => Some(n.div_ceil(2)),
        FieldKind::Vector { components, .. } => Some(*components),
        _ => None,
    }
}

/// Flatten a user comment so it is safe to splice into a single-line (`//`)
/// comment in generated source.
///
/// Node and class comments are free-form multi-line strings — the UI accepts
/// anything and the project format round-trips it. Emitted raw, a comment
/// containing a newline ended the comment and spliced the remainder into the
/// struct body as code, so one stray Enter in a comment field produced a source
/// file that does not compile. Newlines, carriage returns and tabs collapse to
/// single spaces; the result never leaves the comment.
pub(crate) fn escape_comment(comment: &str) -> String {
    let flattened: String = comment
        .chars()
        .map(|c| if c == '\n' || c == '\r' || c == '\t' { ' ' } else { c })
        .collect();
    // Collapse the runs the mapping can create so a multi-line comment does not
    // emit a stretch of blank space.
    let mut out = String::with_capacity(flattened.len());
    let mut last_space = false;
    for c in flattened.chars() {
        if c == ' ' {
            if !last_space {
                out.push(c);
            }
            last_space = true;
        } else {
            out.push(c);
            last_space = false;
        }
    }
    out.trim().to_string()
}

/// Sanitize an identifier: replace characters that are not alphanumeric or `_`
/// with `_`. If the result starts with a digit, prefix with `_`.
pub(crate) fn sanitize_ident(name: &str) -> String {
    if name.is_empty() {
        return "_unnamed".to_string();
    }
    let mut out: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '_' { c } else { '_' })
        .collect();
    if out.starts_with(|c: char| c.is_ascii_digit()) {
        out.insert(0, '_');
    }
    out
}

/// Compute the byte size that a `ClassInstance` node contributes when embedded
/// inline. This must be done in codegen where a `Project` is available, rather
/// than in the model's `memory_size()` which has no project context.
///
/// Recursion is guarded by `visited` (a set of UUIDs currently on the call
/// stack). A cycle is detected when a UUID is already in the set; the
/// contribution for that node is 0 (emit a `// cyclic` fallback comment
/// instead of recursing forever). Pointer-to-self is not a hazard — pointers
/// are fixed 8 bytes — only inline `ClassInstance` embeds can recurse.
pub fn resolved_class_size(
    class: &crate::class::ClassNode,
    project: &Project,
    visited: &mut HashSet<uuid::Uuid>,
) -> usize {
    class.children.iter().map(|child| {
        resolved_node_size(child.as_ref(), project, visited)
    }).fold(0usize, usize::saturating_add)
}

/// [`resolved_class_size`] with the cycle guard seeded correctly — **the entry
/// point every caller outside this module should use**.
///
/// The recursive form takes the `visited` set as a parameter, and callers that
/// passed a bare `HashSet::new()` never seeded it with the root class's own
/// UUID. A class that embeds itself (directly or through a cycle) therefore got
/// a different answer depending on who asked: the C++ `static_assert`, the Rust
/// size assert, `Project::resolved_class_size` and the UI's field layout could
/// all disagree about the same class. Seeding here means one answer everywhere.
pub fn class_size(class: &crate::class::ClassNode, project: &Project) -> usize {
    let mut visited = HashSet::new();
    visited.insert(class.uuid);
    resolved_class_size(class, project, &mut visited)
}

/// Size that a single node contributes. For `ClassInstance`, recurses into the
/// referenced class. For everything else, falls back to `Node::memory_size()`.
pub fn resolved_node_size(
    node: &dyn crate::node::Node,
    project: &Project,
    visited: &mut HashSet<uuid::Uuid>,
) -> usize {
    let def = node.to_node_def();
    if def.type_tag == "ClassInstance" {
        let maybe_uuid = def
            .attrs
            .get("class_uuid")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<uuid::Uuid>().ok());

        if let Some(uuid) = maybe_uuid {
            if visited.contains(&uuid) {
                // Cycle detected — stop recursing, contribute 0.
                return 0;
            }
            if let Some(target_class) = project.get_class(&uuid) {
                visited.insert(uuid);
                let sz = resolved_class_size(target_class, project, visited);
                visited.remove(&uuid);
                return sz;
            }
            // UUID present but class not in project → unresolvable; contribute 0.
            return 0;
        }
        // Malformed ClassInstance (no class_uuid attr) → 0.
        return 0;
    }
    // All other node types: trust the model's own memory_size().
    node.memory_size()
}

/// A resolved field description produced by walking a `ClassNode`'s children.
/// Enough information for each generator to emit one struct field line.
#[derive(Debug)]
pub(crate) struct FieldInfo {
    pub name: String,
    pub offset: usize,
    pub kind: FieldKind,
    pub comment: String,
}

#[derive(Debug)]
pub(crate) enum FieldKind {
    /// int8_t / sbyte / i8, etc.
    Primitive(PrimKind),
    /// Raw bytes of known size (Hex8/16/32/64 nodes).
    RawBytes(usize),
    /// `T*` — optional target type name (None → void* / usize).
    Pointer(Option<String>),
    /// Inline nested struct by type name.
    ClassInstance(String),
    /// Raw byte array of total size (count × element_size).
    /// The Hex* and untyped Array nodes both map here.
    Array { count: usize },
    /// `char[length]` (UTF-8).
    Utf8Text(usize),
    /// `wchar_t[length]` (UTF-16, length in bytes → length/2 chars).
    Utf16Text(usize),
    /// A `Vector2/3/4` — `components` contiguous floats of `width`.
    Vector { components: usize, width: FloatWidth },
    /// A row-major `Matrix3x3/3x4/4x4` of floats of `width`.
    Matrix { rows: usize, cols: usize, width: FloatWidth },
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum PrimKind {
    Int8,
    Int16,
    Int32,
    Int64,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Float,
    Double,
    Bool,
}

/// Walk one `ClassNode`'s children, computing running offsets and resolving
/// `ClassInstance` UUID references against the project.
///
/// Key invariant: every field's `offset` and the total returned from summing
/// sizes both agree with [`resolved_class_size`], so the size comment/assert
/// emitted by generators and the per-field `[FieldOffset]`/`// 0x….` annotations
/// all describe the same layout.
pub(crate) fn resolve_fields(
    class_node: &crate::class::ClassNode,
    project: &Project,
    registry: &NodeRegistry,
) -> Vec<FieldInfo> {
    let mut fields = Vec::new();
    let mut offset = 0usize;
    // Visited set shared across the entire walk of this class's children so
    // that a single call to resolve_fields does not double-count recursion guards.
    let mut visited: HashSet<uuid::Uuid> = HashSet::new();

    for child in &class_node.children {
        let def = child.to_node_def();
        let name = sanitize_ident(child.name());
        let comment = child.comment().to_string();

        // Resolve the size this child contributes to the running offset.
        // For ClassInstance this MUST go through resolved_node_size so we get
        // the referenced class's real byte width, not the placeholder 0.
        let contributed_size = resolved_node_size(child.as_ref(), project, &mut visited);

        let kind = match def.type_tag.as_str() {
            "Int8"   => FieldKind::Primitive(PrimKind::Int8),
            "Int16"  => FieldKind::Primitive(PrimKind::Int16),
            "Int32"  => FieldKind::Primitive(PrimKind::Int32),
            "Int64"  => FieldKind::Primitive(PrimKind::Int64),
            "UInt8"  => FieldKind::Primitive(PrimKind::UInt8),
            "UInt16" => FieldKind::Primitive(PrimKind::UInt16),
            "UInt32" => FieldKind::Primitive(PrimKind::UInt32),
            "UInt64" => FieldKind::Primitive(PrimKind::UInt64),
            "Float"  => FieldKind::Primitive(PrimKind::Float),
            "Double" => FieldKind::Primitive(PrimKind::Double),
            "Bool"   => FieldKind::Primitive(PrimKind::Bool),

            "Hex8"  => FieldKind::RawBytes(1),
            "Hex16" => FieldKind::RawBytes(2),
            "Hex32" => FieldKind::RawBytes(4),
            "Hex64" => FieldKind::RawBytes(8),

            "Pointer" => {
                // Resolve optional target class name.
                let target_name = def
                    .attrs
                    .get("target_class_uuid")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<uuid::Uuid>().ok())
                    .and_then(|uuid| project.get_class(&uuid))
                    .map(|c| sanitize_ident(&c.name));
                FieldKind::Pointer(target_name)
            }

            "ClassInstance" => {
                let maybe_uuid = def
                    .attrs
                    .get("class_uuid")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<uuid::Uuid>().ok());

                match maybe_uuid {
                    Some(uuid) if project.get_class(&uuid).is_some() => {
                        // Resolved: emit the named type.
                        let class_name = sanitize_ident(&project.get_class(&uuid).unwrap().name);
                        FieldKind::ClassInstance(class_name)
                    }
                    Some(uuid) => {
                        // UUID present but not in project: emit a defined-size byte
                        // blob with a comment so output still compiles and we know
                        // something is missing. Size is 0 (we have no information).
                        // The comment carries the UUID for diagnostics.
                        let comment_with_uuid = if comment.is_empty() {
                            format!("UNRESOLVED {uuid}")
                        } else {
                            format!("{comment} UNRESOLVED {uuid}")
                        };
                        fields.push(FieldInfo {
                            name,
                            offset,
                            kind: FieldKind::RawBytes(0),
                            comment: comment_with_uuid,
                        });
                        offset = offset.saturating_add(contributed_size); // 0
                        continue;
                    }
                    None => {
                        // Malformed node (no class_uuid attr): emit 0-byte blob.
                        fields.push(FieldInfo {
                            name,
                            offset,
                            kind: FieldKind::RawBytes(0),
                            comment: if comment.is_empty() {
                                "UNRESOLVED (missing class_uuid)".to_string()
                            } else {
                                format!("{comment} UNRESOLVED (missing class_uuid)")
                            },
                        });
                        offset = offset.saturating_add(contributed_size); // 0
                        continue;
                    }
                }
            }

            "Array" => {
                let count = def
                    .attrs
                    .get("count")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0) as usize;
                let element_size = def
                    .attrs
                    .get("element_size")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(1) as usize;
                // We don't know the element type from Array alone (it's untyped raw
                // bytes in our model), so we emit as a u8/byte array of total size.
                let total = count.saturating_mul(element_size);
                FieldKind::Array { count: total }
            }

            "Utf8Text" => {
                let length = def
                    .attrs
                    .get("length")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0) as usize;
                FieldKind::Utf8Text(length)
            }

            "Utf16Text" => {
                let length = def
                    .attrs
                    .get("length")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(0) as usize;
                // length is in bytes; each UTF-16 code unit is 2 bytes.
                FieldKind::Utf16Text(length)
            }

            // Pointer to a UTF-8 string: an 8-byte `char*` — emit as an untyped
            // pointer so the field width and semantics stay correct.
            "StrPtr" => FieldKind::Pointer(None),

            // Vector / matrix: the shape is encoded in the tag itself.
            tag if vector_shape(tag).is_some() => {
                let (components, width) = vector_shape(tag).unwrap();
                FieldKind::Vector { components: components as usize, width }
            }
            tag if matrix_shape(tag).is_some() => {
                let (rows, cols, width) = matrix_shape(tag).unwrap();
                FieldKind::Matrix { rows: rows as usize, cols: cols as usize, width }
            }

            // Unknown / Class container nodes embedded as children: emit a
            // raw-bytes fallback so the total size still advances correctly.
            _ => {
                let _ = registry; // registry available if needed in the future
                FieldKind::RawBytes(contributed_size)
            }
        };

        fields.push(FieldInfo { name, offset, kind, comment });
        offset = offset.saturating_add(contributed_size);
    }

    fields
}
