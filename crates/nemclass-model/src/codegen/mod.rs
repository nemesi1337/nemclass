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
        FieldKind::Utf32Text(n) => Some(n.div_ceil(4)),
        FieldKind::Vector { components, .. } => Some(*components),
        FieldKind::TypedArray { count, .. } => Some(*count),
        FieldKind::ClassInstanceArray { count, .. } => Some(*count),
        FieldKind::Custom { array_len: Some(n), .. } => Some(*n),
        FieldKind::Union { members } => Some(members.len()),
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
    match def.type_tag.as_str() {
        "ClassInstance" => referenced_class_size(&def, project, visited),
        "ClassInstanceArray" => {
            let stride = referenced_class_size(&def, project, visited);
            let count = def.attrs.get("count").and_then(|v| v.as_integer()).unwrap_or(0) as usize;
            stride.saturating_mul(count)
        }
        // A union is as wide as its widest member — and a member may itself be a
        // `ClassInstance`, so the width has to be resolved here rather than left
        // to `UnionNode::memory_size`, which has no project to resolve against.
        "Union" => node
            .children()
            .iter()
            .map(|c| resolved_node_size(c.as_ref(), project, visited))
            .max()
            .unwrap_or(0),
        // All other node types: trust the model's own memory_size().
        _ => node.memory_size(),
    }
}

/// Byte width of the class a `class_uuid` attribute points at, or 0 when the
/// reference is missing, malformed, unresolvable, or cyclic.
fn referenced_class_size(
    def: &crate::serialize::NodeDef,
    project: &Project,
    visited: &mut HashSet<uuid::Uuid>,
) -> usize {
    let Some(uuid) = def
        .attrs
        .get("class_uuid")
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<uuid::Uuid>().ok())
    else {
        return 0;
    };
    if visited.contains(&uuid) {
        // Cycle detected — stop recursing, contribute 0.
        return 0;
    }
    let Some(target_class) = project.get_class(&uuid) else {
        return 0;
    };
    visited.insert(uuid);
    let sz = resolved_class_size(target_class, project, visited);
    visited.remove(&uuid);
    sz
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
    /// `char16_t[length/2]` (UTF-16, length in bytes).
    Utf16Text(usize),
    /// `char32_t[length/4]` (UTF-32, length in bytes).
    Utf32Text(usize),
    /// A `Vector2/3/4` — `components` contiguous floats of `width`.
    Vector { components: usize, width: FloatWidth },
    /// A row-major `Matrix3x3/3x4/4x4` of floats of `width`.
    Matrix { rows: usize, cols: usize, width: FloatWidth },
    /// `intptr_t`/`uintptr_t` — an integer as wide as a target pointer.
    NativeInt { signed: bool, size: usize },
    /// A field displayed through a project enum. `type_name` is the generated
    /// enum's identifier; `size` is its underlying width, so a generator that
    /// cannot name the enum still emits something of the right width.
    Enum { type_name: Option<String>, size: usize },
    /// A run of bits inside an unsigned integer `size` bytes wide.
    BitField { size: usize, bits: usize },
    /// `count` inline copies of a named class, each `stride` bytes.
    ClassInstanceArray { type_name: String, count: usize, stride: usize },
    /// `count` elements, each spelled by `element`.
    TypedArray { element: Box<FieldKind>, count: usize },
    /// Overlapping members, every one of them at this field's own offset.
    Union { members: Vec<FieldInfo> },
    /// A node type that supplied its own spelling through
    /// [`NodeRegistry::register_codegen`](crate::NodeRegistry::register_codegen).
    Custom { type_name: String, array_len: Option<usize> },
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
    language: Language,
) -> Vec<FieldInfo> {
    // Visited set shared across the entire walk of this class's children so
    // that a single call to resolve_fields does not double-count recursion guards.
    let mut visited: HashSet<uuid::Uuid> = HashSet::new();
    resolve_child_list(&class_node.children, project, registry, language, &mut visited)
}

/// Walk one list of sibling nodes, accumulating offsets. Shared by the class
/// body and by `Union` members — the only difference is that a union's caller
/// resets each member's offset to the union's own.
fn resolve_child_list(
    children: &[Box<dyn crate::node::Node>],
    project: &Project,
    registry: &NodeRegistry,
    language: Language,
    visited: &mut HashSet<uuid::Uuid>,
) -> Vec<FieldInfo> {
    let mut fields = Vec::new();
    let mut offset = 0usize;

    for child in children {
        let def = child.to_node_def();
        let name = sanitize_ident(child.name());
        let comment = child.comment().to_string();

        // Resolve the size this child contributes to the running offset.
        // For ClassInstance this MUST go through resolved_node_size so we get
        // the referenced class's real byte width, not the placeholder 0.
        let contributed_size = resolved_node_size(child.as_ref(), project, visited);

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

            "ClassInstanceArray" => {
                let target = def
                    .attrs
                    .get("class_uuid")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<uuid::Uuid>().ok())
                    .and_then(|uuid| project.get_class(&uuid));
                let count = attr_count(&def);
                match target {
                    Some(c) => FieldKind::ClassInstanceArray {
                        type_name: sanitize_ident(&c.name),
                        count,
                        // Divide rather than re-resolve: `contributed_size` is
                        // already `count × stride` from `resolved_node_size`, and
                        // deriving the stride from it keeps the two in step even
                        // when the reference is cyclic and both collapse to 0.
                        stride: contributed_size.checked_div(count).unwrap_or(0),
                    },
                    None => FieldKind::RawBytes(contributed_size),
                }
            }

            "Array" => {
                let count = attr_count(&def);
                let element_size = def
                    .attrs
                    .get("element_size")
                    .and_then(|v| v.as_integer())
                    .unwrap_or(1) as usize;
                let element_tag = def.attrs.get("element_type").and_then(|v| v.as_str());
                match element_tag.and_then(|tag| scalar_field_kind(tag, element_size)) {
                    Some(element) => {
                        FieldKind::TypedArray { element: Box::new(element), count }
                    }
                    // Untyped (or an element type with no scalar spelling): emit
                    // a byte array of the total size, which keeps the layout
                    // right even though the element type is lost.
                    None => FieldKind::Array { count: count.saturating_mul(element_size) },
                }
            }

            "Utf8Text" => FieldKind::Utf8Text(attr_length(&def)),
            // Lengths are in bytes; the generators divide by the code-unit width.
            "Utf16Text" => FieldKind::Utf16Text(attr_length(&def)),
            "Utf32Text" => FieldKind::Utf32Text(attr_length(&def)),

            // A pointer to string data: emit as an untyped pointer so the field
            // width and semantics stay correct.
            "StrPtr" | "Utf8TextPtr" | "Utf16TextPtr" | "Utf32TextPtr" => {
                FieldKind::Pointer(None)
            }

            "NInt" => FieldKind::NativeInt { signed: true, size: contributed_size },
            "NUInt" => FieldKind::NativeInt { signed: false, size: contributed_size },

            "BitField" => {
                let bits = def
                    .attrs
                    .get("bits")
                    .and_then(|v| v.as_integer())
                    .unwrap_or((contributed_size * 8) as i64) as usize;
                FieldKind::BitField { size: contributed_size, bits }
            }

            "Enum" => {
                let enum_name = def.attrs.get("enum_name").and_then(|v| v.as_str()).unwrap_or("");
                // Only name the enum if the project actually declares it — the
                // generators emit definitions from `project.enums`, so naming one
                // that is not there would produce source referencing a type that
                // was never written.
                let type_name = project
                    .enums
                    .iter()
                    .find(|e| e.name == enum_name)
                    .map(|e| sanitize_ident(&e.name));
                FieldKind::Enum { type_name, size: contributed_size }
            }

            "Union" => FieldKind::Union {
                members: resolve_child_list(
                    child.children(),
                    project,
                    registry,
                    language,
                    visited,
                )
                .into_iter()
                // Every member of a union starts where the union starts. The
                // shared walker accumulated offsets as though they were struct
                // fields, so flatten them back to zero.
                .map(|mut f| {
                    f.offset = 0;
                    f
                })
                .collect(),
            },

            // Vector / matrix: the shape is encoded in the tag itself.
            tag if vector_shape(tag).is_some() => {
                let (components, width) = vector_shape(tag).unwrap();
                FieldKind::Vector { components: components as usize, width }
            }
            tag if matrix_shape(tag).is_some() => {
                let (rows, cols, width) = matrix_shape(tag).unwrap();
                FieldKind::Matrix { rows: rows as usize, cols: cols as usize, width }
            }

            // A plugin type that registered its own spelling, else a raw-bytes
            // fallback so the total size still advances correctly.
            _ => match registry.codegen_field(&def, language) {
                Some(custom) => FieldKind::Custom {
                    type_name: custom.type_name,
                    array_len: custom.array_len,
                },
                None => FieldKind::RawBytes(contributed_size),
            },
        };

        fields.push(FieldInfo { name, offset, kind, comment });
        offset = offset.saturating_add(contributed_size);
    }

    fields
}

fn attr_count(def: &crate::serialize::NodeDef) -> usize {
    def.attrs.get("count").and_then(|v| v.as_integer()).unwrap_or(0).max(0) as usize
}

fn attr_length(def: &crate::serialize::NodeDef) -> usize {
    def.attrs.get("length").and_then(|v| v.as_integer()).unwrap_or(0).max(0) as usize
}

/// The field spelling for a scalar type tag, used for typed array elements.
///
/// Only types that can stand alone as an array element are listed: a
/// `ClassInstance` element needs a project lookup, and a container element has
/// no single spelling, so both fall back to the caller's byte-array form.
fn scalar_field_kind(tag: &str, element_size: usize) -> Option<FieldKind> {
    Some(match tag {
        "Int8" => FieldKind::Primitive(PrimKind::Int8),
        "Int16" => FieldKind::Primitive(PrimKind::Int16),
        "Int32" => FieldKind::Primitive(PrimKind::Int32),
        "Int64" => FieldKind::Primitive(PrimKind::Int64),
        "UInt8" => FieldKind::Primitive(PrimKind::UInt8),
        "UInt16" => FieldKind::Primitive(PrimKind::UInt16),
        "UInt32" => FieldKind::Primitive(PrimKind::UInt32),
        "UInt64" => FieldKind::Primitive(PrimKind::UInt64),
        "Float" => FieldKind::Primitive(PrimKind::Float),
        "Double" => FieldKind::Primitive(PrimKind::Double),
        "Bool" => FieldKind::Primitive(PrimKind::Bool),
        "Hex8" => FieldKind::RawBytes(1),
        "Hex16" => FieldKind::RawBytes(2),
        "Hex32" => FieldKind::RawBytes(4),
        "Hex64" => FieldKind::RawBytes(8),
        "NInt" => FieldKind::NativeInt { signed: true, size: element_size },
        "NUInt" => FieldKind::NativeInt { signed: false, size: element_size },
        "Pointer" | "StrPtr" | "Utf8TextPtr" | "Utf16TextPtr" | "Utf32TextPtr"
        | "FunctionPtr" => FieldKind::Pointer(None),
        tag if vector_shape(tag).is_some() => {
            let (components, width) = vector_shape(tag).unwrap();
            FieldKind::Vector { components: components as usize, width }
        }
        _ => return None,
    })
}
