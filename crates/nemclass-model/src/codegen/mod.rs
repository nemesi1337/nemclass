//! Code generation: turn a `Project` into source-code type definitions.
//!
//! Three built-in generators:
//! - [`CppCodeGenerator`]   → C++ `class` with `#pragma pack(push, 1)`
//! - [`CSharpCodeGenerator`] → C# `struct` with `[StructLayout(LayoutKind.Explicit)]`
//! - [`RustCodeGenerator`]  → Rust `#[repr(C)] struct`
//!
//! All three implement [`CodeGenerator`]. Use the free [`generate`] helper to
//! dispatch by [`Language`].

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

use crate::node::registry::NodeRegistry;
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
pub(crate) fn resolve_fields(
    class_node: &crate::class::ClassNode,
    project: &Project,
    registry: &NodeRegistry,
) -> Vec<FieldInfo> {
    let mut fields = Vec::new();
    let mut offset = 0usize;

    for child in &class_node.children {
        let def = child.to_node_def();
        let name = sanitize_ident(child.name());
        let comment = child.comment().to_string();
        let size = child.memory_size();

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
                let class_name = def
                    .attrs
                    .get("class_uuid")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<uuid::Uuid>().ok())
                    .and_then(|uuid| project.get_class(&uuid))
                    .map(|c| sanitize_ident(&c.name))
                    .unwrap_or_else(|| "_UnknownClass".to_string());
                FieldKind::ClassInstance(class_name)
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

            // Unknown / Class container nodes embedded as children: skip with a
            // raw-bytes fallback so the total size still advances correctly.
            _ => {
                let _ = registry; // registry available if needed in the future
                FieldKind::RawBytes(size)
            }
        };

        fields.push(FieldInfo { name, offset, kind, comment });
        offset = offset.saturating_add(size);
    }

    fields
}
