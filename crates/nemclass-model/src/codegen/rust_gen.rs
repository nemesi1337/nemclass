//! Rust code generator.
//!
//! Output shape:
//! ```rust
//! // optional class comment
//! #[repr(C, packed)]
//! pub struct PlayerStruct {
//!     pub health: i32,    // 0x0000 player HP
//!     pub speed: f32,     // 0x0004
//! }
//! ```
//!
//! Enums are emitted as `#[repr(...)]` enums with named variants and associated
//! integer constants. Because we don't know which values map to Rust enum variants
//! at code-gen time (the values come from the target process's data), we emit a
//! tuple-struct newtype + associated const block instead of an `enum` keyword, which
//! is safe for any integer value (including bit-flag sets).


use super::{CodeGenerator, FieldKind, Language, PrimKind, class_size, emitted_array_len, escape_comment, resolve_fields, sanitize_ident};
use crate::node::registry::NodeRegistry;
use crate::project::Project;

pub struct RustCodeGenerator;

impl RustCodeGenerator {
    fn prim_type(p: PrimKind) -> &'static str {
        match p {
            PrimKind::Int8   => "i8",
            PrimKind::Int16  => "i16",
            PrimKind::Int32  => "i32",
            PrimKind::Int64  => "i64",
            PrimKind::UInt8  => "u8",
            PrimKind::UInt16 => "u16",
            PrimKind::UInt32 => "u32",
            PrimKind::UInt64 => "u64",
            PrimKind::Float  => "f32",
            PrimKind::Double => "f64",
            PrimKind::Bool   => "bool",
        }
    }

    /// Map `EnumDescription::size` (byte width) to the Rust integer repr.
    fn int_type_for_size(size: u8) -> &'static str {
        match size {
            1 => "i8",
            2 => "i16",
            8 => "i64",
            _ => "i32",
        }
    }

    fn uint_type_for_size(size: usize) -> &'static str {
        match size {
            1 => "u8",
            2 => "u16",
            8 => "u64",
            _ => "u32",
        }
    }

    /// The full Rust type for a field, array suffix included.
    fn field_type(kind: &FieldKind, union_name: &str) -> String {
        match kind {
            FieldKind::Primitive(p) => Self::prim_type(*p).to_string(),
            FieldKind::RawBytes(n) => format!("[u8; {n}]"),
            FieldKind::Pointer(Some(target)) => format!("*mut {target}"),
            FieldKind::Pointer(None) => "usize".to_string(),
            FieldKind::ClassInstance(t) => t.clone(),
            FieldKind::Array { count } => format!("[u8; {count}]"),
            FieldKind::Utf8Text(len) => format!("[u8; {len}]"),
            // div_ceil so an odd byte length rounds up rather than silently
            // dropping the trailing byte.
            FieldKind::Utf16Text(len) => format!("[u16; {}]", len.div_ceil(2)),
            FieldKind::Utf32Text(len) => format!("[u32; {}]", len.div_ceil(4)),
            FieldKind::Vector { components, width } => {
                format!("[{}; {}]", width.rust_ty(), components)
            }
            // Row-major: the outer array indexes rows.
            FieldKind::Matrix { rows, cols, width } => {
                format!("[[{}; {}]; {}]", width.rust_ty(), cols, rows)
            }
            // Exact-width rather than `isize`/`usize`: the generating host's
            // pointer width is not necessarily the target's, and a mismatch
            // would break the size assertion this file emits.
            FieldKind::NativeInt { signed, size } => {
                if *signed {
                    Self::int_type_for_size(*size as u8).to_string()
                } else {
                    Self::uint_type_for_size(*size).to_string()
                }
            }
            FieldKind::Enum { type_name: Some(t), .. } => t.clone(),
            FieldKind::Enum { type_name: None, size } => {
                Self::int_type_for_size(*size as u8).to_string()
            }
            FieldKind::BitField { size, .. } => Self::uint_type_for_size(*size).to_string(),
            FieldKind::ClassInstanceArray { type_name, count, .. } => {
                format!("[{type_name}; {count}]")
            }
            FieldKind::TypedArray { element, count } => {
                format!("[{}; {}]", Self::field_type(element, union_name), count)
            }
            FieldKind::Union { .. } => union_name.to_string(),
            FieldKind::Custom { type_name, array_len: Some(n), .. } => {
                format!("[{type_name}; {n}]")
            }
            FieldKind::Custom { type_name, array_len: None, .. } => type_name.clone(),
        }
    }

    /// A `#[repr(C, packed)] pub union` item for a `FieldKind::Union` field.
    ///
    /// Emitted as its own item because Rust, unlike C++ and C#, has no anonymous
    /// unions. Members that are not trivially `Copy` — a generated struct — are
    /// wrapped in `ManuallyDrop`, which is what Rust requires of a union field
    /// whose type may implement `Drop`.
    fn union_item(name: &str, members: &[super::FieldInfo]) -> String {
        let mut out = String::from("#[repr(C, packed)]\npub union ");
        out.push_str(name);
        out.push_str(" {\n");
        if members.is_empty() {
            out.push_str("    _empty: [u8; 0],\n");
        }
        for m in members {
            let nested = format!("{name}_{}", m.name);
            let ty = Self::field_type(&m.kind, &nested);
            let needs_manually_drop = matches!(
                m.kind,
                FieldKind::ClassInstance(_)
                    | FieldKind::ClassInstanceArray { .. }
                    | FieldKind::Union { .. }
                    | FieldKind::Custom { .. }
            );
            let ty =
                if needs_manually_drop { format!("std::mem::ManuallyDrop<{ty}>") } else { ty };
            let comment = if m.comment.is_empty() {
                String::new()
            } else {
                format!(" // {}", escape_comment(&m.comment))
            };
            out.push_str(&format!("    pub {}: {ty},{comment}\n", m.name));
        }
        out.push_str("}\n\n");
        out
    }
}

impl CodeGenerator for RustCodeGenerator {
    fn language(&self) -> Language { Language::Rust }

    fn generate(&self, project: &Project, registry: &NodeRegistry) -> String {
        let mut out = String::new();

        out.push_str("// Generated by nemclass-rs\n");
        out.push_str("#![allow(non_camel_case_types, dead_code)]\n\n");

        // Enums: newtype + associated consts so all integer values are representable.
        for e in &project.enums {
            let ename = sanitize_ident(&e.name);
            let repr = Self::int_type_for_size(e.size);

            if e.use_flags {
                // Bit-flag set: newtype wrapper + bit-flag consts
                out.push_str(&format!(
                    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
                     pub struct {ename}(pub {repr});\n\n\
                     impl {ename} {{\n"
                ));
                for (vname, vval) in &e.values {
                    let vname = sanitize_ident(vname);
                    out.push_str(&format!(
                        "    pub const {vname}: {repr} = {vval};\n"
                    ));
                }
                out.push_str("}\n\n");
            } else {
                // Ordinary enum: emit a proper #[repr] enum.
                // We verify uniqueness isn't required here — the caller is responsible
                // for ensuring discriminants don't collide (mirrors C# behavior).
                out.push_str(&format!(
                    "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
                     #[repr({repr})]\n\
                     pub enum {ename} {{\n"
                ));
                for (vname, vval) in &e.values {
                    let vname = sanitize_ident(vname);
                    out.push_str(&format!("    {vname} = {vval},\n"));
                }
                out.push_str("}\n\n");
            }
        }

        // Structs
        for class in project.classes_in_order() {
            let cname = sanitize_ident(&class.name);
            // Use resolved size so ClassInstance fields count their target's
            // real byte width rather than the placeholder 0 from memory_size().
            let total_size = class_size(class, project);

            // The comment goes on its own line *above* the item, not trailing
            // the `pub struct X` line: appending `// …` there put the opening
            // brace inside the comment, so every class carrying a comment
            // generated a Rust file that does not parse.
            let fields = resolve_fields(class, project, registry, Language::Rust);

            // Rust has no anonymous unions, so each union field needs a named
            // item ahead of the struct that refers to it.
            for f in &fields {
                if let FieldKind::Union { members } = &f.kind {
                    out.push_str(&Self::union_item(&format!("{cname}_{}", f.name), members));
                }
            }

            if !class.comment.is_empty() {
                out.push_str(&format!("// {}\n", escape_comment(&class.comment)));
            }
            // `packed`, not bare `repr(C)`. These structs describe a layout
            // that already exists in the target's memory at exactly the offsets
            // shown — the same layout the C++ generator gets from `#pragma
            // pack(1)`. Bare `repr(C)` inserts alignment padding, so any class
            // whose fields are not already naturally aligned would fail the size
            // assertion emitted just below it.
            out.push_str("#[repr(C, packed)]\n");
            out.push_str(&format!("pub struct {cname} {{\n"));

            for f in &fields {
                let comment_part = if f.comment.is_empty() {
                    format!(" // 0x{:04X}", f.offset)
                } else {
                    format!(" // 0x{:04X} {}", f.offset, escape_comment(&f.comment))
                };

                // A zero-length member is not representable in this
                // language; the field contributes no bytes, so record it as a
                // comment and keep the layout identical.
                if emitted_array_len(&f.kind) == Some(0) {
                    out.push_str(&format!("    // {} — 0 bytes, omitted{}\n", f.name, comment_part));
                    continue;
                }

                let ty = Self::field_type(&f.kind, &format!("{cname}_{}", f.name));
                out.push_str(&format!("    pub {}: {ty},{}\n", f.name, comment_part));
            }

            out.push_str("}\n\n");
            out.push_str(&format!(
                "const _: () = assert!(std::mem::size_of::<{cname}>() == 0x{total_size:X});\n\n"
            ));
        }

        // Trim trailing double-newline
        while out.ends_with("\n\n") {
            out.pop();
        }

        out
    }
}
