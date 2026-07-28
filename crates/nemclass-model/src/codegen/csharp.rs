//! C# code generator.
//!
//! Output shape:
//! ```csharp
//! using System.Runtime.InteropServices;
//!
//! [StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi)]
//! public struct PlayerStruct // optional comment
//! {
//!     [FieldOffset(0x0)]
//!     public readonly int health; // player HP
//!     [FieldOffset(0x4)]
//!     public readonly float speed;
//! }
//! ```

use super::{
    CodeGenerator, FieldKind, Language, PrimKind, emitted_array_len, escape_comment, resolve_fields, sanitize_ident,
};
use crate::node::registry::NodeRegistry;
use crate::node::vector::FloatWidth;
use crate::project::Project;
// Note: C# generator does not currently emit a sizeof assertion (C# structs with
// `unsafe fixed` arrays require an `unsafe` context for Marshal.SizeOf). The
// resolved total size is correct when read from resolve_fields offsets.

pub struct CSharpCodeGenerator;

impl CSharpCodeGenerator {
    fn prim_type(p: PrimKind) -> &'static str {
        match p {
            PrimKind::Int8   => "sbyte",
            PrimKind::Int16  => "short",
            PrimKind::Int32  => "int",
            PrimKind::Int64  => "long",
            PrimKind::UInt8  => "byte",
            PrimKind::UInt16 => "ushort",
            PrimKind::UInt32 => "uint",
            PrimKind::UInt64 => "ulong",
            PrimKind::Float  => "float",
            PrimKind::Double => "double",
            PrimKind::Bool   => "bool",
        }
    }

    fn int_type_for_size(size: u8) -> &'static str {
        match size {
            1 => "sbyte",
            2 => "short",
            8 => "long",
            _ => "int",
        }
    }

    fn float_type(w: FloatWidth) -> &'static str {
        match w {
            FloatWidth::F32 => "float",
            FloatWidth::F64 => "double",
        }
    }

    fn uint_type_for_size(size: usize) -> &'static str {
        match size {
            1 => "byte",
            2 => "ushort",
            8 => "ulong",
            _ => "uint",
        }
    }

    /// Emit one field at an explicit offset.
    ///
    /// Factored out because a union is not a separate construct in
    /// `LayoutKind.Explicit` — it is simply several fields declared at the same
    /// offset, so union members go through this same writer with the union's own
    /// offset.
    fn emit_field(out: &mut String, f: &super::FieldInfo, offset: usize, indent: &str) {
        let comment_part = if f.comment.is_empty() {
            String::new()
        } else {
            format!(" // {}", escape_comment(&f.comment))
        };

        // `fixed byte x[0]` is a hard C# error (CS0842), as is `SizeConst = 0`.
        // The field contributes no bytes, so record it as a comment and keep the
        // layout identical.
        if emitted_array_len(&f.kind) == Some(0) {
            out.push_str(&format!(
                "{indent}// {} — 0 bytes at 0x{offset:X}, omitted{comment_part}\n",
                f.name
            ));
            return;
        }

        // A union's members each get their own declaration at this offset;
        // nothing is emitted for the union itself.
        if let FieldKind::Union { members } = &f.kind {
            out.push_str(&format!(
                "{indent}// union {} at 0x{offset:X}{comment_part}\n",
                f.name
            ));
            for m in members {
                Self::emit_field(out, m, offset, indent);
            }
            return;
        }

        let mut decl = |body: String| {
            out.push_str(&format!("{indent}[FieldOffset(0x{offset:X})]\n"));
            out.push_str(&format!("{indent}{body}{comment_part}\n"));
        };

        match &f.kind {
            FieldKind::Primitive(p) => {
                decl(format!("public readonly {} {};", Self::prim_type(*p), f.name));
            }
            FieldKind::RawBytes(n) | FieldKind::Array { count: n } => {
                decl(format!("public unsafe fixed byte {}[{}];", f.name, n));
            }
            // All pointers become IntPtr in C# (platform-width).
            FieldKind::Pointer(_) => {
                decl(format!("public readonly IntPtr {};", f.name));
            }
            FieldKind::ClassInstance(tname) => {
                decl(format!("public {} {};", tname, f.name));
            }
            FieldKind::ClassInstanceArray { type_name, count, .. } => {
                // `fixed` buffers only accept primitives, so an array of structs
                // has to be spelled out one element per offset. Emitting a single
                // `fixed` here would not compile.
                out.push_str(&format!(
                    "{indent}// {}[{}] — {} inline copies{comment_part}\n",
                    f.name, count, count
                ));
                for i in 0..*count {
                    let stride = match &f.kind {
                        FieldKind::ClassInstanceArray { stride, .. } => *stride,
                        _ => 0,
                    };
                    out.push_str(&format!(
                        "{indent}[FieldOffset(0x{:X})]\n",
                        offset + i * stride
                    ));
                    out.push_str(&format!(
                        "{indent}public {} {}_{};\n",
                        type_name, f.name, i
                    ));
                }
            }
            // A fixed byte array, not a marshalled `string`. `ByValTStr` declares
            // a *reference* field, and a reference inside an explicit-layout
            // struct throws `TypeLoadException` at runtime the moment it overlaps
            // or is misaligned — the type would not even load.
            FieldKind::Utf8Text(len) => {
                decl(format!(
                    "public unsafe fixed byte {}[{}]; // UTF-8",
                    f.name, len
                ));
            }
            FieldKind::Utf16Text(len) => {
                // Keep the byte count even so a stray odd length cannot land
                // half a code unit in the field.
                let byte_count = len.div_ceil(2) * 2;
                decl(format!(
                    "public unsafe fixed byte {}[{}]; // UTF-16 LE",
                    f.name, byte_count
                ));
            }
            FieldKind::Utf32Text(len) => {
                let byte_count = len.div_ceil(4) * 4;
                decl(format!(
                    "public unsafe fixed byte {}[{}]; // UTF-32 LE",
                    f.name, byte_count
                ));
            }
            FieldKind::Vector { components, width } => {
                decl(format!(
                    "public unsafe fixed {} {}[{}];",
                    Self::float_type(*width),
                    f.name,
                    components
                ));
            }
            FieldKind::Matrix { rows, cols, width } => {
                // C# `fixed` buffers are one-dimensional, so a matrix is
                // flattened row-major — index it as `m[row * cols + col]`.
                decl(format!(
                    "public unsafe fixed {} {}[{}]; // {}x{} row-major",
                    Self::float_type(*width),
                    f.name,
                    rows * cols,
                    rows,
                    cols
                ));
            }
            FieldKind::NativeInt { signed, size } => {
                let ty = if *signed {
                    Self::int_type_for_size(*size as u8)
                } else {
                    Self::uint_type_for_size(*size)
                };
                decl(format!("public readonly {ty} {};", f.name));
            }
            FieldKind::Enum { type_name: Some(t), .. } => {
                decl(format!("public readonly {t} {};", f.name));
            }
            FieldKind::Enum { type_name: None, size } => {
                decl(format!(
                    "public readonly {} {};",
                    Self::int_type_for_size(*size as u8),
                    f.name
                ));
            }
            FieldKind::BitField { size, bits } => {
                decl(format!(
                    "public readonly {} {}; // {bits} bits",
                    Self::uint_type_for_size(*size),
                    f.name
                ));
            }
            FieldKind::TypedArray { element, count } => match element.as_ref() {
                FieldKind::Primitive(p) => decl(format!(
                    "public unsafe fixed {} {}[{}];",
                    Self::prim_type(*p),
                    f.name,
                    count
                )),
                // Anything else has no `fixed`-compatible element type; fall back
                // to the byte span the elements occupy.
                other => {
                    let elem_bytes = emitted_array_len(other).unwrap_or(1).max(1);
                    decl(format!(
                        "public unsafe fixed byte {}[{}]; // {count} elements",
                        f.name,
                        count * elem_bytes
                    ))
                }
            },
            FieldKind::Custom { type_name, array_len, .. } => match array_len {
                Some(n) => decl(format!(
                    "public unsafe fixed {type_name} {}[{}];",
                    f.name, n
                )),
                None => decl(format!("public {type_name} {};", f.name)),
            },
            // Handled above.
            FieldKind::Union { .. } => unreachable!("unions are emitted before this match"),
        }
    }
}

impl CodeGenerator for CSharpCodeGenerator {
    fn language(&self) -> Language { Language::CSharp }

    fn generate(&self, project: &Project, registry: &NodeRegistry) -> String {
        let mut out = String::new();

        out.push_str("// Generated by nemclass-rs\n");
        out.push_str("// Warning: The C# code generator doesn't support all node types!\n\n");
        out.push_str("using System.Runtime.InteropServices;\n\n");

        // Enums
        for e in &project.enums {
            let ename = sanitize_ident(&e.name);
            let underlying = Self::int_type_for_size(e.size);
            out.push_str(&format!("public enum {ename} : {underlying}\n{{\n"));
            let last = e.values.len().saturating_sub(1);
            for (i, (vname, vval)) in e.values.iter().enumerate() {
                let vname = sanitize_ident(vname);
                if i < last {
                    out.push_str(&format!("    {vname} = {vval},\n"));
                } else {
                    out.push_str(&format!("    {vname} = {vval}\n"));
                }
            }
            out.push_str("}\n\n");
        }

        // Classes
        for class in project.classes_in_order() {
            let cname = sanitize_ident(&class.name);

            out.push_str("[StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi)]\n");
            out.push_str(&format!("public struct {cname}"));
            if !class.comment.is_empty() {
                out.push_str(&format!(" // {}", escape_comment(&class.comment)));
            }
            out.push_str("\n{\n");

            let fields = resolve_fields(class, project, registry, Language::CSharp);

            for f in &fields {
                Self::emit_field(&mut out, f, f.offset, "    ");
            }

            out.push_str("}\n\n");
        }

        // Trim trailing newline to one
        while out.ends_with("\n\n") {
            out.pop();
        }

        out
    }
}
