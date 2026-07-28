use bytemuck::pod_read_unaligned;
use uuid::Uuid;

use super::{DEFAULT_POINTER_SIZE, Node, RenderedValue};
use crate::node_common_accessors;
use crate::serialize::NodeDef;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn read_bytes(buf: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    let end = offset.checked_add(size)?;
    if end <= buf.len() { Some(&buf[offset..end]) } else { None }
}

/// Read a little-endian pointer of `size` bytes (4 or 8) as a `u64`.
pub(crate) fn read_ptr_sized(buf: &[u8], offset: usize, size: usize) -> Option<u64> {
    let bytes = read_bytes(buf, offset, size)?;
    let mut v = 0u64;
    for (i, b) in bytes.iter().enumerate() {
        v |= (*b as u64) << (i * 8);
    }
    Some(v)
}

fn fallback(type_tag: &'static str, size: usize) -> RenderedValue {
    RenderedValue { value: "<?>".to_string(), type_tag, memory_size: size }
}

pub(crate) type Attrs = std::collections::BTreeMap<String, toml::Value>;

/// Build a `NodeDef` with the fields every node carries.
///
/// `hidden` is written only when set: the flag defaults to false, and emitting
/// `hidden = false` on every one of a large project's nodes would triple the
/// file size for no information.
pub(crate) fn node_def(
    type_tag: &str,
    name: &str,
    comment: &str,
    hidden: bool,
    mut attrs: Attrs,
) -> NodeDef {
    if hidden {
        attrs.insert("hidden".to_string(), toml::Value::Boolean(true));
    }
    NodeDef {
        type_tag: type_tag.to_string(),
        name: name.to_string(),
        comment: comment.to_string(),
        attrs,
        nodes: Vec::new(),
    }
}

fn simple_def(type_tag: &'static str, name: &str, comment: &str, hidden: bool) -> NodeDef {
    node_def(type_tag, name, comment, hidden, Attrs::new())
}

// ---------------------------------------------------------------------------
// Macro for simple scalar leaf nodes
// ---------------------------------------------------------------------------

macro_rules! simple_node {
    (
        $struct_name:ident,
        $tag:literal,
        $size:expr,
        $render_expr:expr
    ) => {
        pub struct $struct_name {
            pub name: String,
            pub comment: String,
            pub hidden: bool,
        }

        impl $struct_name {
            pub fn new(name: impl Into<String>) -> Self {
                Self { name: name.into(), comment: String::new(), hidden: false }
            }
        }

        impl Node for $struct_name {
            fn type_tag(&self) -> &'static str { $tag }
            node_common_accessors!();
            fn memory_size(&self) -> usize { $size }
            fn children(&self) -> &[Box<dyn Node>] { &[] }
            fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
            fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
                let size: usize = $size;
                let Some(bytes) = read_bytes(buf, base_offset, size) else {
                    return fallback($tag, size);
                };
                let render_fn: fn(&[u8]) -> String = $render_expr;
                RenderedValue {
                    value: render_fn(bytes),
                    type_tag: $tag,
                    memory_size: size,
                }
            }
            fn to_node_def(&self) -> NodeDef {
                simple_def($tag, &self.name, &self.comment, self.hidden)
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Signed integers
// ---------------------------------------------------------------------------

simple_node!(Int8Node,  "Int8",  1, |b: &[u8]| pod_read_unaligned::<i8>(b).to_string());
simple_node!(Int16Node, "Int16", 2, |b: &[u8]| pod_read_unaligned::<i16>(b).to_string());
simple_node!(Int32Node, "Int32", 4, |b: &[u8]| pod_read_unaligned::<i32>(b).to_string());
simple_node!(Int64Node, "Int64", 8, |b: &[u8]| pod_read_unaligned::<i64>(b).to_string());

// ---------------------------------------------------------------------------
// Unsigned integers
// ---------------------------------------------------------------------------

simple_node!(UInt8Node,  "UInt8",  1, |b: &[u8]| pod_read_unaligned::<u8>(b).to_string());
simple_node!(UInt16Node, "UInt16", 2, |b: &[u8]| pod_read_unaligned::<u16>(b).to_string());
simple_node!(UInt32Node, "UInt32", 4, |b: &[u8]| pod_read_unaligned::<u32>(b).to_string());
simple_node!(UInt64Node, "UInt64", 8, |b: &[u8]| pod_read_unaligned::<u64>(b).to_string());

// ---------------------------------------------------------------------------
// Floats
// ---------------------------------------------------------------------------

simple_node!(Float32Node, "Float",  4, |b: &[u8]| pod_read_unaligned::<f32>(b).to_string());
simple_node!(Float64Node, "Double", 8, |b: &[u8]| pod_read_unaligned::<f64>(b).to_string());

// ---------------------------------------------------------------------------
// Bool
// ---------------------------------------------------------------------------

simple_node!(BoolNode, "Bool", 1, |b: &[u8]| {
    if b[0] != 0 { "true".to_string() } else { "false".to_string() }
});

// ---------------------------------------------------------------------------
// Hex nodes
// ---------------------------------------------------------------------------

simple_node!(Hex8Node,  "Hex8",  1, |b: &[u8]| format!("0x{:02X}", pod_read_unaligned::<u8>(b)));
simple_node!(Hex16Node, "Hex16", 2, |b: &[u8]| format!("0x{:04X}", pod_read_unaligned::<u16>(b)));
simple_node!(Hex32Node, "Hex32", 4, |b: &[u8]| format!("0x{:08X}", pod_read_unaligned::<u32>(b)));
simple_node!(Hex64Node, "Hex64", 8, |b: &[u8]| format!("0x{:016X}", pod_read_unaligned::<u64>(b)));

// ---------------------------------------------------------------------------
// NInt / NUInt — integers exactly as wide as a target pointer
// ---------------------------------------------------------------------------

macro_rules! native_int_node {
    ($struct_name:ident, $tag:literal, $signed:literal) => {
        /// A pointer-width integer (ReClass.NET's `NIntNode` / `NUIntNode`).
        ///
        /// Four bytes against a 32-bit target and eight against a 64-bit one,
        /// which is the whole reason the type exists — `size_t`, `intptr_t` and
        /// every handle-shaped field change width with the target.
        pub struct $struct_name {
            pub name: String,
            pub comment: String,
            pub hidden: bool,
            pointer_size: usize,
        }

        impl $struct_name {
            pub fn new(name: impl Into<String>) -> Self {
                Self {
                    name: name.into(),
                    comment: String::new(),
                    hidden: false,
                    pointer_size: DEFAULT_POINTER_SIZE,
                }
            }
        }

        impl Node for $struct_name {
            fn type_tag(&self) -> &'static str { $tag }
            node_common_accessors!();
            fn memory_size(&self) -> usize { self.pointer_size }
            fn children(&self) -> &[Box<dyn Node>] { &[] }
            fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
            fn set_pointer_size(&mut self, size: usize) { self.pointer_size = size; }
            fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
                let Some(raw) = read_ptr_sized(buf, base_offset, self.pointer_size) else {
                    return fallback($tag, self.pointer_size);
                };
                let value = if $signed {
                    // Sign-extend from the target's width, not from 64 bits: on a
                    // 32-bit target 0xFFFFFFFF is -1, not 4294967295.
                    let shift = 64 - self.pointer_size * 8;
                    (((raw << shift) as i64) >> shift).to_string()
                } else {
                    raw.to_string()
                };
                RenderedValue { value, type_tag: $tag, memory_size: self.pointer_size }
            }
            fn to_node_def(&self) -> NodeDef {
                simple_def($tag, &self.name, &self.comment, self.hidden)
            }
        }
    };
}

native_int_node!(NIntNode, "NInt", true);
native_int_node!(NUIntNode, "NUInt", false);

// ---------------------------------------------------------------------------
// PointerNode
// ---------------------------------------------------------------------------

pub struct PointerNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    pub target_class_uuid: Option<Uuid>,
    pointer_size: usize,
}

impl PointerNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            hidden: false,
            target_class_uuid: None,
            pointer_size: DEFAULT_POINTER_SIZE,
        }
    }

    pub fn pointer_size(&self) -> usize {
        self.pointer_size
    }
}

impl Node for PointerNode {
    fn type_tag(&self) -> &'static str { "Pointer" }
    node_common_accessors!();
    fn memory_size(&self) -> usize { self.pointer_size }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn set_pointer_size(&mut self, size: usize) { self.pointer_size = size; }
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr_sized(buf, base_offset, self.pointer_size) else {
            return fallback("Pointer", self.pointer_size);
        };
        // 12 hex digits, not 16: that covers the whole 47-bit user-space range
        // on x86-64 and keeps the value column narrow enough to show in full.
        // `{:012X}` is a *minimum* width, so a kernel pointer still prints all
        // 16 digits rather than being truncated.
        RenderedValue {
            value: format!("0x{v:012X}"),
            type_tag: "Pointer",
            memory_size: self.pointer_size,
        }
    }
    fn pointer_target_class(&self) -> Option<Uuid> { self.target_class_uuid }
    fn set_pointer_target(&mut self, target: Uuid) -> bool {
        self.target_class_uuid = Some(target);
        true
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = Attrs::new();
        if let Some(uuid) = &self.target_class_uuid {
            attrs.insert("target_class_uuid".to_string(), toml::Value::String(uuid.to_string()));
        }
        node_def("Pointer", &self.name, &self.comment, self.hidden, attrs)
    }
}

// ---------------------------------------------------------------------------
// ClassInstanceNode — zero-size placeholder referencing another class by UUID
// ---------------------------------------------------------------------------

pub struct ClassInstanceNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    pub class_uuid: Uuid,
}

impl ClassInstanceNode {
    pub fn new(name: impl Into<String>, class_uuid: Uuid) -> Self {
        Self { name: name.into(), comment: String::new(), hidden: false, class_uuid }
    }
}

impl Node for ClassInstanceNode {
    fn type_tag(&self) -> &'static str { "ClassInstance" }
    node_common_accessors!();
    fn memory_size(&self) -> usize { 0 }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        RenderedValue {
            value: format!("<class:{}>", self.class_uuid),
            type_tag: "ClassInstance",
            memory_size: 0,
        }
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = Attrs::new();
        attrs.insert("class_uuid".to_string(), toml::Value::String(self.class_uuid.to_string()));
        node_def("ClassInstance", &self.name, &self.comment, self.hidden, attrs)
    }
}

// ---------------------------------------------------------------------------
// ClassInstanceArrayNode — `count` inline copies of another class
// ---------------------------------------------------------------------------

/// An inline array of class instances (ReClass.NET's `ClassInstanceArrayNode`).
///
/// Like [`ClassInstanceNode`], its width is only knowable with a `Project` in
/// hand, so `memory_size` reports 0 and
/// [`resolved_node_size`](crate::codegen::resolved_node_size) supplies the real
/// `count × sizeof(class)`.
pub struct ClassInstanceArrayNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    pub class_uuid: Uuid,
    pub count: usize,
}

impl ClassInstanceArrayNode {
    pub fn new(name: impl Into<String>, class_uuid: Uuid, count: usize) -> Self {
        Self { name: name.into(), comment: String::new(), hidden: false, class_uuid, count }
    }
}

impl Node for ClassInstanceArrayNode {
    fn type_tag(&self) -> &'static str { "ClassInstanceArray" }
    node_common_accessors!();
    fn memory_size(&self) -> usize { 0 }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        RenderedValue {
            value: format!("<class:{} \u{00d7} {}>", self.class_uuid, self.count),
            type_tag: "ClassInstanceArray",
            memory_size: 0,
        }
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = Attrs::new();
        attrs.insert("class_uuid".to_string(), toml::Value::String(self.class_uuid.to_string()));
        attrs.insert("count".to_string(), toml::Value::Integer(self.count as i64));
        node_def("ClassInstanceArray", &self.name, &self.comment, self.hidden, attrs)
    }
}

// ---------------------------------------------------------------------------
// ArrayNode
// ---------------------------------------------------------------------------

/// A fixed-length array.
///
/// `element_tag` names the element's node type when the array is typed
/// (`Int32`, `Float`, …); an empty tag means the historical untyped form, which
/// generates as a raw byte blob. `element_size` is always the authoritative
/// width — it is kept in step with the tag by [`ArrayNode::set_element_type`] so
/// that `memory_size` needs no registry lookup.
pub struct ArrayNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    pub count: usize,
    pub element_size: usize,
    pub element_tag: String,
}

impl ArrayNode {
    pub fn new(name: impl Into<String>, count: usize, element_size: usize) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            hidden: false,
            count,
            element_size,
            element_tag: String::new(),
        }
    }

    /// Type this array's elements. The width comes from the registry-constructed
    /// prototype, so the array stays consistent with whatever the element type
    /// reports — including pointer-width-dependent types.
    pub fn set_element_type(&mut self, tag: &str, element_size: usize) {
        self.element_tag = tag.to_string();
        self.element_size = element_size.max(1);
    }
}

impl Node for ArrayNode {
    fn type_tag(&self) -> &'static str { "Array" }
    node_common_accessors!();
    // Saturating: count/element_size come from (untrusted) project files.
    fn memory_size(&self) -> usize { self.count.saturating_mul(self.element_size) }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        let value = if self.element_tag.is_empty() {
            format!("[{} \u{00d7} {}B]", self.count, self.element_size)
        } else {
            format!("{}[{}]", self.element_tag, self.count)
        };
        RenderedValue { value, type_tag: "Array", memory_size: self.memory_size() }
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = Attrs::new();
        attrs.insert("count".to_string(), toml::Value::Integer(self.count as i64));
        attrs.insert("element_size".to_string(), toml::Value::Integer(self.element_size as i64));
        if !self.element_tag.is_empty() {
            attrs.insert(
                "element_type".to_string(),
                toml::Value::String(self.element_tag.clone()),
            );
        }
        node_def("Array", &self.name, &self.comment, self.hidden, attrs)
    }
}

// ---------------------------------------------------------------------------
// Text nodes — a fixed-length buffer of characters, inline in the class
// ---------------------------------------------------------------------------

/// How a text node's bytes decode. The value is also the code-unit width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextEncoding {
    Utf8,
    Utf16,
    Utf32,
}

impl TextEncoding {
    pub fn unit_size(self) -> usize {
        match self {
            TextEncoding::Utf8 => 1,
            TextEncoding::Utf16 => 2,
            TextEncoding::Utf32 => 4,
        }
    }

    /// Decode up to the first NUL, lossily. `bytes` is the raw field content.
    pub fn decode(self, bytes: &[u8]) -> String {
        match self {
            TextEncoding::Utf8 => {
                let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                String::from_utf8_lossy(&bytes[..end]).into_owned()
            }
            TextEncoding::Utf16 => {
                let units: Vec<u16> =
                    bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
                String::from_utf16_lossy(&units[..end])
            }
            TextEncoding::Utf32 => {
                let units: Vec<u32> =
                    bytes.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c)).collect();
                let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
                units[..end].iter().map(|&c| char::from_u32(c).unwrap_or('\u{fffd}')).collect()
            }
        }
    }
}

macro_rules! text_node {
    ($struct_name:ident, $tag:literal, $enc:expr) => {
        /// A fixed-length inline text field. `length` is in **bytes**, matching
        /// the rest of the model's sizes (not in code units).
        pub struct $struct_name {
            pub name: String,
            pub comment: String,
            pub hidden: bool,
            pub length: usize,
        }

        impl $struct_name {
            pub fn new(name: impl Into<String>, length: usize) -> Self {
                Self { name: name.into(), comment: String::new(), hidden: false, length }
            }

            pub const ENCODING: TextEncoding = $enc;
        }

        impl Node for $struct_name {
            fn type_tag(&self) -> &'static str { $tag }
            node_common_accessors!();
            fn memory_size(&self) -> usize { self.length }
            fn children(&self) -> &[Box<dyn Node>] { &[] }
            fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
            fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
                let Some(bytes) = read_bytes(buf, base_offset, self.length) else {
                    return fallback($tag, self.length);
                };
                let s = $enc.decode(bytes);
                RenderedValue {
                    value: format!("\"{s}\""),
                    type_tag: $tag,
                    memory_size: self.length,
                }
            }
            fn to_node_def(&self) -> NodeDef {
                let mut attrs = Attrs::new();
                attrs.insert("length".to_string(), toml::Value::Integer(self.length as i64));
                node_def($tag, &self.name, &self.comment, self.hidden, attrs)
            }
        }
    };
}

text_node!(Utf8TextNode, "Utf8Text", TextEncoding::Utf8);
text_node!(Utf16TextNode, "Utf16Text", TextEncoding::Utf16);
text_node!(Utf32TextNode, "Utf32Text", TextEncoding::Utf32);

// ---------------------------------------------------------------------------
// Text pointer nodes — a pointer whose target is a NUL-terminated string
// ---------------------------------------------------------------------------

macro_rules! text_ptr_node {
    ($struct_name:ident, $tag:literal, $enc:expr) => {
        /// A pointer to a NUL-terminated string.
        ///
        /// The field itself holds only the pointer, so `render` — which sees the
        /// owning class's buffer and nothing else — can surface the address
        /// alone. The UI dereferences it against the live process to show the
        /// characters.
        pub struct $struct_name {
            pub name: String,
            pub comment: String,
            pub hidden: bool,
            pointer_size: usize,
        }

        impl $struct_name {
            pub fn new(name: impl Into<String>) -> Self {
                Self {
                    name: name.into(),
                    comment: String::new(),
                    hidden: false,
                    pointer_size: DEFAULT_POINTER_SIZE,
                }
            }

            pub const ENCODING: TextEncoding = $enc;
        }

        impl Node for $struct_name {
            fn type_tag(&self) -> &'static str { $tag }
            node_common_accessors!();
            fn memory_size(&self) -> usize { self.pointer_size }
            fn children(&self) -> &[Box<dyn Node>] { &[] }
            fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
            fn set_pointer_size(&mut self, size: usize) { self.pointer_size = size; }
            fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
                let Some(v) = read_ptr_sized(buf, base_offset, self.pointer_size) else {
                    return fallback($tag, self.pointer_size);
                };
                RenderedValue {
                    value: format!("0x{v:016X}"),
                    type_tag: $tag,
                    memory_size: self.pointer_size,
                }
            }
            fn to_node_def(&self) -> NodeDef {
                simple_def($tag, &self.name, &self.comment, self.hidden)
            }
        }
    };
}

// `StrPtr` predates the ReClass-aligned names and appears in projects already on
// disk, so its tag is kept rather than migrated; it is a UTF-8 text pointer.
text_ptr_node!(StrPtrNode, "StrPtr", TextEncoding::Utf8);
text_ptr_node!(Utf8TextPtrNode, "Utf8TextPtr", TextEncoding::Utf8);
text_ptr_node!(Utf16TextPtrNode, "Utf16TextPtr", TextEncoding::Utf16);
text_ptr_node!(Utf32TextPtrNode, "Utf32TextPtr", TextEncoding::Utf32);

/// The text encoding behind a text or text-pointer type tag, if it is one.
pub fn text_encoding(tag: &str) -> Option<TextEncoding> {
    match tag {
        "Utf8Text" | "Utf8TextPtr" | "StrPtr" => Some(TextEncoding::Utf8),
        "Utf16Text" | "Utf16TextPtr" => Some(TextEncoding::Utf16),
        "Utf32Text" | "Utf32TextPtr" => Some(TextEncoding::Utf32),
        _ => None,
    }
}
