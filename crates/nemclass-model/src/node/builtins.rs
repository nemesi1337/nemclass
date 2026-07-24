use bytemuck::pod_read_unaligned;
use uuid::Uuid;

use crate::serialize::NodeDef;
use super::{Node, RenderedValue};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_bytes(buf: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    let end = offset.checked_add(size)?;
    if end <= buf.len() { Some(&buf[offset..end]) } else { None }
}

fn fallback(type_tag: &'static str, size: usize) -> RenderedValue {
    RenderedValue { value: "<?>".to_string(), type_tag, memory_size: size }
}

fn simple_def(type_tag: &'static str, name: &str, comment: &str) -> NodeDef {
    NodeDef {
        type_tag: type_tag.to_string(),
        name: name.to_string(),
        comment: comment.to_string(),
        attrs: std::collections::HashMap::new(),
        nodes: Vec::new(),
    }
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
        }

        impl $struct_name {
            pub fn new(name: impl Into<String>) -> Self {
                Self { name: name.into(), comment: String::new() }
            }
        }

        impl Node for $struct_name {
            fn type_tag(&self) -> &'static str { $tag }
            fn name(&self) -> &str { &self.name }
            fn set_name(&mut self, n: String) { self.name = n; }
            fn comment(&self) -> &str { &self.comment }
            fn set_comment(&mut self, c: String) { self.comment = c; }
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
                simple_def($tag, &self.name, &self.comment)
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
// PointerNode — always 8 bytes (64-bit pointer)
// ---------------------------------------------------------------------------

pub struct PointerNode {
    pub name: String,
    pub comment: String,
    pub target_class_uuid: Option<Uuid>,
}

impl PointerNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), comment: String::new(), target_class_uuid: None }
    }
}

impl Node for PointerNode {
    fn type_tag(&self) -> &'static str { "Pointer" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }
    fn memory_size(&self) -> usize { 8 }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(bytes) = read_bytes(buf, base_offset, 8) else {
            return fallback("Pointer", 8);
        };
        let v = pod_read_unaligned::<u64>(bytes);
        RenderedValue { value: format!("0x{v:016X}"), type_tag: "Pointer", memory_size: 8 }
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = std::collections::HashMap::new();
        if let Some(uuid) = &self.target_class_uuid {
            attrs.insert("target_class_uuid".to_string(), toml::Value::String(uuid.to_string()));
        }
        NodeDef {
            type_tag: "Pointer".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs,
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ClassInstanceNode — zero-size placeholder referencing another class by UUID
// ---------------------------------------------------------------------------

pub struct ClassInstanceNode {
    pub name: String,
    pub comment: String,
    pub class_uuid: Uuid,
}

impl ClassInstanceNode {
    pub fn new(name: impl Into<String>, class_uuid: Uuid) -> Self {
        Self { name: name.into(), comment: String::new(), class_uuid }
    }
}

impl Node for ClassInstanceNode {
    fn type_tag(&self) -> &'static str { "ClassInstance" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }
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
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("class_uuid".to_string(), toml::Value::String(self.class_uuid.to_string()));
        NodeDef {
            type_tag: "ClassInstance".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs,
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// ArrayNode
// ---------------------------------------------------------------------------

pub struct ArrayNode {
    pub name: String,
    pub comment: String,
    pub count: usize,
    pub element_size: usize,
}

impl ArrayNode {
    pub fn new(name: impl Into<String>, count: usize, element_size: usize) -> Self {
        Self { name: name.into(), comment: String::new(), count, element_size }
    }
}

impl Node for ArrayNode {
    fn type_tag(&self) -> &'static str { "Array" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }
    fn memory_size(&self) -> usize { self.count * self.element_size }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        RenderedValue {
            value: format!("[{} \u{00d7} {}B]", self.count, self.element_size),
            type_tag: "Array",
            memory_size: self.memory_size(),
        }
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("count".to_string(), toml::Value::Integer(self.count as i64));
        attrs.insert("element_size".to_string(), toml::Value::Integer(self.element_size as i64));
        NodeDef {
            type_tag: "Array".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs,
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Utf8TextNode
// ---------------------------------------------------------------------------

pub struct Utf8TextNode {
    pub name: String,
    pub comment: String,
    pub length: usize,
}

impl Utf8TextNode {
    pub fn new(name: impl Into<String>, length: usize) -> Self {
        Self { name: name.into(), comment: String::new(), length }
    }
}

impl Node for Utf8TextNode {
    fn type_tag(&self) -> &'static str { "Utf8Text" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }
    fn memory_size(&self) -> usize { self.length }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(bytes) = read_bytes(buf, base_offset, self.length) else {
            return fallback("Utf8Text", self.length);
        };
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let s = String::from_utf8_lossy(&bytes[..end]).into_owned();
        RenderedValue { value: format!("\"{s}\""), type_tag: "Utf8Text", memory_size: self.length }
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("length".to_string(), toml::Value::Integer(self.length as i64));
        NodeDef {
            type_tag: "Utf8Text".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs,
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Utf16TextNode (little-endian UTF-16, length in bytes)
// ---------------------------------------------------------------------------

pub struct Utf16TextNode {
    pub name: String,
    pub comment: String,
    pub length: usize,
}

impl Utf16TextNode {
    pub fn new(name: impl Into<String>, length: usize) -> Self {
        Self { name: name.into(), comment: String::new(), length }
    }
}

impl Node for Utf16TextNode {
    fn type_tag(&self) -> &'static str { "Utf16Text" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }
    fn memory_size(&self) -> usize { self.length }
    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(bytes) = read_bytes(buf, base_offset, self.length) else {
            return fallback("Utf16Text", self.length);
        };
        let u16s: Vec<u16> = bytes.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let end = u16s.iter().position(|&c| c == 0).unwrap_or(u16s.len());
        let s = String::from_utf16_lossy(&u16s[..end]);
        RenderedValue { value: format!("\"{s}\""), type_tag: "Utf16Text", memory_size: self.length }
    }
    fn to_node_def(&self) -> NodeDef {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("length".to_string(), toml::Value::Integer(self.length as i64));
        NodeDef {
            type_tag: "Utf16Text".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs,
            nodes: Vec::new(),
        }
    }
}
