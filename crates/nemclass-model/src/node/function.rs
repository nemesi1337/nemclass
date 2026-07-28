//! Function and function-pointer nodes — model half of the function dissection
//! view.
//!
//! These are the Rust equivalents of ReClass.NET's `FunctionNode` and the
//! `BaseFunctionPtrNode` → `FunctionPtrNode` hierarchy.  Live disassembly is
//! intentionally absent here: that belongs in the UI layer (which has process
//! access).  The model renders a pure static view from the byte buffer supplied
//! by the caller.
//!
//! Memory sizes:
//! - Both `FunctionNode` and `FunctionPtrNode` occupy **8 bytes** — a single
//!   pointer slot — matching `BaseFunctionPtrNode.MemorySize = IntPtr.Size`
//!   and the C# `FunctionNode.memorySize` initial value of `IntPtr.Size`.

use bytemuck::pod_read_unaligned;

use crate::serialize::NodeDef;
use crate::node::{Node, RenderedValue};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_ptr(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    if end <= buf.len() {
        Some(pod_read_unaligned::<u64>(&buf[offset..end]))
    } else {
        None
    }
}

fn fallback_rv(type_tag: &'static str) -> RenderedValue {
    RenderedValue { value: "<?>".to_string(), type_tag, memory_size: 8 }
}

// ---------------------------------------------------------------------------
// FunctionNode
// ---------------------------------------------------------------------------

/// A function node (Rust port of `FunctionNode`).
///
/// Stores an editable `signature` string (e.g. `"void Func()"`) which the
/// user or a plugin sets to annotate the function's calling convention and
/// parameters.  The node occupies 8 bytes (a pointer-sized slot).
///
/// `render` returns the signature together with the raw code address read from
/// the buffer; live disassembly of the pointed-to code is the UI's concern.
pub struct FunctionNode {
    pub name: String,
    pub comment: String,
    /// Editable function signature, e.g. `"void Update(float dt)"`.
    pub signature: String,
}

impl FunctionNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            signature: "void Func()".to_string(),
        }
    }
}

impl Node for FunctionNode {
    fn type_tag(&self) -> &'static str { "Function" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }

    /// 8 bytes — one pointer-sized slot.
    fn memory_size(&self) -> usize { 8 }

    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }

    /// Read the 8-byte code address at `base_offset` and format it together
    /// with the stored signature.  Format: `"{signature} @ 0x{addr:016X}"`.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr(buf, base_offset) else {
            return fallback_rv("Function");
        };
        RenderedValue {
            value: format!("{} @ 0x{v:016X}", self.signature),
            type_tag: "Function",
            memory_size: 8,
        }
    }

    fn to_node_def(&self) -> NodeDef {
        let mut attrs = std::collections::BTreeMap::new();
        attrs.insert("signature".to_string(), toml::Value::String(self.signature.clone()));
        NodeDef {
            type_tag: "Function".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs,
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionPtrNode
// ---------------------------------------------------------------------------

/// A function-pointer node (Rust port of `BaseFunctionPtrNode` as a concrete
/// leaf type).
///
/// Simpler than `FunctionNode`: it carries no editable signature — it just
/// shows the 8-byte pointer value as a code address.  This maps to ReClass's
/// generic function-pointer slot that the user hasn't annotated yet.
pub struct FunctionPtrNode {
    pub name: String,
    pub comment: String,
}

impl FunctionPtrNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), comment: String::new() }
    }
}

impl Node for FunctionPtrNode {
    fn type_tag(&self) -> &'static str { "FunctionPtr" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }

    /// 8 bytes — one pointer-sized slot.
    fn memory_size(&self) -> usize { 8 }

    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }

    /// Read the 8-byte pointer and render it as a hex code address.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr(buf, base_offset) else {
            return fallback_rv("FunctionPtr");
        };
        RenderedValue {
            value: format!("0x{v:016X}"),
            type_tag: "FunctionPtr",
            memory_size: 8,
        }
    }

    fn to_node_def(&self) -> NodeDef {
        NodeDef {
            type_tag: "FunctionPtr".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs: std::collections::BTreeMap::new(),
            nodes: Vec::new(),
        }
    }
}
