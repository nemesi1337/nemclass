//! Function and function-pointer nodes — model half of the function dissection
//! view.
//!
//! These are the Rust equivalents of ReClass.NET's `FunctionNode` and the
//! `BaseFunctionPtrNode` → `FunctionPtrNode` hierarchy.  Live disassembly is
//! intentionally absent here: that belongs in the UI layer (which has process
//! access).  The model renders a pure static view from the byte buffer supplied
//! by the caller.
//!
//! Memory sizes: both nodes occupy one pointer — matching
//! `BaseFunctionPtrNode.MemorySize = IntPtr.Size` and the C# `FunctionNode`'s
//! initial `memorySize` — and follow the project's target pointer width.

use crate::node::builtins::{Attrs, node_def, read_ptr_sized};
use crate::node::{DEFAULT_POINTER_SIZE, Node, RenderedValue};
use crate::node_common_accessors;
use crate::serialize::NodeDef;

fn fallback_rv(type_tag: &'static str, size: usize) -> RenderedValue {
    RenderedValue { value: "<?>".to_string(), type_tag, memory_size: size }
}

// ---------------------------------------------------------------------------
// FunctionNode
// ---------------------------------------------------------------------------

/// A function node (Rust port of `FunctionNode`).
///
/// Stores an editable `signature` string (e.g. `"void Func()"`) which the
/// user or a plugin sets to annotate the function's calling convention and
/// parameters.  The node occupies one pointer-sized slot.
///
/// `render` returns the signature together with the raw code address read from
/// the buffer; live disassembly of the pointed-to code is the UI's concern.
pub struct FunctionNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    /// Editable function signature, e.g. `"void Update(float dt)"`.
    pub signature: String,
    pointer_size: usize,
}

impl FunctionNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            hidden: false,
            signature: "void Func()".to_string(),
            pointer_size: DEFAULT_POINTER_SIZE,
        }
    }
}

impl Node for FunctionNode {
    fn type_tag(&self) -> &'static str { "Function" }
    node_common_accessors!();

    fn memory_size(&self) -> usize { self.pointer_size }

    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }

    fn set_pointer_size(&mut self, size: usize) { self.pointer_size = size; }

    /// Read the code address at `base_offset` and format it together with the
    /// stored signature.  Format: `"{signature} @ 0x{addr:016X}"`.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr_sized(buf, base_offset, self.pointer_size) else {
            return fallback_rv("Function", self.pointer_size);
        };
        RenderedValue {
            value: format!("{} @ 0x{v:016X}", self.signature),
            type_tag: "Function",
            memory_size: self.pointer_size,
        }
    }

    fn to_node_def(&self) -> NodeDef {
        let mut attrs = Attrs::new();
        attrs.insert("signature".to_string(), toml::Value::String(self.signature.clone()));
        node_def("Function", &self.name, &self.comment, self.hidden, attrs)
    }
}

// ---------------------------------------------------------------------------
// FunctionPtrNode
// ---------------------------------------------------------------------------

/// A function-pointer node (Rust port of `BaseFunctionPtrNode` as a concrete
/// leaf type).
///
/// Simpler than `FunctionNode`: it carries no editable signature — it just
/// shows the pointer value as a code address.  This maps to ReClass's generic
/// function-pointer slot that the user hasn't annotated yet.
pub struct FunctionPtrNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    pointer_size: usize,
}

impl FunctionPtrNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            hidden: false,
            pointer_size: DEFAULT_POINTER_SIZE,
        }
    }
}

impl Node for FunctionPtrNode {
    fn type_tag(&self) -> &'static str { "FunctionPtr" }
    node_common_accessors!();

    fn memory_size(&self) -> usize { self.pointer_size }

    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }

    fn set_pointer_size(&mut self, size: usize) { self.pointer_size = size; }

    /// Read the pointer and render it as a hex code address.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr_sized(buf, base_offset, self.pointer_size) else {
            return fallback_rv("FunctionPtr", self.pointer_size);
        };
        RenderedValue {
            value: format!("0x{v:016X}"),
            type_tag: "FunctionPtr",
            memory_size: self.pointer_size,
        }
    }

    fn to_node_def(&self) -> NodeDef {
        node_def("FunctionPtr", &self.name, &self.comment, self.hidden, Attrs::new())
    }
}
