//! VTable and virtual-method nodes — model half of the vtable dissection view.
//!
//! These are the Rust equivalents of ReClass.NET's `VirtualMethodTableNode`
//! and `VirtualMethodNode`.  The live pointer read + disassembly that
//! ReClass.NET performs inside `Draw()` belongs in the UI layer (which has
//! process access); everything here is pure static formatting from a byte
//! buffer.
//!
//! Memory layout rationale:
//! - `VTableNode` occupies **8 bytes** in its parent class — it is a single
//!   pointer slot (the vptr) stored inline.  The `VMethodNode` children
//!   describe the *pointed-to* table; they do not add to the parent's size.
//! - `VMethodNode` reports **8 bytes** (one pointer-sized slot in the vtable
//!   array), matching `BaseFunctionPtrNode.MemorySize = IntPtr.Size` in the
//!   C# source.

use bytemuck::pod_read_unaligned;

use crate::serialize::NodeDef;
use crate::node::{Node, RenderedValue};

// ---------------------------------------------------------------------------
// Internal helpers (mirror builtins.rs)
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
// VTableNode
// ---------------------------------------------------------------------------

/// A virtual-method-table pointer node (Rust port of `VirtualMethodTableNode`).
///
/// This is a **container** node: its `children` are the `VMethodNode`s that
/// describe each slot of the pointed-to vtable.  Like a `PointerNode`, it
/// occupies exactly 8 bytes in its parent class — the vptr — while the child
/// slots are in the memory *beyond* that pointer.
pub struct VTableNode {
    pub name: String,
    pub comment: String,
    /// The vtable-slot nodes (children must all be `VMethodNode`s in practice,
    /// but the trait uses `Box<dyn Node>` for uniformity).
    pub children: Vec<Box<dyn Node>>,
}

impl VTableNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), comment: String::new(), children: Vec::new() }
    }
}

impl Node for VTableNode {
    fn type_tag(&self) -> &'static str { "VTable" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }

    /// The node itself is an 8-byte pointer slot in its parent class.
    fn memory_size(&self) -> usize { 8 }

    fn children(&self) -> &[Box<dyn Node>] { &self.children }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { Some(&mut self.children) }

    /// Read the 8-byte vptr at `base_offset` and format it as `-> 0x…` (or
    /// `-> null`).  No live process interaction — the caller provides the
    /// buffer.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr(buf, base_offset) else {
            return fallback_rv("VTable");
        };
        let value = if v == 0 {
            "-> null".to_string()
        } else {
            format!("-> 0x{v:016X}")
        };
        RenderedValue { value, type_tag: "VTable", memory_size: 8 }
    }

    /// Serialize to a `NodeDef`.  Children are serialized separately by
    /// `NodeRegistry::serialize_node_recursive` — `to_node_def` only fills
    /// the node's own fields and attrs; the registry appends `nodes`.
    fn to_node_def(&self) -> NodeDef {
        NodeDef {
            type_tag: "VTable".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs: std::collections::BTreeMap::new(),
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// VMethodNode
// ---------------------------------------------------------------------------

/// One virtual-method slot inside a vtable (Rust port of `VirtualMethodNode`).
///
/// The slot's **index** within the vtable is its position among the parent
/// `VTableNode`'s children — derived at use-time rather than stored, matching
/// ReClass.NET's `Offset / IntPtr.Size` formula.  The editable `name` carries
/// the resolved or user-supplied method name (e.g. from a symbol file or
/// manual annotation); it is empty by default.
pub struct VMethodNode {
    pub name: String,
    pub comment: String,
}

impl VMethodNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), comment: String::new() }
    }
}

impl Node for VMethodNode {
    fn type_tag(&self) -> &'static str { "VMethod" }
    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }

    /// Each vtable slot holds one 8-byte function pointer.
    fn memory_size(&self) -> usize { 8 }

    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }

    /// Read the function pointer at `base_offset` and render as
    /// `{name} -> 0x{addr:016X}`.  When the name is empty the raw address is
    /// shown alone (the UI / symbol layer fills the name in later).
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr(buf, base_offset) else {
            return fallback_rv("VMethod");
        };
        let value = if self.name.is_empty() {
            format!("0x{v:016X}")
        } else {
            format!("{} -> 0x{v:016X}", self.name)
        };
        RenderedValue { value, type_tag: "VMethod", memory_size: 8 }
    }

    fn to_node_def(&self) -> NodeDef {
        NodeDef {
            type_tag: "VMethod".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs: std::collections::BTreeMap::new(),
            nodes: Vec::new(),
        }
    }
}
