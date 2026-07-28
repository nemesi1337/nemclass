//! VTable and virtual-method nodes — model half of the vtable dissection view.
//!
//! These are the Rust equivalents of ReClass.NET's `VirtualMethodTableNode`
//! and `VirtualMethodNode`.  The live pointer read + disassembly that
//! ReClass.NET performs inside `Draw()` belongs in the UI layer (which has
//! process access); everything here is pure static formatting from a byte
//! buffer.
//!
//! Memory layout rationale:
//! - `VTableNode` occupies **one pointer** in its parent class — the vptr,
//!   stored inline.  The `VMethodNode` children describe the *pointed-to*
//!   table; they do not add to the parent's size.
//! - `VMethodNode` reports one pointer-sized slot in the vtable array, matching
//!   `BaseFunctionPtrNode.MemorySize = IntPtr.Size` in the C# source.
//!
//! Both widths follow the project's target pointer size, so a 32-bit target's
//! vtable is four bytes per slot rather than the eight this used to hardcode.

use crate::node::builtins::{Attrs, node_def, read_ptr_sized};
use crate::node::{DEFAULT_POINTER_SIZE, Node, RenderedValue};
use crate::node_common_accessors;
use crate::serialize::NodeDef;

fn fallback_rv(type_tag: &'static str, size: usize) -> RenderedValue {
    RenderedValue { value: "<?>".to_string(), type_tag, memory_size: size }
}

// ---------------------------------------------------------------------------
// VTableNode
// ---------------------------------------------------------------------------

/// A virtual-method-table pointer node (Rust port of `VirtualMethodTableNode`).
///
/// This is a **container** node: its `children` are the `VMethodNode`s that
/// describe each slot of the pointed-to vtable.  Like a `PointerNode`, it
/// occupies exactly one pointer in its parent class — the vptr — while the
/// child slots are in the memory *beyond* that pointer.
pub struct VTableNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    /// The vtable-slot nodes (children must all be `VMethodNode`s in practice,
    /// but the trait uses `Box<dyn Node>` for uniformity).
    pub children: Vec<Box<dyn Node>>,
    pointer_size: usize,
}

impl VTableNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            hidden: false,
            children: Vec::new(),
            pointer_size: DEFAULT_POINTER_SIZE,
        }
    }
}

impl Node for VTableNode {
    fn type_tag(&self) -> &'static str { "VTable" }
    node_common_accessors!();

    /// The node itself is one pointer slot in its parent class.
    fn memory_size(&self) -> usize { self.pointer_size }

    fn children(&self) -> &[Box<dyn Node>] { &self.children }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { Some(&mut self.children) }

    fn set_pointer_size(&mut self, size: usize) { self.pointer_size = size; }

    /// Read the vptr at `base_offset` and format it as `-> 0x…` (or
    /// `-> null`).  No live process interaction — the caller provides the
    /// buffer.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr_sized(buf, base_offset, self.pointer_size) else {
            return fallback_rv("VTable", self.pointer_size);
        };
        let value = if v == 0 {
            "-> null".to_string()
        } else {
            format!("-> 0x{v:016X}")
        };
        RenderedValue { value, type_tag: "VTable", memory_size: self.pointer_size }
    }

    /// Serialize to a `NodeDef`.  Children are serialized separately by
    /// `NodeRegistry::serialize_node_recursive` — `to_node_def` only fills
    /// the node's own fields and attrs; the registry appends `nodes`.
    fn to_node_def(&self) -> NodeDef {
        node_def("VTable", &self.name, &self.comment, self.hidden, Attrs::new())
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
    pub hidden: bool,
    pointer_size: usize,
}

impl VMethodNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            hidden: false,
            pointer_size: DEFAULT_POINTER_SIZE,
        }
    }
}

impl Node for VMethodNode {
    fn type_tag(&self) -> &'static str { "VMethod" }
    node_common_accessors!();

    /// Each vtable slot holds one function pointer.
    fn memory_size(&self) -> usize { self.pointer_size }

    fn children(&self) -> &[Box<dyn Node>] { &[] }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { None }

    fn set_pointer_size(&mut self, size: usize) { self.pointer_size = size; }

    /// Read the function pointer at `base_offset` and render as
    /// `{name} -> 0x{addr:016X}`.  When the name is empty the raw address is
    /// shown alone (the UI / symbol layer fills the name in later).
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(v) = read_ptr_sized(buf, base_offset, self.pointer_size) else {
            return fallback_rv("VMethod", self.pointer_size);
        };
        let value = if self.name.is_empty() {
            format!("0x{v:016X}")
        } else {
            format!("{} -> 0x{v:016X}", self.name)
        };
        RenderedValue { value, type_tag: "VMethod", memory_size: self.pointer_size }
    }

    fn to_node_def(&self) -> NodeDef {
        node_def("VMethod", &self.name, &self.comment, self.hidden, Attrs::new())
    }
}
