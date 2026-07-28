//! `UnionNode` — overlapping children, all at offset 0.
//!
//! Port of ReClass.NET's `UnionNode`. The one thing that makes a union unlike
//! every other container in this model: its children do **not** accumulate
//! offsets. Each starts at the union's own address, and the union is as wide as
//! its widest member.

use crate::node::builtins::{Attrs, node_def};
use crate::node::{Node, RenderedValue};
use crate::node_common_accessors;
use crate::serialize::NodeDef;

pub struct UnionNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    pub children: Vec<Box<dyn Node>>,
}

impl UnionNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), comment: String::new(), hidden: false, children: Vec::new() }
    }
}

impl Node for UnionNode {
    fn type_tag(&self) -> &'static str {
        "Union"
    }
    node_common_accessors!();

    /// The widest member, not the sum — `max`, where every other container sums.
    ///
    /// Note this is the *unresolved* width: a union whose members include a
    /// `ClassInstance` needs a `Project` to measure, which
    /// [`resolved_node_size`](crate::codegen::resolved_node_size) supplies.
    fn memory_size(&self) -> usize {
        self.children.iter().map(|n| n.memory_size()).max().unwrap_or(0)
    }

    fn children(&self) -> &[Box<dyn Node>] {
        &self.children
    }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> {
        Some(&mut self.children)
    }

    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        RenderedValue {
            value: format!("union [{} members]", self.children.len()),
            type_tag: "Union",
            memory_size: self.memory_size(),
        }
    }

    fn to_node_def(&self) -> NodeDef {
        node_def("Union", &self.name, &self.comment, self.hidden, Attrs::new())
    }
}
