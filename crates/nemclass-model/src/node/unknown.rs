//! A placeholder for a node type this build does not know about.
//!
//! A project file can legitimately contain a node type the running binary has
//! no deserializer for: it was written by a newer build, or by a build with a
//! plugin registered that this one lacks. Before [`UnknownNode`], hitting one
//! made [`crate::node::registry::NodeRegistry::deserialize_node`] return
//! `UnknownNodeType`, which `Project::from_toml` propagated with `?` — so a
//! single unrecognised node made the **entire project unopenable**.
//!
//! ReClass.NET does not do that: its reader logs and skips the node, keeping
//! the rest of the project. Skipping still loses data, so nemclass goes one
//! better and keeps the node's serialized form verbatim. The node renders as an
//! explicit placeholder in the UI and writes itself back out byte-for-byte on
//! save, so opening and re-saving a project in an older build no longer strips
//! the fields it did not understand.

use crate::node::{Node, NodeDef, RenderedValue};

/// A node whose `type_tag` had no registered deserializer, holding the original
/// [`NodeDef`] so it can be written back unchanged.
#[derive(Debug, Clone)]
pub struct UnknownNode {
    /// The definition exactly as it was read, including its original
    /// `type_tag`, attributes and children.
    def: NodeDef,
}

impl UnknownNode {
    /// Wrap a definition whose type tag this build does not recognise.
    pub fn new(def: NodeDef) -> Self {
        Self { def }
    }

    /// The `type_tag` from the file — the type this build could not construct.
    ///
    /// [`Node::type_tag`] must return `&'static str` and so reports the
    /// placeholder's own tag; this is the real one, for diagnostics and for the
    /// UI to show the user what they are looking at.
    pub fn original_tag(&self) -> &str {
        &self.def.type_tag
    }
}

impl Node for UnknownNode {
    fn type_tag(&self) -> &'static str {
        "Unknown"
    }

    fn name(&self) -> &str {
        &self.def.name
    }

    fn set_name(&mut self, n: String) {
        self.def.name = n;
    }

    fn comment(&self) -> &str {
        &self.def.comment
    }

    fn set_comment(&mut self, c: String) {
        self.def.comment = c;
    }

    /// Zero: the byte width of an unknown type is, by definition, unknown.
    ///
    /// Fields after it therefore keep the offsets they had in the file rather
    /// than shifting by a guess. The node is a placeholder to be replaced, not a
    /// layout element, and reporting a made-up size would silently move every
    /// subsequent field.
    fn memory_size(&self) -> usize {
        0
    }

    fn children(&self) -> &[Box<dyn Node>] {
        &[]
    }

    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> {
        None
    }

    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        RenderedValue {
            value: format!("<unknown type '{}'>", self.def.type_tag),
            type_tag: "Unknown",
            memory_size: 0,
        }
    }

    /// The original definition, verbatim — this is what makes the round trip
    /// lossless.
    fn to_node_def(&self) -> NodeDef {
        self.def.clone()
    }
}
