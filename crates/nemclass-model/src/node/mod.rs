pub mod builtins;
pub mod function;
pub mod registry;
pub mod vtable;

use uuid::Uuid;

use crate::serialize::NodeDef;

/// A single rendered value from a node, with metadata.
#[derive(Debug, Clone)]
pub struct RenderedValue {
    pub value: String,
    pub type_tag: &'static str,
    pub memory_size: usize,
}

/// Object-safe node trait — the Rust equivalent of ReClass.NET's BaseNode.
pub trait Node: Send + Sync {
    fn type_tag(&self) -> &'static str;
    fn name(&self) -> &str;
    fn set_name(&mut self, name: String);
    fn comment(&self) -> &str;
    fn set_comment(&mut self, comment: String);
    /// Size of this node in bytes.
    fn memory_size(&self) -> usize;
    /// Direct children (empty for leaf nodes).
    fn children(&self) -> &[Box<dyn Node>];
    /// Mutable child list for container nodes; `None` for leaf nodes (which
    /// have no children to mutate).
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>>;
    /// Pure value render from an in-memory byte buffer (no live process needed).
    /// `base_offset` is the byte offset within `buf` where this node starts.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue;
    /// Serialize this node to a `NodeDef` intermediate. Children must be serialized
    /// separately by the registry (via `serialize_children`).
    fn to_node_def(&self) -> NodeDef;

    /// For pointer-to-class nodes, the UUID of the class the pointer targets;
    /// `None` for every other node type. Lets the UI offer a "follow pointer →
    /// open target class" action without downcasting.
    fn pointer_target_class(&self) -> Option<Uuid> {
        None
    }

    /// For pointer-to-class nodes, set the target class UUID and return `true`.
    /// The default returns `false` (not a pointer node), so callers such as the
    /// scripting host can point a Pointer node at a class without downcasting.
    fn set_pointer_target(&mut self, _target: Uuid) -> bool {
        false
    }
}
