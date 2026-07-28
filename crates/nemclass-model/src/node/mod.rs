pub mod bitfield;
pub mod builtins;
pub mod enum_node;
pub mod function;
pub mod registry;
pub mod union;
pub mod unknown;
pub mod vector;
pub mod vtable;

use uuid::Uuid;

use crate::serialize::NodeDef;

/// Pointer width, in bytes, assumed by a project whose target architecture has
/// not been told to us.
///
/// Every pointer-shaped node (`Pointer`, `VTable`, `Function`, the text
/// pointers, `NInt`/`NUInt`) used to hardcode 8, which made a 32-bit target's
/// layout literally unrepresentable: every field after the first pointer landed
/// four bytes late. The width now lives on the [`Project`](crate::Project) and
/// is pushed into the nodes by [`Project::set_pointer_size`].
pub const DEFAULT_POINTER_SIZE: usize = 8;

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

    /// Whether the view should collapse this node to a single placeholder row.
    ///
    /// ReClass.NET persists this per node (`IsHidden` in `.rcnet`), so it is
    /// part of the model rather than of any one view's transient state.
    fn hidden(&self) -> bool {
        false
    }

    /// Set the hidden flag. Nodes that cannot be hidden ignore this.
    fn set_hidden(&mut self, _hidden: bool) {}

    /// Adopt the project's pointer width.
    ///
    /// Only pointer-shaped nodes override this; everything else keeps a fixed
    /// size and ignores the call. Containers do **not** need to forward it —
    /// [`Project::set_pointer_size`](crate::Project::set_pointer_size) walks the
    /// whole tree through [`Node::children_mut`].
    fn set_pointer_size(&mut self, _size: usize) {}

    /// For `Enum` nodes, the name of the project enum this field renders
    /// through; `None` for every other node type.
    fn enum_binding(&self) -> Option<&str> {
        None
    }

    /// For `Enum` nodes, refresh the cached width and value table.
    ///
    /// `None` means the description named by [`Node::enum_binding`] is no
    /// longer in the project, so the node should stop claiming to resolve.
    fn bind_enum(&mut self, _desc: Option<&crate::enums::EnumDescription>) {}

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

/// The `name` / `comment` / `hidden` accessors, which every node implements
/// identically over three same-named fields.
///
/// Written out by hand this was six near-identical lines per node type across
/// nine files; the only thing a reader ever checked was that a node had not
/// accidentally omitted one.
#[macro_export]
#[doc(hidden)]
macro_rules! node_common_accessors {
    () => {
        fn name(&self) -> &str {
            &self.name
        }
        fn set_name(&mut self, n: String) {
            self.name = n;
        }
        fn comment(&self) -> &str {
            &self.comment
        }
        fn set_comment(&mut self, c: String) {
            self.comment = c;
        }
        fn hidden(&self) -> bool {
            self.hidden
        }
        fn set_hidden(&mut self, h: bool) {
            self.hidden = h;
        }
    };
}
