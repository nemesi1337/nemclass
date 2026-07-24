use std::collections::HashMap;

use crate::error::{ModelError, Result};
use crate::node::Node;
use crate::serialize::NodeDef;

pub type NodeConstructor = fn() -> Box<dyn Node>;
pub type NodeDeserializer = fn(NodeDef, &NodeRegistry) -> Result<Box<dyn Node>>;

/// Maximum node-tree nesting accepted when deserializing from (untrusted) TOML.
/// Bounds the recursive `deserialize_node_inner` below so a crafted/corrupt
/// project file errors instead of overflowing the stack. (Extremely deep input
/// could still overflow `toml`'s own parser upstream in `Project::from_toml`;
/// this guard covers our own recursion, which was previously unbounded.)
const MAX_NODE_DEPTH: usize = 128;

/// Measures the deepest nesting in `def` iteratively (explicit stack — so the
/// check itself can't overflow) and rejects trees past [`MAX_NODE_DEPTH`].
fn check_node_depth(def: &NodeDef) -> Result<()> {
    let mut stack = vec![(def, 1usize)];
    while let Some((d, depth)) = stack.pop() {
        if depth > MAX_NODE_DEPTH {
            return Err(ModelError::MaxDepthExceeded(MAX_NODE_DEPTH));
        }
        for child in &d.nodes {
            stack.push((child, depth + 1));
        }
    }
    Ok(())
}

pub struct NodeRegistry {
    entries: HashMap<&'static str, (NodeConstructor, NodeDeserializer)>,
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn register(
        &mut self,
        tag: &'static str,
        ctor: NodeConstructor,
        de: NodeDeserializer,
    ) {
        self.entries.insert(tag, (ctor, de));
    }

    pub fn construct(&self, tag: &str) -> Option<Box<dyn Node>> {
        self.entries.get(tag).map(|(ctor, _)| ctor())
    }

    /// Serialize a node to its intermediate NodeDef (delegates to `node.to_node_def()`).
    pub fn serialize_node(&self, node: &dyn Node) -> NodeDef {
        node.to_node_def()
    }

    /// Serialize a node and recursively serialize all children.
    pub fn serialize_node_recursive(&self, node: &dyn Node) -> NodeDef {
        let mut def = node.to_node_def();
        for child in node.children() {
            def.nodes.push(self.serialize_node_recursive(child.as_ref()));
        }
        def
    }

    /// Public entry: bounds the tree depth once (against untrusted input), then
    /// deserializes. Recursive re-entry goes through [`Self::deserialize_node_inner`]
    /// so the depth scan runs a single time, not per subtree.
    pub fn deserialize_node(&self, def: NodeDef) -> Result<Box<dyn Node>> {
        check_node_depth(&def)?;
        self.deserialize_node_inner(def)
    }

    /// Recursive core (depth already bounded by [`Self::deserialize_node`]).
    pub(crate) fn deserialize_node_inner(&self, def: NodeDef) -> Result<Box<dyn Node>> {
        let tag = def.type_tag.clone();
        match self.entries.get(tag.as_str()) {
            Some((_, de)) => de(def, self),
            None => Err(ModelError::UnknownNodeType(tag)),
        }
    }

    /// Register all M1 built-in node types.
    pub fn with_builtins(mut self) -> Self {
        register_builtins(&mut self);
        self
    }
}

fn register_builtins(reg: &mut NodeRegistry) {
    use crate::node::builtins::*;
    use crate::class::ClassNode;
    use toml::Value as TV;
    use uuid::Uuid;

    macro_rules! reg_simple {
        ($tag:literal, $ty:ty) => {{
            fn ctor() -> Box<dyn Node> { Box::new(<$ty>::new("")) }
            fn de(def: NodeDef, _reg: &NodeRegistry) -> Result<Box<dyn Node>> {
                let mut n = <$ty>::new(def.name);
                n.comment = def.comment;
                Ok(Box::new(n))
            }
            reg.register($tag, ctor, de);
        }};
    }

    reg_simple!("Int8",   Int8Node);
    reg_simple!("Int16",  Int16Node);
    reg_simple!("Int32",  Int32Node);
    reg_simple!("Int64",  Int64Node);
    reg_simple!("UInt8",  UInt8Node);
    reg_simple!("UInt16", UInt16Node);
    reg_simple!("UInt32", UInt32Node);
    reg_simple!("UInt64", UInt64Node);
    reg_simple!("Float",  Float32Node);
    reg_simple!("Double", Float64Node);
    reg_simple!("Bool",   BoolNode);
    reg_simple!("Hex8",   Hex8Node);
    reg_simple!("Hex16",  Hex16Node);
    reg_simple!("Hex32",  Hex32Node);
    reg_simple!("Hex64",  Hex64Node);

    // PointerNode
    {
        fn ctor() -> Box<dyn Node> { Box::new(PointerNode::new("")) }
        fn de(def: NodeDef, _reg: &NodeRegistry) -> Result<Box<dyn Node>> {
            let mut n = PointerNode::new(def.name);
            n.comment = def.comment;
            if let Some(TV::String(s)) = def.attrs.get("target_class_uuid") {
                n.target_class_uuid = s.parse::<Uuid>().ok();
            }
            Ok(Box::new(n))
        }
        reg.register("Pointer", ctor, de);
    }

    // ClassInstanceNode
    {
        fn ctor() -> Box<dyn Node> { Box::new(ClassInstanceNode::new("", Uuid::nil())) }
        fn de(def: NodeDef, _reg: &NodeRegistry) -> Result<Box<dyn Node>> {
            let uuid_str = def.attrs.get("class_uuid")
                .and_then(|v| if let TV::String(s) = v { Some(s.as_str()) } else { None })
                .unwrap_or("");
            let class_uuid = uuid_str.parse::<Uuid>().unwrap_or(Uuid::nil());
            let mut n = ClassInstanceNode::new(def.name, class_uuid);
            n.comment = def.comment;
            Ok(Box::new(n))
        }
        reg.register("ClassInstance", ctor, de);
    }

    // ArrayNode
    {
        fn ctor() -> Box<dyn Node> { Box::new(ArrayNode::new("", 0, 1)) }
        fn de(def: NodeDef, _reg: &NodeRegistry) -> Result<Box<dyn Node>> {
            let count = def.attrs.get("count")
                .and_then(|v| if let TV::Integer(i) = v { Some(*i as usize) } else { None })
                .unwrap_or(0);
            let element_size = def.attrs.get("element_size")
                .and_then(|v| if let TV::Integer(i) = v { Some(*i as usize) } else { None })
                .unwrap_or(1);
            let mut n = ArrayNode::new(def.name, count, element_size);
            n.comment = def.comment;
            Ok(Box::new(n))
        }
        reg.register("Array", ctor, de);
    }

    // Utf8TextNode
    {
        fn ctor() -> Box<dyn Node> { Box::new(Utf8TextNode::new("", 64)) }
        fn de(def: NodeDef, _reg: &NodeRegistry) -> Result<Box<dyn Node>> {
            let length = def.attrs.get("length")
                .and_then(|v| if let TV::Integer(i) = v { Some(*i as usize) } else { None })
                .unwrap_or(64);
            let mut n = Utf8TextNode::new(def.name, length);
            n.comment = def.comment;
            Ok(Box::new(n))
        }
        reg.register("Utf8Text", ctor, de);
    }

    // Utf16TextNode
    {
        fn ctor() -> Box<dyn Node> { Box::new(Utf16TextNode::new("", 64)) }
        fn de(def: NodeDef, _reg: &NodeRegistry) -> Result<Box<dyn Node>> {
            let length = def.attrs.get("length")
                .and_then(|v| if let TV::Integer(i) = v { Some(*i as usize) } else { None })
                .unwrap_or(64);
            let mut n = Utf16TextNode::new(def.name, length);
            n.comment = def.comment;
            Ok(Box::new(n))
        }
        reg.register("Utf16Text", ctor, de);
    }

    // ClassNode (container) — recursive via registry
    {
        fn ctor() -> Box<dyn Node> { Box::new(ClassNode::new("")) }
        fn de(def: NodeDef, reg: &NodeRegistry) -> Result<Box<dyn Node>> {
            use uuid::Uuid;
            let uuid_str = def.attrs.get("uuid")
                .and_then(|v| if let TV::String(s) = v { Some(s.as_str()) } else { None })
                .unwrap_or("");
            // Empty = a genuinely new class (mint a fresh id). A PRESENT but
            // malformed uuid is an error, not a silently-minted random identity
            // (which would break cross-class references).
            let uuid = if uuid_str.is_empty() {
                Uuid::new_v4()
            } else {
                uuid_str.parse::<Uuid>().map_err(|e| {
                    ModelError::DeserializeError(format!("bad class node uuid '{uuid_str}': {e}"))
                })?
            };
            let address_formula = def.attrs.get("address_formula")
                .and_then(|v| if let TV::String(s) = v { Some(s.clone()) } else { None })
                .unwrap_or_default();
            let mut class = ClassNode::with_uuid(uuid, def.name);
            class.comment = def.comment;
            class.address_formula = address_formula;
            for child_def in def.nodes {
                // Depth already bounded by the public entry point.
                class.children.push(reg.deserialize_node_inner(child_def)?);
            }
            Ok(Box::new(class))
        }
        reg.register("Class", ctor, de);
    }
}
