use std::collections::HashMap;

use crate::codegen::Language;
use crate::error::{ModelError, Result};
use crate::node::Node;
use crate::serialize::NodeDef;

/// Builds a fresh node of one registered type.
///
/// A boxed closure rather than a bare `fn` pointer: a plugin that wants to
/// register, say, a `Vector<N>` family has to *capture* N, and a `fn` cannot
/// close over anything. The old signature forced plugins into one free function
/// per shape — which is exactly why the built-in vector and matrix tags below
/// were twelve near-identical macro expansions.
pub type NodeConstructor = Box<dyn Fn() -> Box<dyn Node> + Send + Sync>;

/// Rebuilds a node of one registered type from its serialized form.
pub type NodeDeserializer =
    Box<dyn Fn(NodeDef, &NodeRegistry) -> Result<Box<dyn Node>> + Send + Sync>;

/// How a node type spells itself as a field in generated source.
///
/// Returned by a [`CodegenHook`]. Without one, an unrecognised type generates as
/// an anonymous byte blob of the right width — correct layout, useless names.
#[derive(Debug, Clone)]
pub struct CustomFieldType {
    /// The type as written in the target language, e.g. `MyVec3` or `uint32_t`.
    pub type_name: String,
    /// When `Some(n)`, emit the field as an `n`-element array of `type_name`.
    pub array_len: Option<usize>,
}

/// Per-language spelling for a registered node type.
pub type CodegenHook =
    Box<dyn Fn(&NodeDef, Language) -> Option<CustomFieldType> + Send + Sync>;

struct NodeTypeInfo {
    ctor: NodeConstructor,
    de: NodeDeserializer,
    codegen: Option<CodegenHook>,
}

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

/// Apply the fields every node carries, however it was constructed.
///
/// Deserializers used to set `comment` by hand and nothing set `hidden` at all,
/// so each new common field meant editing thirty call sites and missing some.
pub fn apply_common(node: &mut dyn Node, def: &NodeDef) {
    node.set_comment(def.comment.clone());
    if def.attrs.get("hidden").and_then(|v| v.as_bool()).unwrap_or(false) {
        node.set_hidden(true);
    }
}

/// Read an integer attribute, or `default` if it is missing or the wrong shape.
pub fn attr_usize(def: &NodeDef, key: &str, default: usize) -> usize {
    def.attrs
        .get(key)
        .and_then(|v| v.as_integer())
        .and_then(|i| usize::try_from(i).ok())
        .unwrap_or(default)
}

/// Read a string attribute, or `""` if it is missing or the wrong shape.
pub fn attr_str<'a>(def: &'a NodeDef, key: &str) -> &'a str {
    def.attrs.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

pub struct NodeRegistry {
    entries: HashMap<String, NodeTypeInfo>,
    /// Registration order, so a type menu built from the registry is stable
    /// rather than following `HashMap` iteration.
    order: Vec<String>,
}

impl Default for NodeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeRegistry {
    pub fn new() -> Self {
        Self { entries: HashMap::new(), order: Vec::new() }
    }

    /// Register a node type.
    ///
    /// `tag` is owned: a plugin that computes its tag at load time used to have
    /// to `Box::leak` the string to satisfy `&'static str`, leaking once per
    /// registered type for the life of the process.
    pub fn register(
        &mut self,
        tag: impl Into<String>,
        ctor: impl Fn() -> Box<dyn Node> + Send + Sync + 'static,
        de: impl Fn(NodeDef, &NodeRegistry) -> Result<Box<dyn Node>> + Send + Sync + 'static,
    ) {
        let tag = tag.into();
        if !self.entries.contains_key(&tag) {
            self.order.push(tag.clone());
        }
        self.entries.insert(
            tag,
            NodeTypeInfo { ctor: Box::new(ctor), de: Box::new(de), codegen: None },
        );
    }

    /// Teach the code generators how to spell an already-registered type.
    ///
    /// Returns `false` if `tag` is not registered — registering a spelling for a
    /// type that cannot be constructed is a caller bug, not something to store.
    pub fn register_codegen(
        &mut self,
        tag: &str,
        hook: impl Fn(&NodeDef, Language) -> Option<CustomFieldType> + Send + Sync + 'static,
    ) -> bool {
        match self.entries.get_mut(tag) {
            Some(info) => {
                info.codegen = Some(Box::new(hook));
                true
            }
            None => false,
        }
    }

    /// The generated-source spelling for `def`'s type in `language`, if the type
    /// registered one.
    pub fn codegen_field(&self, def: &NodeDef, language: Language) -> Option<CustomFieldType> {
        self.entries
            .get(def.type_tag.as_str())
            .and_then(|info| info.codegen.as_ref())
            .and_then(|hook| hook(def, language))
    }

    pub fn construct(&self, tag: &str) -> Option<Box<dyn Node>> {
        self.entries.get(tag).map(|info| (info.ctor)())
    }

    /// The byte width a freshly constructed `tag` reports, if it is registered.
    ///
    /// Used by typed [`ArrayNode`](crate::node::builtins::ArrayNode)s, which
    /// store their element width rather than looking it up on every size query.
    pub fn element_size(&self, tag: &str) -> Option<usize> {
        self.construct(tag).map(|n| n.memory_size())
    }

    pub fn is_registered(&self, tag: &str) -> bool {
        self.entries.contains_key(tag)
    }

    /// Every registered tag, in registration order.
    pub fn tags(&self) -> impl Iterator<Item = &str> {
        self.order.iter().map(String::as_str)
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
        match self.entries.get(def.type_tag.as_str()) {
            Some(info) => (info.de)(def, self),
            // Deliberately not an error. This propagated out of
            // `Project::from_toml` with `?`, so one node written by a newer
            // build — or by a build with a plugin this one lacks — made the
            // whole project file unopenable. Keep the definition verbatim
            // instead, so it renders as a placeholder and is written back
            // unchanged on save rather than silently stripped.
            None => Ok(Box::new(crate::node::unknown::UnknownNode::new(def))),
        }
    }

    /// Register all built-in node types.
    pub fn with_builtins(mut self) -> Self {
        register_builtins(&mut self);
        self
    }
}

fn register_builtins(reg: &mut NodeRegistry) {
    use crate::class::ClassNode;
    use crate::node::bitfield::BitFieldNode;
    use crate::node::builtins::*;
    use crate::node::enum_node::EnumNode;
    use crate::node::function::{FunctionNode, FunctionPtrNode};
    use crate::node::union::UnionNode;
    use crate::node::vector::{MATRIX_SHAPES, MatrixNode, VECTOR_SHAPES, VectorNode};
    use crate::node::vtable::{VMethodNode, VTableNode};
    use uuid::Uuid;

    /// Leaf types whose whole definition is name + comment + hidden.
    macro_rules! reg_simple {
        ($tag:literal, $ty:ty) => {{
            reg.register(
                $tag,
                || Box::new(<$ty>::new("")),
                |def, _reg| {
                    let mut n = <$ty>::new(def.name.clone());
                    apply_common(&mut n, &def);
                    Ok(Box::new(n))
                },
            );
        }};
    }

    reg_simple!("Int8", Int8Node);
    reg_simple!("Int16", Int16Node);
    reg_simple!("Int32", Int32Node);
    reg_simple!("Int64", Int64Node);
    reg_simple!("UInt8", UInt8Node);
    reg_simple!("UInt16", UInt16Node);
    reg_simple!("UInt32", UInt32Node);
    reg_simple!("UInt64", UInt64Node);
    reg_simple!("NInt", NIntNode);
    reg_simple!("NUInt", NUIntNode);
    reg_simple!("Float", Float32Node);
    reg_simple!("Double", Float64Node);
    reg_simple!("Bool", BoolNode);
    reg_simple!("Hex8", Hex8Node);
    reg_simple!("Hex16", Hex16Node);
    reg_simple!("Hex32", Hex32Node);
    reg_simple!("Hex64", Hex64Node);
    reg_simple!("FunctionPtr", FunctionPtrNode);
    reg_simple!("VMethod", VMethodNode);
    // `StrPtr` predates the ReClass-aligned names but appears in projects
    // already on disk, so the tag stays.
    reg_simple!("StrPtr", StrPtrNode);
    reg_simple!("Utf8TextPtr", Utf8TextPtrNode);
    reg_simple!("Utf16TextPtr", Utf16TextPtrNode);
    reg_simple!("Utf32TextPtr", Utf32TextPtrNode);

    // PointerNode
    reg.register(
        "Pointer",
        || Box::new(PointerNode::new("")),
        |def, _reg| {
            let mut n = PointerNode::new(def.name.clone());
            apply_common(&mut n, &def);
            n.target_class_uuid = attr_str(&def, "target_class_uuid").parse::<Uuid>().ok();
            Ok(Box::new(n))
        },
    );

    // ClassInstanceNode
    reg.register(
        "ClassInstance",
        || Box::new(ClassInstanceNode::new("", Uuid::nil())),
        |def, _reg| {
            let class_uuid = attr_str(&def, "class_uuid").parse::<Uuid>().unwrap_or(Uuid::nil());
            let mut n = ClassInstanceNode::new(def.name.clone(), class_uuid);
            apply_common(&mut n, &def);
            Ok(Box::new(n))
        },
    );

    // ClassInstanceArrayNode
    reg.register(
        "ClassInstanceArray",
        || Box::new(ClassInstanceArrayNode::new("", Uuid::nil(), 0)),
        |def, _reg| {
            let class_uuid = attr_str(&def, "class_uuid").parse::<Uuid>().unwrap_or(Uuid::nil());
            let count = attr_usize(&def, "count", 0);
            let mut n = ClassInstanceArrayNode::new(def.name.clone(), class_uuid, count);
            apply_common(&mut n, &def);
            Ok(Box::new(n))
        },
    );

    // ArrayNode — `element_type` is optional; without it the array is the
    // historical untyped byte blob.
    reg.register(
        "Array",
        || Box::new(ArrayNode::new("", 0, 1)),
        |def, _reg| {
            let count = attr_usize(&def, "count", 0);
            let element_size = attr_usize(&def, "element_size", 1);
            let mut n = ArrayNode::new(def.name.clone(), count, element_size);
            let element_tag = attr_str(&def, "element_type");
            if !element_tag.is_empty() {
                n.set_element_type(element_tag, element_size);
            }
            apply_common(&mut n, &def);
            Ok(Box::new(n))
        },
    );

    // Fixed-length inline text.
    macro_rules! reg_text {
        ($tag:literal, $ty:ty) => {{
            reg.register(
                $tag,
                || Box::new(<$ty>::new("", 64)),
                |def, _reg| {
                    let length = attr_usize(&def, "length", 64);
                    let mut n = <$ty>::new(def.name.clone(), length);
                    apply_common(&mut n, &def);
                    Ok(Box::new(n))
                },
            );
        }};
    }

    reg_text!("Utf8Text", Utf8TextNode);
    reg_text!("Utf16Text", Utf16TextNode);
    reg_text!("Utf32Text", Utf32TextNode);

    // BitFieldNode
    reg.register(
        "BitField",
        || Box::new(BitFieldNode::new("")),
        |def, _reg| {
            let mut n = BitFieldNode::new(def.name.clone());
            n.set_bits(attr_usize(&def, "bits", crate::node::DEFAULT_POINTER_SIZE * 8));
            apply_common(&mut n, &def);
            Ok(Box::new(n))
        },
    );

    // EnumNode — the value table is bound later by `Project::bind_enums`, which
    // is the only place that can see the project's enum list.
    reg.register(
        "Enum",
        || Box::new(EnumNode::new("")),
        |def, _reg| {
            let mut n = EnumNode::new(def.name.clone());
            n.enum_name = attr_str(&def, "enum_name").to_string();
            apply_common(&mut n, &def);
            Ok(Box::new(n))
        },
    );

    // UnionNode (container) — recursive via registry.
    reg.register(
        "Union",
        || Box::new(UnionNode::new("")),
        |def, reg| {
            let mut n = UnionNode::new(def.name.clone());
            apply_common(&mut n, &def);
            for child_def in def.nodes {
                n.children.push(reg.deserialize_node_inner(child_def)?);
            }
            Ok(Box::new(n))
        },
    );

    // Vector / matrix nodes. The shape lives in the type tag (see
    // `node::vector`). Now that constructors are closures the shape is
    // *captured* rather than macro-expanded, so these are two loops over the
    // shape tables instead of twelve near-identical blocks.
    for (tag, components, width) in VECTOR_SHAPES {
        reg.register(
            tag,
            move || Box::new(VectorNode::new("", components, width)),
            move |def, _reg| {
                let mut n = VectorNode::new(def.name.clone(), components, width);
                apply_common(&mut n, &def);
                Ok(Box::new(n))
            },
        );
    }

    for (tag, rows, cols, width) in MATRIX_SHAPES {
        reg.register(
            tag,
            move || Box::new(MatrixNode::new("", rows, cols, width)),
            move |def, _reg| {
                let mut n = MatrixNode::new(def.name.clone(), rows, cols, width);
                apply_common(&mut n, &def);
                Ok(Box::new(n))
            },
        );
    }

    // VTableNode (container) — recursive via registry; children are VMethodNodes.
    reg.register(
        "VTable",
        || Box::new(VTableNode::new("")),
        |def, reg| {
            let mut n = VTableNode::new(def.name.clone());
            apply_common(&mut n, &def);
            for child_def in def.nodes {
                n.children.push(reg.deserialize_node_inner(child_def)?);
            }
            Ok(Box::new(n))
        },
    );

    // FunctionNode — leaf with an editable `signature` attr.
    reg.register(
        "Function",
        || Box::new(FunctionNode::new("")),
        |def, _reg| {
            let mut n = FunctionNode::new(def.name.clone());
            let signature = attr_str(&def, "signature");
            if !signature.is_empty() {
                n.signature = signature.to_string();
            }
            apply_common(&mut n, &def);
            Ok(Box::new(n))
        },
    );

    // ClassNode (container) — recursive via registry.
    reg.register(
        "Class",
        || Box::new(ClassNode::new("")),
        |def, reg| {
            let uuid_str = attr_str(&def, "uuid");
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
            let mut class = ClassNode::with_uuid(uuid, def.name.clone());
            class.address_formula = attr_str(&def, "address_formula").to_string();
            apply_common(&mut class, &def);
            for child_def in def.nodes {
                // Depth already bounded by the public entry point.
                class.children.push(reg.deserialize_node_inner(child_def)?);
            }
            Ok(Box::new(class))
        },
    );
}
