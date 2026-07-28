use uuid::Uuid;

use crate::address::{MemoryReader, ModuleResolver, resolve_formula};
use crate::class::ClassNode;
use crate::enums::EnumDescription;
use crate::node::builtins::*;
use crate::node::function::{FunctionNode, FunctionPtrNode};
use crate::node::vtable::{VMethodNode, VTableNode};
use crate::node::Node;
use crate::project::Project;
use crate::NodeRegistry;

// ---------------------------------------------------------------------------
// memory_size() for each built-in leaf type
// ---------------------------------------------------------------------------

#[test]
fn leaf_memory_sizes() {
    assert_eq!(Int8Node::new("").memory_size(), 1);
    assert_eq!(Int16Node::new("").memory_size(), 2);
    assert_eq!(Int32Node::new("").memory_size(), 4);
    assert_eq!(Int64Node::new("").memory_size(), 8);
    assert_eq!(UInt8Node::new("").memory_size(), 1);
    assert_eq!(UInt16Node::new("").memory_size(), 2);
    assert_eq!(UInt32Node::new("").memory_size(), 4);
    assert_eq!(UInt64Node::new("").memory_size(), 8);
    assert_eq!(Float32Node::new("").memory_size(), 4);
    assert_eq!(Float64Node::new("").memory_size(), 8);
    assert_eq!(BoolNode::new("").memory_size(), 1);
    assert_eq!(Hex8Node::new("").memory_size(), 1);
    assert_eq!(Hex16Node::new("").memory_size(), 2);
    assert_eq!(Hex32Node::new("").memory_size(), 4);
    assert_eq!(Hex64Node::new("").memory_size(), 8);
    assert_eq!(PointerNode::new("").memory_size(), 8);
    assert_eq!(ClassInstanceNode::new("", Uuid::nil()).memory_size(), 0);
    assert_eq!(ArrayNode::new("", 10, 4).memory_size(), 40);
    assert_eq!(Utf8TextNode::new("", 32).memory_size(), 32);
    assert_eq!(Utf16TextNode::new("", 64).memory_size(), 64);
}

// ---------------------------------------------------------------------------
// Container size == sum of children
// ---------------------------------------------------------------------------

#[test]
fn container_size_equals_children_sum() {
    let mut class = ClassNode::new("Test");
    class.children.push(Box::new(Int32Node::new("a")));  // 4
    class.children.push(Box::new(Float64Node::new("b"))); // 8
    class.children.push(Box::new(UInt8Node::new("c")));   // 1
    assert_eq!(class.memory_size(), 13);
}

// ---------------------------------------------------------------------------
// render() for various types from in-memory buffers
// ---------------------------------------------------------------------------

#[test]
fn render_int32() {
    let val: i32 = -42;
    let buf = val.to_le_bytes();
    let r = Int32Node::new("x").render(&buf, 0);
    assert_eq!(r.value, "-42");
    assert_eq!(r.type_tag, "Int32");
    assert_eq!(r.memory_size, 4);
}

#[test]
fn render_uint8() {
    let buf = [255u8];
    let r = UInt8Node::new("x").render(&buf, 0);
    assert_eq!(r.value, "255");
}

#[test]
fn render_float32() {
    let val: f32 = 1.25;
    let buf = val.to_le_bytes();
    let r = Float32Node::new("x").render(&buf, 0);
    assert!(r.value.starts_with("1.25"), "got: {}", r.value);
}

#[test]
fn render_float64() {
    let val: f64 = 9.75;
    let buf = val.to_le_bytes();
    let r = Float64Node::new("x").render(&buf, 0);
    assert!(r.value.starts_with("9.75"), "got: {}", r.value);
}

#[test]
fn render_bool_true_false() {
    assert_eq!(BoolNode::new("").render(&[1u8], 0).value, "true");
    assert_eq!(BoolNode::new("").render(&[0u8], 0).value, "false");
}

#[test]
fn render_hex32() {
    let val: u32 = 0xDEADBEEF;
    let buf = val.to_le_bytes();
    let r = Hex32Node::new("x").render(&buf, 0);
    assert_eq!(r.value, "0xDEADBEEF");
}

#[test]
fn render_utf8_text() {
    let mut buf = b"hello\0world".to_vec();
    buf.resize(32, 0);
    let r = Utf8TextNode::new("x", 32).render(&buf, 0);
    assert_eq!(r.value, "\"hello\"");
}

#[test]
fn render_utf16_text() {
    // "Hi" in UTF-16LE
    let buf: Vec<u8> = "Hi\0".encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut padded = buf.clone();
    padded.resize(16, 0);
    let r = Utf16TextNode::new("x", 16).render(&padded, 0);
    assert_eq!(r.value, "\"Hi\"");
}

#[test]
fn strptr_is_eight_byte_pointer() {
    let n = StrPtrNode::new("s");
    assert_eq!(n.memory_size(), 8);
    assert_eq!(n.type_tag(), "StrPtr");
    // render surfaces the raw pointer value; the UI dereferences it live.
    let buf = 0x1234_5678_9ABC_DEF0u64.to_le_bytes();
    assert_eq!(n.render(&buf, 0).value, "0x123456789ABCDEF0");
}

#[test]
fn strptr_round_trips_through_registry() {
    let reg = NodeRegistry::new().with_builtins();
    let mut n = StrPtrNode::new("name_ptr");
    n.comment = "points at a C string".into();
    let def = n.to_node_def();
    let back = reg.deserialize_node(def).expect("StrPtr registered");
    assert_eq!(back.type_tag(), "StrPtr");
    assert_eq!(back.name(), "name_ptr");
    assert_eq!(back.comment(), "points at a C string");
    assert_eq!(back.memory_size(), 8);
}

#[test]
fn render_buffer_underrun_returns_placeholder() {
    // buf too small — should return "<?>"
    let r = Int32Node::new("x").render(&[0u8, 1u8], 0);
    assert_eq!(r.value, "<?>");
}

#[test]
fn render_at_nonzero_offset() {
    // two i32s back-to-back; read the second one
    let a: i32 = 100;
    let b: i32 = 200;
    let mut buf = a.to_le_bytes().to_vec();
    buf.extend_from_slice(&b.to_le_bytes());
    let r = Int32Node::new("x").render(&buf, 4);
    assert_eq!(r.value, "200");
}

// ---------------------------------------------------------------------------
// Address formula parser tests
// ---------------------------------------------------------------------------

struct MockReader {
    memory: std::collections::HashMap<usize, usize>,
}

impl MemoryReader for MockReader {
    fn read_usize(&self, addr: usize) -> crate::error::Result<usize> {
        self.memory.get(&addr).copied().ok_or_else(||
            crate::error::ModelError::ResolveError(format!("no mock value at 0x{addr:x}"))
        )
    }
}

struct MockModules {
    modules: Vec<(String, usize)>,
}

impl ModuleResolver for MockModules {
    fn resolve_module(&self, name: &str) -> Option<usize> {
        self.modules.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, base)| *base)
    }
}

fn make_reader(pairs: &[(usize, usize)]) -> MockReader {
    MockReader { memory: pairs.iter().cloned().collect() }
}

fn make_modules(pairs: &[(&str, usize)]) -> MockModules {
    MockModules { modules: pairs.iter().map(|(n, b)| (n.to_string(), *b)).collect() }
}

#[test]
fn parse_module_plus_offset() {
    let mods = make_modules(&[("game.exe", 0x400000)]);
    let reader = make_reader(&[]);
    let result = resolve_formula("<game.exe>+0x10", &mods, &reader).unwrap();
    assert_eq!(result, 0x400010);
}

#[test]
fn parse_quoted_module_plus_offset() {
    let mods = make_modules(&[("game.exe", 0x400000)]);
    let reader = make_reader(&[]);
    let result = resolve_formula("\"game.exe\"+0x10", &mods, &reader).unwrap();
    assert_eq!(result, 0x400010);
}

#[test]
fn parse_precedence_mul_before_add() {
    // 0x100 + 0x20 * 2 == 0x100 + 0x40 == 0x140
    let mods = make_modules(&[]);
    let reader = make_reader(&[]);
    let result = resolve_formula("0x100 + 0x20 * 2", &mods, &reader).unwrap();
    assert_eq!(result, 0x100 + 0x40);
}

#[test]
fn parse_parens_override_precedence() {
    // (0x100 + 0x20) * 2 == 0x120 * 2 == 0x240
    let mods = make_modules(&[]);
    let reader = make_reader(&[]);
    let result = resolve_formula("(0x100 + 0x20) * 2", &mods, &reader).unwrap();
    assert_eq!(result, 0x240);
}

#[test]
fn parse_deref_chain() {
    // [0x1000]+0x8: read pointer at 0x1000, then add 0x8
    let reader = make_reader(&[(0x1000, 0x5000)]);
    let mods = make_modules(&[]);
    let result = resolve_formula("[0x1000]+0x8", &mods, &reader).unwrap();
    assert_eq!(result, 0x5008);
}

#[test]
fn parse_nested_deref() {
    // [[0x1000]+0x8]: pointer at 0x1000 = 0x5000, pointer at 0x5008 = 0xBEEF
    let reader = make_reader(&[(0x1000, 0x5000), (0x5008, 0xBEEF)]);
    let mods = make_modules(&[]);
    let result = resolve_formula("[[0x1000]+0x8]", &mods, &reader).unwrap();
    assert_eq!(result, 0xBEEF);
}

#[test]
fn parse_modulo() {
    let mods = make_modules(&[]);
    let reader = make_reader(&[]);
    let result = resolve_formula("10 % 3", &mods, &reader).unwrap();
    assert_eq!(result, 1);
}

#[test]
fn parse_negate() {
    // 0x100 + -0x10 == 0xF0 (wrapping)
    let mods = make_modules(&[]);
    let reader = make_reader(&[]);
    let result = resolve_formula("0x100 + -0x10", &mods, &reader).unwrap();
    assert_eq!(result, 0xF0usize);
}

// ---------------------------------------------------------------------------
// TOML round-trip
// ---------------------------------------------------------------------------

fn make_test_project() -> (Project, NodeRegistry) {
    let registry = NodeRegistry::new().with_builtins();

    let mut project = Project::new("TestProject");

    // Enum
    let mut e = EnumDescription::new("Direction");
    e.size = 4;
    e.use_flags = false;
    e.values = vec![
        ("North".to_string(), 0),
        ("South".to_string(), 1),
        ("East".to_string(), 2),
        ("West".to_string(), 3),
    ];
    project.enums.push(e);

    // Inner class
    let inner_uuid = Uuid::new_v4();
    let mut inner = ClassNode::with_uuid(inner_uuid, "Vec3");
    inner.address_formula = String::new();
    inner.children.push(Box::new(Float32Node::new("x")));
    inner.children.push(Box::new(Float32Node::new("y")));
    inner.children.push(Box::new(Float32Node::new("z")));
    project.add_class(inner);

    // Outer class referencing inner via ClassInstance
    let outer_uuid = Uuid::new_v4();
    let mut outer = ClassNode::with_uuid(outer_uuid, "Player");
    outer.address_formula = "<game.exe>+0x100".to_string();
    outer.comment = "main player struct".to_string();

    let mut hp = Int32Node::new("health");
    hp.comment = "player HP".to_string();
    outer.children.push(Box::new(hp));

    let mut pos = ClassInstanceNode::new("position", inner_uuid);
    pos.comment = "world position".to_string();
    outer.children.push(Box::new(pos));

    let mut name_field = Utf8TextNode::new("name", 64);
    name_field.comment = "player name".to_string();
    outer.children.push(Box::new(name_field));

    let mut arr = ArrayNode::new("inventory", 20, 4);
    arr.comment = "item IDs".to_string();
    outer.children.push(Box::new(arr));

    let mut ptr = PointerNode::new("next_player");
    ptr.target_class_uuid = Some(outer_uuid);
    outer.children.push(Box::new(ptr));

    project.add_class(outer);

    (project, registry)
}

#[test]
fn toml_round_trip_lossless() {
    let (project, registry) = make_test_project();

    let toml_str = project.to_toml(&registry).expect("serialization failed");

    // Sanity check the TOML contains expected keys
    assert!(toml_str.contains("[project]"), "missing [project]: {toml_str}");
    assert!(toml_str.contains("name = \"TestProject\""), "missing project name");
    assert!(toml_str.contains("name = \"Player\""), "missing Player class");
    assert!(toml_str.contains("type = \"Int32\""), "missing Int32 node");
    assert!(toml_str.contains("type = \"ClassInstance\""), "missing ClassInstance node");

    let project2 = Project::from_toml(&toml_str, &registry).expect("deserialization failed");

    // Project metadata
    assert_eq!(project2.name, "TestProject");

    // Enums
    assert_eq!(project2.enums.len(), 1);
    assert_eq!(project2.enums[0].name, "Direction");
    assert_eq!(project2.enums[0].values.len(), 4);
    assert_eq!(project2.enums[0].values[0], ("North".to_string(), 0));

    // Classes
    let classes: Vec<&ClassNode> = project2.classes_in_order().collect();
    assert_eq!(classes.len(), 2, "expected 2 classes");

    let vec3 = classes.iter().find(|c| c.name == "Vec3").expect("Vec3 not found");
    assert_eq!(vec3.children.len(), 3);
    assert_eq!(vec3.children[0].type_tag(), "Float");
    assert_eq!(vec3.children[0].name(), "x");
    assert_eq!(vec3.memory_size(), 12);

    let player = classes.iter().find(|c| c.name == "Player").expect("Player not found");
    assert_eq!(player.address_formula, "<game.exe>+0x100");
    assert_eq!(player.comment, "main player struct");
    assert_eq!(player.children.len(), 5);

    // child[0]: Int32 health
    assert_eq!(player.children[0].type_tag(), "Int32");
    assert_eq!(player.children[0].name(), "health");
    assert_eq!(player.children[0].comment(), "player HP");

    // child[1]: ClassInstance position
    assert_eq!(player.children[1].type_tag(), "ClassInstance");
    assert_eq!(player.children[1].name(), "position");

    // child[2]: Utf8Text name (length preserved)
    assert_eq!(player.children[2].type_tag(), "Utf8Text");
    assert_eq!(player.children[2].memory_size(), 64);

    // child[3]: Array inventory (count + element_size preserved)
    assert_eq!(player.children[3].type_tag(), "Array");
    assert_eq!(player.children[3].memory_size(), 80); // 20 * 4

    // child[4]: Pointer next_player
    assert_eq!(player.children[4].type_tag(), "Pointer");
    assert_eq!(player.children[4].memory_size(), 8);
}

#[test]
fn remove_referenced_class_returns_error() {
    let mut project = Project::new("P");
    let inner_uuid = Uuid::new_v4();
    let inner = ClassNode::with_uuid(inner_uuid, "Inner");
    project.add_class(inner);

    let mut outer = ClassNode::new("Outer");
    outer.children.push(Box::new(ClassInstanceNode::new("field", inner_uuid)));
    project.add_class(outer);

    let result = project.remove_class(&inner_uuid);
    assert!(result.is_err(), "expected ClassReferenced error");
    let err = result.err().unwrap();
    match err {
        crate::error::ModelError::ClassReferenced { ref_count, .. } => {
            assert_eq!(ref_count, 1);
        }
        e => panic!("unexpected error: {e}"),
    }
}

#[test]
fn remove_unreferenced_class_succeeds() {
    let mut project = Project::new("P");
    let uuid = Uuid::new_v4();
    project.add_class(ClassNode::with_uuid(uuid, "Solo"));
    let removed = project.remove_class(&uuid).unwrap();
    assert_eq!(removed.name, "Solo");
    assert!(project.get_class(&uuid).is_none());
}

// ---------------------------------------------------------------------------
// Hardening against malformed / hostile input (review findings M1, M2)
// ---------------------------------------------------------------------------

#[test]
fn array_memory_size_saturates_instead_of_panicking() {
    // count * element_size would overflow usize; saturating_mul clamps (no panic).
    let n = ArrayNode::new("", usize::MAX, 4);
    assert_eq!(n.memory_size(), usize::MAX);
}

#[test]
fn deserialize_rejects_overdeep_tree_instead_of_overflowing() {
    use crate::error::ModelError;
    use crate::serialize::NodeDef;
    use std::collections::BTreeMap;

    // Build a Class-node chain far deeper than MAX_NODE_DEPTH (128), iteratively
    // so the test itself never recurses.
    fn class_def(child: Option<NodeDef>) -> NodeDef {
        NodeDef {
            type_tag: "Class".to_string(),
            name: "n".to_string(),
            comment: String::new(),
            attrs: BTreeMap::new(),
            nodes: child.into_iter().collect(),
        }
    }
    let mut def = class_def(None);
    for _ in 0..300 {
        def = class_def(Some(def));
    }

    let reg = NodeRegistry::new().with_builtins();
    // Note: `matches!` (not `unwrap_err`) — the Ok type `Box<dyn Node>` is not `Debug`.
    let result = reg.deserialize_node(def);
    assert!(
        matches!(result, Err(ModelError::MaxDepthExceeded(_))),
        "expected MaxDepthExceeded"
    );
}

// ---------------------------------------------------------------------------
// M5.4 — VTable / VMethod / Function / FunctionPtr nodes
// ---------------------------------------------------------------------------

// --- memory_size() ---

#[test]
fn vtable_memory_size_is_8() {
    assert_eq!(VTableNode::new("").memory_size(), 8);
}

#[test]
fn vmethod_memory_size_is_8() {
    assert_eq!(VMethodNode::new("").memory_size(), 8);
}

#[test]
fn function_node_memory_size_is_8() {
    assert_eq!(FunctionNode::new("").memory_size(), 8);
}

#[test]
fn function_ptr_node_memory_size_is_8() {
    assert_eq!(FunctionPtrNode::new("").memory_size(), 8);
}

// --- render() from fixture buffer ---

/// Build an 8-byte little-endian buffer from a known u64 address.
fn ptr_buf(addr: u64) -> [u8; 8] {
    addr.to_le_bytes()
}

#[test]
fn vtable_render_nonzero_pointer() {
    let buf = ptr_buf(0x00007FF8_AABB0000);
    let r = VTableNode::new("vtable").render(&buf, 0);
    assert_eq!(r.value, "-> 0x00007FF8AABB0000");
    assert_eq!(r.type_tag, "VTable");
    assert_eq!(r.memory_size, 8);
}

#[test]
fn vtable_render_null_pointer() {
    let buf = ptr_buf(0);
    let r = VTableNode::new("vtable").render(&buf, 0);
    assert_eq!(r.value, "-> null");
}

#[test]
fn vtable_render_underrun_returns_placeholder() {
    // Buffer too small — returns "<?>".
    let r = VTableNode::new("vtable").render(&[0u8; 4], 0);
    assert_eq!(r.value, "<?>");
}

#[test]
fn vmethod_render_named() {
    let buf = ptr_buf(0x0000_7FF8_DEAD_CAFE);
    let mut n = VMethodNode::new("Update");
    n.comment = "called every frame".to_string();
    let r = n.render(&buf, 0);
    assert_eq!(r.value, "Update -> 0x00007FF8DEADCAFE");
    assert_eq!(r.type_tag, "VMethod");
    assert_eq!(r.memory_size, 8);
}

#[test]
fn vmethod_render_unnamed_shows_raw_address() {
    // When name is empty the UI hasn't resolved the symbol yet — show raw addr.
    let buf = ptr_buf(0x0000_1234_5678_9ABC);
    let r = VMethodNode::new("").render(&buf, 0);
    assert_eq!(r.value, "0x000012345678_9ABC".replace('_', ""));
    assert_eq!(r.type_tag, "VMethod");
}

#[test]
fn function_node_render() {
    let buf = ptr_buf(0x0000_7FFE_CAFE_0000);
    let mut n = FunctionNode::new("Update");
    n.signature = "void Update(float dt)".to_string();
    let r = n.render(&buf, 0);
    assert_eq!(r.value, "void Update(float dt) @ 0x00007FFECAFE0000");
    assert_eq!(r.type_tag, "Function");
    assert_eq!(r.memory_size, 8);
}

#[test]
fn function_ptr_node_render() {
    let buf = ptr_buf(0x0000_DEAD_BEEF_0042);
    let r = FunctionPtrNode::new("OnClick").render(&buf, 0);
    assert_eq!(r.value, "0x0000DEADBEEF0042");
    assert_eq!(r.type_tag, "FunctionPtr");
    assert_eq!(r.memory_size, 8);
}

#[test]
fn render_at_nonzero_offset_vtable() {
    // Two pointer-sized values; read the second (offset 8).
    let mut buf = ptr_buf(0x1111_1111_1111_1111).to_vec();
    buf.extend_from_slice(&ptr_buf(0x0000_7FF8_AABB_CCDD));
    let r = VTableNode::new("").render(&buf, 8);
    assert_eq!(r.value, "-> 0x00007FF8AABBCCDD");
}

// --- construct-by-tag ---

#[test]
fn registry_construct_vtable() {
    let reg = NodeRegistry::new().with_builtins();
    let n = reg.construct("VTable").expect("VTable not registered");
    assert_eq!(n.type_tag(), "VTable");
}

#[test]
fn registry_construct_vmethod() {
    let reg = NodeRegistry::new().with_builtins();
    let n = reg.construct("VMethod").expect("VMethod not registered");
    assert_eq!(n.type_tag(), "VMethod");
}

#[test]
fn registry_construct_function() {
    let reg = NodeRegistry::new().with_builtins();
    let n = reg.construct("Function").expect("Function not registered");
    assert_eq!(n.type_tag(), "Function");
}

#[test]
fn registry_construct_function_ptr() {
    let reg = NodeRegistry::new().with_builtins();
    let n = reg.construct("FunctionPtr").expect("FunctionPtr not registered");
    assert_eq!(n.type_tag(), "FunctionPtr");
}

// --- NodeDef round-trip ---

/// Build a `VTableNode` containing 3 named `VMethodNode`s, one `FunctionNode`
/// (with a custom signature), and one `FunctionPtrNode`, then assert that a
/// TOML serialize → deserialize cycle is lossless: type_tags, names, comments,
/// and the `signature` attr all survive.
#[test]
fn vtable_nodedef_round_trip() {
    let reg = NodeRegistry::new().with_builtins();

    // Build the tree.
    let mut vtable = VTableNode::new("vtable_ptr");
    vtable.comment = "main vtable".to_string();

    let mut m0 = VMethodNode::new("Init");
    m0.comment = "slot 0".to_string();
    vtable.children.push(Box::new(m0));

    let mut m1 = VMethodNode::new("Update");
    m1.comment = "slot 1".to_string();
    vtable.children.push(Box::new(m1));

    let mut m2 = VMethodNode::new("Render");
    m2.comment = "slot 2".to_string();
    vtable.children.push(Box::new(m2));

    let mut func = FunctionNode::new("destructor");
    func.comment = "custom dtor".to_string();
    func.signature = "void ~Obj()".to_string();
    vtable.children.push(Box::new(func));

    let mut fptr = FunctionPtrNode::new("callback");
    fptr.comment = "event cb".to_string();
    vtable.children.push(Box::new(fptr));

    // Serialize: registry recursively walks the tree.
    let def = reg.serialize_node_recursive(&vtable);

    // Verify the serialized NodeDef structure before deserialization.
    assert_eq!(def.type_tag, "VTable");
    assert_eq!(def.name, "vtable_ptr");
    assert_eq!(def.comment, "main vtable");
    assert_eq!(def.nodes.len(), 5);

    // VMethod children
    assert_eq!(def.nodes[0].type_tag, "VMethod");
    assert_eq!(def.nodes[0].name, "Init");
    assert_eq!(def.nodes[0].comment, "slot 0");

    assert_eq!(def.nodes[1].type_tag, "VMethod");
    assert_eq!(def.nodes[1].name, "Update");

    assert_eq!(def.nodes[2].type_tag, "VMethod");
    assert_eq!(def.nodes[2].name, "Render");

    // FunctionNode: signature attr must be present.
    assert_eq!(def.nodes[3].type_tag, "Function");
    assert_eq!(def.nodes[3].name, "destructor");
    assert_eq!(
        def.nodes[3].attrs.get("signature"),
        Some(&toml::Value::String("void ~Obj()".to_string())),
    );

    // FunctionPtrNode: no extra attrs.
    assert_eq!(def.nodes[4].type_tag, "FunctionPtr");
    assert_eq!(def.nodes[4].name, "callback");
    assert!(def.nodes[4].attrs.is_empty());

    // Deserialize and verify structural equality.
    let node_box = reg.deserialize_node(def).expect("deserialize failed");

    assert_eq!(node_box.type_tag(), "VTable");
    assert_eq!(node_box.name(), "vtable_ptr");
    assert_eq!(node_box.comment(), "main vtable");
    assert_eq!(node_box.memory_size(), 8);

    let children = node_box.children();
    assert_eq!(children.len(), 5, "VTable must have 5 children after round-trip");

    assert_eq!(children[0].type_tag(), "VMethod");
    assert_eq!(children[0].name(), "Init");
    assert_eq!(children[0].comment(), "slot 0");
    assert_eq!(children[0].memory_size(), 8);

    assert_eq!(children[1].type_tag(), "VMethod");
    assert_eq!(children[1].name(), "Update");
    assert_eq!(children[1].comment(), "slot 1");

    assert_eq!(children[2].type_tag(), "VMethod");
    assert_eq!(children[2].name(), "Render");

    // FunctionNode: check the signature survived (via render as proxy).
    assert_eq!(children[3].type_tag(), "Function");
    assert_eq!(children[3].name(), "destructor");
    assert_eq!(children[3].comment(), "custom dtor");
    let buf = ptr_buf(0x0000_7FFF_1234_5678);
    let r3 = children[3].render(&buf, 0);
    assert!(r3.value.starts_with("void ~Obj()"), "signature lost: {}", r3.value);

    // FunctionPtrNode.
    assert_eq!(children[4].type_tag(), "FunctionPtr");
    assert_eq!(children[4].name(), "callback");
    assert_eq!(children[4].comment(), "event cb");
}

/// TOML-level round-trip: encode via `toml::to_string` → decode via
/// `toml::from_str`, then re-deserialize through the registry.  This exercises
/// the `NodeDef` serde derive end-to-end (including the `#[serde(flatten)]`
/// attrs map and the nested `nodes` array).
#[test]
fn vtable_toml_string_round_trip() {
    use crate::serialize::NodeDef;

    let reg = NodeRegistry::new().with_builtins();

    let mut vtable = VTableNode::new("vptr");
    let mut m = VMethodNode::new("Tick");
    m.comment = "game tick".to_string();
    vtable.children.push(Box::new(m));
    let mut func = FunctionNode::new("init");
    func.signature = "bool Init()".to_string();
    vtable.children.push(Box::new(func));

    let def = reg.serialize_node_recursive(&vtable);

    // Wrap in a table so toml::to_string has a root map.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Wrapper { node: NodeDef }
    let wrapper = Wrapper { node: def };
    let toml_str = toml::to_string(&wrapper).expect("toml serialize failed");

    // The TOML must contain the nested VMethod and Function entries.
    assert!(toml_str.contains("type = \"VTable\""),   "missing VTable: {toml_str}");
    assert!(toml_str.contains("type = \"VMethod\""),  "missing VMethod: {toml_str}");
    assert!(toml_str.contains("type = \"Function\""), "missing Function: {toml_str}");
    assert!(toml_str.contains("signature"),           "missing signature attr: {toml_str}");

    let w2: Wrapper = toml::from_str(&toml_str).expect("toml deserialize failed");
    let node = reg.deserialize_node(w2.node).expect("registry deserialize failed");

    assert_eq!(node.type_tag(), "VTable");
    assert_eq!(node.name(), "vptr");
    let ch = node.children();
    assert_eq!(ch.len(), 2);
    assert_eq!(ch[0].type_tag(), "VMethod");
    assert_eq!(ch[0].name(), "Tick");
    assert_eq!(ch[0].comment(), "game tick");
    assert_eq!(ch[1].type_tag(), "Function");
    // Signature survives: render against a zero buffer (address shows as null ptr).
    let buf = ptr_buf(0xCAFE_BABE_0000_0001);
    let r = ch[1].render(&buf, 0);
    assert!(r.value.starts_with("bool Init()"), "signature lost: {}", r.value);
}

// ---------------------------------------------------------------------------
// Forward compatibility: a node type this build does not know
// ---------------------------------------------------------------------------

/// A project file written by a newer build, or by one with a plugin this build
/// lacks, contains a node type with no registered deserializer. That used to
/// make `from_toml` return `UnknownNodeType`, which `Project::from_toml`
/// propagated with `?` — so one unrecognised node made the whole project
/// unopenable.
const FUTURE_PROJECT: &str = r#"
[project]
name = "FromTheFuture"
version = "1"

[[classes]]
uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
name = "Player"
comment = ""
address_formula = ""

[[classes.nodes]]
type = "Int32"
name = "health"
comment = ""

[[classes.nodes]]
type = "QuantumFloat"
name = "spooky"
comment = "from a newer build"
precision = 42
flavour = "strange"

[[classes.nodes]]
type = "Int32"
name = "mana"
comment = ""
"#;

#[test]
fn an_unknown_node_type_does_not_make_the_project_unopenable() {
    let reg = NodeRegistry::new().with_builtins();
    let project = Project::from_toml(FUTURE_PROJECT, &reg)
        .expect("an unrecognised node type must not fail the whole load");

    let class = project.classes_in_order().next().expect("Player");
    assert_eq!(class.children.len(), 3, "no node may be dropped");
    assert_eq!(class.children[0].name(), "health");
    assert_eq!(class.children[1].name(), "spooky");
    assert_eq!(class.children[2].name(), "mana");
    assert_eq!(class.children[1].type_tag(), "Unknown");
}

#[test]
fn an_unknown_node_round_trips_byte_for_byte() {
    // Opening and re-saving in an older build must not strip the fields it did
    // not understand.
    let reg = NodeRegistry::new().with_builtins();
    let project = Project::from_toml(FUTURE_PROJECT, &reg).unwrap();
    let saved = project.to_toml(&reg).unwrap();

    assert!(saved.contains("QuantumFloat"), "original type tag lost:\n{saved}");
    assert!(saved.contains("precision"), "unknown attribute lost:\n{saved}");
    assert!(saved.contains("flavour"), "unknown attribute lost:\n{saved}");
    assert!(saved.contains("from a newer build"), "comment lost:\n{saved}");

    // And it survives a second trip unchanged.
    let reloaded = Project::from_toml(&saved, &reg).unwrap();
    assert_eq!(reloaded.to_toml(&reg).unwrap(), saved);
}

#[test]
fn a_duplicate_class_uuid_is_an_error_not_a_silent_loss() {
    // `add_class` overwrites on a UUID collision and does not push to
    // `class_order`, so the file used to load with a class simply missing.
    let reg = NodeRegistry::new().with_builtins();
    let dup = r#"
[project]
name = "Dup"
version = "1"

[[classes]]
uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
name = "First"
comment = ""
address_formula = ""

[[classes]]
uuid = "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
name = "Second"
comment = ""
address_formula = ""
"#;
    let Err(err) = Project::from_toml(dup, &reg) else {
        panic!("a duplicate uuid must be reported");
    };
    let msg = err.to_string();
    assert!(msg.contains("duplicate class uuid"), "unhelpful error: {msg}");
}

#[test]
fn a_newer_schema_version_is_refused_rather_than_half_loaded() {
    let reg = NodeRegistry::new().with_builtins();
    let future = FUTURE_PROJECT.replace(r#"version = "1""#, r#"version = "99""#);
    let Err(err) = Project::from_toml(&future, &reg) else {
        panic!("a newer schema must be refused");
    };
    assert!(err.to_string().contains("newer than this build"), "{err}");
}
