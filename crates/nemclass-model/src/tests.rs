use uuid::Uuid;

use crate::address::{MemoryReader, ModuleResolver, resolve_formula};
use crate::class::ClassNode;
use crate::enums::EnumDescription;
use crate::node::builtins::*;
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
    let val: f32 = 3.14;
    let buf = val.to_le_bytes();
    let r = Float32Node::new("x").render(&buf, 0);
    assert!(r.value.starts_with("3.14"), "got: {}", r.value);
}

#[test]
fn render_float64() {
    let val: f64 = 2.718281828;
    let buf = val.to_le_bytes();
    let r = Float64Node::new("x").render(&buf, 0);
    assert!(r.value.starts_with("2.718"), "got: {}", r.value);
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
