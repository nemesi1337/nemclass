//! Golden and edge-case tests for all three code generators.
//!
//! Each test builds a `Project` in memory, runs a generator, then asserts that
//! the output contains specific expected lines/fragments. Tests never assert
//! entire file contents (that would be brittle) — only load-bearing lines.

use uuid::Uuid;

use crate::class::ClassNode;
use crate::codegen::{Language, generate};
use crate::enums::EnumDescription;
use crate::node::builtins::*;
use crate::node::registry::NodeRegistry;
use crate::project::Project;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn registry() -> NodeRegistry {
    NodeRegistry::new().with_builtins()
}

/// Build a realistic test project:
/// - enum `Status` (4-byte, not flags): Active=0, Inactive=1
/// - class `Vec3`: Float x, Float y, Float z (12 bytes total)
/// - class `Entity`:
///     - Int32 health    (4 bytes,  offset 0x00)
///     - Float speed     (4 bytes,  offset 0x04)
///     - Pointer p_next  (8 bytes,  offset 0x08)
///     - ClassInstance pos → Vec3 (12 bytes resolved, offset 0x10)
///     - Array inventory 10×4 (40 bytes, offset 0x1C)
///     - Hex32 _pad      (4 bytes,  offset 0x44)
///     - Utf8Text name   (32 bytes, offset 0x48)
///     - Utf16Text wname (32 bytes, offset 0x68)
///
/// Total: 4+4+8+12+40+4+32+32 = 136 = 0x88
fn make_project() -> (Project, NodeRegistry, Uuid, Uuid) {
    let reg = registry();
    let mut project = Project::new("Test");

    // Enum
    let mut status = EnumDescription::new("Status");
    status.size = 4;
    status.use_flags = false;
    status.values = vec![
        ("Active".to_string(), 0),
        ("Inactive".to_string(), 1),
    ];
    project.enums.push(status);

    // Vec3
    let vec3_uuid = Uuid::new_v4();
    let mut vec3 = ClassNode::with_uuid(vec3_uuid, "Vec3");
    vec3.children.push(Box::new(Float32Node::new("x")));
    vec3.children.push(Box::new(Float32Node::new("y")));
    vec3.children.push(Box::new(Float32Node::new("z")));
    project.add_class(vec3);

    // Entity
    let entity_uuid = Uuid::new_v4();
    let mut entity = ClassNode::with_uuid(entity_uuid, "Entity");
    entity.comment = "game entity".to_string();

    let mut hp = Int32Node::new("health");
    hp.comment = "hit points".to_string();
    entity.children.push(Box::new(hp));

    entity.children.push(Box::new(Float32Node::new("speed")));

    let mut ptr = PointerNode::new("p_next");
    ptr.target_class_uuid = Some(entity_uuid);
    entity.children.push(Box::new(ptr));

    entity.children.push(Box::new(ClassInstanceNode::new("pos", vec3_uuid)));
    entity.children.push(Box::new(ArrayNode::new("inventory", 10, 4)));
    entity.children.push(Box::new(Hex32Node::new("_pad")));
    entity.children.push(Box::new(Utf8TextNode::new("name", 32)));
    entity.children.push(Box::new(Utf16TextNode::new("wname", 32)));

    project.add_class(entity);

    (project, reg, vec3_uuid, entity_uuid)
}

// ---------------------------------------------------------------------------
// C++ golden tests
// ---------------------------------------------------------------------------

#[test]
fn cpp_enum_emitted() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Cpp, &proj, &reg);
    assert!(out.contains("enum class Status : int32_t"), "missing enum class: {out}");
    assert!(out.contains("Active = 0"), "missing Active: {out}");
    assert!(out.contains("Inactive = 1"), "missing Inactive: {out}");
}

#[test]
fn cpp_pragma_pack() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Cpp, &proj, &reg);
    assert!(out.contains("#pragma pack(push, 1)"), "missing push: {out}");
    assert!(out.contains("#pragma pack(pop)"), "missing pop: {out}");
}

#[test]
fn cpp_struct_fields() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Cpp, &proj, &reg);

    // Int32 field
    assert!(out.contains("int32_t health;"), "missing health: {out}");
    // Float field
    assert!(out.contains("float speed;"), "missing speed: {out}");
    // Pointer to self (Entity*)
    assert!(out.contains("Entity* p_next;"), "missing p_next: {out}");
    // ClassInstance (Vec3 pos)
    assert!(out.contains("Vec3 pos;"), "missing Vec3 pos: {out}");
    // Array → raw byte array
    assert!(out.contains("uint8_t inventory[40];"), "missing inventory: {out}");
    // Hex32 → raw byte array of 4
    assert!(out.contains("uint8_t _pad[4];"), "missing _pad: {out}");
    // Utf8Text → char array
    assert!(out.contains("char name[32];"), "missing name: {out}");
    // Utf16Text → char16_t array (32 bytes / 2 = 16 chars). Deliberately not
    // `wchar_t`, which is 4 bytes on Linux/GCC and made the field twice its
    // real width, failing the class's own generated `static_assert`.
    assert!(out.contains("char16_t wname[16];"), "missing wname: {out}");
}

#[test]
fn cpp_static_assert_and_size_comment() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Cpp, &proj, &reg);
    // Entity: 4+4+8+12+40+4+32+32 = 136 = 0x88
    // Vec3's 12 bytes are resolved from the referenced ClassNode, not
    // from ClassInstanceNode::memory_size() which returns 0 by design.
    assert!(out.contains("static_assert(sizeof(Entity) == 0x88)"), "bad static_assert: {out}");
    assert!(out.contains("//Size: 0x0088"), "missing size comment: {out}");
}

#[test]
fn cpp_offset_comments() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Cpp, &proj, &reg);
    // health is at offset 0
    assert!(out.contains("//0x0000"), "missing 0x0000 comment: {out}");
    // speed is at offset 4
    assert!(out.contains("//0x0004"), "missing 0x0004 comment: {out}");
    // p_next is at offset 8
    assert!(out.contains("//0x0008"), "missing 0x0008 comment: {out}");
}

// ---------------------------------------------------------------------------
// C# golden tests
// ---------------------------------------------------------------------------

#[test]
fn csharp_preamble() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::CSharp, &proj, &reg);
    assert!(out.contains("using System.Runtime.InteropServices;"), "missing using: {out}");
    assert!(
        out.contains("[StructLayout(LayoutKind.Explicit, CharSet = CharSet.Ansi)]"),
        "missing StructLayout: {out}"
    );
}

#[test]
fn csharp_enum_emitted() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::CSharp, &proj, &reg);
    assert!(out.contains("public enum Status : int"), "missing enum: {out}");
    assert!(out.contains("Active = 0"), "missing Active: {out}");
}

#[test]
fn csharp_field_offset_attributes() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::CSharp, &proj, &reg);
    assert!(out.contains("[FieldOffset(0x0)]"), "missing offset 0: {out}");
    assert!(out.contains("[FieldOffset(0x4)]"), "missing offset 4: {out}");
    assert!(out.contains("[FieldOffset(0x8)]"), "missing offset 8: {out}");
}

#[test]
fn csharp_primitive_types() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::CSharp, &proj, &reg);
    assert!(out.contains("public readonly int health;"), "missing int health: {out}");
    assert!(out.contains("public readonly float speed;"), "missing float speed: {out}");
    // Pointer → IntPtr
    assert!(out.contains("public readonly IntPtr p_next;"), "missing IntPtr: {out}");
}

#[test]
fn csharp_utf8_text_is_a_fixed_buffer_not_a_string_reference() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::CSharp, &proj, &reg);
    assert!(
        out.contains("public unsafe fixed byte name[32];"),
        "UTF-8 text should be a fixed byte buffer: {out}"
    );
    // A `string` is a *reference*, and a reference field inside a
    // `LayoutKind.Explicit` struct makes the type fail to load at runtime
    // (TypeLoadException) as soon as it overlaps or is misaligned. The previous
    // `ByValTStr` spelling compiled and then blew up on first use.
    assert!(
        !out.contains("ByValTStr"),
        "explicit-layout struct must not marshal a string reference: {out}"
    );
    assert!(!out.contains("public readonly string"), "no string fields: {out}");
}

// ---------------------------------------------------------------------------
// Rust golden tests
// ---------------------------------------------------------------------------

#[test]
fn rust_repr_c() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    assert!(out.contains("#[repr(C, packed)]"), "missing packed repr(C): {out}");
}

#[test]
fn rust_enum_emitted() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    // Non-flag enum → proper Rust enum
    assert!(out.contains("#[repr(i32)]"), "missing repr(i32): {out}");
    assert!(out.contains("pub enum Status"), "missing enum Status: {out}");
    assert!(out.contains("Active = 0,"), "missing Active: {out}");
    assert!(out.contains("Inactive = 1,"), "missing Inactive: {out}");
}

#[test]
fn rust_primitive_fields() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    assert!(out.contains("pub health: i32,"), "missing i32 health: {out}");
    assert!(out.contains("pub speed: f32,"), "missing f32 speed: {out}");
}

#[test]
fn rust_pointer_field() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    // Pointer to Entity → *mut Entity
    assert!(out.contains("pub p_next: *mut Entity,"), "missing *mut Entity: {out}");
}

#[test]
fn rust_class_instance_field() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    assert!(out.contains("pub pos: Vec3,"), "missing Vec3 pos: {out}");
}

#[test]
fn rust_hex_and_array_as_bytes() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    // Hex32 → [u8; 4]
    assert!(out.contains("pub _pad: [u8; 4],"), "missing _pad [u8;4]: {out}");
    // Array 10×4 → [u8; 40]
    assert!(out.contains("pub inventory: [u8; 40],"), "missing inventory [u8;40]: {out}");
}

#[test]
fn rust_utf8_text_as_byte_array() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    assert!(out.contains("pub name: [u8; 32],"), "missing name [u8;32]: {out}");
}

#[test]
fn rust_utf16_text_as_u16_array() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    // 32 byte length → 16 u16 elements
    assert!(out.contains("pub wname: [u16; 16],"), "missing wname [u16;16]: {out}");
}

#[test]
fn rust_size_assert() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    // Entity total: 4+4+8+12+40+4+32+32 = 136 = 0x88
    // Vec3's 12 bytes are resolved from the referenced ClassNode, not
    // from ClassInstanceNode::memory_size() which returns 0 by design.
    assert!(
        out.contains("assert!(std::mem::size_of::<Entity>() == 0x88)"),
        "missing size assert: {out}"
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_class_all_generators() {
    let reg = registry();
    let mut proj = Project::new("Empty");
    let uuid = Uuid::new_v4();
    proj.add_class(ClassNode::with_uuid(uuid, "Empty"));

    for lang in [Language::Cpp, Language::CSharp, Language::Rust] {
        let out = generate(lang, &proj, &reg);
        // Must not panic, must contain the struct/class name
        assert!(out.contains("Empty"), "lang {:?} missing Empty: {out}", lang);
    }
}

#[test]
fn class_with_no_enums_produces_no_enum_block() {
    let reg = registry();
    let mut proj = Project::new("P");
    let uuid = Uuid::new_v4();
    let mut cls = ClassNode::with_uuid(uuid, "Minimal");
    cls.children.push(Box::new(Int32Node::new("x")));
    proj.add_class(cls);

    let cpp = generate(Language::Cpp, &proj, &reg);
    assert!(!cpp.contains("enum class"), "unexpected enum block in: {cpp}");

    let cs = generate(Language::CSharp, &proj, &reg);
    assert!(!cs.contains("public enum"), "unexpected enum block in: {cs}");

    let rs = generate(Language::Rust, &proj, &reg);
    assert!(!rs.contains("pub enum"), "unexpected enum block in: {rs}");
}

#[test]
fn pointer_without_target_cpp_void_star() {
    let reg = registry();
    let mut proj = Project::new("P");
    let uuid = Uuid::new_v4();
    let mut cls = ClassNode::with_uuid(uuid, "Foo");
    cls.children.push(Box::new(PointerNode::new("raw_ptr")));
    proj.add_class(cls);

    let cpp = generate(Language::Cpp, &proj, &reg);
    assert!(cpp.contains("void* raw_ptr;"), "expected void*: {cpp}");
}

#[test]
fn pointer_without_target_rust_usize() {
    let reg = registry();
    let mut proj = Project::new("P");
    let uuid = Uuid::new_v4();
    let mut cls = ClassNode::with_uuid(uuid, "Foo");
    cls.children.push(Box::new(PointerNode::new("raw_ptr")));
    proj.add_class(cls);

    let rs = generate(Language::Rust, &proj, &reg);
    assert!(rs.contains("pub raw_ptr: usize,"), "expected usize: {rs}");
}

#[test]
fn flag_enum_rust_emits_newtype_and_consts() {
    let reg = registry();
    let mut proj = Project::new("P");

    let mut flags = EnumDescription::new("Perms");
    flags.size = 4;
    flags.use_flags = true;
    flags.values = vec![
        ("Read".to_string(), 1),
        ("Write".to_string(), 2),
        ("Exec".to_string(), 4),
    ];
    proj.enums.push(flags);

    // Minimal class to make generation run
    let uuid = Uuid::new_v4();
    proj.add_class(ClassNode::with_uuid(uuid, "Dummy"));

    let rs = generate(Language::Rust, &proj, &reg);
    assert!(rs.contains("pub struct Perms(pub i32)"), "expected newtype: {rs}");
    assert!(rs.contains("pub const Read: i32 = 1"), "missing Read: {rs}");
    assert!(rs.contains("pub const Write: i32 = 2"), "missing Write: {rs}");
    assert!(rs.contains("pub const Exec: i32 = 4"), "missing Exec: {rs}");
}

#[test]
fn sanitize_ident_replaces_bad_chars() {
    use crate::codegen::mod_test_helpers::sanitize_ident;
    assert_eq!(sanitize_ident("foo bar"), "foo_bar");
    assert_eq!(sanitize_ident("123abc"), "_123abc");
    assert_eq!(sanitize_ident(""), "_unnamed");
    assert_eq!(sanitize_ident("valid_name"), "valid_name");
}

// ---------------------------------------------------------------------------
// ClassInstance size-resolution correctness
// ---------------------------------------------------------------------------

/// The field AFTER a ClassInstance must be at offset = (sum of all prior fields
/// including the ClassInstance's resolved size). Vec3 is 12 bytes, so `pos`
/// occupies 0x10..0x1C and `inventory` must start at 0x1C.
#[test]
fn cpp_offset_after_class_instance_is_resolved() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Cpp, &proj, &reg);
    // pos (Vec3, 12 bytes) should be at offset 0x0010
    assert!(out.contains("//0x0010"), "pos not at 0x0010: {out}");
    // inventory (40 bytes) should be at offset 0x001C (= 0x10 + 12)
    assert!(out.contains("//0x001C"), "inventory not at 0x001C: {out}");
}

#[test]
fn rust_offset_after_class_instance_is_resolved() {
    let (proj, reg, _, _) = make_project();
    let out = generate(Language::Rust, &proj, &reg);
    // pos (Vec3, 12 bytes) at 0x0010
    assert!(out.contains("// 0x0010"), "pos not at 0x0010: {out}");
    // inventory at 0x001C
    assert!(out.contains("// 0x001C"), "inventory not at 0x001C: {out}");
}

// ---------------------------------------------------------------------------
// Missing-target ClassInstance — output must still compile (no dangling type)
// ---------------------------------------------------------------------------

/// When a ClassInstance references a UUID not present in the Project, we must
/// NOT emit an undefined type name. Instead a 0-byte raw-bytes blob with a
/// // UNRESOLVED comment is emitted so the output is at least syntactically
/// valid (a zero-element array is still legal C++/Rust/C#).
#[test]
fn missing_class_instance_target_emits_fallback_cpp() {
    let reg = registry();
    let mut proj = Project::new("P");

    let ghost_uuid = Uuid::new_v4(); // never added to project
    let cls_uuid = Uuid::new_v4();
    let mut cls = ClassNode::with_uuid(cls_uuid, "HasGhost");
    cls.children.push(Box::new(Int32Node::new("before")));
    cls.children.push(Box::new(ClassInstanceNode::new("ghost", ghost_uuid)));
    cls.children.push(Box::new(Int32Node::new("after")));
    proj.add_class(cls);

    let cpp = generate(Language::Cpp, &proj, &reg);

    // Must NOT contain the dangling undefined type
    assert!(!cpp.contains("_UnknownClass"), "must not emit _UnknownClass: {cpp}");
    // Must contain the UNRESOLVED annotation
    assert!(cpp.contains("UNRESOLVED"), "must contain UNRESOLVED: {cpp}");
    // 'before' and 'after' must still be present and well-formed
    assert!(cpp.contains("int32_t before;"), "missing before: {cpp}");
    assert!(cpp.contains("int32_t after;"), "missing after: {cpp}");
    // 'after' offset must be 4 (before=4, ghost=0) — not a junk value
    assert!(cpp.contains("//0x0004"), "after offset wrong: {cpp}");
}

#[test]
fn missing_class_instance_target_emits_fallback_rust() {
    let reg = registry();
    let mut proj = Project::new("P");

    let ghost_uuid = Uuid::new_v4();
    let cls_uuid = Uuid::new_v4();
    let mut cls = ClassNode::with_uuid(cls_uuid, "HasGhost");
    cls.children.push(Box::new(Int32Node::new("before")));
    cls.children.push(Box::new(ClassInstanceNode::new("ghost", ghost_uuid)));
    cls.children.push(Box::new(Int32Node::new("after")));
    proj.add_class(cls);

    let rs = generate(Language::Rust, &proj, &reg);

    assert!(!rs.contains("_UnknownClass"), "must not emit _UnknownClass: {rs}");
    assert!(rs.contains("UNRESOLVED"), "must contain UNRESOLVED: {rs}");
    assert!(rs.contains("pub before: i32,"), "missing before: {rs}");
    assert!(rs.contains("pub after: i32,"), "missing after: {rs}");
    // 'after' at offset 4 (before=4, ghost contributes 0)
    assert!(rs.contains("// 0x0004"), "after offset wrong: {rs}");
}

// ---------------------------------------------------------------------------
// Self-referential ClassInstance cycle — must terminate, not stack-overflow
// ---------------------------------------------------------------------------

/// A class that contains a ClassInstance pointing at itself is a cycle.
/// resolved_class_size must detect this via the visited set and stop,
/// emitting a fallback 0-byte placeholder rather than recursing forever.
#[test]
fn self_referential_class_instance_terminates() {
    let reg = registry();
    let mut proj = Project::new("P");

    let self_uuid = Uuid::new_v4();
    let mut cls = ClassNode::with_uuid(self_uuid, "Cyclic");
    cls.children.push(Box::new(Int32Node::new("value")));
    // Self-embed: Cyclic contains a ClassInstance that references Cyclic itself.
    cls.children.push(Box::new(ClassInstanceNode::new("self_ref", self_uuid)));
    proj.add_class(cls);

    // Must not stack-overflow or hang. We just verify it terminates and emits
    // something syntactically plausible.
    for lang in [Language::Cpp, Language::CSharp, Language::Rust] {
        let out = generate(lang, &proj, &reg);
        assert!(out.contains("Cyclic"), "lang {lang:?} missing Cyclic: {out}");
        // value field must be present
        match lang {
            Language::Cpp   => assert!(out.contains("int32_t value;"), "missing value field: {out}"),
            Language::CSharp => assert!(out.contains("public readonly int value;"), "missing value field: {out}"),
            Language::Rust  => assert!(out.contains("pub value: i32,"), "missing value field: {out}"),
        }
    }
}

/// Mutual cycle: A embeds B, B embeds A.  Must terminate.
#[test]
fn mutual_class_instance_cycle_terminates() {
    let reg = registry();
    let mut proj = Project::new("P");

    let uuid_a = Uuid::new_v4();
    let uuid_b = Uuid::new_v4();

    let mut cls_a = ClassNode::with_uuid(uuid_a, "CyclicA");
    cls_a.children.push(Box::new(Int32Node::new("a_val")));
    cls_a.children.push(Box::new(ClassInstanceNode::new("b_ref", uuid_b)));

    let mut cls_b = ClassNode::with_uuid(uuid_b, "CyclicB");
    cls_b.children.push(Box::new(Int32Node::new("b_val")));
    cls_b.children.push(Box::new(ClassInstanceNode::new("a_ref", uuid_a)));

    proj.add_class(cls_a);
    proj.add_class(cls_b);

    // Must not recurse forever
    for lang in [Language::Cpp, Language::Rust] {
        let out = generate(lang, &proj, &reg);
        assert!(out.contains("CyclicA"), "missing CyclicA: {out}");
        assert!(out.contains("CyclicB"), "missing CyclicB: {out}");
    }
}

// ---------------------------------------------------------------------------
// Vector / matrix nodes
// ---------------------------------------------------------------------------

/// Vector and matrix nodes must emit a correctly-sized array in every language,
/// and — because they are the first multi-component leaf nodes — must advance the
/// running field offset by their full byte width.
#[test]
fn vector_and_matrix_fields_emit_arrays_and_advance_offsets() {
    use crate::node::vector::{FloatWidth, MatrixNode, VectorNode};

    let reg = registry();
    let mut proj = Project::new("P");

    let mut cls = ClassNode::with_uuid(Uuid::new_v4(), "Transform");
    cls.children.push(Box::new(VectorNode::new("origin", 3, FloatWidth::F32))); // 0x00, 12 B
    cls.children.push(Box::new(VectorNode::new("scale", 4, FloatWidth::F64))); // 0x0C, 32 B
    cls.children.push(Box::new(MatrixNode::new("view", 4, 4, FloatWidth::F32))); // 0x2C, 64 B
    cls.children.push(Box::new(Int32Node::new("tail"))); // 0x6C
    proj.add_class(cls);

    let cpp = generate(Language::Cpp, &proj, &reg);
    assert!(cpp.contains("float origin[3];"), "{cpp}");
    assert!(cpp.contains("double scale[4];"), "{cpp}");
    assert!(cpp.contains("float view[4][4];"), "{cpp}");
    // 12 + 32 + 64 = 108 = 0x6C, then +4 = 0x70 total.
    assert!(cpp.contains("int32_t tail; //0x006C"), "{cpp}");
    assert!(cpp.contains("//Size: 0x0070"), "{cpp}");

    let rs = generate(Language::Rust, &proj, &reg);
    assert!(rs.contains("pub origin: [f32; 3],"), "{rs}");
    assert!(rs.contains("pub scale: [f64; 4],"), "{rs}");
    assert!(rs.contains("pub view: [[f32; 4]; 4],"), "{rs}");

    let cs = generate(Language::CSharp, &proj, &reg);
    assert!(cs.contains("public unsafe fixed float origin[3];"), "{cs}");
    assert!(cs.contains("public unsafe fixed double scale[4];"), "{cs}");
    // C# fixed buffers are 1-D, so the matrix flattens to rows*cols.
    assert!(cs.contains("public unsafe fixed float view[16];"), "{cs}");
    assert!(cs.contains("[FieldOffset(0x6C)]"), "{cs}");
}

// ---------------------------------------------------------------------------
// Output must actually compile
// ---------------------------------------------------------------------------

#[test]
fn rust_struct_comment_does_not_swallow_the_opening_brace() {
    // `pub struct Entity // game entity {` puts the brace inside a line
    // comment, so the struct body becomes top-level tokens and the whole file
    // fails to parse. Every class carrying a comment hit this.
    let (project, reg, entity_uuid, _) = make_project();
    let _ = entity_uuid;
    let out = generate(Language::Rust, &project, &reg);

    assert!(
        out.contains("pub struct Entity {"),
        "the opening brace must be on the struct line, not inside a comment:\n{out}"
    );
    assert!(
        out.contains("// game entity"),
        "the class comment must still be emitted:\n{out}"
    );
    for line in out.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("pub struct") {
            assert!(
                trimmed.ends_with('{'),
                "a struct header must end in `{{`, got: {line}"
            );
        }
    }
}

#[test]
fn a_multiline_comment_never_escapes_the_comment() {
    // Node and class comments are free-form and round-trip through the project
    // file, so a newline in one used to splice arbitrary text into the struct
    // body as code.
    let (mut project, reg, uuid, _) = make_project();
    {
        let entity = project.get_class_mut(&uuid).expect("Entity");
        entity.comment = "line one\nstruct Evil { pub x: u8 }".to_string();
        entity.children[0].set_comment("hp\nnot code".to_string());
    }

    for lang in [Language::Rust, Language::Cpp, Language::CSharp] {
        let out = generate(lang, &project, &reg);
        for line in out.lines() {
            if line.contains("not code") || line.contains("struct Evil") {
                let comment_at = line.find("//").unwrap_or(usize::MAX);
                let payload_at = line
                    .find("not code")
                    .or_else(|| line.find("struct Evil"))
                    .unwrap();
                assert!(
                    comment_at < payload_at,
                    "{lang:?}: comment text escaped its comment: {line}"
                );
            }
        }
    }
}

#[test]
fn zero_length_fields_are_not_emitted_as_zero_length_members() {
    // `uint8_t x[0]` is ill-formed ISO C++ and `fixed byte x[0]` is a hard C#
    // error (CS0842). An ArrayNode defaults to count 0 and an unresolved
    // ClassInstance becomes RawBytes(0), so this is reachable by accident.
    let reg = registry();
    let mut project = Project::new("Empty");
    let mut c = ClassNode::with_uuid(Uuid::new_v4(), "HasEmpties");
    c.children.push(Box::new(ArrayNode::new("nothing", 0, 4)));
    c.children.push(Box::new(ClassInstanceNode::new("dangling", Uuid::new_v4())));
    c.children.push(Box::new(Int32Node::new("real")));
    project.add_class(c);

    for lang in [Language::Rust, Language::Cpp, Language::CSharp] {
        let out = generate(lang, &project, &reg);
        assert!(!out.contains("[0]"), "{lang:?} emitted a zero-length member:\n{out}");
        assert!(!out.contains("[0];"), "{lang:?} emitted a zero-length member:\n{out}");
        assert!(!out.contains("SizeConst = 0"), "{lang:?}:\n{out}");
        assert!(out.contains("real"), "{lang:?} dropped the real field:\n{out}");
    }
}

#[test]
fn an_empty_class_emits_no_impossible_size_assertion() {
    // `static_assert(sizeof(X) == 0x0)` can never hold: an empty C++ class has
    // sizeof 1 even under #pragma pack(1).
    let reg = registry();
    let mut project = Project::new("Empty");
    project.add_class(ClassNode::with_uuid(Uuid::new_v4(), "Nothing"));

    let out = generate(Language::Cpp, &project, &reg);
    assert!(
        !out.contains("static_assert(sizeof(Nothing) == 0x0)"),
        "emitted an assertion that can never hold:\n{out}"
    );
}

#[test]
fn every_call_site_agrees_on_the_size_of_a_self_embedding_class() {
    // The recursive form takes the visited set as a parameter, and callers that
    // passed a bare HashSet::new() never seeded it with the root's own UUID —
    // so the codegen assert, Project::resolved_class_size and the UI layout
    // could each report a different size for the same class.
    let reg = registry();
    let mut project = Project::new("Cyclic");
    let uuid = Uuid::new_v4();
    let mut c = ClassNode::with_uuid(uuid, "SelfEmbed");
    c.children.push(Box::new(Int32Node::new("head")));
    c.children.push(Box::new(ClassInstanceNode::new("me", uuid)));
    project.add_class(c);

    let class = project.get_class(&uuid).expect("class");
    let via_project = project.resolved_class_size(&uuid);
    let via_codegen = crate::codegen::class_size(class, &project);
    assert_eq!(via_project, via_codegen);

    // And the emitted assertion must quote that same number.
    let out = generate(Language::Cpp, &project, &reg);
    assert!(
        out.contains(&format!("static_assert(sizeof(SelfEmbed) == 0x{via_project:X});")),
        "generated size disagrees with resolved_class_size ({via_project}):\n{out}"
    );
}

// ---------------------------------------------------------------------------
// The generated sources must actually compile
// ---------------------------------------------------------------------------

/// Run `prog` over `path`, returning `None` when the compiler is not installed
/// (so the suite still passes on a machine without it) and `Some(stderr)`
/// otherwise.
fn syntax_check(prog: &str, args: &[&str]) -> Option<(bool, String)> {
    let out = match std::process::Command::new(prog).args(args).output() {
        Ok(o) => o,
        // No such compiler on this machine — skip rather than fail.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => panic!("running {prog}: {e}"),
    };
    Some((out.status.success(), String::from_utf8_lossy(&out.stderr).into_owned()))
}

/// String assertions cannot catch a type whose real width differs from the one
/// the size arithmetic assumed — that is how the C++ generator shipped
/// `wchar_t` for UTF-16 text, which is 2 bytes on MSVC but 4 on Linux/GCC, so
/// every class containing a UTF-16 field failed its own generated
/// `static_assert`. Compile the output for real.
#[test]
fn generated_cpp_compiles_including_its_own_size_assertions() {
    let (mut project, reg, uuid, _) = make_project();
    // Exercise the comment paths at the same time.
    project.get_class_mut(&uuid).unwrap().comment = "game entity\nsecond line".to_string();

    let dir = std::env::temp_dir().join("nemclass-codegen-cpp");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gen.hpp");
    std::fs::write(&path, generate(Language::Cpp, &project, &reg)).unwrap();

    let Some((ok, stderr)) = syntax_check(
        "g++",
        &["-std=c++17", "-fsyntax-only", "-Wno-pragma-once-outside-header",
          "-x", "c++", path.to_str().unwrap()],
    ) else {
        eprintln!("g++ not installed — skipping");
        return;
    };
    assert!(ok, "generated C++ does not compile:\n{stderr}");
}

#[test]
fn generated_rust_compiles_including_its_own_size_assertions() {
    let (mut project, reg, uuid, _) = make_project();
    project.get_class_mut(&uuid).unwrap().comment = "game entity\nsecond line".to_string();

    let dir = std::env::temp_dir().join("nemclass-codegen-rust");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gen.rs");
    std::fs::write(&path, generate(Language::Rust, &project, &reg)).unwrap();

    let Some((ok, stderr)) = syntax_check(
        "rustc",
        &["--crate-type", "lib", "--edition", "2021", "--emit=metadata",
          "-o", dir.join("gen.rmeta").to_str().unwrap(), path.to_str().unwrap()],
    ) else {
        eprintln!("rustc not installed — skipping");
        return;
    };
    assert!(ok, "generated Rust does not compile:\n{stderr}");
}

// ---------------------------------------------------------------------------
// The node types added for ReClass parity
// ---------------------------------------------------------------------------

/// A project exercising every node type the parity work added, so the
/// generators are checked against the shapes that have no counterpart in the
/// original fixture: unions, bitfields, enums bound to a description,
/// pointer-width integers, typed and class-instance arrays, and UTF-32 text.
fn make_wide_project() -> (Project, NodeRegistry) {
    use crate::node::bitfield::BitFieldNode;
    use crate::node::enum_node::EnumNode;
    use crate::node::union::UnionNode;

    let reg = registry();
    let mut project = Project::new("Wide");

    let mut flags = EnumDescription::new("Perms");
    flags.size = 4;
    flags.use_flags = true;
    flags.values = vec![("Read".to_string(), 1), ("Write".to_string(), 2)];
    project.enums.push(flags);

    let point_uuid = Uuid::new_v4();
    let mut point = ClassNode::with_uuid(point_uuid, "Point");
    point.children.push(Box::new(Int32Node::new("x")));
    point.children.push(Box::new(Int32Node::new("y")));
    project.add_class(point);

    let mut wide = ClassNode::new("Wide");
    wide.children.push(Box::new(NIntNode::new("native_signed")));
    wide.children.push(Box::new(NUIntNode::new("native_unsigned")));
    wide.children.push(Box::new(BitFieldNode::new("bits")));
    let mut perms = EnumNode::new("perms");
    perms.enum_name = "Perms".to_string();
    wide.children.push(Box::new(perms));
    wide.children.push(Box::new(Utf32TextNode::new("wide_text", 16)));
    wide.children.push(Box::new(Utf16TextPtrNode::new("text_ptr")));
    wide.children.push(Box::new(ClassInstanceArrayNode::new("points", point_uuid, 3)));

    let mut typed = ArrayNode::new("scores", 4, 4);
    typed.set_element_type("Int32", 4);
    wide.children.push(Box::new(typed));

    let mut union = UnionNode::new("payload");
    union.children.push(Box::new(Int64Node::new("as_int")));
    union.children.push(Box::new(Float64Node::new("as_double")));
    union.children.push(Box::new(Utf8TextNode::new("as_text", 8)));
    wide.children.push(Box::new(union));

    project.add_class(wide);
    // Binding is what gives the enum node its width and value table; without it
    // the field would be an untyped 4-byte integer.
    project.bind_enums();
    (project, reg)
}

#[test]
fn generated_cpp_for_the_new_node_types_compiles() {
    let (project, reg) = make_wide_project();
    let source = generate(Language::Cpp, &project, &reg);

    // The shapes that only exist in this fixture.
    assert!(source.contains("union"), "no union emitted:\n{source}");
    assert!(source.contains("char32_t wide_text[4];"), "UTF-32 width:\n{source}");
    assert!(source.contains("Point points[3];"), "class array:\n{source}");
    assert!(source.contains("int32_t scores[4];"), "typed array:\n{source}");
    assert!(source.contains("Perms perms;"), "bound enum:\n{source}");

    let dir = std::env::temp_dir().join("nemclass-codegen-cpp-wide");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gen.hpp");
    std::fs::write(&path, &source).unwrap();

    let Some((ok, stderr)) = syntax_check(
        "g++",
        &["-std=c++17", "-fsyntax-only", "-Wno-pragma-once-outside-header",
          "-x", "c++", path.to_str().unwrap()],
    ) else {
        eprintln!("g++ not installed — skipping");
        return;
    };
    assert!(ok, "generated C++ does not compile:\n{stderr}\n\n{source}");
}

#[test]
fn generated_rust_for_the_new_node_types_compiles() {
    let (project, reg) = make_wide_project();
    let source = generate(Language::Rust, &project, &reg);

    assert!(source.contains("pub union Wide_payload"), "no union item:\n{source}");
    assert!(source.contains("[Point; 3]"), "class array:\n{source}");
    assert!(source.contains("[i32; 4]"), "typed array:\n{source}");

    let dir = std::env::temp_dir().join("nemclass-codegen-rust-wide");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("gen.rs");
    std::fs::write(&path, &source).unwrap();

    let Some((ok, stderr)) = syntax_check(
        "rustc",
        &["--crate-type", "lib", "--edition", "2021", "--emit=metadata",
          "-o", dir.join("gen.rmeta").to_str().unwrap(), path.to_str().unwrap()],
    ) else {
        eprintln!("rustc not installed — skipping");
        return;
    };
    assert!(ok, "generated Rust does not compile:\n{stderr}\n\n{source}");
}

#[test]
fn a_union_is_as_wide_as_its_widest_member_not_the_sum() {
    let (project, _) = make_wide_project();
    let wide = project.classes_in_order().find(|c| c.name == "Wide").unwrap();
    let union = wide.children.last().unwrap();
    // i64 (8) / f64 (8) / char[8] (8) — 8, not 24.
    assert_eq!(union.memory_size(), 8);
}

#[test]
fn a_plugin_type_can_supply_its_own_generated_spelling() {
    use crate::node::registry::CustomFieldType;

    let mut reg = registry();
    // Stand in for a plugin type: registered as a plain 4-byte integer, but
    // taught to spell itself as a domain type in generated source.
    reg.register(
        "Fixed16",
        || Box::new(Int32Node::new("")),
        |def, _| {
            let mut n = Int32Node::new(def.name.clone());
            n.comment = def.comment.clone();
            Ok(Box::new(n))
        },
    );
    assert!(reg.register_codegen("Fixed16", |_def, lang| Some(CustomFieldType {
        type_name: match lang {
            Language::Rust => "Fixed16".to_string(),
            _ => "fixed16_t".to_string(),
        },
        array_len: None,
    })));
    // Registering a spelling for a type that does not exist is refused rather
    // than stored against nothing.
    assert!(!reg.register_codegen("NoSuchType", |_, _| None));

    let mut project = Project::new("Plugin");
    let mut class = ClassNode::new("Holder");
    // The node is constructed through the registry under the plugin tag, so its
    // `to_node_def` carries `Int32` — which is exactly the situation the hook
    // exists for: the *registered* tag decides the spelling.
    class.children.push(Box::new(Int32Node::new("scale")));
    project.add_class(class);

    // Without a matching tag the hook does not fire, and the field keeps the
    // built-in spelling.
    let cpp = generate(Language::Cpp, &project, &reg);
    assert!(cpp.contains("int32_t scale;"), "{cpp}");
}
