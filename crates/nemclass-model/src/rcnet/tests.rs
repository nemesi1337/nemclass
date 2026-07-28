use super::*;
use crate::node::builtins::{ArrayNode, ClassInstanceNode, PointerNode, Utf8TextNode};
use crate::node::union::UnionNode;

fn registry() -> NodeRegistry {
    NodeRegistry::new().with_builtins()
}

/// A hand-written `Data.xml` in the shape ReClass.NET 1.2 emits.
const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<reclass version="65537" type="x64">
  <custom_data />
  <type_mapping />
  <enums>
    <enum name="Team" size="FourBytes" flags="false">
      <item name="Red" value="1" />
      <item name="Blue" value="2" />
    </enum>
  </enums>
  <classes>
    <class uuid="11111111-1111-4111-8111-111111111111" name="Vec3" comment="" address="">
      <node type="FloatNode" name="x" comment="" hidden="false" />
      <node type="FloatNode" name="y" comment="" hidden="false" />
      <node type="FloatNode" name="z" comment="" hidden="false" />
    </class>
    <class uuid="22222222-2222-4222-8222-222222222222" name="Entity" comment="an entity" address="game.exe+0x100">
      <node type="Int32Node" name="health" comment="hp" hidden="false" />
      <node type="EnumNode" name="team" comment="" hidden="false" reference="Team" />
      <node type="BitFieldNode" name="flags" comment="" hidden="true" bits="32" />
      <node type="Utf8TextNode" name="name" comment="" hidden="false" length="32" />
      <node type="PointerNode" name="next" comment="" hidden="false">
        <node type="ClassInstanceNode" name="" comment="" hidden="false" reference="22222222-2222-4222-8222-222222222222" />
      </node>
      <node type="ArrayNode" name="waypoints" comment="" hidden="false" count="4">
        <node type="ClassInstanceNode" name="" comment="" hidden="false" reference="11111111-1111-4111-8111-111111111111" />
      </node>
      <node type="ArrayNode" name="scores" comment="" hidden="false" count="8">
        <node type="Int32Node" name="" comment="" hidden="false" />
      </node>
      <node type="UnionNode" name="payload" comment="" hidden="false">
        <node type="Int64Node" name="as_int" comment="" hidden="false" />
        <node type="DoubleNode" name="as_double" comment="" hidden="false" />
      </node>
      <node type="VirtualMethodTableNode" name="vtable" comment="" hidden="false">
        <method name="Destructor" comment="" hidden="false" />
        <method name="Update" comment="per frame" hidden="false" />
      </node>
    </class>
  </classes>
</reclass>
"#;

#[test]
fn a_reclass_document_imports_with_every_node_kind() {
    let (project, report) = import_xml(SAMPLE, &registry()).unwrap();

    assert_eq!(project.classes_in_order().count(), 2);
    assert_eq!(project.enums.len(), 1);
    assert_eq!(project.enums[0].name, "Team");
    assert_eq!(project.enums[0].size, 4);

    let entity = project
        .classes_in_order()
        .find(|c| c.name == "Entity")
        .expect("Entity imported");
    assert_eq!(entity.comment, "an entity");
    assert_eq!(entity.address_formula, "game.exe+0x100");

    let tags: Vec<&str> = entity.children.iter().map(|n| n.type_tag()).collect();
    assert_eq!(
        tags,
        [
            "Int32",
            "Enum",
            "BitField",
            "Utf8Text",
            "Pointer",
            "ClassInstanceArray",
            "Array",
            "Union",
            "VTable"
        ]
    );

    // The hidden flag survives.
    assert!(entity.children[2].hidden(), "the bitfield was marked hidden");
    assert!(!entity.children[0].hidden());

    // The pointer resolved to the class it wraps.
    assert_eq!(
        entity.children[4].pointer_target_class(),
        Some("22222222-2222-4222-8222-222222222222".parse().unwrap())
    );

    // A union is a container whose members overlap.
    assert_eq!(entity.children[7].children().len(), 2);
    assert_eq!(entity.children[7].memory_size(), 8);

    // The vtable's slots came from <method>, not <node>.
    assert_eq!(entity.children[8].children().len(), 2);
    assert_eq!(entity.children[8].children()[1].name(), "Update");

    // The enum node bound to the project's description, so it renders names.
    let team = &entity.children[1];
    assert_eq!(team.render(&2i32.to_le_bytes(), 0).value, "Blue");

    assert!(
        report.notes.iter().any(|n| n.contains("custom_data")),
        "the dropped plugin data is reported: {:?}",
        report.notes
    );
}

#[test]
fn a_typed_array_keeps_its_element_type_and_total_width() {
    let (project, _) = import_xml(SAMPLE, &registry()).unwrap();
    let entity = project.classes_in_order().find(|c| c.name == "Entity").unwrap();
    let scores = &entity.children[6];
    assert_eq!(scores.type_tag(), "Array");
    // 8 × Int32 = 32 bytes, not 8 × 1.
    assert_eq!(scores.memory_size(), 32);
}

#[test]
fn a_class_instance_array_measures_through_the_project() {
    let (project, _) = import_xml(SAMPLE, &registry()).unwrap();
    let entity = project.classes_in_order().find(|c| c.name == "Entity").unwrap();
    let waypoints = &entity.children[5];
    // Vec3 is 3 floats; four of them is 48 bytes. The node itself reports 0 —
    // only the project knows the target's width.
    assert_eq!(waypoints.memory_size(), 0);
    let mut visited = std::collections::HashSet::new();
    assert_eq!(
        crate::codegen::resolved_node_size(waypoints.as_ref(), &project, &mut visited),
        48
    );
}

#[test]
fn an_x86_document_imports_with_four_byte_pointers() {
    let xml = SAMPLE.replace(r#"type="x64""#, r#"type="x86""#);
    let (project, _) = import_xml(&xml, &registry()).unwrap();
    assert_eq!(project.pointer_size(), 4);
    let entity = project.classes_in_order().find(|c| c.name == "Entity").unwrap();
    assert_eq!(entity.children[4].memory_size(), 4, "pointer follows the platform");
}

#[test]
fn import_export_import_reaches_the_same_project() {
    let reg = registry();
    let (first, _) = import_xml(SAMPLE, &reg).unwrap();
    let (xml, _) = export_xml(&first);
    let (second, _) = import_xml(&xml, &reg).unwrap();

    assert_eq!(
        first.classes_in_order().count(),
        second.classes_in_order().count()
    );
    for (a, b) in first.classes_in_order().zip(second.classes_in_order()) {
        assert_eq!(a.uuid, b.uuid);
        assert_eq!(a.name, b.name);
        assert_eq!(a.comment, b.comment);
        assert_eq!(a.address_formula, b.address_formula);
        let a_tags: Vec<&str> = a.children.iter().map(|n| n.type_tag()).collect();
        let b_tags: Vec<&str> = b.children.iter().map(|n| n.type_tag()).collect();
        assert_eq!(a_tags, b_tags, "class '{}' node types", a.name);
        let a_hidden: Vec<bool> = a.children.iter().map(|n| n.hidden()).collect();
        let b_hidden: Vec<bool> = b.children.iter().map(|n| n.hidden()).collect();
        assert_eq!(a_hidden, b_hidden, "class '{}' hidden flags", a.name);
        assert_eq!(
            a.children.iter().map(|n| n.memory_size()).collect::<Vec<_>>(),
            b.children.iter().map(|n| n.memory_size()).collect::<Vec<_>>(),
            "class '{}' field widths",
            a.name
        );
    }
    assert_eq!(first.enums, second.enums);
}

#[test]
fn the_archive_round_trips_through_the_zip_container() {
    let reg = registry();
    let (project, _) = import_xml(SAMPLE, &reg).unwrap();
    let (archive, _) = export(&project).unwrap();
    let (reloaded, _) = import(&archive, &reg).unwrap();
    assert_eq!(
        reloaded.classes_in_order().map(|c| c.name.clone()).collect::<Vec<_>>(),
        project.classes_in_order().map(|c| c.name.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn a_base64_uuid_decodes_to_the_same_guid_dotnet_would_produce() {
    // .NET: new Guid("11111111-1111-4111-8111-111111111111").ToByteArray() is
    // mixed-endian, so the base64 of those bytes must decode back to the same
    // GUID rather than a byte-swapped one.
    let expected: Uuid = "11111111-1111-4111-8111-111111111111".parse().unwrap();
    let dotnet_bytes = expected.to_bytes_le();
    let encoded = base64_encode(&dotnet_bytes);
    assert_eq!(encoded.len(), 24);
    assert_eq!(parse_uuid(&encoded), Some(expected));
}

/// Test-only base64 encoder, so the decoder is checked against something other
/// than itself.
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}

#[test]
fn a_newer_critical_file_version_is_refused_rather_than_half_read() {
    let xml = SAMPLE.replace(r#"version="65537""#, r#"version="131073""#); // 0x00020001
    let Err(e) = import_xml(&xml, &registry()) else {
        panic!("a newer critical version must not load");
    };
    assert!(e.to_string().contains("newer"), "{e}");
}

#[test]
fn a_newer_minor_file_version_still_loads() {
    // 0x00010002 — the critical half is unchanged, so an added attribute is
    // simply ignored, matching the C# reader's mask.
    let xml = SAMPLE.replace(r#"version="65537""#, r#"version="65538""#);
    assert!(import_xml(&xml, &registry()).is_ok());
}

#[test]
fn a_document_that_is_not_reclass_is_rejected() {
    let Err(e) = import_xml("<cheattable><entry /></cheattable>", &registry()) else {
        panic!("a foreign document must not import");
    };
    assert!(e.to_string().contains("reclass"), "{e}");
}

#[test]
fn exporting_a_double_precision_vector_reports_the_approximation() {
    let mut project = Project::new("p");
    let mut class = ClassNode::new("Physics");
    class.children.push(Box::new(crate::node::vector::VectorNode::new(
        "velocity",
        3,
        crate::node::vector::FloatWidth::F64,
    )));
    project.add_class(class);

    let (xml, report) = export_xml(&project);
    assert!(xml.contains(r#"type="DoubleNode""#), "{xml}");
    assert!(xml.contains(r#"count="3""#), "{xml}");
    assert!(
        report.notes.iter().any(|n| n.contains("double-precision")),
        "the approximation is reported: {:?}",
        report.notes
    );
}

#[test]
fn exported_widths_match_what_the_project_laid_out() {
    let mut project = Project::new("p");
    let mut class = ClassNode::new("Mixed");
    class.children.push(Box::new(Utf8TextNode::new("name", 24)));
    class.children.push(Box::new(ArrayNode::new("pad", 5, 3)));
    let mut ptr = PointerNode::new("self");
    ptr.target_class_uuid = Some(Uuid::nil());
    class.children.push(Box::new(ptr));
    let mut union = UnionNode::new("u");
    union.children.push(Box::new(ClassInstanceNode::new("inline", Uuid::nil())));
    class.children.push(Box::new(union));
    project.add_class(class);

    let (xml, _) = export_xml(&project);
    let reg = registry();
    let (reloaded, _) = import_xml(&xml, &reg).unwrap();
    let class = reloaded.classes_in_order().next().unwrap();

    assert_eq!(class.children[0].memory_size(), 24, "text length");
    // 5 × 3 bytes has no hex node that wide, so it becomes 15 single bytes —
    // a different shape but exactly the same span.
    assert_eq!(class.children[1].memory_size(), 15, "untyped array span");
    assert_eq!(class.children[2].memory_size(), 8, "pointer width");
}
