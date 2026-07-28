//! ReClass.NET `.rcnet` project import and export.
//!
//! A `.rcnet` file is a ZIP archive holding a single `Data.xml`. This module
//! maps that document to and from [`Project`], so a project built in
//! ReClass.NET opens here and a project built here opens there.
//!
//! ## What does not survive the trip
//!
//! The two models are close but not identical, and the differences are
//! reported rather than silently absorbed — [`ImportReport`] and
//! [`ExportReport`] carry a line per lossy decision:
//!
//! - ReClass wraps: its `PointerNode` and `ArrayNode` hold an *inner node*,
//!   where nemclass stores a target UUID and an element type tag. A pointer to
//!   anything but a class, or an array of anything but a scalar or a class,
//!   arrives as the closest fixed-width equivalent.
//! - nemclass has double-precision vectors and matrices (`Vector3d`,
//!   `Matrix4x4d`); ReClass has no such types, so they export as arrays of
//!   `DoubleNode`.
//! - `custom_data` and `type_mapping` are plugin state with no nemclass
//!   equivalent; they are dropped on import and not written on export.

pub mod xml;
pub mod zip;

use uuid::Uuid;

use crate::class::ClassNode;
use crate::enums::EnumDescription;
use crate::error::{ModelError, Result};
use crate::node::Node;
use crate::node::registry::NodeRegistry;
use crate::project::Project;
use crate::serialize::NodeDef;
use xml::Element;

/// The single entry a `.rcnet` archive contains.
const DATA_ENTRY: &str = "Data.xml";

/// The file version ReClass.NET 1.2 writes (`0x00010001`).
const FILE_VERSION: u32 = 0x0001_0001;

/// Only the high half of the version is compatibility-critical, matching
/// `FileVersionCriticalMask` in the C# reader.
const FILE_VERSION_CRITICAL_MASK: u32 = 0xFFFF_0000;

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/// What an import had to approximate or drop.
#[derive(Debug, Default, Clone)]
pub struct ImportReport {
    pub notes: Vec<String>,
}

/// What an export had to approximate or drop.
#[derive(Debug, Default, Clone)]
pub struct ExportReport {
    pub notes: Vec<String>,
}

impl ImportReport {
    fn note(&mut self, msg: impl Into<String>) {
        self.notes.push(msg.into());
    }
}

impl ExportReport {
    fn note(&mut self, msg: impl Into<String>) {
        self.notes.push(msg.into());
    }
}

// ---------------------------------------------------------------------------
// Type-tag mapping
// ---------------------------------------------------------------------------

/// nemclass tag for a ReClass.NET node class name, for the types that map
/// one-to-one. Wrapping types (`PointerNode`, `ArrayNode`) and container types
/// are handled structurally instead.
fn tag_from_reclass(reclass: &str) -> Option<&'static str> {
    Some(match reclass {
        "BoolNode" => "Bool",
        "Int8Node" => "Int8",
        "Int16Node" => "Int16",
        "Int32Node" => "Int32",
        "Int64Node" => "Int64",
        "UInt8Node" => "UInt8",
        "UInt16Node" => "UInt16",
        "UInt32Node" => "UInt32",
        "UInt64Node" => "UInt64",
        "NIntNode" => "NInt",
        "NUIntNode" => "NUInt",
        "FloatNode" => "Float",
        "DoubleNode" => "Double",
        "Hex8Node" => "Hex8",
        "Hex16Node" => "Hex16",
        "Hex32Node" => "Hex32",
        "Hex64Node" => "Hex64",
        // The `UTF*` spellings are the pre-rename names the C# reader still
        // accepts; files in the wild contain both.
        "Utf8TextNode" | "UTF8TextNode" => "Utf8Text",
        "Utf16TextNode" | "UTF16TextNode" => "Utf16Text",
        "Utf32TextNode" | "UTF32TextNode" => "Utf32Text",
        "Utf8TextPtrNode" | "UTF8TextPtrNode" => "Utf8TextPtr",
        "Utf16TextPtrNode" | "UTF16TextPtrNode" => "Utf16TextPtr",
        "Utf32TextPtrNode" | "UTF32TextPtrNode" => "Utf32TextPtr",
        "Vector2Node" => "Vector2",
        "Vector3Node" => "Vector3",
        "Vector4Node" => "Vector4",
        "Matrix3x3Node" => "Matrix3x3",
        "Matrix3x4Node" => "Matrix3x4",
        "Matrix4x4Node" => "Matrix4x4",
        "FunctionPtrNode" => "FunctionPtr",
        "BitFieldNode" => "BitField",
        _ => return None,
    })
}

/// The ReClass.NET class name for a nemclass tag, where one exists.
fn reclass_from_tag(tag: &str) -> Option<&'static str> {
    Some(match tag {
        "Bool" => "BoolNode",
        "Int8" => "Int8Node",
        "Int16" => "Int16Node",
        "Int32" => "Int32Node",
        "Int64" => "Int64Node",
        "UInt8" => "UInt8Node",
        "UInt16" => "UInt16Node",
        "UInt32" => "UInt32Node",
        "UInt64" => "UInt64Node",
        "NInt" => "NIntNode",
        "NUInt" => "NUIntNode",
        "Float" => "FloatNode",
        "Double" => "DoubleNode",
        "Hex8" => "Hex8Node",
        "Hex16" => "Hex16Node",
        "Hex32" => "Hex32Node",
        "Hex64" => "Hex64Node",
        "Utf8Text" => "Utf8TextNode",
        "Utf16Text" => "Utf16TextNode",
        "Utf32Text" => "Utf32TextNode",
        "Utf8TextPtr" | "StrPtr" => "Utf8TextPtrNode",
        "Utf16TextPtr" => "Utf16TextPtrNode",
        "Utf32TextPtr" => "Utf32TextPtrNode",
        "Vector2" => "Vector2Node",
        "Vector3" => "Vector3Node",
        "Vector4" => "Vector4Node",
        "Matrix3x3" => "Matrix3x3Node",
        "Matrix3x4" => "Matrix3x4Node",
        "Matrix4x4" => "Matrix4x4Node",
        "FunctionPtr" => "FunctionPtrNode",
        "BitField" => "BitFieldNode",
        _ => return None,
    })
}

/// The hex node that exactly covers `size` bytes, used as the element type of
/// an array whose real element type does not survive the trip.
fn hex_tag_for_size(size: usize) -> &'static str {
    match size {
        8 => "Hex64Node",
        4 => "Hex32Node",
        2 => "Hex16Node",
        _ => "Hex8Node",
    }
}

/// Parse the `size` attribute of an `<enum>`, which C# writes as the *name* of
/// its `UnderlyingTypeSize` enumerator rather than a number.
fn enum_size_from_attr(raw: &str) -> u8 {
    match raw {
        "OneByte" | "1" => 1,
        "TwoBytes" | "2" => 2,
        "EightBytes" | "8" => 8,
        _ => 4,
    }
}

fn enum_size_to_attr(size: u8) -> &'static str {
    match size {
        1 => "OneByte",
        2 => "TwoBytes",
        8 => "EightBytes",
        _ => "FourBytes",
    }
}

/// Parse a `.rcnet` UUID.
///
/// C# writes either the standard hyphenated form or, for compactness, the
/// 24-character base64 of the raw 16 bytes. Those bytes are in .NET's
/// mixed-endian `Guid` order — the first three fields little-endian — which is
/// why this uses `from_bytes_le` rather than the RFC big-endian constructor.
fn parse_uuid(raw: &str) -> Option<Uuid> {
    if raw.len() == 24 {
        let bytes = base64_decode(raw)?;
        let array: [u8; 16] = bytes.try_into().ok()?;
        return Some(Uuid::from_bytes_le(array));
    }
    Uuid::parse_str(raw).ok()
}

fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a') as u32 + 26,
            b'0'..=b'9' => (c - b'0') as u32 + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        if chunk.len() != 4 {
            return None;
        }
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        let mut acc = 0u32;
        for &c in chunk {
            acc = (acc << 6) | if c == b'=' { 0 } else { value(c)? };
        }
        let full = [(acc >> 16) as u8, (acc >> 8) as u8, acc as u8];
        out.extend_from_slice(&full[..3 - pad]);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Read a `.rcnet` archive into a [`Project`].
pub fn import(archive: &[u8], registry: &NodeRegistry) -> Result<(Project, ImportReport)> {
    let data = zip::read_entry(archive, DATA_ENTRY)?;
    let text = String::from_utf8(data)
        .map_err(|e| ModelError::DeserializeError(format!("{DATA_ENTRY} is not UTF-8: {e}")))?;
    import_xml(&text, registry)
}

/// Read a `Data.xml` document into a [`Project`] — the archive already opened.
pub fn import_xml(text: &str, registry: &NodeRegistry) -> Result<(Project, ImportReport)> {
    let root = xml::parse(text)?;
    if root.name != "reclass" {
        return Err(ModelError::DeserializeError(format!(
            "not a ReClass.NET document (root element is <{}>, expected <reclass>)",
            root.name
        )));
    }

    let mut report = ImportReport::default();

    // Only the critical half of the version blocks a load, matching the C#
    // reader: a bumped minor version adds attributes an older reader ignores.
    if let Some(version) = root.attr("version").and_then(|v| v.trim().parse::<u32>().ok())
        && (version & FILE_VERSION_CRITICAL_MASK) > (FILE_VERSION & FILE_VERSION_CRITICAL_MASK)
    {
        return Err(ModelError::DeserializeError(format!(
            "file version 0x{version:08X} is newer than this build reads \
             (max 0x{FILE_VERSION:08X})"
        )));
    }

    let mut project = Project::new("Imported");

    // The platform attribute decides pointer width, and it has to be applied
    // before any class is added: `add_class` pushes the width into the nodes it
    // is handed, so a class added first would keep the default.
    match root.attr("type") {
        Some("x86") => project.set_pointer_size(4)?,
        Some("x64") | None => {}
        Some(other) => report.note(format!(
            "unknown platform '{other}'; assuming 64-bit pointers"
        )),
    }

    if root.child("custom_data").is_some() || root.child("type_mapping").is_some() {
        report.note(
            "plugin custom_data / type_mapping dropped — nemclass has no equivalent".to_string(),
        );
    }

    if let Some(enums) = root.child("enums") {
        for e in enums.children_named("enum") {
            let mut desc = EnumDescription::new(e.attr_or_empty("name"));
            desc.size = enum_size_from_attr(e.attr_or_empty("size"));
            desc.use_flags = e.attr_bool("flags");
            for item in e.children_named("item") {
                desc.values
                    .push((item.attr_or_empty("name").to_string(), item.attr_i64("value").unwrap_or(0)));
            }
            project.enums.push(desc);
        }
    }

    let Some(classes) = root.child("classes") else {
        return Err(ModelError::DeserializeError(
            "document has no <classes> element".to_string(),
        ));
    };

    // Two passes: every class has to exist before nodes that reference classes
    // by UUID are built, since a `PointerNode` may point forward.
    let mut pending = Vec::new();
    for element in classes.children_named("class") {
        let raw = element.attr_or_empty("uuid");
        let Some(uuid) = parse_uuid(raw) else {
            report.note(format!("skipped class with unreadable uuid '{raw}'"));
            continue;
        };
        if project.get_class(&uuid).is_some() {
            report.note(format!(
                "skipped duplicate class '{}' (uuid {uuid})",
                element.attr_or_empty("name")
            ));
            continue;
        }
        let mut class = ClassNode::with_uuid(uuid, element.attr_or_empty("name"));
        class.comment = element.attr_or_empty("comment").to_string();
        class.address_formula = element.attr_or_empty("address").to_string();
        project.add_class(class);
        pending.push((uuid, element));
    }

    for (uuid, element) in pending {
        let mut children = Vec::new();
        for node_element in element.children_named("node") {
            match node_to_def(node_element, &mut report) {
                Some(def) => children.push(registry.deserialize_node(def)?),
                None => report.note(format!(
                    "skipped node '{}' of unsupported type '{}'",
                    node_element.attr_or_empty("name"),
                    node_element.attr_or_empty("type")
                )),
            }
        }
        if let Some(class) = project.get_class_mut(&uuid) {
            class.children = children;
        }
    }

    // Applied after the classes are in: both walks need the finished tree.
    let pointer_size = project.pointer_size();
    project.set_pointer_size(pointer_size)?;
    project.bind_enums();

    Ok((project, report))
}

/// Build a [`NodeDef`] from one `<node>` element, or `None` if the type has no
/// nemclass equivalent at all.
fn node_to_def(element: &Element, report: &mut ImportReport) -> Option<NodeDef> {
    let reclass_type = element.attr_or_empty("type");
    let name = element.attr_or_empty("name").to_string();
    let comment = element.attr_or_empty("comment").to_string();
    let hidden = element.attr_bool("hidden");

    let mut def = NodeDef {
        type_tag: String::new(),
        name,
        comment,
        attrs: Default::default(),
        nodes: Vec::new(),
    };
    if hidden {
        def.attrs.insert("hidden".to_string(), toml::Value::Boolean(true));
    }

    // Types that carry only name/comment/hidden plus at most one scalar attr.
    if let Some(tag) = tag_from_reclass(reclass_type) {
        def.type_tag = tag.to_string();
        if let Some(length) = element.attr_i64("length") {
            def.attrs.insert("length".to_string(), toml::Value::Integer(length));
        }
        if let Some(bits) = element.attr_i64("bits") {
            def.attrs.insert("bits".to_string(), toml::Value::Integer(bits));
        }
        return Some(def);
    }

    match reclass_type {
        // A class instance: `reference` names the class.
        "ClassInstanceNode" | "ClassPtrNode" => {
            let reference = element.attr_or_empty("reference");
            let uuid = parse_uuid(reference)?;
            // `ClassPtrNode` is the legacy pointer-to-class; it is a pointer,
            // not an inline instance, so it must not become one.
            def.type_tag =
                if reclass_type == "ClassPtrNode" { "Pointer" } else { "ClassInstance" }
                    .to_string();
            let key = if reclass_type == "ClassPtrNode" { "target_class_uuid" } else { "class_uuid" };
            def.attrs.insert(key.to_string(), toml::Value::String(uuid.to_string()));
            Some(def)
        }

        // A pointer wraps an inner node. nemclass models only "pointer to a
        // class" and "untyped pointer", so anything else keeps the width and
        // loses the pointee's type.
        "PointerNode" => {
            def.type_tag = "Pointer".to_string();
            if let Some(inner) = element.children_named("node").next() {
                match parse_uuid(inner.attr_or_empty("reference")) {
                    Some(uuid) if inner.attr_or_empty("type").contains("ClassInstance") => {
                        def.attrs.insert(
                            "target_class_uuid".to_string(),
                            toml::Value::String(uuid.to_string()),
                        );
                    }
                    _ => report.note(format!(
                        "pointer '{}' points at a '{}', which nemclass cannot type; \
                         kept as an untyped pointer",
                        def.name,
                        inner.attr_or_empty("type")
                    )),
                }
            }
            Some(def)
        }

        "UnionNode" => {
            def.type_tag = "Union".to_string();
            for child in element.children_named("node") {
                if let Some(child_def) = node_to_def(child, report) {
                    def.nodes.push(child_def);
                }
            }
            Some(def)
        }

        "VirtualMethodTableNode" | "VTableNode" => {
            def.type_tag = "VTable".to_string();
            // vtable slots are `<method>`, not `<node>`.
            for method in element.children_named("method") {
                let mut slot = NodeDef {
                    type_tag: "VMethod".to_string(),
                    name: method.attr_or_empty("name").to_string(),
                    comment: method.attr_or_empty("comment").to_string(),
                    attrs: Default::default(),
                    nodes: Vec::new(),
                };
                if method.attr_bool("hidden") {
                    slot.attrs.insert("hidden".to_string(), toml::Value::Boolean(true));
                }
                def.nodes.push(slot);
            }
            Some(def)
        }

        "FunctionNode" => {
            def.type_tag = "Function".to_string();
            def.attrs.insert(
                "signature".to_string(),
                toml::Value::String(element.attr_or_empty("signature").to_string()),
            );
            Some(def)
        }

        "EnumNode" => {
            def.type_tag = "Enum".to_string();
            def.attrs.insert(
                "enum_name".to_string(),
                toml::Value::String(element.attr_or_empty("reference").to_string()),
            );
            Some(def)
        }

        // An array wraps an inner node and a count.
        "ArrayNode" | "ClassInstanceArrayNode" | "ClassPtrArrayNode" => {
            let count = element.attr_i64("count").unwrap_or(0).max(0);
            let inner = element.children_named("node").next();

            // An array of class instances is its own nemclass type.
            let class_reference = inner
                .filter(|i| i.attr_or_empty("type").contains("ClassInstance"))
                .and_then(|i| parse_uuid(i.attr_or_empty("reference")))
                .or_else(|| {
                    (reclass_type == "ClassInstanceArrayNode")
                        .then(|| parse_uuid(element.attr_or_empty("reference")))
                        .flatten()
                });
            if let Some(uuid) = class_reference {
                def.type_tag = "ClassInstanceArray".to_string();
                def.attrs
                    .insert("class_uuid".to_string(), toml::Value::String(uuid.to_string()));
                def.attrs.insert("count".to_string(), toml::Value::Integer(count));
                return Some(def);
            }

            def.type_tag = "Array".to_string();
            def.attrs.insert("count".to_string(), toml::Value::Integer(count));
            match inner.map(|i| i.attr_or_empty("type")).and_then(tag_from_reclass) {
                Some(element_tag) => {
                    let size = element_size_for_tag(element_tag, inner);
                    def.attrs
                        .insert("element_type".to_string(), toml::Value::String(element_tag.to_string()));
                    def.attrs
                        .insert("element_size".to_string(), toml::Value::Integer(size as i64));
                }
                None => {
                    report.note(format!(
                        "array '{}' has element type '{}', which nemclass cannot type; \
                         kept as raw bytes",
                        def.name,
                        inner.map(|i| i.attr_or_empty("type")).unwrap_or("(none)")
                    ));
                    def.attrs.insert("element_size".to_string(), toml::Value::Integer(1));
                }
            }
            Some(def)
        }

        _ => None,
    }
}

/// Byte width of an array element, for the element types an import can produce.
///
/// Deliberately not a registry lookup: the element widths that matter here are
/// fixed by the tag, and a text element's width comes from the *element's own*
/// `length` attribute rather than any default.
fn element_size_for_tag(tag: &str, element: Option<&Element>) -> usize {
    if let Some(length) = element.and_then(|e| e.attr_i64("length")) {
        return length.max(0) as usize;
    }
    match tag {
        "Int8" | "UInt8" | "Bool" | "Hex8" => 1,
        "Int16" | "UInt16" | "Hex16" => 2,
        "Int32" | "UInt32" | "Float" | "Hex32" => 4,
        "Int64" | "UInt64" | "Double" | "Hex64" => 8,
        "Vector2" => 8,
        "Vector3" => 12,
        "Vector4" => 16,
        "Matrix3x3" => 36,
        "Matrix3x4" => 48,
        "Matrix4x4" => 64,
        // Pointer-width types: the project's width is applied to the array's
        // element size by the caller only for typed arrays it constructs, so
        // assume 64-bit here and let a 32-bit import correct it below.
        _ => 8,
    }
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Write a [`Project`] as a `.rcnet` archive.
pub fn export(project: &Project) -> Result<(Vec<u8>, ExportReport)> {
    let (text, report) = export_xml(project);
    Ok((zip::write_entry(DATA_ENTRY, text.as_bytes())?, report))
}

/// Render a [`Project`] as the `Data.xml` document a `.rcnet` holds.
pub fn export_xml(project: &Project) -> (String, ExportReport) {
    let mut report = ExportReport::default();

    let mut root = Element::new("reclass");
    root.set("version", FILE_VERSION.to_string());
    root.set("type", if project.pointer_size() == 4 { "x86" } else { "x64" });

    let mut enums = Element::new("enums");
    for e in &project.enums {
        let mut element = Element::new("enum");
        element.set("name", e.name.clone());
        element.set("size", enum_size_to_attr(e.size));
        element.set("flags", if e.use_flags { "true" } else { "false" });
        for (name, value) in &e.values {
            let mut item = Element::new("item");
            item.set("name", name.clone());
            item.set("value", value.to_string());
            element.push(item);
        }
        enums.push(element);
    }
    root.push(enums);

    let mut classes = Element::new("classes");
    for class in project.classes_in_order() {
        let mut element = Element::new("class");
        element.set("uuid", class.uuid.to_string());
        element.set("name", class.name.clone());
        element.set("comment", class.comment.clone());
        element.set("address", class.address_formula.clone());
        for child in &class.children {
            match node_to_element(child.as_ref(), &mut report) {
                Some(node_element) => {
                    element.push(node_element);
                }
                None => report.note(format!(
                    "dropped node '{}' of type '{}' — ReClass.NET has no equivalent",
                    child.name(),
                    child.type_tag()
                )),
            }
        }
        classes.push(element);
    }
    root.push(classes);

    (root.to_document(), report)
}

fn node_to_element(node: &dyn Node, report: &mut ExportReport) -> Option<Element> {
    let def = node.to_node_def();
    let tag = def.type_tag.as_str();

    let mut element = Element::new("node");
    element.set("name", def.name.clone());
    element.set("comment", def.comment.clone());
    element.set("hidden", if node.hidden() { "true" } else { "false" });

    let attr_str = |key: &str| def.attrs.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string();
    let attr_int = |key: &str| def.attrs.get(key).and_then(|v| v.as_integer()).unwrap_or(0);

    if let Some(reclass) = reclass_from_tag(tag) {
        element.set("type", reclass);
        match tag {
            "Utf8Text" | "Utf16Text" | "Utf32Text" => {
                element.set("length", attr_int("length").to_string());
            }
            "BitField" => {
                element.set("bits", attr_int("bits").to_string());
            }
            _ => {}
        }
        return Some(element);
    }

    match tag {
        "ClassInstance" => {
            element.set("type", "ClassInstanceNode");
            element.set("reference", attr_str("class_uuid"));
            Some(element)
        }

        "Pointer" => {
            element.set("type", "PointerNode");
            // ReClass models the pointee as a wrapped inner node, so a typed
            // pointer needs a `ClassInstanceNode` child rather than an attribute.
            let target = attr_str("target_class_uuid");
            if !target.is_empty() {
                let mut inner = Element::new("node");
                inner.set("type", "ClassInstanceNode");
                inner.set("name", "");
                inner.set("comment", "");
                inner.set("hidden", "false");
                inner.set("reference", target);
                element.push(inner);
            }
            Some(element)
        }

        "ClassInstanceArray" => {
            element.set("type", "ArrayNode");
            element.set("count", attr_int("count").to_string());
            let mut inner = Element::new("node");
            inner.set("type", "ClassInstanceNode");
            inner.set("name", "");
            inner.set("comment", "");
            inner.set("hidden", "false");
            inner.set("reference", attr_str("class_uuid"));
            element.push(inner);
            Some(element)
        }

        "Array" => {
            element.set("type", "ArrayNode");
            let element_tag = attr_str("element_type");
            let element_size = attr_int("element_size").max(1) as usize;
            let mut inner = Element::new("node");
            inner.set("name", "");
            inner.set("comment", "");
            inner.set("hidden", "false");
            match reclass_from_tag(&element_tag) {
                Some(reclass_element) => {
                    element.set("count", attr_int("count").to_string());
                    inner.set("type", reclass_element);
                    if element_tag.starts_with("Utf") && !element_tag.ends_with("Ptr") {
                        inner.set("length", element_size.to_string());
                    }
                }
                None => {
                    // Untyped, or an element type ReClass lacks: keep the byte
                    // span exactly by choosing the hex node of that width.
                    element.set("count", attr_int("count").to_string());
                    inner.set("type", hex_tag_for_size(element_size));
                    if !matches!(element_size, 1 | 2 | 4 | 8) {
                        // No hex node is this wide, so widen the count instead —
                        // same total bytes, one element per byte.
                        element.set(
                            "count",
                            (attr_int("count").max(0) as usize * element_size).to_string(),
                        );
                        inner.set("type", "Hex8Node");
                    }
                }
            }
            element.push(inner);
            Some(element)
        }

        "Union" => {
            element.set("type", "UnionNode");
            for child in node.children() {
                match node_to_element(child.as_ref(), report) {
                    Some(child_element) => {
                        element.push(child_element);
                    }
                    None => report.note(format!(
                        "dropped union member '{}' of type '{}'",
                        child.name(),
                        child.type_tag()
                    )),
                }
            }
            Some(element)
        }

        "VTable" => {
            element.set("type", "VirtualMethodTableNode");
            for child in node.children() {
                let mut method = Element::new("method");
                method.set("name", child.name().to_string());
                method.set("comment", child.comment().to_string());
                method.set("hidden", if child.hidden() { "true" } else { "false" });
                element.push(method);
            }
            Some(element)
        }

        "Function" => {
            element.set("type", "FunctionNode");
            element.set("signature", attr_str("signature"));
            element.set("reference", Uuid::nil().to_string());
            Some(element)
        }

        "Enum" => {
            element.set("type", "EnumNode");
            element.set("reference", attr_str("enum_name"));
            Some(element)
        }

        // Double-precision vectors and matrices: ReClass is single-precision
        // only, so keep the bytes as an array of doubles rather than silently
        // halving the field.
        tag if tag.ends_with('d') && (tag.starts_with("Vector") || tag.starts_with("Matrix")) => {
            let components = node.memory_size() / 8;
            report.note(format!(
                "'{}' is a {tag}; ReClass.NET has no double-precision \
                 vector/matrix, so it is exported as DoubleNode[{components}]",
                def.name
            ));
            element.set("type", "ArrayNode");
            element.set("count", components.to_string());
            let mut inner = Element::new("node");
            inner.set("type", "DoubleNode");
            inner.set("name", "");
            inner.set("comment", "");
            inner.set("hidden", "false");
            element.push(inner);
            Some(element)
        }

        // A node this build did not recognise on load: if its original tag is a
        // ReClass one it came from a `.rcnet` in the first place, so send it
        // back with the tag it arrived with.
        "Unknown" => {
            let original = def.type_tag.as_str();
            report.note(format!(
                "node '{}' has unknown type '{original}'; written back verbatim",
                def.name
            ));
            element.set("type", original);
            Some(element)
        }

        // Nodes with no ReClass shape at all (`VMethod` outside a vtable, a
        // plugin type) fall through to the caller's "dropped" note.
        _ => None,
    }
}

#[cfg(test)]
mod tests;
