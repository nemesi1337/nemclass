use uuid::Uuid;

use crate::node::{Node, RenderedValue};
use crate::serialize::NodeDef;

pub struct ClassNode {
    pub uuid: Uuid,
    pub name: String,
    pub comment: String,
    pub address_formula: String,
    pub children: Vec<Box<dyn Node>>,
}

impl ClassNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: name.into(),
            comment: String::new(),
            address_formula: String::new(),
            children: Vec::new(),
        }
    }

    pub fn with_uuid(uuid: Uuid, name: impl Into<String>) -> Self {
        Self {
            uuid,
            name: name.into(),
            comment: String::new(),
            address_formula: String::new(),
            children: Vec::new(),
        }
    }

    pub fn memory_size(&self) -> usize {
        self.children.iter().map(|n| n.memory_size()).sum()
    }

    /// Check if any child (recursively) references `target_uuid` as a ClassInstance or Pointer.
    pub fn references_class(&self, target_uuid: &Uuid) -> bool {
        children_reference_class(&self.children, target_uuid)
    }
}

/// Recursively check if any node in `children` (or their children) has a
/// ClassInstance or Pointer that references `target`.
pub(crate) fn children_reference_class(children: &[Box<dyn Node>], target: &Uuid) -> bool {
    let target_str = target.to_string();
    for child in children {
        let def = child.to_node_def();
        match def.type_tag.as_str() {
            "ClassInstance" => {
                if def.attrs.get("class_uuid")
                    .and_then(|v| v.as_str())
                    .map(|s| s == target_str)
                    .unwrap_or(false)
                {
                    return true;
                }
            }
            "Pointer"
                if def.attrs.get("target_class_uuid")
                    .and_then(|v| v.as_str())
                    .map(|s| s == target_str)
                    .unwrap_or(false) =>
            {
                return true;
            }
            _ => {}
        }
        if children_reference_class(child.children(), target) {
            return true;
        }
    }
    false
}

impl Node for ClassNode {
    fn type_tag(&self) -> &'static str { "Class" }

    fn name(&self) -> &str { &self.name }
    fn set_name(&mut self, n: String) { self.name = n; }
    fn comment(&self) -> &str { &self.comment }
    fn set_comment(&mut self, c: String) { self.comment = c; }

    fn memory_size(&self) -> usize {
        self.children.iter().map(|n| n.memory_size()).sum()
    }

    fn children(&self) -> &[Box<dyn Node>] { &self.children }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> { Some(&mut self.children) }

    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        RenderedValue {
            value: format!("class:{}", self.name),
            type_tag: "Class",
            memory_size: self.memory_size(),
        }
    }

    fn to_node_def(&self) -> NodeDef {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("uuid".to_string(), toml::Value::String(self.uuid.to_string()));
        attrs.insert(
            "address_formula".to_string(),
            toml::Value::String(self.address_formula.clone()),
        );
        NodeDef {
            type_tag: "Class".to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs,
            nodes: Vec::new(), // children serialized separately by the registry
        }
    }
}
