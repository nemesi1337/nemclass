use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Intermediate representation of a node for TOML serialization.
/// The `type` field is the type_tag string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDef {
    #[serde(rename = "type")]
    pub type_tag: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// Extra type-specific attributes (count, length, class_uuid, etc.)
    #[serde(flatten)]
    pub attrs: HashMap<String, toml::Value>,
    /// Nested children for container nodes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<NodeDef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectFile {
    pub project: ProjectMeta,
    #[serde(default)]
    pub enums: Vec<EnumDef>,
    #[serde(default)]
    pub classes: Vec<ClassDef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnumDef {
    pub name: String,
    pub size: u8,
    pub use_flags: bool,
    #[serde(default)]
    pub values: Vec<EnumValueDef>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnumValueDef {
    pub name: String,
    pub value: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassDef {
    pub uuid: String,
    pub name: String,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub address_formula: String,
    #[serde(default)]
    pub nodes: Vec<NodeDef>,
}
