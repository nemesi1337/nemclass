#![doc = include_str!("detailed_docs.md")]
//! nemclass-model: domain model for the RE tool.
//!
//! Nodes (the ReClass node hierarchy), classes, project, enums, the
//! address-formula parser, `project.nemclass` (TOML) serialization,
//! and multi-language code generation.

pub mod address;
pub mod cheat_table;
pub mod class;
pub mod codegen;
pub mod dissect;
pub mod enums;
pub mod error;
pub mod node;
pub mod patch;
pub mod project;
pub mod rcnet;
pub mod serialize;

pub use address::{MemoryReader, ModuleResolver, parse as parse_address, resolve_formula};
pub use cheat_table::{CheatEntry, CheatTable};
pub use class::ClassNode;
pub use codegen::{
    CodeGenerator, Language, class_size, generate as generate_code, resolved_class_size,
    resolved_node_size,
};
pub use enums::EnumDescription;
pub use error::{ModelError, Result};
pub use node::bitfield::BitFieldNode;
pub use node::builtins::{TextEncoding, text_encoding};
pub use node::enum_node::EnumNode;
pub use node::registry::{CustomFieldType, NodeRegistry};
pub use node::union::UnionNode;
pub use node::vector::{
    FloatWidth, MATRIX_SHAPES, MatrixNode, VECTOR_SHAPES, VectorNode, matrix_shape, vector_shape,
};
pub use node::unknown::UnknownNode;
pub use node::{DEFAULT_POINTER_SIZE, Node, RenderedValue};
pub use patch::{Patch, PatchSet};
pub use project::{Project, SCHEMA_VERSION, SCHEMA_VERSION_BASE};
pub use rcnet::{ExportReport, ImportReport};

#[cfg(test)]
mod tests;
