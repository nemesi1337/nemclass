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
pub mod project;
pub mod serialize;

pub use address::{MemoryReader, ModuleResolver, parse as parse_address, resolve_formula};
pub use cheat_table::{CheatEntry, CheatTable};
pub use class::ClassNode;
pub use codegen::{CodeGenerator, Language, generate as generate_code, resolved_class_size, resolved_node_size};
pub use enums::EnumDescription;
pub use error::{ModelError, Result};
pub use node::registry::NodeRegistry;
pub use node::vector::{
    FloatWidth, MATRIX_SHAPES, MatrixNode, VECTOR_SHAPES, VectorNode, matrix_shape, vector_shape,
};
pub use node::{Node, RenderedValue};
pub use project::Project;

#[cfg(test)]
mod tests;
