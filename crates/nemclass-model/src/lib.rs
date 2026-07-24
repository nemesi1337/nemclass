//! nemclass-model: domain model for the RE tool.
//!
//! Nodes (the ReClass node hierarchy), classes, project, enums, the
//! address-formula parser, and `project.nemclass` (TOML) serialization.

pub mod address;
pub mod class;
pub mod enums;
pub mod error;
pub mod node;
pub mod project;
pub mod serialize;

pub use address::{MemoryReader, ModuleResolver, parse as parse_address, resolve_formula};
pub use class::ClassNode;
pub use enums::EnumDescription;
pub use error::{ModelError, Result};
pub use node::registry::NodeRegistry;
pub use node::{Node, RenderedValue};
pub use project::Project;

#[cfg(test)]
mod tests;
