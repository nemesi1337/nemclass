use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("class '{name}' is still referenced by {ref_count} other class(es)")]
    ClassReferenced { name: String, ref_count: usize },
    #[error("class not found: {0}")]
    ClassNotFound(uuid::Uuid),
    #[error("address formula parse error: {0}")]
    ParseError(String),
    #[error("address resolution error: {0}")]
    ResolveError(String),
    #[error("serialization error: {0}")]
    SerializeError(String),
    #[error("deserialization error: {0}")]
    DeserializeError(String),
    #[error("unknown node type: {0}")]
    UnknownNodeType(String),
    #[error("cycle detected in class references")]
    CycleDetected,
    #[error("buffer too small: need {need} bytes at offset {offset}, got {got}")]
    BufferTooSmall { need: usize, offset: usize, got: usize },
    #[error("node nesting exceeds the maximum depth of {0}")]
    MaxDepthExceeded(usize),
}

pub type Result<T> = std::result::Result<T, ModelError>;
