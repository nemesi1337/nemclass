#[derive(Debug, Clone, PartialEq)]
pub struct EnumDescription {
    pub name: String,
    /// Underlying type size: 1, 2, 4, or 8 bytes.
    pub size: u8,
    pub use_flags: bool,
    pub values: Vec<(String, i64)>,
}

impl EnumDescription {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            size: 4,
            use_flags: false,
            values: Vec::new(),
        }
    }
}
