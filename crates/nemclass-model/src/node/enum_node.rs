//! `EnumNode` — an integer field displayed through a project enum.
//!
//! Port of ReClass.NET's `EnumNode`. The node stores only the *name* of the
//! [`EnumDescription`](crate::EnumDescription) it renders through, because the
//! descriptions live on the project and the user may edit or re-order them
//! after the field is placed. The width and the value table are copied in by
//! [`Project::bind_enums`](crate::Project::bind_enums) whenever either side
//! changes, so `render` — which has no project access — still shows names.

use crate::enums::EnumDescription;
use crate::node::builtins::{Attrs, node_def, read_bytes};
use crate::node::{Node, RenderedValue};
use crate::node_common_accessors;
use crate::serialize::NodeDef;

pub struct EnumNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    /// The project enum this field renders through.
    pub enum_name: String,
    /// Underlying integer width in bytes (1/2/4/8). Mirrors the bound
    /// description; 4 until one is bound, matching `EnumDescription::new`.
    size: usize,
    /// Bound value table, `(name, value)`. Empty when the description is
    /// missing — the field then renders as a plain integer rather than
    /// pretending the enum resolved.
    values: Vec<(String, i64)>,
    use_flags: bool,
}

impl EnumNode {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            hidden: false,
            enum_name: String::new(),
            size: 4,
            values: Vec::new(),
            use_flags: false,
        }
    }

    /// Copy the description's width and value table into this node.
    pub fn bind(&mut self, desc: &EnumDescription) {
        self.enum_name = desc.name.clone();
        self.size = (desc.size as usize).clamp(1, 8);
        self.values = desc.values.clone();
        self.use_flags = desc.use_flags;
    }

    /// Forget a binding whose description no longer exists.
    pub fn unbind(&mut self) {
        self.values.clear();
        self.use_flags = false;
    }

    pub fn is_bound(&self) -> bool {
        !self.values.is_empty()
    }

    /// Format `raw` through the bound value table.
    ///
    /// Flag enums decompose into `A | B`; a leftover with no matching flag is
    /// appended as a hex remainder rather than dropped, so the display never
    /// claims to have accounted for bits it did not.
    fn format(&self, raw: i64) -> String {
        if self.values.is_empty() {
            return raw.to_string();
        }
        if !self.use_flags {
            return match self.values.iter().find(|(_, v)| *v == raw) {
                Some((name, _)) => name.clone(),
                None => raw.to_string(),
            };
        }
        if raw == 0 {
            return match self.values.iter().find(|(_, v)| *v == 0) {
                Some((name, _)) => name.clone(),
                None => "0".to_string(),
            };
        }
        let mut parts = Vec::new();
        let mut remaining = raw;
        for (name, value) in &self.values {
            if *value != 0 && (remaining & *value) == *value {
                parts.push(name.clone());
                remaining &= !*value;
            }
        }
        if remaining != 0 {
            parts.push(format!("0x{remaining:X}"));
        }
        if parts.is_empty() { raw.to_string() } else { parts.join(" | ") }
    }
}

impl Node for EnumNode {
    fn type_tag(&self) -> &'static str {
        "Enum"
    }
    node_common_accessors!();

    fn memory_size(&self) -> usize {
        self.size
    }

    fn children(&self) -> &[Box<dyn Node>] {
        &[]
    }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> {
        None
    }

    fn enum_binding(&self) -> Option<&str> {
        Some(&self.enum_name)
    }

    fn bind_enum(&mut self, desc: Option<&EnumDescription>) {
        match desc {
            Some(d) => self.bind(d),
            None => self.unbind(),
        }
    }

    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let Some(bytes) = read_bytes(buf, base_offset, self.size) else {
            return RenderedValue {
                value: "<?>".to_string(),
                type_tag: "Enum",
                memory_size: self.size,
            };
        };
        let mut raw = 0u64;
        for (i, b) in bytes.iter().enumerate() {
            raw |= (*b as u64) << (i * 8);
        }
        // Sign-extend from the underlying width so a negative enumerator matches.
        let shift = 64 - self.size * 8;
        let signed = ((raw << shift) as i64) >> shift;
        RenderedValue {
            value: self.format(signed),
            type_tag: "Enum",
            memory_size: self.size,
        }
    }

    fn to_node_def(&self) -> NodeDef {
        let mut attrs = Attrs::new();
        attrs.insert("enum_name".to_string(), toml::Value::String(self.enum_name.clone()));
        // The width is persisted too: it lets a field keep its layout when the
        // project's enum list is missing the description, instead of silently
        // resizing to 4 and shifting every field after it.
        attrs.insert("size".to_string(), toml::Value::Integer(self.size as i64));
        node_def("Enum", &self.name, &self.comment, self.hidden, attrs)
    }
}
