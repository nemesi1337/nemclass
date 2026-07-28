//! `BitFieldNode` — a run of bits inside a pointer-width-or-smaller integer.
//!
//! Port of ReClass.NET's `BitFieldNode`. The underlying storage is the smallest
//! of 8/16/32/64 bits that holds the requested bit count, so the node's
//! `memory_size` is `bits / 8` — the field occupies whole bytes even when only
//! some of them are meaningful.

use crate::node::builtins::{Attrs, node_def, read_bytes};
use crate::node::{DEFAULT_POINTER_SIZE, Node, RenderedValue};
use crate::node_common_accessors;
use crate::serialize::NodeDef;

pub struct BitFieldNode {
    pub name: String,
    pub comment: String,
    pub hidden: bool,
    bits: usize,
}

impl BitFieldNode {
    pub fn new(name: impl Into<String>) -> Self {
        let mut n =
            Self { name: name.into(), comment: String::new(), hidden: false, bits: 0 };
        n.set_bits(DEFAULT_POINTER_SIZE * 8);
        n
    }

    pub fn bits(&self) -> usize {
        self.bits
    }

    /// Round `bits` down to the next storage width the target can address.
    ///
    /// ReClass.NET clamps the same way (`>= 64 → 64`, `>= 32 → 32`, …): a
    /// bitfield is drawn over a real integer, and there is no 24-bit load.
    pub fn set_bits(&mut self, bits: usize) {
        self.bits = if bits >= 64 {
            64
        } else if bits >= 32 {
            32
        } else if bits >= 16 {
            16
        } else {
            8
        };
    }
}

impl Node for BitFieldNode {
    fn type_tag(&self) -> &'static str {
        "BitField"
    }
    node_common_accessors!();

    fn memory_size(&self) -> usize {
        self.bits / 8
    }

    fn children(&self) -> &[Box<dyn Node>] {
        &[]
    }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> {
        None
    }

    fn set_pointer_size(&mut self, size: usize) {
        // Only a *default*-width bitfield follows the target: a field the user
        // pinned to 8 or 16 bits describes the data, not the architecture.
        if self.bits == DEFAULT_POINTER_SIZE * 8 || self.bits == 32 {
            self.set_bits(size * 8);
        }
    }

    /// Render as a binary literal, most-significant bit first, grouped in bytes.
    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let size = self.memory_size();
        let Some(bytes) = read_bytes(buf, base_offset, size) else {
            return RenderedValue {
                value: "<?>".to_string(),
                type_tag: "BitField",
                memory_size: size,
            };
        };
        let mut out = String::with_capacity(self.bits + size);
        // Little-endian storage: the most significant bit lives in the last byte.
        for (i, byte) in bytes.iter().enumerate().rev() {
            if i != bytes.len() - 1 {
                out.push(' ');
            }
            for bit in (0..8).rev() {
                out.push(if byte & (1 << bit) != 0 { '1' } else { '0' });
            }
        }
        RenderedValue { value: out, type_tag: "BitField", memory_size: size }
    }

    fn to_node_def(&self) -> NodeDef {
        let mut attrs = Attrs::new();
        attrs.insert("bits".to_string(), toml::Value::Integer(self.bits as i64));
        node_def("BitField", &self.name, &self.comment, self.hidden, attrs)
    }
}
