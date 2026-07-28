//! Vector and matrix nodes — fixed-length groups of floating-point components.
//!
//! These are the ReClass.NET `Vector2/3/4` and `Matrix3x3/3x4/4x4` node types,
//! generalized over the component width so both `f32` (the game-engine default)
//! and `f64` layouts are expressible.
//!
//! ## Why one struct per family, but many type tags
//!
//! [`NodeRegistry`](crate::node::registry::NodeRegistry) keys on a `&'static str`
//! tag and constructs a node from that tag alone — there is no place to pass a
//! shape. So each concrete shape gets its own tag (`Vector3`, `Vector3d`,
//! `Matrix4x4`, …) and the shape is recovered from the tag rather than stored in
//! `NodeDef::attrs`. That keeps "change this node's type" a one-tag operation in
//! the UI and keeps the serialized project readable.
//!
//! The `d` suffix means `f64` components; an unsuffixed tag is `f32`.

use bytemuck::pod_read_unaligned;

use super::{Node, RenderedValue};
use crate::serialize::NodeDef;

// ---------------------------------------------------------------------------
// FloatWidth
// ---------------------------------------------------------------------------

/// Component width of a vector/matrix: single or double precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FloatWidth {
    F32,
    F64,
}

impl FloatWidth {
    /// Size of one component in bytes.
    pub const fn size(self) -> usize {
        match self {
            FloatWidth::F32 => 4,
            FloatWidth::F64 => 8,
        }
    }

    /// Rust type name (`f32` / `f64`).
    pub const fn rust_ty(self) -> &'static str {
        match self {
            FloatWidth::F32 => "f32",
            FloatWidth::F64 => "f64",
        }
    }

    /// C/C++ type name (`float` / `double`).
    pub const fn c_ty(self) -> &'static str {
        match self {
            FloatWidth::F32 => "float",
            FloatWidth::F64 => "double",
        }
    }

    /// Read one component from the front of `bytes`, widened to `f64`.
    /// Returns `None` when `bytes` is shorter than one component.
    pub fn read(self, bytes: &[u8]) -> Option<f64> {
        let n = self.size();
        if bytes.len() < n {
            return None;
        }
        Some(match self {
            FloatWidth::F32 => pod_read_unaligned::<f32>(&bytes[..4]) as f64,
            FloatWidth::F64 => pod_read_unaligned::<f64>(&bytes[..8]),
        })
    }

    /// Parse user-typed text into this width's native-endian bytes.
    /// `None` when the text isn't a valid float of this width.
    pub fn parse_to_ne_bytes(self, text: &str) -> Option<Vec<u8>> {
        let t = text.trim();
        match self {
            FloatWidth::F32 => t.parse::<f32>().ok().map(|v| v.to_ne_bytes().to_vec()),
            FloatWidth::F64 => t.parse::<f64>().ok().map(|v| v.to_ne_bytes().to_vec()),
        }
    }

    /// Format a component for display. Trims to a fixed precision so a row of
    /// components stays readable rather than showing full `f64` expansions.
    pub fn format(self, v: f64) -> String {
        let s = format!("{v:.3}");
        // Drop a trailing ".000" so whole numbers read as "1" not "1.000".
        match s.strip_suffix(".000") {
            Some(head) => head.to_string(),
            None => s,
        }
    }
}

// ---------------------------------------------------------------------------
// Tag <-> shape mapping
// ---------------------------------------------------------------------------

/// Every vector tag, paired with its `(components, width)` shape.
pub const VECTOR_SHAPES: [(&str, u8, FloatWidth); 6] = [
    ("Vector2", 2, FloatWidth::F32),
    ("Vector3", 3, FloatWidth::F32),
    ("Vector4", 4, FloatWidth::F32),
    ("Vector2d", 2, FloatWidth::F64),
    ("Vector3d", 3, FloatWidth::F64),
    ("Vector4d", 4, FloatWidth::F64),
];

/// Every matrix tag, paired with its `(rows, cols, width)` shape.
pub const MATRIX_SHAPES: [(&str, u8, u8, FloatWidth); 6] = [
    ("Matrix3x3", 3, 3, FloatWidth::F32),
    ("Matrix3x4", 3, 4, FloatWidth::F32),
    ("Matrix4x4", 4, 4, FloatWidth::F32),
    ("Matrix3x3d", 3, 3, FloatWidth::F64),
    ("Matrix3x4d", 3, 4, FloatWidth::F64),
    ("Matrix4x4d", 4, 4, FloatWidth::F64),
];

/// Shape behind a vector type tag, or `None` if `tag` isn't a vector.
pub fn vector_shape(tag: &str) -> Option<(u8, FloatWidth)> {
    VECTOR_SHAPES
        .iter()
        .find(|(t, _, _)| *t == tag)
        .map(|&(_, c, w)| (c, w))
}

/// Shape behind a matrix type tag, or `None` if `tag` isn't a matrix.
pub fn matrix_shape(tag: &str) -> Option<(u8, u8, FloatWidth)> {
    MATRIX_SHAPES
        .iter()
        .find(|(t, _, _, _)| *t == tag)
        .map(|&(_, r, c, w)| (r, c, w))
}

/// The canonical tag for a vector shape. Falls back to `Vector3`/`Vector3d` for
/// component counts outside 2..=4 (which [`VectorNode::new`] clamps anyway).
fn vector_tag(components: u8, width: FloatWidth) -> &'static str {
    VECTOR_SHAPES
        .iter()
        .find(|(_, c, w)| *c == components && *w == width)
        .map(|&(t, _, _)| t)
        .unwrap_or(match width {
            FloatWidth::F32 => "Vector3",
            FloatWidth::F64 => "Vector3d",
        })
}

/// The canonical tag for a matrix shape, defaulting to 4x4 for unknown shapes.
fn matrix_tag(rows: u8, cols: u8, width: FloatWidth) -> &'static str {
    MATRIX_SHAPES
        .iter()
        .find(|(_, r, c, w)| *r == rows && *c == cols && *w == width)
        .map(|&(t, _, _, _)| t)
        .unwrap_or(match width {
            FloatWidth::F32 => "Matrix4x4",
            FloatWidth::F64 => "Matrix4x4d",
        })
}

// ---------------------------------------------------------------------------
// VectorNode
// ---------------------------------------------------------------------------

/// A contiguous run of 2–4 floating-point components (`Vector2/3/4`).
///
/// Rendered as `(x, y, z)`; the UI edits each component independently.
pub struct VectorNode {
    pub name: String,
    pub comment: String,
    components: u8,
    width: FloatWidth,
}

impl VectorNode {
    /// `components` is clamped to 2..=4 so the node always has a valid type tag.
    pub fn new(name: impl Into<String>, components: u8, width: FloatWidth) -> Self {
        Self {
            name: name.into(),
            comment: String::new(),
            components: components.clamp(2, 4),
            width,
        }
    }

    pub fn components(&self) -> u8 {
        self.components
    }

    pub fn width(&self) -> FloatWidth {
        self.width
    }

    /// Read every component out of `buf` starting at `base_offset`. Components
    /// past the end of the buffer are omitted, so a short buffer yields a short
    /// (possibly empty) vec rather than panicking.
    pub fn read_components(&self, buf: &[u8], base_offset: usize) -> Vec<f64> {
        read_components(buf, base_offset, self.components as usize, self.width)
    }
}

impl Node for VectorNode {
    fn type_tag(&self) -> &'static str {
        vector_tag(self.components, self.width)
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn set_name(&mut self, n: String) {
        self.name = n;
    }
    fn comment(&self) -> &str {
        &self.comment
    }
    fn set_comment(&mut self, c: String) {
        self.comment = c;
    }
    fn memory_size(&self) -> usize {
        self.components as usize * self.width.size()
    }
    fn children(&self) -> &[Box<dyn Node>] {
        &[]
    }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> {
        None
    }

    fn render(&self, buf: &[u8], base_offset: usize) -> RenderedValue {
        let tag = self.type_tag();
        let size = self.memory_size();
        let comps = self.read_components(buf, base_offset);
        if comps.len() != self.components as usize {
            return RenderedValue { value: "<?>".to_string(), type_tag: tag, memory_size: size };
        }
        let body = comps
            .iter()
            .map(|v| self.width.format(*v))
            .collect::<Vec<_>>()
            .join(", ");
        RenderedValue { value: format!("({body})"), type_tag: tag, memory_size: size }
    }

    fn to_node_def(&self) -> NodeDef {
        NodeDef {
            type_tag: self.type_tag().to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs: std::collections::BTreeMap::new(),
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// MatrixNode
// ---------------------------------------------------------------------------

/// A row-major matrix of floating-point components (`Matrix3x3/3x4/4x4`).
///
/// The collapsed value is a shape summary (`[4x4 f32]`); the UI expands it into
/// one table row per matrix row, each cell independently editable.
pub struct MatrixNode {
    pub name: String,
    pub comment: String,
    rows: u8,
    cols: u8,
    width: FloatWidth,
}

impl MatrixNode {
    /// Unsupported shapes fall back to 4x4 so the node always has a valid tag.
    pub fn new(name: impl Into<String>, rows: u8, cols: u8, width: FloatWidth) -> Self {
        let (rows, cols) = match (rows, cols) {
            (3, 3) | (3, 4) | (4, 4) => (rows, cols),
            _ => (4, 4),
        };
        Self { name: name.into(), comment: String::new(), rows, cols, width }
    }

    pub fn rows(&self) -> u8 {
        self.rows
    }

    pub fn cols(&self) -> u8 {
        self.cols
    }

    pub fn width(&self) -> FloatWidth {
        self.width
    }

    /// All `rows * cols` components in row-major order (see
    /// [`VectorNode::read_components`] for the short-buffer behaviour).
    pub fn read_components(&self, buf: &[u8], base_offset: usize) -> Vec<f64> {
        read_components(
            buf,
            base_offset,
            self.rows as usize * self.cols as usize,
            self.width,
        )
    }
}

impl Node for MatrixNode {
    fn type_tag(&self) -> &'static str {
        matrix_tag(self.rows, self.cols, self.width)
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn set_name(&mut self, n: String) {
        self.name = n;
    }
    fn comment(&self) -> &str {
        &self.comment
    }
    fn set_comment(&mut self, c: String) {
        self.comment = c;
    }
    fn memory_size(&self) -> usize {
        self.rows as usize * self.cols as usize * self.width.size()
    }
    fn children(&self) -> &[Box<dyn Node>] {
        &[]
    }
    fn children_mut(&mut self) -> Option<&mut Vec<Box<dyn Node>>> {
        None
    }

    fn render(&self, _buf: &[u8], _base_offset: usize) -> RenderedValue {
        RenderedValue {
            value: format!("[{}x{} {}]", self.rows, self.cols, self.width.rust_ty()),
            type_tag: self.type_tag(),
            memory_size: self.memory_size(),
        }
    }

    fn to_node_def(&self) -> NodeDef {
        NodeDef {
            type_tag: self.type_tag().to_string(),
            name: self.name.clone(),
            comment: self.comment.clone(),
            attrs: std::collections::BTreeMap::new(),
            nodes: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

/// Read `count` components of `width` from `buf` at `base_offset`, stopping
/// early if the buffer runs out.
fn read_components(buf: &[u8], base_offset: usize, count: usize, width: FloatWidth) -> Vec<f64> {
    let wsz = width.size();
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let Some(start) = base_offset.checked_add(i * wsz) else { break };
        let Some(end) = start.checked_add(wsz) else { break };
        if end > buf.len() {
            break;
        }
        match width.read(&buf[start..end]) {
            Some(v) => out.push(v),
            None => break,
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_tags_round_trip_to_their_shapes() {
        for (tag, comps, width) in VECTOR_SHAPES {
            let node = VectorNode::new("v", comps, width);
            assert_eq!(node.type_tag(), tag);
            assert_eq!(vector_shape(tag), Some((comps, width)));
            assert_eq!(node.memory_size(), comps as usize * width.size());
        }
    }

    #[test]
    fn matrix_tags_round_trip_to_their_shapes() {
        for (tag, rows, cols, width) in MATRIX_SHAPES {
            let node = MatrixNode::new("m", rows, cols, width);
            assert_eq!(node.type_tag(), tag);
            assert_eq!(matrix_shape(tag), Some((rows, cols, width)));
            assert_eq!(node.memory_size(), rows as usize * cols as usize * width.size());
        }
    }

    #[test]
    fn vector_renders_each_component() {
        let mut buf = Vec::new();
        for v in [1.0f32, -2.5, 3.25] {
            buf.extend_from_slice(&v.to_ne_bytes());
        }
        let node = VectorNode::new("pos", 3, FloatWidth::F32);
        assert_eq!(node.render(&buf, 0).value, "(1, -2.500, 3.250)");
    }

    #[test]
    fn vector_render_on_short_buffer_is_unknown_not_a_panic() {
        let node = VectorNode::new("pos", 3, FloatWidth::F32);
        assert_eq!(node.render(&[0u8; 4], 0).value, "<?>");
        assert_eq!(node.render(&[], 0).value, "<?>");
    }

    #[test]
    fn matrix_reads_row_major_components() {
        let vals: Vec<f32> = (0..16).map(|i| i as f32).collect();
        let buf: Vec<u8> = vals.iter().flat_map(|v| v.to_ne_bytes()).collect();
        let node = MatrixNode::new("view", 4, 4, FloatWidth::F32);
        let comps = node.read_components(&buf, 0);
        assert_eq!(comps.len(), 16);
        // Row 1, column 2 is index 1*4 + 2 = 6.
        assert_eq!(comps[6], 6.0);
    }

    #[test]
    fn unsupported_shapes_clamp_to_a_valid_tag() {
        assert_eq!(VectorNode::new("v", 9, FloatWidth::F32).components(), 4);
        assert_eq!(VectorNode::new("v", 0, FloatWidth::F32).components(), 2);
        let m = MatrixNode::new("m", 7, 2, FloatWidth::F64);
        assert_eq!((m.rows(), m.cols()), (4, 4));
        assert_eq!(m.type_tag(), "Matrix4x4d");
    }
}
