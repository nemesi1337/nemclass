//! Auto-dissect: heuristic type-guessing pass over a raw memory buffer.
//!
//! This is the model-layer analog of Cheat Engine's "dissect data" view and
//! ReClass.NET's `MemoryDissectorJob`. Given a byte buffer (already read from
//! a target process) and an injected pointer classifier, it walks the buffer in
//! 8-byte (pointer-sized) steps and assigns the most plausible [`NodeDef`] type
//! to each slot.
//!
//! # Design choices
//!
//! - **Pure core, thin process wrapper.** [`dissect_buffer`] takes a
//!   `classify: impl Fn(u64) -> PointerClass` closure and the already-read
//!   buffer, so it is fully unit-testable without a live process and compiles on
//!   every platform. The only process-touching code is [`auto_dissect`], which is
//!   `#[cfg(target_os = "linux")]`-gated.
//!
//! - **String-first at each offset.** Before interpreting 8 bytes as a machine
//!   word, the dissector checks whether a printable run starts *exactly* at the
//!   current offset (via [`nemclass_core::string_at`] with `min_len = 4`).
//!   When a qualifying run is found it wins over any pointer interpretation,
//!   because in practice a struct member that starts with four printable bytes is
//!   almost certainly an inline character array, not a pointer that happens to
//!   look printable. UTF-16LE is preferred over ASCII by `string_at` when both
//!   qualify (same tie-break the core detection pass uses).
//!
//! - **String advance.** After emitting a text node the offset advances by
//!   `run.len_bytes` rounded up to the next 8-byte boundary. This keeps
//!   subsequent fields pointer-aligned, matching how compilers lay out structs
//!   with inline arrays: the array member is padded to the next pointer-sized
//!   boundary. If the run already ends on an 8-byte boundary (e.g. a 16-byte
//!   UTF-16LE run) no extra padding is added.
//!
//! - **Integer heuristic.** When the 8-byte word is `Null` or `NotPointer`,
//!   the dissector interprets it as a signed i64 and applies a simple smallness
//!   test: if `|v as i64| < INT64_SMALL_BOUND` (currently 0x1_0000_0000, i.e.
//!   anything that fits in a 32-bit range, positive or negative), it emits
//!   `Int64`; otherwise `Hex64`. The bound is deliberately documented here so
//!   callers can reason about false positives (very large integer constants will
//!   be shown as hex, which is usually what the user wants anyway).

use std::collections::HashMap;

use nemclass_core::{PointerClass, StrKind, string_at};

use crate::serialize::NodeDef;

// ---------------------------------------------------------------------------
// Heuristic constants — kept explicit so the rationale is auditable.
// ---------------------------------------------------------------------------

/// Minimum printable-run length (in characters) required to treat a buffer
/// region as an inline string rather than interpreting the 8 bytes as a word.
const STRING_MIN_LEN: usize = 4;

/// Signed-integer "smallness" threshold. A `Null`/`NotPointer` word whose
/// absolute signed value is below this bound is reported as `Int64`; values at
/// or above are reported as `Hex64` (they are more likely addresses, constants,
/// or flags than human-scale counts). 0x1_0000_0000 means anything that fits
/// in a signed 32-bit range (±2 GiB) is treated as an integer.
const INT64_SMALL_BOUND: i64 = 0x1_0000_0000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Constructs a bare [`NodeDef`] with the given type tag and name, no attrs,
/// and no children.
fn leaf_def(type_tag: &'static str, name: String) -> NodeDef {
    NodeDef {
        type_tag: type_tag.to_string(),
        name,
        comment: String::new(),
        attrs: HashMap::new(),
        nodes: Vec::new(),
    }
}

/// Constructs a [`NodeDef`] with a single integer attribute.
fn leaf_def_with_int(type_tag: &'static str, name: String, attr: &str, val: i64) -> NodeDef {
    let mut attrs = HashMap::new();
    attrs.insert(attr.to_string(), toml::Value::Integer(val));
    NodeDef {
        type_tag: type_tag.to_string(),
        name,
        comment: String::new(),
        attrs,
        nodes: Vec::new(),
    }
}

/// Round `n` up to the next multiple of `align`. When `n` is already a
/// multiple of `align`, returns `n` unchanged. `align` must be non-zero.
#[inline]
fn round_up(n: usize, align: usize) -> usize {
    debug_assert!(align > 0 && align.is_power_of_two());
    (n + align - 1) & !(align - 1)
}

// ---------------------------------------------------------------------------
// Pure core
// ---------------------------------------------------------------------------

/// Walk `buf` from offset 0 in 8-byte steps, assigning the most plausible
/// [`NodeDef`] type to each slot.
///
/// # Arguments
///
/// - `base`: the process-side virtual address that `buf[0]` corresponds to.
///   Currently unused in the pure core (it is available for future use in name
///   generation or address annotation), but accepted so the signature matches
///   the process wrapper and tests can pass realistic addresses.
/// - `buf`: the raw bytes of the memory region to dissect.
/// - `classify`: an injected closure that maps a `u64` machine word to a
///   [`PointerClass`]. In production this wraps `nemclass_core::classify_value`;
///   in tests it is a simple `match` over pre-canned values.
///
/// # Offset advancement
///
/// | Slot kind       | Bytes consumed                             |
/// |-----------------|---------------------------------------------|
/// | String (ASCII)  | `round_up(run.len_bytes, 8)`               |
/// | String (UTF-16) | `round_up(run.len_bytes, 8)`               |
/// | Pointer / code / vtable / integer / hex | 8              |
///
/// When fewer than 8 bytes remain at an offset, the loop terminates (no
/// partial-word nodes are emitted). Trailing bytes of a string pad region are
/// silently consumed as part of the string's advance.
pub fn dissect_buffer(
    _base: usize,
    buf: &[u8],
    classify: impl Fn(u64) -> PointerClass,
) -> Vec<NodeDef> {
    let mut out: Vec<NodeDef> = Vec::new();
    let mut offset: usize = 0;

    while buf.len().saturating_sub(offset) >= 8 {
        let name = format!("field_{offset:#x}");

        // ------------------------------------------------------------------
        // 1. Inline-string check (string-first heuristic).
        //    `string_at` returns a run only if one starts *exactly* at
        //    `offset`; it prefers UTF-16LE over ASCII when both qualify.
        // ------------------------------------------------------------------
        if let Some(run) = string_at(buf, offset, STRING_MIN_LEN) {
            let (type_tag, length_bytes): (&'static str, usize) = match run.kind {
                StrKind::Ascii => ("Utf8Text", run.len_bytes),
                StrKind::Utf16Le => ("Utf16Text", run.len_bytes),
            };

            // The `length` attr mirrors Utf8TextNode / Utf16TextNode's
            // `to_node_def`: both use `"length"` (bytes, not chars).
            let def = leaf_def_with_int(type_tag, name, "length", length_bytes as i64);
            out.push(def);

            // Advance past the string, padded to the next 8-byte boundary so
            // subsequent fields remain pointer-aligned (compiler struct layout).
            offset += round_up(run.len_bytes, 8);
            continue;
        }

        // ------------------------------------------------------------------
        // 2. Pointer-word interpretation.
        // ------------------------------------------------------------------
        // Safety: we've verified buf.len() - offset >= 8 above.
        let word_bytes: [u8; 8] = buf[offset..offset + 8].try_into().unwrap();
        let value = u64::from_le_bytes(word_bytes);

        let def = match classify(value) {
            // ----------------------------------------------------------------
            // VTablePtr: emit a VTable node containing `method_count` VMethod
            // children named "method_0", "method_1", …
            // ----------------------------------------------------------------
            PointerClass::VTablePtr { method_count } => {
                let mut vtable_def = leaf_def("VTable", name);
                for i in 0..method_count {
                    vtable_def.nodes.push(leaf_def("VMethod", format!("method_{i}")));
                }
                vtable_def
            }

            // ----------------------------------------------------------------
            // CodePtr: a bare function pointer (unannotated).
            // ----------------------------------------------------------------
            PointerClass::CodePtr => leaf_def("FunctionPtr", name),

            // ----------------------------------------------------------------
            // DataPtr: a generic data pointer (no target UUID yet — the user
            // can refine it in the class editor later).
            // ----------------------------------------------------------------
            PointerClass::DataPtr => leaf_def("Pointer", name),

            // ----------------------------------------------------------------
            // Null / NotPointer: interpret the 8 bytes as a signed integer
            // and apply the smallness heuristic.
            //
            // Heuristic: |v as i64| < INT64_SMALL_BOUND → Int64 (a human-scale
            // count, index, enum value, etc.). Otherwise → Hex64 (more likely
            // a bit-field, hash, flag mask, or garbage that happens to live
            // here).  Zero (Null) is always "small" and becomes Int64.
            // ----------------------------------------------------------------
            PointerClass::Null | PointerClass::NotPointer => {
                let signed = value as i64;
                if signed.unsigned_abs() < INT64_SMALL_BOUND as u64 {
                    leaf_def("Int64", name)
                } else {
                    leaf_def("Hex64", name)
                }
            }
        };

        out.push(def);
        offset += 8;
    }

    out
}

// ---------------------------------------------------------------------------
// Process-facing wrapper (Linux only)
// ---------------------------------------------------------------------------

/// Read `len` bytes from `process` at virtual address `base`, then run the
/// auto-dissect heuristic pass and return the inferred [`NodeDef`] sequence.
///
/// Short reads are handled gracefully: if [`Process::read_buf`] returns fewer
/// bytes than requested (e.g. the region ends before `base + len`), the
/// dissector works on what it received rather than returning an error. A
/// completely failed read propagates as an error.
///
/// # Platform
///
/// Linux-only (`#[cfg(target_os = "linux")]`) because it uses
/// [`RegionIndex::from_pid`] (which parses `/proc/<pid>/maps`) and because
/// the `Process` handle is the Linux native/kernel backend. The pure
/// [`dissect_buffer`] core is platform-neutral and tested without this wrapper.
#[cfg(target_os = "linux")]
pub fn auto_dissect(
    process: &nemclass_core::Process,
    base: usize,
    len: usize,
) -> nemclass_core::Result<Vec<NodeDef>> {
    use nemclass_core::{RegionIndex, classify_value};

    // Read `len` bytes; tolerate short reads by dissecting what arrived.
    let mut buf = vec![0u8; len];
    let n = process.read_buf(base, &mut buf)?;
    // Truncate to the bytes actually read so dissect_buffer doesn't try to
    // interpret zero-filled padding as real data.
    buf.truncate(n);

    let index = RegionIndex::from_pid(process.pid())?;

    Ok(dissect_buffer(base, &buf, |value| {
        classify_value(value, &index, |addr, b| process.read_buf(addr, b))
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::registry::NodeRegistry;

    // -----------------------------------------------------------------------
    // Fake value constants — picked so the fake classify closure can
    // distinguish them with a simple match, and so they don't accidentally
    // trigger a real classifier.  All are in the 0xDEAD_xxxx range which is
    // deliberately unmapped on any real system.
    // -----------------------------------------------------------------------

    /// Encodes as LE bytes at a given offset in the test buffer.
    fn write_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Fake sentinel values the test classify closure recognises.
    const VTABLE_SENTINEL: u64 = 0xDEAD_0001_0000_0001;
    const CODE_SENTINEL: u64   = 0xDEAD_0002_0000_0002;
    const DATA_SENTINEL: u64   = 0xDEAD_0003_0000_0003;
    // offset 24 is an inline ASCII string; no sentinel needed.
    /// Small integer that should emit Int64.
    const SMALL_INT: u64 = 42;
    /// Large/garbage value that should emit Hex64.
    const BIG_VAL: u64   = 0xFFFF_DEAD_BEEF_0000;

    /// Build a fake classify closure for the tests above.
    fn fake_classify(value: u64) -> PointerClass {
        match value {
            VTABLE_SENTINEL => PointerClass::VTablePtr { method_count: 3 },
            CODE_SENTINEL   => PointerClass::CodePtr,
            DATA_SENTINEL   => PointerClass::DataPtr,
            v if v == SMALL_INT => PointerClass::NotPointer,
            v if v == BIG_VAL   => PointerClass::NotPointer,
            _               => PointerClass::Null,
        }
    }

    // -----------------------------------------------------------------------
    // Helper: build the canonical test buffer used by several tests.
    //
    // Layout (each slot is 8 bytes unless noted):
    //
    //   offset  0 : VTABLE_SENTINEL  → VTable(3 children)
    //   offset  8 : CODE_SENTINEL    → FunctionPtr
    //   offset 16 : DATA_SENTINEL    → Pointer
    //   offset 24 : ASCII "Hello\0xx" → Utf8Text(len=5), advance to 32
    //   offset 32 : SMALL_INT (42)   → Int64
    //   offset 40 : BIG_VAL          → Hex64
    // -----------------------------------------------------------------------
    fn build_test_buf() -> Vec<u8> {
        // Total: 48 bytes (6 × 8-byte slots)
        let mut buf = vec![0u8; 48];
        write_u64(&mut buf, 0,  VTABLE_SENTINEL);
        write_u64(&mut buf, 8,  CODE_SENTINEL);
        write_u64(&mut buf, 16, DATA_SENTINEL);
        // offset 24: ASCII "Hello" (5 printable chars) followed by NUL then padding
        buf[24] = b'H'; buf[25] = b'e'; buf[26] = b'l'; buf[27] = b'l'; buf[28] = b'o';
        buf[29] = 0x00; // NUL terminator (not printable — ends ASCII run)
        // bytes 30–31 are zero padding (within the rounded-up 8-byte slot)
        write_u64(&mut buf, 32, SMALL_INT);
        write_u64(&mut buf, 40, BIG_VAL);
        buf
    }

    // -----------------------------------------------------------------------
    // Test 1: VTablePtr → VTable node with correct method children
    // -----------------------------------------------------------------------
    #[test]
    fn vtable_sentinel_emits_vtable_with_three_children() {
        let buf = build_test_buf();
        let nodes = dissect_buffer(0x1000, &buf, fake_classify);

        // First node must be VTable
        let vtable = nodes.iter().find(|n| n.type_tag == "VTable")
            .expect("expected a VTable node");
        assert_eq!(vtable.name, "field_0x0", "VTable name includes hex offset");
        assert_eq!(vtable.nodes.len(), 3, "VTable must have 3 VMethod children");
        for (i, child) in vtable.nodes.iter().enumerate() {
            assert_eq!(child.type_tag, "VMethod");
            assert_eq!(child.name, format!("method_{i}"));
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: CodePtr → FunctionPtr
    // -----------------------------------------------------------------------
    #[test]
    fn code_sentinel_emits_function_ptr() {
        let buf = build_test_buf();
        let nodes = dissect_buffer(0x1000, &buf, fake_classify);

        let fp = nodes.iter().find(|n| n.type_tag == "FunctionPtr")
            .expect("expected a FunctionPtr node");
        assert_eq!(fp.name, "field_0x8");
    }

    // -----------------------------------------------------------------------
    // Test 3: DataPtr → Pointer
    // -----------------------------------------------------------------------
    #[test]
    fn data_sentinel_emits_pointer() {
        let buf = build_test_buf();
        let nodes = dissect_buffer(0x1000, &buf, fake_classify);

        let ptr = nodes.iter().find(|n| n.type_tag == "Pointer")
            .expect("expected a Pointer node");
        assert_eq!(ptr.name, "field_0x10");
    }

    // -----------------------------------------------------------------------
    // Test 4: Inline ASCII string → Utf8Text; offset advances correctly
    // -----------------------------------------------------------------------
    #[test]
    fn inline_ascii_emits_utf8text_and_advances_to_next_slot() {
        let buf = build_test_buf();
        let nodes = dissect_buffer(0x1000, &buf, fake_classify);

        let txt = nodes.iter().find(|n| n.type_tag == "Utf8Text")
            .expect("expected a Utf8Text node");
        assert_eq!(txt.name, "field_0x18", "string starts at offset 24 = 0x18");

        // The run is 5 bytes ("Hello"); length attr must reflect that.
        let length = txt.attrs.get("length")
            .and_then(|v| if let toml::Value::Integer(i) = v { Some(*i) } else { None })
            .expect("Utf8Text must have a 'length' attr");
        assert_eq!(length, 5, "run length is 5 bytes");

        // After the string (5 bytes, rounded up to 8) the next field is at
        // offset 32, so we expect Int64 there.
        let int_node = nodes.iter().find(|n| n.type_tag == "Int64")
            .expect("expected an Int64 node after the string");
        assert_eq!(int_node.name, "field_0x20", "Int64 at offset 32 = 0x20");
    }

    // -----------------------------------------------------------------------
    // Test 5: Small integer → Int64; large/garbage → Hex64
    // -----------------------------------------------------------------------
    #[test]
    fn integer_heuristic_small_is_int64_large_is_hex64() {
        let buf = build_test_buf();
        let nodes = dissect_buffer(0x1000, &buf, fake_classify);

        let int_node = nodes.iter().find(|n| n.type_tag == "Int64")
            .expect("expected Int64 for small integer");
        assert_eq!(int_node.name, "field_0x20");

        let hex_node = nodes.iter().find(|n| n.type_tag == "Hex64")
            .expect("expected Hex64 for large value");
        assert_eq!(hex_node.name, "field_0x28");
    }

    // -----------------------------------------------------------------------
    // Test 6: Full sequence — correct node count and order
    // -----------------------------------------------------------------------
    #[test]
    fn full_sequence_node_count_and_type_order() {
        let buf = build_test_buf();
        let nodes = dissect_buffer(0x1000, &buf, fake_classify);

        // Expected: VTable, FunctionPtr, Pointer, Utf8Text, Int64, Hex64
        assert_eq!(nodes.len(), 6, "expected exactly 6 nodes from 48-byte buffer");

        let tags: Vec<&str> = nodes.iter().map(|n| n.type_tag.as_str()).collect();
        assert_eq!(
            tags,
            &["VTable", "FunctionPtr", "Pointer", "Utf8Text", "Int64", "Hex64"],
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: Null word (value == 0) → Int64 (zero is "small")
    // -----------------------------------------------------------------------
    #[test]
    fn null_word_emits_int64() {
        let buf = [0u8; 8]; // single null word
        let nodes = dissect_buffer(0, &buf, fake_classify);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].type_tag, "Int64");
    }

    // -----------------------------------------------------------------------
    // Test 8: Buffer too short (< 8 bytes) → no nodes emitted
    // -----------------------------------------------------------------------
    #[test]
    fn short_buffer_emits_no_nodes() {
        let buf = [0u8; 7];
        let nodes = dissect_buffer(0, &buf, |_| PointerClass::Null);
        assert!(nodes.is_empty(), "fewer than 8 bytes must not produce any nodes");
    }

    // -----------------------------------------------------------------------
    // Test 9: Registry round-trip — each emitted def deserializes via
    //         NodeRegistry::with_builtins() into a live node with the right
    //         type_tag.  This proves dissect_buffer produces valid NodeDefs.
    // -----------------------------------------------------------------------
    #[test]
    fn emitted_defs_survive_registry_round_trip() {
        let buf = build_test_buf();
        let nodes = dissect_buffer(0x1000, &buf, fake_classify);
        let reg = NodeRegistry::new().with_builtins();

        for def in &nodes {
            let tag = def.type_tag.clone();
            let live = reg.deserialize_node(def.clone())
                .unwrap_or_else(|e| panic!("failed to deserialize '{tag}' NodeDef: {e}"));
            assert_eq!(
                live.type_tag(), tag.as_str(),
                "round-trip tag mismatch for '{tag}'"
            );
            // For VTable, verify children deserialized correctly.
            if tag == "VTable" {
                assert_eq!(live.children().len(), 3, "VTable must have 3 children after round-trip");
                for child in live.children() {
                    assert_eq!(child.type_tag(), "VMethod");
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Test 10: UTF-16LE inline string → Utf16Text node
    // -----------------------------------------------------------------------
    #[test]
    fn inline_utf16le_emits_utf16text() {
        // Build an 8-byte buffer with "Hi!!" as UTF-16LE (4 chars = 8 bytes
        // exactly), fitting in one 8-byte slot.
        // 'H'=0x48, 'i'=0x69, '!'=0x21, '!'=0x21 → each followed by 0x00.
        let buf: Vec<u8> = vec![
            0x48, 0x00, 0x69, 0x00, 0x21, 0x00, 0x21, 0x00,
        ];
        // The classify closure is never reached because string_at fires first.
        let nodes = dissect_buffer(0, &buf, |_| PointerClass::Null);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].type_tag, "Utf16Text");
        let length = nodes[0].attrs.get("length")
            .and_then(|v| if let toml::Value::Integer(i) = v { Some(*i) } else { None })
            .expect("Utf16Text must have 'length' attr");
        assert_eq!(length, 8, "4 UTF-16LE chars = 8 bytes");
    }
}
