//! Printable-run detection over a raw byte buffer.
//!
//! The memory viewer/dissector snapshots a region of a target's memory into a
//! `&[u8]` and asks "where are the strings?". These helpers answer that purely,
//! with no process dependency, so they compile and test on every platform.
//!
//! Two encodings are recognised: NUL-terminated / packed **ASCII** (a run of
//! printable bytes) and **UTF-16LE** (printable ASCII code points stored as
//! `char, 0x00` pairs — the common Windows/Wine wide-string layout). When a span
//! of bytes reads as UTF-16LE *and* as ASCII (the low bytes alone), UTF-16LE
//! wins so the same bytes aren't reported twice.

/// The encoding a detected [`StringRun`] was recognised as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrKind {
    /// A packed run of printable ASCII bytes (one byte per character).
    Ascii,
    /// Little-endian UTF-16 of printable ASCII code points (`char, 0x00` pairs).
    Utf16Le,
}

/// One printable run found in a buffer: where it starts, how many *bytes* it
/// spans, its decoded text and its encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringRun {
    /// Byte offset of the run's first byte within the scanned buffer.
    pub offset: usize,
    /// Length of the run in *bytes* (for UTF-16LE this is `2 * chars`).
    pub len_bytes: usize,
    /// The decoded text.
    pub text: String,
    /// The encoding the run was recognised as.
    pub kind: StrKind,
}

/// Is `b` a byte we treat as a printable string character?
///
/// Printable ASCII (`0x20..=0x7E`) plus `\t` — the same permissive set
/// ReClass.NET uses so that paths and tab-separated text survive, while control
/// bytes and high-bit bytes terminate a run.
#[inline]
fn is_printable(b: u8) -> bool {
    b == b'\t' || (0x20..=0x7E).contains(&b)
}

/// Measures a UTF-16LE run starting at `buf[start]`: consecutive `char, 0x00`
/// pairs whose low byte is [`is_printable`]. Returns `(char_count, text)`.
///
/// The `0x00` high byte is what distinguishes a wide-string from packed ASCII —
/// only Basic-Latin code points (high byte 0) are accepted, which is exactly the
/// set that would *also* read as ASCII, hence the UTF-16-wins tie-break in
/// [`detect_strings`].
fn measure_utf16le(buf: &[u8], start: usize) -> (usize, String) {
    let mut text = String::new();
    let mut i = start;
    while i + 1 < buf.len() && is_printable(buf[i]) && buf[i + 1] == 0x00 {
        text.push(buf[i] as char);
        i += 2;
    }
    (text.len(), text)
}

/// Measures an ASCII run starting at `buf[start]`: consecutive [`is_printable`]
/// bytes. Returns `(byte_count, text)`.
fn measure_ascii(buf: &[u8], start: usize) -> (usize, String) {
    let mut text = String::new();
    let mut i = start;
    while i < buf.len() && is_printable(buf[i]) {
        text.push(buf[i] as char);
        i += 1;
    }
    (text.len(), text)
}

/// Scans `buf` for printable runs of at least `min_len` characters and returns
/// them in ascending offset order.
///
/// At each candidate offset a UTF-16LE run is preferred over an ASCII run when
/// both qualify (`>= min_len` chars), so a wide string's low bytes aren't *also*
/// reported as a shorter ASCII fragment. A `min_len` of `0` is treated as `1`
/// (an empty run is never a string).
pub fn detect_strings(buf: &[u8], min_len: usize) -> Vec<StringRun> {
    let min_len = min_len.max(1);
    let mut out = Vec::new();
    let mut i = 0;

    while i < buf.len() {
        // Prefer UTF-16LE when the interleave pattern holds for >= min_len chars.
        let (u16_chars, u16_text) = measure_utf16le(buf, i);
        if u16_chars >= min_len {
            let len_bytes = u16_chars * 2;
            out.push(StringRun {
                offset: i,
                len_bytes,
                text: u16_text,
                kind: StrKind::Utf16Le,
            });
            i += len_bytes;
            continue;
        }

        // Otherwise fall back to a packed-ASCII run.
        let (a_chars, a_text) = measure_ascii(buf, i);
        if a_chars >= min_len {
            out.push(StringRun {
                offset: i,
                len_bytes: a_chars,
                text: a_text,
                kind: StrKind::Ascii,
            });
            i += a_chars;
            continue;
        }

        // No qualifying run here: advance one byte. (Advancing by the failed
        // ASCII length would be wrong when a sub-`min_len` printable prefix is
        // followed by a qualifying UTF-16LE run.)
        i += 1;
    }

    out
}

/// Reports whether a printable run of at least `min_len` characters starts
/// *exactly* at `offset`, returning it if so.
///
/// This is the pointed-at-string probe the pointer classifier / dissector uses:
/// given a data pointer, is `*ptr` the first byte of a string? UTF-16LE is again
/// preferred over ASCII when both qualify. Returns `None` for an out-of-range
/// offset or a too-short / non-printable start.
pub fn string_at(buf: &[u8], offset: usize, min_len: usize) -> Option<StringRun> {
    let min_len = min_len.max(1);
    if offset >= buf.len() {
        return None;
    }

    let (u16_chars, u16_text) = measure_utf16le(buf, offset);
    if u16_chars >= min_len {
        return Some(StringRun {
            offset,
            len_bytes: u16_chars * 2,
            text: u16_text,
            kind: StrKind::Utf16Le,
        });
    }

    let (a_chars, a_text) = measure_ascii(buf, offset);
    if a_chars >= min_len {
        return Some(StringRun {
            offset,
            len_bytes: a_chars,
            text: a_text,
            kind: StrKind::Ascii,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ascii_c_string() {
        // "hello\0" — the run is the 5 printable bytes, NUL terminates it.
        let buf = b"hello\0";
        let runs = detect_strings(buf, 4);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].offset, 0);
        assert_eq!(runs[0].len_bytes, 5);
        assert_eq!(runs[0].text, "hello");
        assert_eq!(runs[0].kind, StrKind::Ascii);
    }

    #[test]
    fn detects_utf16le_string() {
        // "Hi!" as UTF-16LE: 48 00 69 00 21 00.
        let buf = [0x48, 0x00, 0x69, 0x00, 0x21, 0x00];
        let runs = detect_strings(&buf, 3);
        assert_eq!(runs.len(), 1, "must not also report the ascii low bytes");
        assert_eq!(runs[0].offset, 0);
        assert_eq!(runs[0].len_bytes, 6);
        assert_eq!(runs[0].text, "Hi!");
        assert_eq!(runs[0].kind, StrKind::Utf16Le);
    }

    #[test]
    fn rejects_too_short_run() {
        // "ab\0" is only 2 printable chars; min_len 4 rejects it.
        let buf = b"ab\0\0\0\0";
        assert!(detect_strings(buf, 4).is_empty());
    }

    #[test]
    fn detects_both_ascii_and_utf16_in_one_buffer() {
        // ascii "path" (4 chars), a NUL, then UTF-16LE "OK!" (3 chars).
        let mut buf = Vec::new();
        buf.extend_from_slice(b"path\0");
        buf.extend_from_slice(&[0x4F, 0x00, 0x4B, 0x00, 0x21, 0x00]); // "OK!"
        let runs = detect_strings(&buf, 3);
        assert_eq!(runs.len(), 2);

        assert_eq!(runs[0].text, "path");
        assert_eq!(runs[0].kind, StrKind::Ascii);
        assert_eq!(runs[0].offset, 0);

        assert_eq!(runs[1].text, "OK!");
        assert_eq!(runs[1].kind, StrKind::Utf16Le);
        assert_eq!(runs[1].offset, 5);
    }

    #[test]
    fn string_at_requires_exact_start() {
        let buf = b"\0hello";
        // No run starts at offset 0 (it's a NUL).
        assert!(string_at(buf, 0, 4).is_none());
        // A run does start at offset 1.
        let run = string_at(buf, 1, 4).expect("string starts at offset 1");
        assert_eq!(run.text, "hello");
        assert_eq!(run.offset, 1);
        // Out-of-range offset.
        assert!(string_at(buf, 99, 4).is_none());
    }

    #[test]
    fn short_ascii_prefix_does_not_hide_utf16_run() {
        // "ab" (2 printable) is below min_len 4; a UTF-16LE run follows and must
        // still be found — i.e. we don't skip past the failed ascii length.
        let mut buf = Vec::new();
        buf.extend_from_slice(b"ab"); // printable but too short on its own
        buf.push(0xFF); // non-printable break
        buf.extend_from_slice(&[0x77, 0x00, 0x69, 0x00, 0x64, 0x00, 0x65, 0x00]); // "wide"
        let runs = detect_strings(&buf, 4);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].text, "wide");
        assert_eq!(runs[0].kind, StrKind::Utf16Le);
    }
}
