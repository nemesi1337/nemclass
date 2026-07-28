//! AOB signature **generation** — the inverse of pattern scanning.
//!
//! Given a module's bytes and an offset of interest, produce the shortest
//! exact-byte signature that occurs exactly once in the module, formatted as an
//! IDA-style hex string (`"48 8B 05 …"`) ready to feed back into
//! [`crate::BytePattern::parse`] / `scan.aob`. This is Cheat Engine's / ReClass's
//! "generate signature" operation.
//!
//! v1 emits **exact bytes** (no operand wildcards): it finds a locally-unique
//! run, which is enough to relocate the same code within one image. It does not
//! yet mask relative operands, so a signature may need regenerating across game
//! updates — call sites should treat it as a starting point.

/// Options for [`make_signature`].
#[derive(Debug, Clone, Copy)]
pub struct SignatureConfig {
    /// Never return a signature shorter than this (even if a shorter run is
    /// already unique) — longer signatures are more robust.
    pub min_len: usize,
    /// Give up (return `None`) if no unique run is found by this length.
    pub max_len: usize,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self { min_len: 8, max_len: 64 }
    }
}

/// Generate a unique AOB signature for `haystack[offset..]`.
///
/// Returns the IDA-style hex string of the shortest run (respecting
/// [`SignatureConfig::min_len`]) that appears exactly once in `haystack`, or
/// `None` if `offset` is out of range or no unique run exists within
/// [`SignatureConfig::max_len`].
pub fn make_signature(haystack: &[u8], offset: usize, cfg: &SignatureConfig) -> Option<String> {
    if offset >= haystack.len() || cfg.max_len == 0 {
        return None;
    }
    let first = haystack[offset];

    // Candidate start positions: every index whose byte matches ours. We narrow
    // this set by extending the compared length until only `offset` remains.
    let mut candidates: Vec<usize> = haystack
        .iter()
        .enumerate()
        .filter(|&(_, &b)| b == first)
        .map(|(i, _)| i)
        .collect();

    let max_len = cfg.max_len.min(haystack.len() - offset);
    let mut len = 1usize;

    while len < max_len && candidates.len() > 1 {
        len += 1;
        let cmp = haystack[offset + len - 1];
        candidates.retain(|&p| {
            // Keep positions whose byte at this depth still matches ours and that
            // don't run past the buffer.
            p + len <= haystack.len() && haystack[p + len - 1] == cmp
        });
    }

    // Only `offset` must remain for the run to be unique.
    if candidates != [offset] {
        return None;
    }

    // Extend to at least min_len (bounded by the buffer) for robustness.
    let final_len = len.max(cfg.min_len).min(haystack.len() - offset);
    Some(format_signature(&haystack[offset..offset + final_len]))
}

/// Format a byte slice as an uppercase, space-separated IDA hex string.
pub fn format_signature(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BytePattern;

    #[test]
    fn format_is_ida_style() {
        assert_eq!(format_signature(&[0x48, 0x8b, 0x05]), "48 8B 05");
        assert_eq!(format_signature(&[]), "");
    }

    #[test]
    fn generates_unique_signature_that_finds_itself() {
        // A buffer with a distinctive run only at offset 10.
        let mut buf = vec![0u8; 256];
        let unique = [0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        buf[10..10 + unique.len()].copy_from_slice(&unique);

        let sig = make_signature(&buf, 10, &SignatureConfig::default()).expect("signature");
        // The generated signature must locate exactly offset 10 in the buffer.
        let pat = BytePattern::parse(&sig).expect("parse generated sig");
        let hits: Vec<usize> =
            (0..buf.len()).filter(|&i| pat.matches_at(&buf, i)).collect();
        assert_eq!(hits, vec![10], "signature {sig:?} should match only at 10");
    }

    #[test]
    fn respects_min_len() {
        let mut buf = vec![0u8; 64];
        // A single distinctive byte at offset 5 would be unique at len 1, but
        // min_len must force a longer signature.
        buf[5] = 0xAB;
        let cfg = SignatureConfig { min_len: 4, max_len: 32 };
        let sig = make_signature(&buf, 5, &cfg).expect("signature");
        assert_eq!(sig.split_whitespace().count(), 4, "sig={sig}");
    }

    #[test]
    fn none_when_not_unique() {
        // A fully repeating buffer has no unique run of any bounded length.
        let buf = vec![0xAAu8; 128];
        let cfg = SignatureConfig { min_len: 1, max_len: 16 };
        assert!(make_signature(&buf, 0, &cfg).is_none());
    }

    #[test]
    fn out_of_range_offset_is_none() {
        let buf = vec![1u8, 2, 3];
        assert!(make_signature(&buf, 3, &SignatureConfig::default()).is_none());
    }
}
