//! Host-API traits the scripts call, plus a real IDA-style byte-pattern matcher.
//!
//! The traits ([`PatternScan`], `DeclareType`, `DeclareClass` on [`TypeDeclare`])
//! are the surface the *host* implements and exposes to scripts (in M2, via
//! [`crate::ScriptEngine::register_host_fn`]). M1 defines the contracts and a
//! pure, unit-tested [`find_pattern`] matcher that backs [`PatternScan`];
//! wiring it to live process/module memory is a thin adapter (sketched by
//! [`scan_module`]).

use nemclass_core::Result as CoreResult;
use nemclass_model::EnumDescription;

/// IDA-style pattern scanning over a target module.
///
/// The host implements this against a live [`nemclass_core::Process`]; scripts
/// call it as `pattern_scan("game.exe", "48 8B ?? ??")`. Wildcards are `??` or a
/// single `?` (either matches any byte); other tokens are two hex nibbles.
pub trait PatternScan {
    /// Scans `module` for `pattern`, returning every absolute match address.
    ///
    /// Errors if the module is not present or its memory cannot be read; an
    /// empty `Vec` means "no matches", which is not an error.
    fn pattern_scan(&self, module: &str, pattern: &str) -> CoreResult<Vec<usize>>;
}

/// Declaring custom types and classes from scripts.
///
/// Mirrors ReClass.NET's plugin ability to contribute node/type info. `declare_*`
/// mutates the host's model registries (a [`nemclass_model::NodeRegistry`] and
/// the open [`nemclass_model::Project`]); M2 exposes them to JS as host
/// functions. Kept as a trait so the host owns the model and scripts only
/// declare *into* it.
pub trait TypeDeclare {
    /// Declares a custom type (e.g. an enum) into the host's model.
    ///
    /// M1 models the "type" as an [`EnumDescription`] — the concrete custom-type
    /// payload the model already understands; richer type descriptors slot in
    /// here later without changing the call shape.
    fn declare_type(&mut self, ty: EnumDescription) -> CoreResult<()>;

    /// Declares a class by name with an address formula, returning nothing on
    /// success. The host creates a `ClassNode` and inserts it into the open
    /// project. `address_formula` is an address-parser expression such as
    /// `"game.exe"+0x1000` (see [`nemclass_model::resolve_formula`]).
    fn declare_class(&mut self, name: &str, address_formula: &str) -> CoreResult<()>;
}

/// One parsed pattern element: an exact byte or a wildcard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatByte {
    /// Match this exact byte.
    Byte(u8),
    /// Match any byte (`??` / `?`).
    Any,
}

/// Parses an IDA-style pattern string (`"48 8B ?? ?? E8"`) into a mask.
///
/// Accepted tokens (whitespace-separated):
/// - two hex nibbles → an exact byte (`4A`, `0f`);
/// - `??` or a single `?` → a wildcard byte.
///
/// Returns `None` on any malformed token (bad hex, wrong length) or an empty
/// pattern, so callers can surface a clean error instead of scanning garbage.
fn parse_pattern(pattern: &str) -> Option<Vec<PatByte>> {
    let mut out = Vec::new();
    for tok in pattern.split_whitespace() {
        match tok {
            "?" | "??" => out.push(PatByte::Any),
            hex => {
                if hex.len() != 2 {
                    return None;
                }
                let byte = u8::from_str_radix(hex, 16).ok()?;
                out.push(PatByte::Byte(byte));
            }
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Finds every offset in `haystack` where `pattern` matches (IDA-style).
///
/// `pattern` is parsed by [`parse_pattern`]: hex bytes match exactly, `??`/`?`
/// match any byte. Returns the byte offsets (relative to the start of
/// `haystack`) of every match; a caller scanning a module adds the module base
/// to turn these into absolute addresses (see [`scan_module`]). A malformed or
/// empty pattern yields no matches.
///
/// This is deliberately a pure function over an in-memory buffer so it is cheap
/// and fully testable without a live process.
pub fn find_pattern(haystack: &[u8], pattern: &str) -> Vec<usize> {
    let Some(pat) = parse_pattern(pattern) else {
        return Vec::new();
    };
    if pat.len() > haystack.len() {
        return Vec::new();
    }

    let mut matches = Vec::new();
    // Last start offset at which the pattern can still fit.
    let last = haystack.len() - pat.len();
    for start in 0..=last {
        let window = &haystack[start..start + pat.len()];
        let hit = window
            .iter()
            .zip(&pat)
            .all(|(&b, p)| match p {
                PatByte::Any => true,
                PatByte::Byte(expected) => b == *expected,
            });
        if hit {
            matches.push(start);
        }
    }
    matches
}

/// Thin adapter that turns [`find_pattern`] offsets into absolute addresses in a
/// module.
///
/// The M2 host implementation of [`PatternScan::pattern_scan`] does exactly
/// this: read the module's bytes from the target (via
/// [`nemclass_core::Process`]), run [`find_pattern`], and add `module_base` to
/// each offset. Provided here so the offset→address contract is pinned and
/// tested now; the "read the module bytes" step is the only live-process piece,
/// which is why it is passed in as `module_bytes`.
pub fn scan_module(module_base: usize, module_bytes: &[u8], pattern: &str) -> Vec<usize> {
    find_pattern(module_bytes, pattern)
        .into_iter()
        .map(|off| module_base + off)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HAYSTACK: &[u8] = &[
        0x48, 0x8B, 0x05, 0x10, 0x20, // 0
        0x90, 0x90, // padding
        0x48, 0x8B, 0x05, 0xAA, 0xBB, // 7 (second occurrence, different tail)
        0x48, 0x8B, 0x0D, 0x00, // near-miss (0x0D not 0x05)
    ];

    #[test]
    fn exact_match_single() {
        // Fully specified, unique bytes.
        let hits = find_pattern(HAYSTACK, "48 8B 05 10 20");
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn exact_match_multiple_occurrences() {
        // "48 8B 05" appears at offset 0 and offset 7 (but not at 12: 0x0D).
        let hits = find_pattern(HAYSTACK, "48 8B 05");
        assert_eq!(hits, vec![0, 7]);
    }

    #[test]
    fn wildcard_double_and_single_question_mark() {
        // Both `??` and `?` are wildcards; this matches both 05-tails at 0 and 7.
        let hits = find_pattern(HAYSTACK, "48 8B 05 ?? ??");
        assert_eq!(hits, vec![0, 7]);

        let hits_single = find_pattern(HAYSTACK, "48 8B 05 ? ?");
        assert_eq!(hits_single, vec![0, 7]);
    }

    #[test]
    fn wildcard_in_the_middle() {
        // 48 8B ?? matches all three "48 8B .." triples (0x05, 0x05, 0x0D).
        let hits = find_pattern(HAYSTACK, "48 8B ??");
        assert_eq!(hits, vec![0, 7, 12]);
    }

    #[test]
    fn no_match_returns_empty() {
        assert!(find_pattern(HAYSTACK, "DE AD BE EF").is_empty());
    }

    #[test]
    fn pattern_longer_than_haystack_is_empty() {
        assert!(find_pattern(&[0x48u8], "48 8B 05").is_empty());
    }

    #[test]
    fn lowercase_hex_is_accepted() {
        assert_eq!(find_pattern(HAYSTACK, "48 8b 05"), vec![0, 7]);
    }

    #[test]
    fn malformed_pattern_yields_no_matches() {
        // Non-hex token, wrong-length token, and empty pattern all no-op.
        assert!(find_pattern(HAYSTACK, "48 ZZ 05").is_empty());
        assert!(find_pattern(HAYSTACK, "48 8 05").is_empty());
        assert!(find_pattern(HAYSTACK, "").is_empty());
        assert!(find_pattern(HAYSTACK, "   ").is_empty());
    }

    #[test]
    fn all_wildcards_matches_every_window() {
        let buf = [1u8, 2, 3, 4];
        // Two-wide all-wildcard pattern matches offsets 0,1,2.
        assert_eq!(find_pattern(&buf, "?? ??"), vec![0, 1, 2]);
    }

    #[test]
    fn scan_module_offsets_become_absolute_addresses() {
        let base = 0x1400_0000;
        let hits = scan_module(base, HAYSTACK, "48 8B 05");
        assert_eq!(hits, vec![base, base + 7]);
    }
}
