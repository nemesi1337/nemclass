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
/// call it as `pattern_scan("game.exe", "48 8B ?? ??")`. Tokens are two hex
/// nibbles (`4A`), a full wildcard (`??`/`?`), or a nibble wildcard (`4?`/`?8`).
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

/// Why a pattern string could not be parsed. Lets callers tell a *malformed*
/// pattern (a bug in the script) apart from a valid pattern that simply *did not
/// match* — the two were previously indistinguishable (both an empty `Vec`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    /// The pattern had no tokens.
    #[error("empty pattern")]
    Empty,
    /// A token was neither a hex byte, a nibble-wildcard, nor `?`/`??`.
    #[error("malformed pattern token: '{0}'")]
    BadToken(String),
}

/// One parsed pattern element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatByte {
    /// Match this exact byte.
    Byte(u8),
    /// Match any byte (`??` / `?`).
    Any,
    /// Match only the masked nibble (`4?` → value `0x40`, mask `0xF0`; `?8` →
    /// value `0x08`, mask `0x0F`).
    Nibble { value: u8, mask: u8 },
}

/// Parses one whitespace-separated token into a [`PatByte`].
///
/// Accepted: two hex nibbles (`4A`, `0f`); `?`/`??` (any byte); a mixed
/// nibble/wildcard (`4?`, `?8`). Anything else is a [`PatternError::BadToken`].
fn parse_token(tok: &str) -> Result<PatByte, PatternError> {
    if tok == "?" || tok == "??" {
        return Ok(PatByte::Any);
    }
    let b = tok.as_bytes();
    if b.len() != 2 {
        return Err(PatternError::BadToken(tok.to_string()));
    }
    let hi = (b[0] as char).to_digit(16);
    let lo = (b[1] as char).to_digit(16);
    match (hi, lo, b[0] == b'?', b[1] == b'?') {
        (Some(h), Some(l), _, _) => Ok(PatByte::Byte(((h << 4) | l) as u8)),
        (Some(h), None, _, true) => Ok(PatByte::Nibble { value: (h as u8) << 4, mask: 0xF0 }),
        (None, Some(l), true, _) => Ok(PatByte::Nibble { value: l as u8, mask: 0x0F }),
        _ => Err(PatternError::BadToken(tok.to_string())),
    }
}

/// Parses a full IDA-style pattern string (`"48 8B 4? ?? E8"`) into a mask,
/// erroring on any malformed token or an empty pattern.
fn parse_pattern_checked(pattern: &str) -> Result<Vec<PatByte>, PatternError> {
    let out: Vec<PatByte> = pattern
        .split_whitespace()
        .map(parse_token)
        .collect::<Result<_, _>>()?;
    if out.is_empty() {
        Err(PatternError::Empty)
    } else {
        Ok(out)
    }
}

#[inline]
fn pat_matches(p: &PatByte, b: u8) -> bool {
    match *p {
        PatByte::Byte(expected) => b == expected,
        PatByte::Any => true,
        PatByte::Nibble { value, mask } => (b & mask) == value,
    }
}

/// Finds every offset in `haystack` where `pattern` matches, or a
/// [`PatternError`] if the pattern itself is malformed.
///
/// Prefer this over [`find_pattern`] when scanning a user/script-supplied
/// pattern so a typo surfaces as an error instead of a silent empty result.
pub fn try_find_pattern(haystack: &[u8], pattern: &str) -> Result<Vec<usize>, PatternError> {
    let pat = parse_pattern_checked(pattern)?;
    if pat.len() > haystack.len() {
        return Ok(Vec::new());
    }
    let mut matches = Vec::new();
    // Last start offset at which the pattern can still fit.
    let last = haystack.len() - pat.len();
    for start in 0..=last {
        let hit = haystack[start..start + pat.len()]
            .iter()
            .zip(&pat)
            .all(|(&b, p)| pat_matches(p, b));
        if hit {
            matches.push(start);
        }
    }
    Ok(matches)
}

/// Lenient wrapper over [`try_find_pattern`]: a malformed/empty pattern yields
/// no matches (rather than an error). Kept for callers that only care about the
/// hit list; hex bytes match exactly, `??`/`?` match any byte, `4?`/`?8` match a
/// single nibble. Offsets are relative to `haystack`; add the module base for
/// absolute addresses (see [`scan_module`]). Pure over an in-memory buffer, so
/// it is cheap and fully testable without a live process.
pub fn find_pattern(haystack: &[u8], pattern: &str) -> Vec<usize> {
    try_find_pattern(haystack, pattern).unwrap_or_default()
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

    #[test]
    fn nibble_wildcards_match_masked_half_byte() {
        // "4?" matches 0x40..=0x4F (0x48 qualifies) as the first byte.
        assert_eq!(find_pattern(HAYSTACK, "4? 8B 05"), vec![0, 7]);
        // "?B" matches the low nibble B (0x8B qualifies) as the second byte.
        assert_eq!(find_pattern(HAYSTACK, "48 ?B 05"), vec![0, 7]);
        // "0?" as the third byte matches 0x05 (offsets 0, 7) and 0x0D (offset 12).
        assert_eq!(find_pattern(HAYSTACK, "48 8B 0?"), vec![0, 7, 12]);
    }

    #[test]
    fn try_find_pattern_distinguishes_malformed_from_no_match() {
        // Valid pattern, no match → Ok(empty), NOT an error.
        assert_eq!(try_find_pattern(HAYSTACK, "DE AD BE EF"), Ok(vec![]));
        // Malformed tokens → error (a script typo, not "no matches").
        assert_eq!(
            try_find_pattern(HAYSTACK, "48 ZZ"),
            Err(PatternError::BadToken("ZZ".to_string()))
        );
        assert_eq!(
            try_find_pattern(HAYSTACK, "48 8"),
            Err(PatternError::BadToken("8".to_string()))
        );
        assert_eq!(try_find_pattern(HAYSTACK, ""), Err(PatternError::Empty));
    }
}
