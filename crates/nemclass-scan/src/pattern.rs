//! Array-of-bytes (AOB) pattern with per-nibble `??` wildcards.
//!
//! This is a local reimplementation of the masking idea behind
//! `nemclass_script::find_pattern` (and ReClass.NET's `BytePattern`), kept in
//! this crate so the scanner never depends on `nemclass-script`. A pattern is a
//! fixed-length sequence of byte matchers; each matcher is either an exact byte
//! or carries a per-nibble mask so `A?`, `?B`, and `??` all work.

use core::fmt;

/// One byte of a [`BytePattern`]: a value plus a nibble mask.
///
/// `mask` has a set bit for every nibble that must match: `0xFF` = both nibbles
/// significant (exact byte), `0xF0` = high nibble only (`A?`), `0x0F` = low
/// nibble only (`?B`), `0x00` = full wildcard (`??`). A candidate byte matches
/// when `(candidate & mask) == (value & mask)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternByte {
    value: u8,
    mask: u8,
}

impl PatternByte {
    /// An exact byte (both nibbles significant).
    pub const fn exact(value: u8) -> Self {
        Self { value, mask: 0xFF }
    }

    /// A full `??` wildcard byte (neither nibble significant).
    pub const fn wildcard() -> Self {
        Self { value: 0, mask: 0x00 }
    }

    /// Whether this byte has any wildcard nibble.
    #[inline]
    pub const fn is_wildcard(&self) -> bool {
        self.mask != 0xFF
    }

    /// The matcher's byte value. Only meaningful when it is not a wildcard.
    #[inline]
    pub const fn value(&self) -> u8 {
        self.value
    }

    /// Tests a candidate byte against this matcher.
    #[inline]
    pub const fn matches(&self, candidate: u8) -> bool {
        (candidate & self.mask) == (self.value & self.mask)
    }
}

/// A parse error from [`BytePattern::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError(pub String);

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid byte pattern: {}", self.0)
    }
}

impl std::error::Error for PatternError {}

/// A fixed-length array-of-bytes pattern with optional per-nibble wildcards.
///
/// Parsed from a whitespace-tolerant hex string like `48 8B ?? D? ?E C3`
/// (mirrors ReClass.NET's `BytePattern.Parse`): tokens are two nibbles each,
/// where a nibble is a hex digit or `?`. A lone `?` between whitespace is
/// treated as a full wildcard byte, matching the reference parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern {
    bytes: Vec<PatternByte>,
}

impl BytePattern {
    /// Builds an exact (wildcard-free) pattern from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            bytes: data.iter().copied().map(PatternByte::exact).collect(),
        }
    }

    /// Builds a pattern from explicit matchers.
    pub fn from_matchers(bytes: Vec<PatternByte>) -> Self {
        Self { bytes }
    }

    /// The first byte of the pattern when it is fully significant.
    ///
    /// A scan can skip straight to each occurrence of this byte instead of
    /// testing every position, but only if a match is *required* to start with
    /// it — a leading wildcard makes any byte a legal start.
    pub fn first_literal_byte(&self) -> Option<u8> {
        match self.bytes.first() {
            Some(b) if !b.is_wildcard() => Some(b.value()),
            _ => None,
        }
    }

    /// Parses a hex pattern string with `??`/`A?`/`?B` wildcards.
    ///
    /// Accepts spaces (and any ASCII whitespace) between tokens, upper- or
    /// lower-case hex, and both `AABB` and `AA BB` spacings. A single `?` token
    /// (surrounded by whitespace) becomes a full wildcard byte. Returns
    /// [`PatternError`] on a stray non-hex/non-`?` character or a dangling
    /// nibble, and rejects the empty pattern.
    pub fn parse(input: &str) -> Result<Self, PatternError> {
        let mut bytes = Vec::new();
        let mut chars = input.chars().peekable();

        loop {
            // Skip inter-token whitespace.
            while chars.peek().is_some_and(|c| c.is_whitespace()) {
                chars.next();
            }
            let Some(first) = chars.next() else { break };

            let hi = parse_nibble(first)
                .ok_or_else(|| PatternError(format!("unexpected character '{first}'")))?;

            // The second nibble: a run-on hex/`?` char forms a two-nibble token
            // (`AA`, `A?`); whitespace or end-of-string makes the first nibble a
            // half byte whose low nibble is a wildcard (`A ` -> `A?`, `?` -> `??`).
            let lo = match chars.peek() {
                Some(&c) if !c.is_whitespace() => {
                    let n = parse_nibble(c)
                        .ok_or_else(|| PatternError(format!("unexpected character '{c}'")))?;
                    chars.next();
                    n
                }
                _ => Nibble::Wildcard,
            };

            bytes.push(nibbles_to_byte(hi, lo));
        }

        if bytes.is_empty() {
            return Err(PatternError("pattern is empty".to_owned()));
        }
        Ok(Self { bytes })
    }

    /// Number of bytes the pattern spans (its stride).
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the pattern is empty (only possible via [`BytePattern::from_bytes`]
    /// with an empty slice; [`BytePattern::parse`] rejects it).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether any byte carries a wildcard nibble.
    pub fn has_wildcards(&self) -> bool {
        self.bytes.iter().any(PatternByte::is_wildcard)
    }

    /// Tests whether the pattern matches `data` starting at `index`.
    ///
    /// Returns `false` (never panics) when the pattern would run past the end of
    /// `data`.
    pub fn matches_at(&self, data: &[u8], index: usize) -> bool {
        let Some(window) = data.get(index..index + self.bytes.len()) else {
            return false;
        };
        self.bytes
            .iter()
            .zip(window)
            .all(|(pb, &b)| pb.matches(b))
    }
}

/// A single parsed nibble: a 0-15 value or a wildcard.
enum Nibble {
    Value(u8),
    Wildcard,
}

/// Parses one nibble character (`0-9`/`a-f`/`A-F`/`?`).
fn parse_nibble(c: char) -> Option<Nibble> {
    match c {
        '?' => Some(Nibble::Wildcard),
        _ => c.to_digit(16).map(|d| Nibble::Value(d as u8)),
    }
}

/// Combines a high and low nibble into a [`PatternByte`], propagating wildcards
/// into the nibble mask.
fn nibbles_to_byte(hi: Nibble, lo: Nibble) -> PatternByte {
    let mut value = 0u8;
    let mut mask = 0u8;
    if let Nibble::Value(v) = hi {
        value |= v << 4;
        mask |= 0xF0;
    }
    if let Nibble::Value(v) = lo {
        value |= v;
        mask |= 0x0F;
    }
    PatternByte { value, mask }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_pattern_spaced_and_packed() {
        let a = BytePattern::parse("48 8B C3").unwrap();
        let b = BytePattern::parse("488BC3").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 3);
        assert!(!a.has_wildcards());
        assert!(a.matches_at(&[0x00, 0x48, 0x8B, 0xC3], 1));
        assert!(!a.matches_at(&[0x48, 0x8B, 0xC4], 0));
    }

    #[test]
    fn full_and_nibble_wildcards() {
        // `??` full byte, `D?` high nibble, `?E` low nibble.
        let p = BytePattern::parse("AA ?? D? ?E").unwrap();
        assert!(p.has_wildcards());
        assert!(p.matches_at(&[0xAA, 0x00, 0xD5, 0x7E], 0));
        assert!(p.matches_at(&[0xAA, 0xFF, 0xDF, 0x0E], 0));
        // High nibble of the `D?` byte must be D.
        assert!(!p.matches_at(&[0xAA, 0x00, 0xE5, 0x7E], 0));
        // Low nibble of the `?E` byte must be E.
        assert!(!p.matches_at(&[0xAA, 0x00, 0xD5, 0x7F], 0));
    }

    #[test]
    fn lone_question_mark_is_full_wildcard() {
        let p = BytePattern::parse("? AA ?").unwrap();
        assert_eq!(p.len(), 3);
        assert!(p.matches_at(&[0x12, 0xAA, 0x99], 0));
    }

    #[test]
    fn rejects_garbage_and_empty() {
        assert!(BytePattern::parse("XY").is_err());
        assert!(BytePattern::parse("").is_err());
        assert!(BytePattern::parse("   ").is_err());
    }

    #[test]
    fn no_read_past_end() {
        let p = BytePattern::parse("AA BB CC").unwrap();
        assert!(!p.matches_at(&[0xAA, 0xBB], 0));
        assert!(!p.matches_at(&[0xAA, 0xBB, 0xCC], 1));
    }
}
