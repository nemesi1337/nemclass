//! Scan value types and typed needle parsing/comparison — ports ReClass.NET's
//! `ScanValueType` plus the per-type `*MemoryComparer` logic.
//!
//! A [`ScanValueType`] knows its fixed byte width (its scan *stride*, when it
//! has one) and how to parse a textual needle into a [`Needle`]. The [`Needle`]
//! carries the parsed value(s) and does the actual per-candidate comparison
//! against raw bytes, dispatching on [`crate::ScanCompareType`]. This keeps all
//! endian/width/tolerance concerns in one place, out of the scan loop.
//!
//! Integers are little-endian (the only endianness a live x86/x86-64 Linux or
//! Windows target uses); strings are compared byte-for-byte after encoding the
//! needle (UTF-8 or UTF-16LE).

use crate::compare::ScanCompareType;
use crate::pattern::BytePattern;

/// The default float comparison tolerance for `Exact` (ReClass.NET's `Normal`
/// round mode with 2 significant digits: `±1/10^2 = ±0.01`). A candidate `v`
/// equals needle `n` when `n - tol < v < n + tol`.
pub const DEFAULT_FLOAT_TOLERANCE: f64 = 0.01;

/// The kind of value a scan searches for. Mirrors ReClass.NET's `ScanValueType`,
/// with the integer/float widths spelled out explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanValueType {
    /// Signed 8-bit integer.
    I8,
    /// Signed 16-bit integer.
    I16,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// 32-bit IEEE-754 float.
    F32,
    /// 64-bit IEEE-754 float.
    F64,
    /// Array of bytes / AOB pattern (may contain `??` wildcards).
    Bytes,
    /// UTF-8 encoded string.
    StringUtf8,
    /// UTF-16 (little-endian) encoded string.
    StringUtf16,
    /// UTF-32 (little-endian) encoded string.
    StringUtf32,
}

/// How a float candidate is compared to a float needle for equality — Cheat
/// Engine's and ReClass.NET's "rounding" setting.
///
/// A float almost never holds the value a user typed: `100.0` health may sit in
/// memory as `99.99998`. A single absolute tolerance (the old, only, behaviour)
/// handles that badly at both ends of the range — too coarse near zero, far too
/// fine at `1e7`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FloatRound {
    /// `|value - needle| < tolerance`. The historical behaviour, and still the
    /// default.
    #[default]
    Normal,
    /// Bit-for-bit equality of the two floats. Finds only a value written from
    /// exactly this literal.
    Strict,
    /// Compare the integral parts only: `4.7` matches a needle of `4`. This is
    /// what makes a health bar showing "100" findable when it is really
    /// `100.63`.
    Truncate,
}

impl ScanValueType {
    /// The fixed byte width of a value of this type, if it has one.
    ///
    /// Fixed-width for the numeric types; `None` for [`ScanValueType::Bytes`]
    /// and the string types, whose width is determined by the parsed needle
    /// (its pattern/encoded length) rather than the type itself.
    pub const fn fixed_width(&self) -> Option<usize> {
        match self {
            Self::I8 | Self::U8 => Some(1),
            Self::I16 | Self::U16 => Some(2),
            Self::I32 | Self::U32 | Self::F32 => Some(4),
            Self::I64 | Self::U64 | Self::F64 => Some(8),
            Self::Bytes | Self::StringUtf8 | Self::StringUtf16 | Self::StringUtf32 => None,
        }
    }

    /// Whether this is one of the string types.
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::StringUtf8 | Self::StringUtf16 | Self::StringUtf32)
    }

    /// Bytes per code unit for the string types; `None` for everything else.
    pub const fn code_unit_size(&self) -> Option<usize> {
        match self {
            Self::StringUtf8 => Some(1),
            Self::StringUtf16 => Some(2),
            Self::StringUtf32 => Some(4),
            _ => None,
        }
    }

    /// Compares `cur` against `prev` for a change-relative next scan that has no
    /// needle (`Increased`/`Decreased`/`Changed`/`Unchanged`).
    ///
    /// Interprets both spans *as this type* rather than as a raw magnitude, so
    /// `Increased` is true for an `i32` going `-1 → 1` and for an `f32` going
    /// `-1.5 → -0.5`; a bytewise or unsigned comparison gets both of those
    /// backwards. Routes through the same [`compare_int`]/[`compare_float`] the
    /// needle-ful path uses, with a zero needle the change-relative arms ignore.
    ///
    /// Variable-width types have no numeric ordering: `Changed`/`Unchanged` fall
    /// back to byte (in)equality and `Increased`/`Decreased` never match. Any
    /// needle-requiring compare returns `false` — the [`crate::Scanner`] rejects
    /// those before they reach here.
    pub fn compare_change(&self, compare: ScanCompareType, cur: &[u8], prev: &[u8]) -> bool {
        let Some(width) = self.fixed_width() else {
            return match compare {
                ScanCompareType::Changed => cur != prev,
                ScanCompareType::Unchanged => cur == prev,
                _ => false,
            };
        };
        if cur.len() < width || prev.len() < width {
            return false;
        }
        match self {
            Self::F32 | Self::F64 => {
                let (Some(c), Some(p)) = (read_float(cur, 0, width), read_float(prev, 0, width))
                else {
                    return false;
                };
                compare_float(compare, c, 0.0, None, Some(p), DEFAULT_FLOAT_TOLERANCE, FloatRound::Normal)
            }
            _ => {
                let signed = is_signed(*self);
                let (Some(c), Some(p)) = (
                    read_int(cur, 0, width, signed),
                    read_int(prev, 0, width, signed),
                ) else {
                    return false;
                };
                compare_int(compare, c, 0, None, Some(p))
            }
        }
    }

    /// The canonical lowercase tag for this type — the stable string used by the
    /// JS `scan.value` API and by [`crate::pointerscan`]/cheat-table persistence.
    pub const fn as_tag(&self) -> &'static str {
        match self {
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Bytes => "bytes",
            Self::StringUtf8 => "string_utf8",
            Self::StringUtf16 => "string_utf16",
            Self::StringUtf32 => "string_utf32",
        }
    }

    /// Parse a type tag (case-insensitive) back into a [`ScanValueType`].
    ///
    /// Accepts the canonical [`Self::as_tag`] forms plus common aliases
    /// (`float`→`f32`, `double`→`f64`, `aob`→`bytes`, `string`→`string_utf8`).
    /// Returns `None` for an unknown tag.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag.trim().to_ascii_lowercase().as_str() {
            "i8" => Some(Self::I8),
            "i16" => Some(Self::I16),
            "i32" => Some(Self::I32),
            "i64" => Some(Self::I64),
            "u8" => Some(Self::U8),
            "u16" => Some(Self::U16),
            "u32" => Some(Self::U32),
            "u64" => Some(Self::U64),
            "f32" | "float" => Some(Self::F32),
            "f64" | "double" => Some(Self::F64),
            "bytes" | "aob" => Some(Self::Bytes),
            "string_utf8" | "string" | "utf8" => Some(Self::StringUtf8),
            "string_utf16" | "utf16" => Some(Self::StringUtf16),
            "string_utf32" | "utf32" => Some(Self::StringUtf32),
            _ => None,
        }
    }

    /// Parses a textual `input` into a [`Needle`] of this type.
    ///
    /// Integers accept decimal or `0x`-prefixed hex; floats accept the usual
    /// Rust float syntax. [`ScanValueType::Bytes`] parses an AOB pattern (see
    /// [`BytePattern::parse`]); the string types take the literal text.
    ///
    /// The needle is required by the value/absolute/delta comparisons; the pure
    /// change-relative comparisons ([`ScanCompareType::Unknown`],
    /// `Increased`/`Decreased`/`Changed`/`Unchanged`) do not need one and may be
    /// run without parsing a needle at all — see [`crate::Scanner`].
    pub fn parse_needle(&self, input: &str) -> Result<Needle, NeedleParseError> {
        let s = input.trim();
        let val = match self {
            Self::I8 => NeedleValue::I(parse_signed(s, 1)?, 1, None),
            Self::I16 => NeedleValue::I(parse_signed(s, 2)?, 2, None),
            Self::I32 => NeedleValue::I(parse_signed(s, 4)?, 4, None),
            Self::I64 => NeedleValue::I(parse_signed(s, 8)?, 8, None),
            Self::U8 => NeedleValue::I(parse_uint::<u8>(s)? as i128, 1, None),
            Self::U16 => NeedleValue::I(parse_uint::<u16>(s)? as i128, 2, None),
            Self::U32 => NeedleValue::I(parse_uint::<u32>(s)? as i128, 4, None),
            Self::U64 => NeedleValue::I(parse_uint::<u64>(s)? as i128, 8, None),
            Self::F32 => NeedleValue::F(
                s.parse::<f32>().map_err(|_| NeedleParseError::Float)? as f64,
                4,
                None,
            ),
            Self::F64 => NeedleValue::F(
                s.parse::<f64>().map_err(|_| NeedleParseError::Float)?,
                8,
                None,
            ),
            Self::Bytes => {
                NeedleValue::Bytes(BytePattern::parse(input).map_err(NeedleParseError::Pattern)?)
            }
            Self::StringUtf8 => NeedleValue::Str(input.as_bytes().to_vec()),
            Self::StringUtf16 => {
                let mut bytes = Vec::with_capacity(input.len() * 2);
                for unit in input.encode_utf16() {
                    bytes.extend_from_slice(&unit.to_le_bytes());
                }
                NeedleValue::Str(bytes)
            }
            Self::StringUtf32 => {
                let mut bytes = Vec::with_capacity(input.chars().count() * 4);
                for ch in input.chars() {
                    bytes.extend_from_slice(&(ch as u32).to_le_bytes());
                }
                NeedleValue::Str(bytes)
            }
        };
        Ok(Needle {
            ty: *self,
            value: val,
            tolerance: DEFAULT_FLOAT_TOLERANCE,
            round: FloatRound::Normal,
            case_insensitive: false,
        })
    }
}

/// A parsed, typed needle plus its comparison behaviour.
#[derive(Debug, Clone, PartialEq)]
pub struct Needle {
    ty: ScanValueType,
    value: NeedleValue,
    tolerance: f64,
    round: FloatRound,
    /// Match strings without regard to ASCII case. Only ASCII is folded: the
    /// candidate bytes are raw target memory in a known encoding, and folding
    /// non-ASCII correctly would need full Unicode case mapping over a decoded
    /// string — which is a different (and much slower) scan.
    case_insensitive: bool,
}

/// The typed payload of a [`Needle`]. Integers keep a widening `i128` (holds any
/// `i64`/`u64`) plus their byte width; floats keep an `f64` plus width; `Bytes`
/// keeps the compiled pattern; strings keep the pre-encoded bytes. The trailing
/// `Option` on the numeric variants is the exclusive upper bound for
/// [`ScanCompareType::Between`] (`needle1 < value < needle2`).
#[derive(Debug, Clone, PartialEq)]
enum NeedleValue {
    I(i128, usize, Option<i128>),
    F(f64, usize, Option<f64>),
    Bytes(BytePattern),
    Str(Vec<u8>),
}

impl Needle {
    /// The value type this needle was parsed for.
    pub fn value_type(&self) -> ScanValueType {
        self.ty
    }

    /// Overrides the float equality tolerance (default
    /// [`DEFAULT_FLOAT_TOLERANCE`]). No effect on non-float needles.
    pub fn with_float_tolerance(mut self, tolerance: f64) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Sets how float equality is decided. No effect on non-float needles.
    pub fn with_round_mode(mut self, round: FloatRound) -> Self {
        self.round = round;
        self
    }

    /// The active float rounding mode.
    pub fn round_mode(&self) -> FloatRound {
        self.round
    }

    /// Matches strings ignoring ASCII case. No effect on non-string needles.
    pub fn with_case_insensitive(mut self, yes: bool) -> Self {
        self.case_insensitive = yes;
        self
    }

    /// Whether a [`ScanCompareType::Between`] upper bound has been supplied.
    ///
    /// The scanner checks this rather than letting the comparison quietly
    /// degrade to `value > needle`, which is a different search returning far
    /// more results than the user asked for.
    pub fn has_upper_bound(&self) -> bool {
        matches!(
            &self.value,
            NeedleValue::I(_, _, Some(_)) | NeedleValue::F(_, _, Some(_))
        )
    }

    /// The needle's bytes, when it is a literal byte or string needle.
    ///
    /// Used by the scanner to prefilter a chunk with `memchr` before testing
    /// every position: a long literal is overwhelmingly absent, and skipping
    /// straight to each occurrence of its first byte avoids that work.
    pub(crate) fn literal_prefix(&self) -> Option<u8> {
        match &self.value {
            // A case-insensitive needle has two acceptable first bytes, so a
            // single-byte prefilter would drop half the matches.
            NeedleValue::Str(b) if !self.case_insensitive => b.first().copied(),
            NeedleValue::Bytes(p) => p.first_literal_byte(),
            _ => None,
        }
    }

    /// Sets the exclusive upper bound for [`ScanCompareType::Between`] by parsing
    /// `input` in the same way as [`ScanValueType::parse_needle`]. Only
    /// meaningful for numeric needles; ignored for `Bytes`/string needles.
    pub fn with_upper_bound(mut self, input: &str) -> Result<Self, NeedleParseError> {
        let upper = self.ty.parse_needle(input)?;
        match (&mut self.value, upper.value) {
            (NeedleValue::I(_, _, hi), NeedleValue::I(v, _, _)) => *hi = Some(v),
            (NeedleValue::F(_, _, hi), NeedleValue::F(v, _, _)) => *hi = Some(v),
            _ => {}
        }
        Ok(self)
    }

    /// The scan stride for this needle: the number of bytes each candidate spans
    /// and the step between candidate positions. Fixed by the type for numerics;
    /// the pattern/encoded length for `Bytes`/strings.
    pub fn stride(&self) -> usize {
        match &self.value {
            NeedleValue::I(_, w, _) | NeedleValue::F(_, w, _) => *w,
            NeedleValue::Bytes(p) => p.len(),
            NeedleValue::Str(b) => b.len(),
        }
    }
}

impl Needle {
    /// Compares the candidate value at `data[offset..]` for a **first scan**
    /// (absolute comparisons only; `previous` is `None`). Returns whether the
    /// candidate matches. Never reads past `data`.
    pub fn compare_first(&self, data: &[u8], offset: usize, compare: ScanCompareType) -> bool {
        self.compare(data, offset, compare, None, None)
    }

    /// Compares the candidate value at `data[offset..]` against the `previous`
    /// bytes captured for this address (a **next scan** or change-relative
    /// compare). Never reads past `data`.
    pub fn compare_next(
        &self,
        data: &[u8],
        offset: usize,
        compare: ScanCompareType,
        previous: &[u8],
    ) -> bool {
        self.compare(data, offset, compare, Some(previous), None)
    }

    /// [`Self::compare_next`] with the value the *first* scan captured, for the
    /// same-as-first comparisons.
    pub fn compare_next_with_first(
        &self,
        data: &[u8],
        offset: usize,
        compare: ScanCompareType,
        previous: &[u8],
        first: &[u8],
    ) -> bool {
        self.compare(data, offset, compare, Some(previous), Some(first))
    }

    /// Core comparison. `previous` carries the bytes of the previous scan value
    /// for change-relative comparisons; it is `None` on a first scan.
    fn compare(
        &self,
        data: &[u8],
        offset: usize,
        compare: ScanCompareType,
        previous: Option<&[u8]>,
        first: Option<&[u8]>,
    ) -> bool {
        // The same-as-first compares read the first-scan value in place of the
        // previous one; everything downstream then treats it as `prev`.
        let baseline = if compare.needs_first() { first.or(previous) } else { previous };
        match &self.value {
            NeedleValue::I(needle, width, upper) => {
                let Some(cur) = read_int(data, offset, *width, is_signed(self.ty)) else {
                    return false;
                };
                let prev = baseline.and_then(|p| read_int(p, 0, *width, is_signed(self.ty)));
                compare_int(compare, cur, *needle, *upper, prev)
            }
            NeedleValue::F(needle, width, upper) => {
                let Some(cur) = read_float(data, offset, *width) else {
                    return false;
                };
                let prev = baseline.and_then(|p| read_float(p, 0, *width));
                compare_float(compare, cur, *needle, *upper, prev, self.tolerance, self.round)
            }
            NeedleValue::Bytes(pattern) => {
                // AOB is an equality-family match; ReClass.NET only defines
                // Equal for it. `Exact`/`Unknown` accept a pattern match; every
                // other compare is meaningless for raw bytes and never matches.
                match compare {
                    ScanCompareType::Exact | ScanCompareType::Unknown => {
                        pattern.matches_at(data, offset)
                    }
                    _ => false,
                }
            }
            NeedleValue::Str(needle) => {
                let end = offset + needle.len();
                let Some(window) = data.get(offset..end) else {
                    return false;
                };
                let equal = if self.case_insensitive {
                    // Fold per byte. For UTF-8 that is the ASCII range, which is
                    // where case-insensitive search is actually wanted; for
                    // UTF-16/32 LE the ASCII code units are the low byte of each
                    // unit and the high bytes are zero on both sides, so a
                    // per-byte fold is still correct for ASCII and a no-op
                    // elsewhere.
                    window.len() == needle.len()
                        && window
                            .iter()
                            .zip(needle.iter())
                            .all(|(a, b)| a.eq_ignore_ascii_case(b))
                } else {
                    window == needle.as_slice()
                };
                match compare {
                    ScanCompareType::Exact | ScanCompareType::Unknown => equal,
                    ScanCompareType::NotEqual => !equal,
                    _ => false,
                }
            }
        }
    }
}

/// Whether a value type is a signed integer (for sign-extension on read).
const fn is_signed(ty: ScanValueType) -> bool {
    matches!(
        ty,
        ScanValueType::I8 | ScanValueType::I16 | ScanValueType::I32 | ScanValueType::I64
    )
}

/// Reads a `width`-byte little-endian integer at `data[offset..]`, sign-extended
/// into `i128` when `signed`. Returns `None` if the read would run past `data`.
fn read_int(data: &[u8], offset: usize, width: usize, signed: bool) -> Option<i128> {
    let bytes = data.get(offset..offset + width)?;
    let mut acc: u128 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        acc |= (b as u128) << (8 * i);
    }
    if signed {
        // Sign-extend from the top bit of the `width`-byte value.
        let sign_bit = 1u128 << (width * 8 - 1);
        if acc & sign_bit != 0 {
            let mask = if width * 8 == 128 {
                0
            } else {
                !((1u128 << (width * 8)) - 1)
            };
            acc |= mask;
        }
        Some(acc as i128)
    } else {
        Some(acc as i128)
    }
}

/// Reads a `width`-byte (4 or 8) little-endian float at `data[offset..]` into an
/// `f64`. Returns `None` if the read would run past `data`.
fn read_float(data: &[u8], offset: usize, width: usize) -> Option<f64> {
    let bytes = data.get(offset..offset + width)?;
    match width {
        4 => {
            let arr: [u8; 4] = bytes.try_into().ok()?;
            Some(f32::from_le_bytes(arr) as f64)
        }
        8 => {
            let arr: [u8; 8] = bytes.try_into().ok()?;
            Some(f64::from_le_bytes(arr))
        }
        _ => None,
    }
}

/// Dispatches an integer comparison. `prev` is `Some` only for change-relative
/// compares on a next scan; a change-relative compare without a previous value
/// never matches. `upper` is the exclusive upper bound for `Between`
/// (`needle < value < upper`); a `Between` with no upper bound degrades to
/// `value > needle`.
fn compare_int(
    compare: ScanCompareType,
    cur: i128,
    needle: i128,
    upper: Option<i128>,
    prev: Option<i128>,
) -> bool {
    match compare {
        ScanCompareType::Exact => cur == needle,
        ScanCompareType::NotEqual => cur != needle,
        ScanCompareType::GreaterThan => cur > needle,
        ScanCompareType::LessThan => cur < needle,
        ScanCompareType::Between => cur > needle && upper.is_none_or(|hi| cur < hi),
        ScanCompareType::Unknown => true,
        ScanCompareType::Increased => prev.is_some_and(|p| cur > p),
        ScanCompareType::Decreased => prev.is_some_and(|p| cur < p),
        ScanCompareType::Changed => prev.is_some_and(|p| cur != p),
        ScanCompareType::Unchanged => prev.is_some_and(|p| cur == p),
        ScanCompareType::IncreasedBy => prev.is_some_and(|p| cur == p + needle),
        ScanCompareType::DecreasedBy => prev.is_some_and(|p| cur == p - needle),
        // `>=`/`<=`, not `==`: a percentage of an integer rarely lands on one,
        // so an equality test would match almost nothing.
        ScanCompareType::IncreasedByPercent => {
            prev.is_some_and(|p| (cur as f64) >= p as f64 * (1.0 + needle as f64 / 100.0))
        }
        ScanCompareType::DecreasedByPercent => {
            prev.is_some_and(|p| (cur as f64) <= p as f64 * (1.0 - needle as f64 / 100.0))
        }
        ScanCompareType::UnchangedFromFirst => prev.is_some_and(|p| cur == p),
        ScanCompareType::ChangedFromFirst => prev.is_some_and(|p| cur != p),
    }
}

/// Dispatches a float comparison, using `tol` for equality (Normal round mode).
/// `upper` is the exclusive upper bound for `Between`.
fn compare_float(
    compare: ScanCompareType,
    cur: f64,
    needle: f64,
    upper: Option<f64>,
    prev: Option<f64>,
    tol: f64,
    round: FloatRound,
) -> bool {
    let nearly = |a: f64, b: f64| match round {
        FloatRound::Normal => (a - b).abs() < tol,
        FloatRound::Strict => a == b,
        FloatRound::Truncate => a.trunc() == b.trunc(),
    };
    match compare {
        ScanCompareType::Exact => nearly(cur, needle),
        ScanCompareType::NotEqual => !nearly(cur, needle),
        ScanCompareType::GreaterThan => cur > needle,
        ScanCompareType::LessThan => cur < needle,
        ScanCompareType::Between => cur > needle && upper.is_none_or(|hi| cur < hi),
        ScanCompareType::Unknown => true,
        ScanCompareType::Increased => prev.is_some_and(|p| cur > p),
        ScanCompareType::Decreased => prev.is_some_and(|p| cur < p),
        ScanCompareType::Changed => prev.is_some_and(|p| !nearly(cur, p)),
        ScanCompareType::Unchanged => prev.is_some_and(|p| nearly(cur, p)),
        ScanCompareType::IncreasedBy => prev.is_some_and(|p| nearly(cur, p + needle)),
        ScanCompareType::DecreasedBy => prev.is_some_and(|p| nearly(cur, p - needle)),
        ScanCompareType::IncreasedByPercent => {
            prev.is_some_and(|p| cur >= p * (1.0 + needle / 100.0))
        }
        ScanCompareType::DecreasedByPercent => {
            prev.is_some_and(|p| cur <= p * (1.0 - needle / 100.0))
        }
        ScanCompareType::UnchangedFromFirst => prev.is_some_and(|p| nearly(cur, p)),
        ScanCompareType::ChangedFromFirst => prev.is_some_and(|p| !nearly(cur, p)),
    }
}

/// A failure parsing a textual needle for a given [`ScanValueType`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NeedleParseError {
    /// The text was not a valid integer for the target width.
    Integer,
    /// The text was not a valid float.
    Float,
    /// The AOB pattern was malformed.
    Pattern(crate::pattern::PatternError),
}

impl core::fmt::Display for NeedleParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Integer => write!(f, "invalid integer needle"),
            Self::Float => write!(f, "invalid float needle"),
            Self::Pattern(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for NeedleParseError {}

/// Parses a signed integer needle of `width` bytes: decimal or `0x`-prefixed hex.
///
/// A hex literal that fills the width is read as the *bit pattern*, so
/// `0xFFFFFFFF` for an `i32` is `-1` rather than an out-of-range error. That is
/// what Cheat Engine does and what anyone typing a hex constant means: they are
/// naming bytes, not a magnitude. A decimal literal is still range-checked,
/// because `4294967295` typed as a signed 32-bit value is a mistake.
fn parse_signed(s: &str, width: usize) -> Result<i128, NeedleParseError> {
    let trimmed = s.trim();
    let (neg, body) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, trimmed),
    };
    let is_hex = body.starts_with("0x") || body.starts_with("0X");
    let mag = parse_u128_radix(body)?;

    let bits = width * 8;
    let modulus = 1u128 << bits;
    if neg {
        let mag = mag as i128;
        let min = -(1i128 << (bits - 1));
        if -mag < min {
            return Err(NeedleParseError::Integer);
        }
        return Ok(-mag);
    }
    if is_hex && mag < modulus {
        // Reinterpret the bit pattern as this width's signed value.
        let sign_bit = 1u128 << (bits - 1);
        return Ok(if mag & sign_bit != 0 {
            (mag as i128) - (modulus as i128)
        } else {
            mag as i128
        });
    }
    let max = (1i128 << (bits - 1)) - 1;
    let v = i128::try_from(mag).map_err(|_| NeedleParseError::Integer)?;
    if v > max {
        return Err(NeedleParseError::Integer);
    }
    Ok(v)
}

/// Parses an unsigned integer needle: decimal or `0x`-prefixed hex.
fn parse_uint<T>(s: &str) -> Result<T, NeedleParseError>
where
    T: TryFrom<u128>,
{
    let v = parse_u128_radix(s)?;
    T::try_from(v).map_err(|_| NeedleParseError::Integer)
}

/// Parses a possibly-`0x`-prefixed unsigned integer into a `u128`.
fn parse_u128_radix(s: &str) -> Result<u128, NeedleParseError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(hex, 16).map_err(|_| NeedleParseError::Integer)
    } else {
        s.parse::<u128>().map_err(|_| NeedleParseError::Integer)
    }
}

#[cfg(test)]
mod tag_tests {
    use super::ScanValueType as T;

    #[test]
    fn tag_round_trips_all_variants() {
        for ty in [
            T::I8, T::I16, T::I32, T::I64, T::U8, T::U16, T::U32, T::U64,
            T::F32, T::F64, T::Bytes, T::StringUtf8, T::StringUtf16,
        ] {
            assert_eq!(T::from_tag(ty.as_tag()), Some(ty), "round-trip {:?}", ty);
        }
    }

    #[test]
    fn from_tag_accepts_aliases_and_case() {
        assert_eq!(T::from_tag("Float"), Some(T::F32));
        assert_eq!(T::from_tag("DOUBLE"), Some(T::F64));
        assert_eq!(T::from_tag("aob"), Some(T::Bytes));
        assert_eq!(T::from_tag(" I32 "), Some(T::I32));
        assert_eq!(T::from_tag("string"), Some(T::StringUtf8));
        assert_eq!(T::from_tag("nonsense"), None);
    }
}
