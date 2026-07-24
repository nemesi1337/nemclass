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
            Self::Bytes | Self::StringUtf8 | Self::StringUtf16 => None,
        }
    }

    /// Whether this is one of the string types.
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::StringUtf8 | Self::StringUtf16)
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
            Self::I8 => NeedleValue::I(parse_int::<i8>(s)? as i128, 1, None),
            Self::I16 => NeedleValue::I(parse_int::<i16>(s)? as i128, 2, None),
            Self::I32 => NeedleValue::I(parse_int::<i32>(s)? as i128, 4, None),
            Self::I64 => NeedleValue::I(parse_int::<i64>(s)? as i128, 8, None),
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
        };
        Ok(Needle {
            ty: *self,
            value: val,
            tolerance: DEFAULT_FLOAT_TOLERANCE,
        })
    }
}

/// A parsed, typed needle plus its comparison behaviour.
#[derive(Debug, Clone, PartialEq)]
pub struct Needle {
    ty: ScanValueType,
    value: NeedleValue,
    tolerance: f64,
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
        self.compare(data, offset, compare, None)
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
        self.compare(data, offset, compare, Some(previous))
    }

    /// Core comparison. `previous` carries the bytes of the previous scan value
    /// for change-relative comparisons; it is `None` on a first scan.
    fn compare(
        &self,
        data: &[u8],
        offset: usize,
        compare: ScanCompareType,
        previous: Option<&[u8]>,
    ) -> bool {
        match &self.value {
            NeedleValue::I(needle, width, upper) => {
                let Some(cur) = read_int(data, offset, *width, is_signed(self.ty)) else {
                    return false;
                };
                let prev = previous.and_then(|p| read_int(p, 0, *width, is_signed(self.ty)));
                compare_int(compare, cur, *needle, *upper, prev)
            }
            NeedleValue::F(needle, width, upper) => {
                let Some(cur) = read_float(data, offset, *width) else {
                    return false;
                };
                let prev = previous.and_then(|p| read_float(p, 0, *width));
                compare_float(compare, cur, *needle, *upper, prev, self.tolerance)
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
                match compare {
                    ScanCompareType::Exact | ScanCompareType::Unknown => window == needle.as_slice(),
                    ScanCompareType::NotEqual => window != needle.as_slice(),
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
) -> bool {
    let nearly = |a: f64, b: f64| (a - b).abs() < tol;
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

/// Parses a signed integer needle: decimal or `0x`-prefixed hex.
fn parse_int<T>(s: &str) -> Result<T, NeedleParseError>
where
    T: TryFrom<i128>,
{
    let v = parse_i128_radix(s)?;
    T::try_from(v).map_err(|_| NeedleParseError::Integer)
}

/// Parses an unsigned integer needle: decimal or `0x`-prefixed hex.
fn parse_uint<T>(s: &str) -> Result<T, NeedleParseError>
where
    T: TryFrom<u128>,
{
    let v = parse_u128_radix(s)?;
    T::try_from(v).map_err(|_| NeedleParseError::Integer)
}

/// Parses a possibly-`0x`-prefixed signed integer into an `i128`.
fn parse_i128_radix(s: &str) -> Result<i128, NeedleParseError> {
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let mag = parse_u128_radix(body)? as i128;
    Ok(if neg { -mag } else { mag })
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
