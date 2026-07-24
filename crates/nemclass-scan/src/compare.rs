//! Scan comparison kinds — ports ReClass.NET's `ScanCompareType`.
//!
//! The variants split into two families:
//! - **absolute** comparisons that only need the needle (`Exact`, `NotEqual`,
//!   `GreaterThan`, `LessThan`, `Between`), and
//! - **change-relative** comparisons that need the previous scan's value
//!   (`Unknown`, `Increased`, `IncreasedBy`, `Decreased`, `DecreasedBy`,
//!   `Changed`, `Unchanged`).
//!
//! `Unknown` is the "unknown initial value" first-scan mode: it accepts every
//! candidate so a later change-relative next scan has a baseline to compare
//! against. `IncreasedBy`/`DecreasedBy` are exact-delta refinements of
//! `Increased`/`Decreased` (they carry the needle as the delta) and have no
//! direct ReClass.NET counterpart, but match the Cheat Engine feature.

/// How a candidate value is compared against the needle and/or the previous
/// scan value. Mirrors ReClass.NET's `ScanCompareType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanCompareType {
    /// `value == needle`. (ReClass.NET `Equal`.)
    Exact,
    /// `value != needle`.
    NotEqual,
    /// `value > needle`.
    GreaterThan,
    /// `value < needle`.
    LessThan,
    /// `needle1 < value < needle2` (exclusive), matching ReClass.NET `Between`.
    Between,
    /// Unknown initial value: accepts every candidate (first-scan baseline).
    Unknown,
    /// `value > previous`.
    Increased,
    /// `value == previous + needle` (exact positive delta).
    IncreasedBy,
    /// `value < previous`.
    Decreased,
    /// `value == previous - needle` (exact positive delta).
    DecreasedBy,
    /// `value != previous`.
    Changed,
    /// `value == previous`.
    Unchanged,
}

impl ScanCompareType {
    /// Whether this comparison needs a previous scan value to evaluate. When
    /// `true` it is only valid on a next scan (or with an `Unknown` baseline);
    /// on a first scan the [`crate::Scanner`] rejects it (except `Unknown`,
    /// which is defined precisely as the first-scan baseline).
    pub const fn needs_previous(&self) -> bool {
        matches!(
            self,
            Self::Increased
                | Self::IncreasedBy
                | Self::Decreased
                | Self::DecreasedBy
                | Self::Changed
                | Self::Unchanged
        )
    }

    /// Whether this comparison consults the needle at all. `Unknown` and the
    /// pure change-relative kinds (`Increased`, `Decreased`, `Changed`,
    /// `Unchanged`) ignore it; the delta kinds (`IncreasedBy`/`DecreasedBy`) and
    /// the absolute kinds require it.
    pub const fn needs_needle(&self) -> bool {
        !matches!(
            self,
            Self::Unknown
                | Self::Increased
                | Self::Decreased
                | Self::Changed
                | Self::Unchanged
        )
    }
}
