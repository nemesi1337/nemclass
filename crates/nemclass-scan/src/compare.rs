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

    /// Whether this is the "unknown initial value" baseline, which is only
    /// meaningful on a *first* scan.
    ///
    /// A next scan re-reads the addresses a first scan already accepted, so
    /// "accept everything" there is either a no-op or — depending on whether a
    /// needle happens to be present — a silent wipe. [`crate::Scanner::next_scan`]
    /// rejects it outright, matching Cheat Engine, which offers no such compare
    /// once a scan is under way.
    pub const fn is_baseline(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Parses a compare tag (case-insensitive) into a [`ScanCompareType`].
    ///
    /// Accepts the JS-API vocabulary used by `scan.first`/`scan.next` plus short
    /// aliases: `"exact"|"eq"`, `"notEqual"|"ne"`, `"greater"|"gt"`,
    /// `"less"|"lt"`, `"between"`, `"unknown"`, `"increased"|"inc"`,
    /// `"increasedBy"`, `"decreased"|"dec"`, `"decreasedBy"`, `"changed"`,
    /// `"unchanged"`. Returns `None` for an unknown tag.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag.trim().to_ascii_lowercase().as_str() {
            "exact" | "eq" | "equal" => Some(Self::Exact),
            "notequal" | "ne" => Some(Self::NotEqual),
            "greater" | "gt" | "greaterthan" => Some(Self::GreaterThan),
            "less" | "lt" | "lessthan" => Some(Self::LessThan),
            "between" => Some(Self::Between),
            "unknown" => Some(Self::Unknown),
            "increased" | "inc" => Some(Self::Increased),
            "increasedby" => Some(Self::IncreasedBy),
            "decreased" | "dec" => Some(Self::Decreased),
            "decreasedby" => Some(Self::DecreasedBy),
            "changed" => Some(Self::Changed),
            "unchanged" => Some(Self::Unchanged),
            _ => None,
        }
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

#[cfg(test)]
mod tests {
    use super::ScanCompareType;

    #[test]
    fn from_tag_round_trips_and_aliases() {
        assert_eq!(ScanCompareType::from_tag("exact"), Some(ScanCompareType::Exact));
        assert_eq!(ScanCompareType::from_tag("eq"), Some(ScanCompareType::Exact));
        assert_eq!(ScanCompareType::from_tag("NE"), Some(ScanCompareType::NotEqual));
        assert_eq!(ScanCompareType::from_tag("Greater"), Some(ScanCompareType::GreaterThan));
        assert_eq!(ScanCompareType::from_tag("lt"), Some(ScanCompareType::LessThan));
        assert_eq!(ScanCompareType::from_tag("between"), Some(ScanCompareType::Between));
        assert_eq!(ScanCompareType::from_tag("unknown"), Some(ScanCompareType::Unknown));
        assert_eq!(ScanCompareType::from_tag("increased"), Some(ScanCompareType::Increased));
        assert_eq!(ScanCompareType::from_tag("increasedBy"), Some(ScanCompareType::IncreasedBy));
        assert_eq!(ScanCompareType::from_tag("  DECREASED "), Some(ScanCompareType::Decreased));
        assert_eq!(ScanCompareType::from_tag("decreasedby"), Some(ScanCompareType::DecreasedBy));
        assert_eq!(ScanCompareType::from_tag("changed"), Some(ScanCompareType::Changed));
        assert_eq!(ScanCompareType::from_tag("unchanged"), Some(ScanCompareType::Unchanged));
        assert_eq!(ScanCompareType::from_tag("nonsense"), None);
    }
}
