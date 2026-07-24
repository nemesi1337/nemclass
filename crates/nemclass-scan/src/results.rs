//! Scan results: the addresses that matched, each with the exact bytes captured
//! at match time so a later change-relative next scan has a baseline.

/// A single match: the absolute target address plus the value bytes read there
/// at scan time. The bytes are the previous value for a subsequent next scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    /// Absolute address of the match in the target's address space.
    pub address: usize,
    /// The value bytes captured at `address` when this result was produced
    /// (the scan stride's worth). Used as the "previous value" on a next scan.
    pub previous_value_bytes: Vec<u8>,
}

impl ScanResult {
    /// Builds a result from an address and its captured value bytes.
    pub fn new(address: usize, previous_value_bytes: Vec<u8>) -> Self {
        Self {
            address,
            previous_value_bytes,
        }
    }
}

/// The results of one scan generation, in ascending address order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanResults {
    results: Vec<ScanResult>,
}

impl ScanResults {
    /// An empty result set.
    pub fn new() -> Self {
        Self::default()
    }

    /// A `const`-constructible empty result set, for a `static` sentinel.
    pub const fn new_const() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Builds a result set from a vector of results (assumed ascending by
    /// address, which the [`crate::Scanner`] guarantees).
    pub fn from_vec(results: Vec<ScanResult>) -> Self {
        Self { results }
    }

    /// Number of matches.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether there are no matches.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Iterates the matches in ascending address order.
    pub fn iter(&self) -> core::slice::Iter<'_, ScanResult> {
        self.results.iter()
    }

    /// The matches as a slice.
    pub fn as_slice(&self) -> &[ScanResult] {
        &self.results
    }

    /// Appends a match. Intended for the scanner's internal use as it walks
    /// regions in ascending order.
    pub(crate) fn push(&mut self, result: ScanResult) {
        self.results.push(result);
    }
}

impl<'a> IntoIterator for &'a ScanResults {
    type Item = &'a ScanResult;
    type IntoIter = core::slice::Iter<'a, ScanResult>;

    fn into_iter(self) -> Self::IntoIter {
        self.results.iter()
    }
}

impl IntoIterator for ScanResults {
    type Item = ScanResult;
    type IntoIter = std::vec::IntoIter<ScanResult>;

    fn into_iter(self) -> Self::IntoIter {
        self.results.into_iter()
    }
}
