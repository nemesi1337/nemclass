//! Scan results: the addresses that matched, each with the bytes read there in
//! this generation *and* in the one before it.
//!
//! Stored as parallel columns rather than a `Vec` of structs. A first scan with
//! an unknown initial value produces tens of millions of results, and one heap
//! allocation per result (plus the 24-byte `Vec` header) dominated both memory
//! and scan time. Three flat buffers cost `8 + 2 * stride` bytes per result —
//! 16 bytes for an `i32` — with no per-result allocation at all.
//!
//! The stride is per-generation rather than per-result: every result in one scan
//! is the same width, including for `Bytes`/string scans, where it is the
//! needle's length.

/// A borrowed view of one match: the absolute target address, the bytes read
/// there when this generation was produced, and the bytes from the generation
/// before it.
///
/// On a first scan `previous` and `current` are the same — Cheat Engine shows
/// the value in both columns rather than leaving Previous blank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanResult<'a> {
    /// Absolute address of the match in the target's address space.
    pub address: usize,
    /// The value bytes at `address` as of this generation.
    pub current: &'a [u8],
    /// The value bytes at `address` as of the previous generation.
    pub previous: &'a [u8],
}

/// The results of one scan generation, in ascending address order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanResults {
    /// Byte width of every value in this generation. `0` only for an empty set.
    stride: usize,
    addresses: Vec<usize>,
    /// `addresses.len() * stride` bytes: the value read in this generation.
    current: Vec<u8>,
    /// `addresses.len() * stride` bytes: the value from the generation before.
    previous: Vec<u8>,
}

impl ScanResults {
    /// An empty result set.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty result set for values of `stride` bytes.
    pub fn with_stride(stride: usize) -> Self {
        Self {
            stride,
            ..Self::default()
        }
    }

    /// A `const`-constructible empty result set, for a `static` sentinel.
    pub const fn new_const() -> Self {
        Self {
            stride: 0,
            addresses: Vec::new(),
            current: Vec::new(),
            previous: Vec::new(),
        }
    }

    /// The byte width of every value in this generation.
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// Number of matches.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Whether there are no matches.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// The match at `index`, or `None` if out of range.
    pub fn get(&self, index: usize) -> Option<ScanResult<'_>> {
        let address = *self.addresses.get(index)?;
        let span = index * self.stride..(index + 1) * self.stride;
        Some(ScanResult {
            address,
            current: &self.current[span.clone()],
            previous: &self.previous[span],
        })
    }

    /// Iterates the matches in ascending address order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = ScanResult<'_>> + '_ {
        (0..self.len()).map(|i| {
            let span = i * self.stride..(i + 1) * self.stride;
            ScanResult {
                address: self.addresses[i],
                current: &self.current[span.clone()],
                previous: &self.previous[span],
            }
        })
    }

    /// The matched addresses, without the value columns.
    pub fn addresses(&self) -> &[usize] {
        &self.addresses
    }

    /// Appends a match. Intended for the scanner's internal use as it walks
    /// regions in ascending order.
    ///
    /// `current` and `previous` must both be `stride` bytes; anything longer is
    /// truncated and anything shorter zero-padded, so a caller cannot desync the
    /// columns from the address list.
    pub(crate) fn push(&mut self, address: usize, current: &[u8], previous: &[u8]) {
        self.addresses.push(address);
        push_fixed(&mut self.current, current, self.stride);
        push_fixed(&mut self.previous, previous, self.stride);
    }

    /// Reserves room for `additional` more matches in all three columns.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.addresses.reserve(additional);
        self.current.reserve(additional * self.stride);
        self.previous.reserve(additional * self.stride);
    }
}

/// Appends exactly `stride` bytes of `src` to `dst`, padding with zeroes.
fn push_fixed(dst: &mut Vec<u8>, src: &[u8], stride: usize) {
    let n = src.len().min(stride);
    dst.extend_from_slice(&src[..n]);
    dst.resize(dst.len() + (stride - n), 0);
}

impl<'a> IntoIterator for &'a ScanResults {
    type Item = ScanResult<'a>;
    type IntoIter = Box<dyn ExactSizeIterator<Item = ScanResult<'a>> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::ScanResults;

    #[test]
    fn push_and_iterate_keeps_the_columns_aligned() {
        let mut r = ScanResults::with_stride(4);
        r.push(0x1000, &1i32.to_le_bytes(), &2i32.to_le_bytes());
        r.push(0x2000, &3i32.to_le_bytes(), &4i32.to_le_bytes());

        let rows: Vec<_> = r.iter().collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].address, 0x1000);
        assert_eq!(rows[0].current, 1i32.to_le_bytes());
        assert_eq!(rows[0].previous, 2i32.to_le_bytes());
        assert_eq!(rows[1].address, 0x2000);
        assert_eq!(rows[1].current, 3i32.to_le_bytes());
        assert_eq!(rows[1].previous, 4i32.to_le_bytes());
        assert_eq!(r.addresses(), &[0x1000, 0x2000]);
    }

    #[test]
    fn a_short_value_is_padded_rather_than_desyncing_the_columns() {
        let mut r = ScanResults::with_stride(4);
        r.push(0x1000, &[0xAA], &[0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        let row = r.get(0).unwrap();
        assert_eq!(row.current, [0xAA, 0, 0, 0]);
        assert_eq!(row.previous, [0xBB, 0xCC, 0xDD, 0xEE]);
        assert_eq!(r.get(1), None);
    }
}
