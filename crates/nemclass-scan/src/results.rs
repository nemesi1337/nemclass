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
    /// The value bytes at `address` as of the **first** scan in this session.
    ///
    /// Carried forward through every narrowing so a "same as first scan"
    /// comparison has something to compare against: the previous column only
    /// ever remembers one step back.
    pub first: &'a [u8],
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
    /// `addresses.len() * stride` bytes: the value the first scan captured.
    first: Vec<u8>,
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
            first: Vec::new(),
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
            previous: &self.previous[span.clone()],
            first: &self.first[span],
        })
    }

    /// Iterates the matches in ascending address order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = ScanResult<'_>> + '_ {
        (0..self.len()).map(|i| {
            let span = i * self.stride..(i + 1) * self.stride;
            ScanResult {
                address: self.addresses[i],
                current: &self.current[span.clone()],
                previous: &self.previous[span.clone()],
                first: &self.first[span],
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
        // A first scan is its own baseline: nothing came before it.
        self.push_with_first(address, current, previous, current);
    }

    /// Appends a match, carrying an explicit first-scan value.
    pub(crate) fn push_with_first(
        &mut self,
        address: usize,
        current: &[u8],
        previous: &[u8],
        first: &[u8],
    ) {
        self.addresses.push(address);
        push_fixed(&mut self.current, current, self.stride);
        push_fixed(&mut self.previous, previous, self.stride);
        push_fixed(&mut self.first, first, self.stride);
    }

    /// Reserves room for `additional` more matches in every column.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.addresses.reserve(additional);
        self.current.reserve(additional * self.stride);
        self.previous.reserve(additional * self.stride);
        self.first.reserve(additional * self.stride);
    }

    /// Appends every match of `other`, which must have the same stride.
    ///
    /// Used to join the per-thread partial results of a parallel first scan.
    /// Mismatched strides are refused rather than concatenated, which would
    /// silently desync the value columns from the addresses.
    pub(crate) fn append(&mut self, other: &mut Self) -> bool {
        if self.is_empty() && self.stride == 0 {
            self.stride = other.stride;
        }
        if other.stride != self.stride {
            return false;
        }
        self.addresses.append(&mut other.addresses);
        self.current.append(&mut other.current);
        self.previous.append(&mut other.previous);
        self.first.append(&mut other.first);
        true
    }

    /// Drops every match except those at `keep` (indices into this set), in
    /// order. Used by the UI to remove selected rows.
    pub fn retain_indices(&mut self, keep: &[usize]) {
        let stride = self.stride;
        let mut addresses = Vec::with_capacity(keep.len());
        let mut current = Vec::with_capacity(keep.len() * stride);
        let mut previous = Vec::with_capacity(keep.len() * stride);
        let mut first = Vec::with_capacity(keep.len() * stride);
        for &i in keep {
            let Some(&address) = self.addresses.get(i) else { continue };
            let span = i * stride..(i + 1) * stride;
            addresses.push(address);
            current.extend_from_slice(&self.current[span.clone()]);
            previous.extend_from_slice(&self.previous[span.clone()]);
            first.extend_from_slice(&self.first[span]);
        }
        self.addresses = addresses;
        self.current = current;
        self.previous = previous;
        self.first = first;
    }
}

/// Magic + version for a saved result set.
///
/// A scan session is expensive — minutes over a large working set — and losing
/// it to a closed window or a restarted target meant starting over. Written as
/// a flat binary rather than TOML: the columns are already flat buffers, and a
/// five-million-result set is 100 MB of them.
const RESULTS_MAGIC: &[u8; 8] = b"NEMSCAN\x01";

/// A failure reading a saved result set.
#[derive(Debug)]
pub enum ResultsIoError {
    /// The file is not a nemclass result set, or is from a newer format.
    BadFormat,
    /// The file is internally inconsistent — a truncated or corrupt write.
    Truncated,
    /// The underlying read or write failed.
    Io(std::io::Error),
}

impl core::fmt::Display for ResultsIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadFormat => write!(f, "not a nemclass scan-result file"),
            Self::Truncated => write!(f, "the scan-result file is truncated or corrupt"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ResultsIoError {}

impl From<std::io::Error> for ResultsIoError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl ScanResults {
    /// Serializes this result set, tagged with the `value_type` it was scanned
    /// for so a load can refuse to reinterpret it as something else.
    pub fn to_bytes(&self, value_type: &str) -> Vec<u8> {
        let tag = value_type.as_bytes();
        let mut out = Vec::with_capacity(
            32 + tag.len() + self.addresses.len() * (8 + 3 * self.stride),
        );
        out.extend_from_slice(RESULTS_MAGIC);
        out.extend_from_slice(&(tag.len() as u32).to_le_bytes());
        out.extend_from_slice(tag);
        out.extend_from_slice(&(self.stride as u64).to_le_bytes());
        out.extend_from_slice(&(self.addresses.len() as u64).to_le_bytes());
        for &a in &self.addresses {
            out.extend_from_slice(&(a as u64).to_le_bytes());
        }
        out.extend_from_slice(&self.current);
        out.extend_from_slice(&self.previous);
        out.extend_from_slice(&self.first);
        out
    }

    /// Reads a result set written by [`Self::to_bytes`], returning it with the
    /// value-type tag it was saved under.
    pub fn from_bytes(data: &[u8]) -> Result<(Self, String), ResultsIoError> {
        // A plain function taking the cursor by `&mut`, not a closure: a closure
        // capturing `cursor` would hold the borrow for the whole body and the
        // size check below could not read it.
        fn take<'a>(
            data: &'a [u8],
            cursor: &mut usize,
            n: usize,
        ) -> Result<&'a [u8], ResultsIoError> {
            let end = cursor.checked_add(n).ok_or(ResultsIoError::Truncated)?;
            let slice = data.get(*cursor..end).ok_or(ResultsIoError::Truncated)?;
            *cursor = end;
            Ok(slice)
        }
        let mut cursor = 0usize;
        macro_rules! take {
            ($n:expr) => {
                take(data, &mut cursor, $n)?
            };
        }

        if take!(8) != RESULTS_MAGIC {
            return Err(ResultsIoError::BadFormat);
        }
        let tag_len = u32::from_le_bytes(take!(4).try_into().unwrap()) as usize;
        let tag =
            String::from_utf8(take!(tag_len).to_vec()).map_err(|_| ResultsIoError::BadFormat)?;
        let stride = u64::from_le_bytes(take!(8).try_into().unwrap()) as usize;
        let count = u64::from_le_bytes(take!(8).try_into().unwrap()) as usize;

        // Checked before allocating: `count` and `stride` come straight from the
        // file, and a corrupt header must not be able to ask for a terabyte.
        let column = count.checked_mul(stride).ok_or(ResultsIoError::Truncated)?;
        let needed = count
            .checked_mul(8)
            .and_then(|a| a.checked_add(column.checked_mul(3)?))
            .ok_or(ResultsIoError::Truncated)?;
        if data.len() - cursor != needed {
            return Err(ResultsIoError::Truncated);
        }

        let mut addresses = Vec::with_capacity(count);
        for chunk in take!(count * 8).chunks_exact(8) {
            addresses.push(u64::from_le_bytes(chunk.try_into().unwrap()) as usize);
        }
        let current = take!(column).to_vec();
        let previous = take!(column).to_vec();
        let first = take!(column).to_vec();

        Ok((Self { stride, addresses, current, previous, first }, tag))
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
    fn a_saved_result_set_reloads_identically() {
        let mut r = ScanResults::with_stride(4);
        r.push_with_first(0x1000, &[1, 0, 0, 0], &[2, 0, 0, 0], &[3, 0, 0, 0]);
        r.push_with_first(0x2000, &[4, 0, 0, 0], &[5, 0, 0, 0], &[6, 0, 0, 0]);

        let bytes = r.to_bytes("i32");
        let (back, tag) = ScanResults::from_bytes(&bytes).unwrap();
        assert_eq!(tag, "i32");
        assert_eq!(back, r);
        // The first-scan column is what a "same as first" narrowing reads, so
        // it has to survive the trip too.
        assert_eq!(back.get(1).unwrap().first, [6, 0, 0, 0]);
    }

    #[test]
    fn an_empty_result_set_round_trips() {
        let r = ScanResults::with_stride(8);
        let (back, tag) = ScanResults::from_bytes(&r.to_bytes("f64")).unwrap();
        assert_eq!(tag, "f64");
        assert!(back.is_empty());
        assert_eq!(back.stride(), 8);
    }

    #[test]
    fn a_corrupt_result_file_is_refused_rather_than_allocating_from_its_header() {
        assert!(matches!(
            ScanResults::from_bytes(b"not a scan file"),
            Err(super::ResultsIoError::BadFormat)
        ));

        let mut r = ScanResults::with_stride(4);
        r.push(0x1000, &[1, 0, 0, 0], &[1, 0, 0, 0]);
        let mut bytes = r.to_bytes("i32");
        // Claim a billion results in an eighty-byte file.
        let count_at = 8 + 4 + 3 + 8;
        bytes[count_at..count_at + 8].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        assert!(matches!(
            ScanResults::from_bytes(&bytes),
            Err(super::ResultsIoError::Truncated)
        ));
    }

    #[test]
    fn retain_indices_keeps_exactly_the_named_rows() {
        let mut r = ScanResults::with_stride(1);
        for i in 0..5u8 {
            r.push(0x1000 + i as usize, &[i], &[i]);
        }
        r.retain_indices(&[1, 3]);
        assert_eq!(r.addresses(), &[0x1001, 0x1003]);
        assert_eq!(r.get(0).unwrap().current, [1]);
        assert_eq!(r.get(1).unwrap().current, [3]);
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
