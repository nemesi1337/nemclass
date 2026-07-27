//! The scan engine: first scan over regions, next scan refining previous
//! results, and a short undo history. Generic over [`ScanTarget`] so it is
//! platform-neutral and driven in tests by a mock.
//!
//! Ported from ReClass.NET's `Scanner` (`FirstScan`/`NextScan` + the circular
//! store of result generations). The parallel worker pool is deliberately not
//! ported — a single-threaded chunked walk keeps the engine dependency-free and
//! deterministic for tests; a caller can shard regions across threads later.

use nemclass_core::Result;

use crate::compare::ScanCompareType;
use crate::results::{ScanResult, ScanResults};
use crate::target::{Region, RegionFilter, ScanTarget};
use crate::value_type::{Needle, ScanValueType};

/// The read buffer size for the first-scan chunked region walk (a handful of
/// pages). Regions larger than this are read in overlapping windows so a value
/// straddling a chunk boundary is still found.
const CHUNK_SIZE: usize = 64 * 1024;

/// How many result generations the undo history keeps (matches ReClass.NET's
/// `CircularBuffer<ScanResultStore>(3)`).
const HISTORY_DEPTH: usize = 3;

/// Progress of an in-progress or completed scan pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanProgress {
    /// Work units processed (regions on a first scan, previous results on a next
    /// scan).
    pub done: usize,
    /// Total work units for this pass.
    pub total: usize,
    /// Matches found so far.
    pub matches: usize,
}

/// A stateful scan session over a target `T`.
///
/// Build one with [`Scanner::new`], run [`Scanner::first_scan`] to seed results,
/// then [`Scanner::next_scan`] to refine them. Each scan pushes a generation
/// onto a bounded history so [`Scanner::undo`] can step back.
pub struct Scanner<T: ScanTarget> {
    target: T,
    value_type: ScanValueType,
    /// Which parts of the address space [`Scanner::first_scan`] may walk.
    ///
    /// Consulted by a first scan only: a next scan re-reads the previous
    /// results, which are by construction already inside the first scan's
    /// range. Same contract as ReClass.NET.
    region_filter: RegionFilter,
    /// How many regions the last [`Scanner::first_scan`] actually walked, after
    /// filtering. Zero means the filter excluded everything — a caller should
    /// report that differently from "scanned everything, found nothing".
    scanned_regions: usize,
    /// Result generations, oldest first; the last is the current one. Bounded to
    /// [`HISTORY_DEPTH`].
    history: Vec<ScanResults>,
    /// Whether a first scan has run yet (a next scan before one is an error).
    has_scanned: bool,
}

impl<T: ScanTarget> Scanner<T> {
    /// Creates a scanner over `target` for values of `value_type`.
    pub fn new(target: T, value_type: ScanValueType) -> Self {
        Self {
            target,
            value_type,
            region_filter: RegionFilter::default(),
            scanned_regions: 0,
            history: Vec::new(),
            has_scanned: false,
        }
    }

    /// Restricts which parts of the address space a first scan walks.
    pub fn with_region_filter(mut self, filter: RegionFilter) -> Self {
        self.region_filter = filter;
        self
    }

    /// Replaces the region filter in place. Takes effect on the next
    /// [`Scanner::first_scan`].
    pub fn set_region_filter(&mut self, filter: RegionFilter) {
        self.region_filter = filter;
    }

    /// The active region filter.
    pub fn region_filter(&self) -> &RegionFilter {
        &self.region_filter
    }

    /// How many regions the last first scan walked after filtering.
    ///
    /// Zero after a first scan means the scope matched no memory at all, which
    /// a UI should distinguish from an honest zero-match result.
    pub fn scanned_region_count(&self) -> usize {
        self.scanned_regions
    }

    /// The value type this scanner searches for.
    pub fn value_type(&self) -> ScanValueType {
        self.value_type
    }

    /// The current result generation, or an empty set before any scan.
    pub fn results(&self) -> &ScanResults {
        self.history.last().unwrap_or(&EMPTY_RESULTS)
    }

    /// Whether the previous scan can be undone.
    pub fn can_undo(&self) -> bool {
        self.history.len() > 1
    }

    /// Discards the current generation, restoring the previous results. Returns
    /// `false` if there was nothing to undo.
    pub fn undo(&mut self) -> bool {
        if self.can_undo() {
            self.history.pop();
            true
        } else {
            false
        }
    }

    /// The backing target, for callers that also need to read/freeze it.
    pub fn target(&self) -> &T {
        &self.target
    }

    /// Mutable access to the backing target (e.g. to re-point a live handle).
    pub fn target_mut(&mut self) -> &mut T {
        &mut self.target
    }

    /// Consumes the scanner and returns its target.
    pub fn into_target(self) -> T {
        self.target
    }

    /// Runs the initial scan.
    ///
    /// For absolute/delta comparisons pass the parsed `needle`; for the pure
    /// change-relative first-scan baseline ([`ScanCompareType::Unknown`]) pass
    /// `None` (a `None` needle with any needle-requiring compare is rejected).
    /// Every readable [`Region`] that survives the [`RegionFilter`] is walked in
    /// [`CHUNK_SIZE`] windows and every stride-aligned position is compared.
    pub fn first_scan(
        &mut self,
        compare: ScanCompareType,
        needle: Option<Needle>,
    ) -> Result<&ScanResults> {
        // A first scan cannot use a change-relative compare (there is no previous
        // value yet) — except `Unknown`, which is *defined* as the baseline.
        if compare.needs_previous() {
            return Err(needle_error());
        }
        self.validate_needle(compare, needle.as_ref())?;

        let stride = self.stride(compare, needle.as_ref());
        if stride == 0 {
            // No fixed width and no needle (e.g. `Unknown` on a string/`Bytes`
            // type): nothing sensible to step by.
            return Err(needle_error());
        }

        let regions = self.region_filter.apply(&self.target.regions()?);
        self.scanned_regions = regions.len();
        let mut results = ScanResults::new();
        let mut buf = vec![0u8; CHUNK_SIZE.max(stride)];

        for region in &regions {
            self.scan_region_first(region, compare, needle.as_ref(), stride, &mut buf, &mut results)?;
        }

        self.push_generation(results);
        self.has_scanned = true;
        Ok(self.results())
    }

    /// Refines the current results by re-reading only the previous match
    /// addresses and re-comparing (a next scan).
    ///
    /// Change-relative comparisons here see each result's captured
    /// `previous_value_bytes` as the previous value. Must follow a
    /// [`Scanner::first_scan`]; returns an error otherwise.
    pub fn next_scan(
        &mut self,
        compare: ScanCompareType,
        needle: Option<Needle>,
    ) -> Result<&ScanResults> {
        if !self.has_scanned {
            return Err(needle_error());
        }
        self.validate_needle(compare, needle.as_ref())?;

        let stride = self.stride(compare, needle.as_ref());
        if stride == 0 {
            return Err(needle_error());
        }

        let previous = self.results().clone();
        let mut results = ScanResults::new();
        let mut buf = vec![0u8; stride];

        for prev in previous.iter() {
            // Re-read exactly this result's span and re-compare against its
            // captured previous bytes.
            let read = self.target.read(prev.address, &mut buf)?;
            if read < stride {
                continue;
            }
            let matched = match &needle {
                Some(n) => n.compare_next(&buf, 0, compare, &prev.previous_value_bytes),
                None => compare_needleless_next(compare, &buf, &prev.previous_value_bytes, stride),
            };
            if matched {
                results.push(ScanResult::new(prev.address, buf[..stride].to_vec()));
            }
        }

        self.push_generation(results);
        Ok(self.results())
    }

    /// Progress snapshot for the current (last completed) generation.
    pub fn progress(&self) -> ScanProgress {
        let matches = self.results().len();
        ScanProgress {
            done: matches,
            total: matches,
            matches,
        }
    }

    /// Walks one region in overlapping [`CHUNK_SIZE`] windows, comparing every
    /// stride-aligned position, and appends matches (ascending address).
    fn scan_region_first(
        &self,
        region: &Region,
        compare: ScanCompareType,
        needle: Option<&Needle>,
        stride: usize,
        buf: &mut [u8],
        out: &mut ScanResults,
    ) -> Result<()> {
        let mut addr = region.base;
        let region_end = region.end();

        while addr < region_end {
            // Never read past the region: cap the request to what remains.
            let remaining = region_end - addr;
            let want = buf.len().min(remaining);
            let read = self.target.read(addr, &mut buf[..want])?;
            if read < stride {
                // Not enough bytes left in this region (or a short read at the
                // tail) to hold even one value — done with this region.
                break;
            }

            // The last position where a full stride still fits in what we read.
            let last = read - stride;
            for off in 0..=last {
                let matched = match needle {
                    Some(n) => n.compare_first(&buf[..read], off, compare),
                    None => matches!(compare, ScanCompareType::Unknown),
                };
                if matched {
                    let value = buf[off..off + stride].to_vec();
                    out.push(ScanResult::new(addr + off, value));
                }
            }

            // Advance so the next window overlaps by `stride - 1`, guaranteeing a
            // value straddling the previous chunk boundary is still tested.
            // Advance by at least 1 to make progress even in the degenerate
            // `read == stride` case.
            let step = (read - (stride - 1)).max(1);
            addr += step;
        }
        Ok(())
    }

    /// The scan stride: the needle's width when present, else the type's fixed
    /// width (for a needle-less change-relative scan on a numeric type). `0`
    /// means "no stride available" — a needle-less scan on a variable-width type.
    fn stride(&self, _compare: ScanCompareType, needle: Option<&Needle>) -> usize {
        match needle {
            Some(n) => n.stride(),
            None => self.value_type.fixed_width().unwrap_or(0),
        }
    }

    /// Validates the needle against the compare kind: a needle-requiring compare
    /// must have one, and a supplied needle must match the scanner's type.
    fn validate_needle(&self, compare: ScanCompareType, needle: Option<&Needle>) -> Result<()> {
        match needle {
            Some(n) => {
                if n.value_type() != self.value_type {
                    return Err(needle_error());
                }
            }
            None => {
                if compare.needs_needle() {
                    return Err(needle_error());
                }
            }
        }
        Ok(())
    }

    /// Pushes a new result generation, evicting the oldest past [`HISTORY_DEPTH`].
    fn push_generation(&mut self, results: ScanResults) {
        self.history.push(results);
        if self.history.len() > HISTORY_DEPTH {
            self.history.remove(0);
        }
    }
}

#[cfg(test)]
impl<T: ScanTarget + Clone> Scanner<T> {
    /// Clones the scanner (target, history, value type) so a test can branch two
    /// different next scans off a single baseline. Test-only: a live target is
    /// not `Clone`, and cloning an OS handle has no general meaning.
    pub(crate) fn clone_for_test(&self) -> Self {
        Self {
            target: self.target.clone(),
            value_type: self.value_type,
            region_filter: self.region_filter.clone(),
            scanned_regions: self.scanned_regions,
            history: self.history.clone(),
            has_scanned: self.has_scanned,
        }
    }
}

/// A shared empty result set for [`Scanner::results`] before the first scan.
static EMPTY_RESULTS: ScanResults = ScanResults::new_const();

/// Compares a needle-less change-relative next scan by reinterpreting both the
/// current and previous bytes for the scanner's fixed width. Used when the
/// caller passed no needle (pure `Increased`/`Decreased`/`Changed`/`Unchanged`).
fn compare_needleless_next(
    compare: ScanCompareType,
    cur: &[u8],
    prev: &[u8],
    stride: usize,
) -> bool {
    if cur.len() < stride || prev.len() < stride {
        return false;
    }
    // Byte-wise change comparisons don't need a type: `Changed`/`Unchanged` are
    // pure byte inequality/equality. `Increased`/`Decreased` need a numeric
    // interpretation, so they compare the little-endian magnitude.
    match compare {
        ScanCompareType::Changed => cur[..stride] != prev[..stride],
        ScanCompareType::Unchanged => cur[..stride] == prev[..stride],
        ScanCompareType::Increased => le_magnitude(&cur[..stride]) > le_magnitude(&prev[..stride]),
        ScanCompareType::Decreased => le_magnitude(&cur[..stride]) < le_magnitude(&prev[..stride]),
        // Anything else here is a needle-requiring compare and is rejected before
        // reaching this point.
        _ => false,
    }
}

/// The unsigned little-endian magnitude of up to 16 bytes (used for a needle-less
/// `Increased`/`Decreased`, where no signedness is known).
fn le_magnitude(bytes: &[u8]) -> u128 {
    let mut acc = 0u128;
    for (i, &b) in bytes.iter().take(16).enumerate() {
        acc |= (b as u128) << (8 * i);
    }
    acc
}

/// The generic error a scanner returns for a misuse (missing/mismatched needle,
/// next scan before a first scan, no stride). Reuses the core error vocabulary
/// so callers keep a single `Result` type.
fn needle_error() -> nemclass_core::Error {
    nemclass_core::Error::InvalidString
}
