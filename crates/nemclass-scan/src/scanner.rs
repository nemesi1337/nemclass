//! The scan engine: first scan over regions, next scan refining previous
//! results, and a short undo history. Generic over [`ScanTarget`] so it is
//! platform-neutral and driven in tests by a mock.
//!
//! Ported from ReClass.NET's `Scanner` (`FirstScan`/`NextScan` + the circular
//! store of result generations). The parallel worker pool is deliberately not
//! ported — a single-threaded chunked walk keeps the engine dependency-free and
//! deterministic for tests; a caller can shard regions across threads later.

use crate::compare::ScanCompareType;
use crate::results::{ScanResult, ScanResults};
use crate::target::{Region, RegionFilter, ScanTarget};
use crate::value_type::{Needle, ScanValueType};

/// The result type of a scan pass.
pub type Result<T> = core::result::Result<T, ScanError>;

/// Why a scan could not run, or could not run to completion.
///
/// Every variant used to be a single opaque `Error::InvalidString`, which left
/// the UI showing "invalid string" for six unrelated mistakes. Callers format
/// this with `Display`, so the message reaches the status line as-is.
/// `nemclass_core::Error` is neither `Clone` nor `Eq`, so neither is this; tests
/// match on it with `matches!` rather than `assert_eq!`.
#[derive(Debug)]
pub enum ScanError {
    /// A next scan was requested before any first scan.
    NeedsFirstScan,
    /// A change-relative compare was used on a first scan, where there is no
    /// previous value to compare against.
    CompareNeedsPrevious(ScanCompareType),
    /// [`ScanCompareType::Unknown`] was used on a next scan; it is a first-scan
    /// baseline only.
    CompareIsFirstScanOnly(ScanCompareType),
    /// A compare that requires a needle was given none.
    MissingNeedle(ScanCompareType),
    /// The needle's type does not match the scanner's.
    NeedleTypeMismatch {
        /// The type the needle was parsed as.
        needle: ScanValueType,
        /// The type this scan session searches for.
        scanner: ScanValueType,
    },
    /// A needle-less scan on a variable-width type, which has no stride to
    /// step by.
    NoStride(ScanValueType),
    /// Every address in the previous generation failed to read — the process is
    /// almost certainly gone. Distinguished from "narrowed to zero results" so a
    /// dead target never looks like a successful scan.
    TargetUnreadable(nemclass_core::Error),
    /// Enumerating the target's regions failed.
    Target(nemclass_core::Error),
}

impl core::fmt::Display for ScanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NeedsFirstScan => write!(f, "no scan session yet — run a first scan"),
            Self::CompareNeedsPrevious(c) => write!(
                f,
                "{c:?} compares against the previous scan's value, so it needs a next scan"
            ),
            Self::CompareIsFirstScanOnly(c) => write!(
                f,
                "{c:?} is a first-scan baseline only — narrow with Changed/Increased/Decreased \
                 or an exact value instead"
            ),
            Self::MissingNeedle(c) => write!(f, "{c:?} needs a value"),
            Self::NeedleTypeMismatch { needle, scanner } => write!(
                f,
                "value is a {} but this scan session searches for {} — press New Scan to \
                 change the type",
                needle.as_tag(),
                scanner.as_tag()
            ),
            Self::NoStride(ty) => write!(
                f,
                "{} has no fixed width, so it needs an explicit value to scan for",
                ty.as_tag()
            ),
            Self::TargetUnreadable(e) => {
                write!(f, "no result address could be read ({e}) — has the process exited?")
            }
            Self::Target(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<nemclass_core::Error> for ScanError {
    fn from(e: nemclass_core::Error) -> Self {
        Self::Target(e)
    }
}

/// Per-pass counters from the last completed scan.
///
/// `unreadable` is the interesting one: a next scan re-reads addresses that a
/// previous generation matched, and any of them may have been freed or unmapped
/// since. Those results are dropped individually, and this is how a caller can
/// tell the user that happened.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Candidate positions (first scan) or previous results (next scan) examined.
    pub scanned: usize,
    /// How many matched.
    pub matched: usize,
    /// How many previous results could not be read back and were dropped.
    pub unreadable: usize,
}

/// The read buffer size for the first-scan chunked region walk (a handful of
/// pages). Regions larger than this are read in overlapping windows so a value
/// straddling a chunk boundary is still found.
const CHUNK_SIZE: usize = 64 * 1024;

/// How many result generations the undo history keeps (matches ReClass.NET's
/// `CircularBuffer<ScanResultStore>(3)`).
const HISTORY_DEPTH: usize = 3;

/// Default cap on first-scan matches.
///
/// An `Unknown` baseline matches every candidate position, so its result count
/// is the scanned span divided by the alignment — hundreds of millions over a
/// real working set. The cap turns "the UI wedges and then the process is OOM
/// killed" into "narrow your scan range", which is a message a user can act on.
const DEFAULT_RESULT_LIMIT: usize = 5_000_000;

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
    /// Candidate step for a first scan, in bytes. `None` means "the scan
    /// stride", i.e. Cheat Engine's default Fast Scan.
    alignment: Option<usize>,
    /// Cap on how many matches a first scan will collect.
    result_limit: usize,
    /// Whether the last first scan stopped early on [`Self::result_limit`].
    truncated: bool,
    /// Result generations, oldest first; the last is the current one. Bounded to
    /// [`HISTORY_DEPTH`].
    history: Vec<ScanResults>,
    /// Whether a first scan has run yet (a next scan before one is an error).
    has_scanned: bool,
    /// Counters from the last completed pass.
    last_stats: ScanStats,
}

impl<T: ScanTarget> Scanner<T> {
    /// Creates a scanner over `target` for values of `value_type`.
    pub fn new(target: T, value_type: ScanValueType) -> Self {
        Self {
            target,
            value_type,
            region_filter: RegionFilter::default(),
            scanned_regions: 0,
            alignment: None,
            result_limit: DEFAULT_RESULT_LIMIT,
            truncated: false,
            history: Vec::new(),
            has_scanned: false,
            last_stats: ScanStats::default(),
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

    /// Sets the first-scan candidate step in bytes.
    ///
    /// The default is Cheat Engine's "Fast Scan": the value type's own width,
    /// which assumes a value of width *n* is *n*-aligned. Pass `1` to test every
    /// byte offset, which finds deliberately misaligned values at 4× the results
    /// and 4× the memory for an `i32`.
    ///
    /// Variable-width types ([`ScanValueType::Bytes`] and the string types)
    /// default to 1 instead: a byte pattern or an embedded string has no natural
    /// alignment, and stepping by the needle's length would skip most of them.
    pub fn with_alignment(mut self, alignment: usize) -> Self {
        self.alignment = (alignment > 0).then_some(alignment);
        self
    }

    /// Replaces the first-scan alignment in place. See [`Self::with_alignment`].
    pub fn set_alignment(&mut self, alignment: usize) {
        self.alignment = (alignment > 0).then_some(alignment);
    }

    /// The first-scan candidate step, honouring [`Self::with_alignment`].
    fn alignment(&self) -> usize {
        self.alignment
            .unwrap_or_else(|| self.value_type.fixed_width().unwrap_or(1))
            .max(1)
    }

    /// Caps how many matches a first scan collects. See [`DEFAULT_RESULT_LIMIT`].
    pub fn with_result_limit(mut self, limit: usize) -> Self {
        self.result_limit = limit;
        self
    }

    /// Whether the last first scan stopped early on the result limit, so the
    /// result set is a prefix of the real matches rather than all of them.
    pub fn results_truncated(&self) -> bool {
        self.truncated
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

    /// Reinterprets the existing results as a different value type of the *same*
    /// width (e.g. `i32` ↔ `u32` ↔ `f32`), returning `false` and changing
    /// nothing otherwise.
    ///
    /// A width change is refused because the captured spans in the history are
    /// the old width, so every stored previous value would be truncated or read
    /// past — the caller must start a new scan instead.
    pub fn set_value_type(&mut self, value_type: ScanValueType) -> bool {
        if value_type.fixed_width() != self.value_type.fixed_width() {
            return false;
        }
        self.value_type = value_type;
        true
    }

    /// Counters from the last completed scan pass.
    pub fn last_scan_stats(&self) -> ScanStats {
        self.last_stats
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
    /// [`CHUNK_SIZE`] windows, comparing each position on the alignment lattice
    /// (see [`Scanner::with_alignment`]; the stride by default). Stops early once
    /// [`Scanner::with_result_limit`] matches are collected, which
    /// [`Scanner::results_truncated`] then reports.
    pub fn first_scan(
        &mut self,
        compare: ScanCompareType,
        needle: Option<Needle>,
    ) -> Result<&ScanResults> {
        // A first scan cannot use a change-relative compare (there is no previous
        // value yet) — except `Unknown`, which is *defined* as the baseline.
        if compare.needs_previous() {
            return Err(ScanError::CompareNeedsPrevious(compare));
        }
        self.validate_needle(compare, needle.as_ref())?;

        let stride = self.stride(compare, needle.as_ref());
        if stride == 0 {
            // No fixed width and no needle (e.g. `Unknown` on a string/`Bytes`
            // type): nothing sensible to step by.
            return Err(ScanError::NoStride(self.value_type));
        }

        let regions = self.region_filter.apply(&self.target.regions()?);
        self.scanned_regions = regions.len();
        let mut results = ScanResults::new();
        let mut buf = vec![0u8; CHUNK_SIZE.max(stride)];
        let mut scanned = 0usize;
        self.truncated = false;

        for region in &regions {
            scanned += self.scan_region_first(
                region,
                compare,
                needle.as_ref(),
                stride,
                &mut buf,
                &mut results,
            )?;
            if results.len() >= self.result_limit {
                self.truncated = true;
                break;
            }
        }

        self.last_stats = ScanStats {
            scanned,
            matched: results.len(),
            unreadable: 0,
        };
        self.push_generation(results);
        self.has_scanned = true;
        Ok(self.results())
    }

    /// Refines the current results by re-reading only the previous match
    /// addresses and re-comparing (a next scan).
    ///
    /// Change-relative comparisons here see each result's captured
    /// `previous_value_bytes` as the previous value, interpreted *as the
    /// scanner's value type* — so `Increased` respects signedness and float
    /// ordering rather than raw byte magnitude.
    ///
    /// Must follow a [`Scanner::first_scan`]; returns an error otherwise, as it
    /// does for [`ScanCompareType::Unknown`], which is a first-scan baseline
    /// only. An address that can no longer be read drops that one result; the
    /// count is reported in [`Scanner::last_scan_stats`]. If *every* address
    /// fails the pass errors with [`ScanError::TargetUnreadable`] and leaves the
    /// current generation untouched.
    pub fn next_scan(
        &mut self,
        compare: ScanCompareType,
        needle: Option<Needle>,
    ) -> Result<&ScanResults> {
        if !self.has_scanned {
            return Err(ScanError::NeedsFirstScan);
        }
        // "Unknown initial value" accepts every candidate, which is meaningful
        // only as a first-scan baseline. Reject it here — *before* pushing a
        // generation — so the user's result set survives the mistake instead of
        // being silently emptied.
        if compare.is_baseline() {
            return Err(ScanError::CompareIsFirstScanOnly(compare));
        }
        self.validate_needle(compare, needle.as_ref())?;

        let stride = self.stride(compare, needle.as_ref());
        if stride == 0 {
            return Err(ScanError::NoStride(self.value_type));
        }

        let previous = self.results().clone();
        let mut results = ScanResults::new();
        let mut buf = vec![0u8; stride];
        let mut unreadable = 0usize;
        let mut last_err = None;

        for prev in previous.iter() {
            // Re-read exactly this result's span and re-compare against its
            // captured previous bytes. An address that has since been freed or
            // unmapped drops just that result: a long-running target recycles
            // memory constantly, and aborting the whole pass would make every
            // scan session die the first time one candidate went away.
            match self.target.read(prev.address, &mut buf) {
                Ok(read) if read >= stride => {}
                Ok(_) => {
                    unreadable += 1;
                    continue;
                }
                Err(e) => {
                    unreadable += 1;
                    last_err = Some(e);
                    continue;
                }
            }
            let matched = match &needle {
                Some(n) => n.compare_next(&buf, 0, compare, &prev.previous_value_bytes),
                None => self
                    .value_type
                    .compare_change(compare, &buf[..stride], &prev.previous_value_bytes),
            };
            if matched {
                results.push(ScanResult::new(prev.address, buf[..stride].to_vec()));
            }
        }

        // Everything gone is not a narrowing — it is a dead target. Report it
        // and leave the current generation intact rather than handing back an
        // empty result set that reads as "your value isn't there any more".
        if unreadable == previous.len() && !previous.is_empty() {
            return Err(ScanError::TargetUnreadable(
                last_err.unwrap_or(nemclass_core::Error::ProcessNotFound),
            ));
        }

        self.last_stats = ScanStats {
            scanned: previous.len(),
            matched: results.len(),
            unreadable,
        };
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
    /// Returns how many candidate positions were examined.
    fn scan_region_first(
        &self,
        region: &Region,
        compare: ScanCompareType,
        needle: Option<&Needle>,
        stride: usize,
        buf: &mut [u8],
        out: &mut ScanResults,
    ) -> Result<usize> {
        let align = self.alignment();
        // Start on an aligned address so every candidate in this region sits on
        // the same lattice, independent of where the region happens to begin.
        let mut addr = region.base.next_multiple_of(align);
        let region_end = region.end();
        let mut scanned = 0usize;

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
            // `addr` is aligned, so offset 0 is a candidate and every `align`
            // bytes after it is too.
            for off in (0..=last).step_by(align) {
                scanned += 1;
                let matched = match needle {
                    Some(n) => n.compare_first(&buf[..read], off, compare),
                    None => matches!(compare, ScanCompareType::Unknown),
                };
                if matched {
                    let value = buf[off..off + stride].to_vec();
                    out.push(ScanResult::new(addr + off, value));
                    if out.len() >= self.result_limit {
                        return Ok(scanned);
                    }
                }
            }

            // Advance so the next window overlaps by `stride - 1`, guaranteeing a
            // value straddling the previous chunk boundary is still tested, then
            // round back up to the alignment lattice so candidates stay on it.
            // Advance by at least `align` to make progress even in the degenerate
            // `read == stride` case.
            let step = (read - (stride - 1)).max(1);
            addr = (addr + step).next_multiple_of(align).max(addr + align);
        }
        Ok(scanned)
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
                    return Err(ScanError::NeedleTypeMismatch {
                        needle: n.value_type(),
                        scanner: self.value_type,
                    });
                }
            }
            None => {
                if compare.needs_needle() {
                    return Err(ScanError::MissingNeedle(compare));
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
            alignment: self.alignment,
            result_limit: self.result_limit,
            truncated: self.truncated,
            history: self.history.clone(),
            has_scanned: self.has_scanned,
            last_stats: self.last_stats,
        }
    }
}

/// A shared empty result set for [`Scanner::results`] before the first scan.
static EMPTY_RESULTS: ScanResults = ScanResults::new_const();

