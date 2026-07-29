//! The scan engine: first scan over regions, next scan refining previous
//! results, and a short undo history. Generic over [`ScanTarget`] so it is
//! platform-neutral and driven in tests by a mock.
//!
//! Ported from ReClass.NET's `Scanner` (`FirstScan`/`NextScan` + the circular
//! store of result generations). The parallel worker pool is deliberately not
//! ported — a single-threaded chunked walk keeps the engine dependency-free and
//! deterministic for tests; a caller can shard regions across threads later.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::compare::ScanCompareType;
use crate::results::ScanResults;
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
    /// A `Between` was run without an upper bound.
    BetweenNeedsUpperBound,
    /// Every address in the previous generation failed to read — the process is
    /// almost certainly gone. Distinguished from "narrowed to zero results" so a
    /// dead target never looks like a successful scan.
    TargetUnreadable(nemclass_core::Error),
    /// Enumerating the target's regions failed.
    Target(nemclass_core::Error),
    /// A [`ScanObserver`] aborted the pass. The current generation is untouched.
    Cancelled,
}

/// Whether a region walk ran to completion or was stopped by the observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WalkOutcome {
    Completed,
    Cancelled,
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
            Self::BetweenNeedsUpperBound => write!(
                f,
                "Between needs both bounds — enter the upper one, or use \"greater than\" \
                 if that is what you meant"
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
            Self::Cancelled => write!(f, "scan stopped"),
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
/// The two "could not read" counters are the interesting ones, and they measure
/// different things because the two passes fail differently:
///
/// - `unreadable` (next scan) — a next scan re-reads addresses a previous
///   generation matched, and any of them may have been freed or unmapped since.
///   Those results are dropped individually, and this is how a caller tells the
///   user that happened.
/// - `skipped_bytes` (first scan) — a region listed as readable in the maps
///   snapshot can still fault part-way through (the target `munmap`ped it, or a
///   `PROT_NONE` guard page sits inside a merged mapping). Those spans are
///   stepped over rather than aborting the pass, and this is how many bytes were
///   never examined. Non-zero means the results are incomplete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Candidate positions (first scan) or previous results (next scan) examined.
    pub scanned: usize,
    /// How many matched.
    pub matched: usize,
    /// How many previous results could not be read back and were dropped.
    pub unreadable: usize,
    /// Bytes inside nominally readable regions that a first scan could not read
    /// and therefore skipped.
    pub skipped_bytes: usize,
}

/// The read buffer size for the first-scan chunked region walk (a handful of
/// pages). Regions larger than this are read in overlapping windows so a value
/// straddling a chunk boundary is still found.
const CHUNK_SIZE: usize = 64 * 1024;

/// The granularity a first scan steps over an unreadable span at. Faults happen
/// per page, so this is the smallest useful skip.
const PAGE_SIZE: usize = 4096;

/// How many consecutive faulting windows a region tolerates before the walk
/// gives up on it. Without a cap, a region that has been unmapped in its
/// entirety would cost one syscall per page across its whole span.
const MAX_CONSECUTIVE_FAULTS: usize = 16;

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

/// The largest span one worker takes in a parallel first scan. Small enough that
/// a single huge mapping is shared out rather than pinning one thread, large
/// enough that the per-shard setup is noise.
const SHARD_SPAN: usize = 8 * 1024 * 1024;

/// Below this total span a first scan stays single-threaded: spawning threads
/// costs more than the walk saves, and the deterministic path is easier to
/// reason about when something goes wrong.
const PARALLEL_THRESHOLD: usize = 4 * 1024 * 1024;

/// How often a scan reports progress: every this many candidate positions on a
/// first scan, or previous results on a next scan. Frequent enough for a smooth
/// bar and a responsive Stop, rare enough that the callback is not measurable.
const PROGRESS_INTERVAL: usize = 4096;

/// Progress of an in-flight scan pass, as passed to a [`ScanObserver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanProgress {
    /// Work units processed so far: candidate positions on a first scan,
    /// previous results re-read on a next scan.
    pub done: usize,
    /// Total work units for this pass. An estimate on a first scan (the region
    /// span divided by the alignment), exact on a next scan.
    pub total: usize,
    /// Matches found so far.
    pub matches: usize,
}

/// Called periodically during a scan. Returning `false` aborts the pass, which
/// then leaves the current result generation untouched.
///
/// Scans run on a background worker that cannot be killed from outside, so
/// stopping one has to be cooperative. This is also the only honest source of
/// progress: the total is not known until the region walk has been set up.
///
/// `Send` because a parallel first scan ticks from its workers (through one
/// lock, so an implementation still never sees concurrent calls).
pub trait ScanObserver: Send {
    /// Reports progress. Return `false` to abort.
    fn tick(&mut self, progress: ScanProgress) -> bool;
}

impl<F: FnMut(ScanProgress) -> bool + Send> ScanObserver for F {
    fn tick(&mut self, progress: ScanProgress) -> bool {
        self(progress)
    }
}

/// A [`ScanObserver`] that ignores progress and never aborts, for the
/// non-cancellable entry points.
pub struct NoObserver;

impl ScanObserver for NoObserver {
    fn tick(&mut self, _progress: ScanProgress) -> bool {
        true
    }
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
    /// Worker threads for a first scan. `None` asks the platform.
    threads: Option<usize>,
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
            threads: None,
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

    /// Sets how many worker threads a first scan uses. `1` forces the
    /// single-threaded walk; `0` or unset asks the platform.
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.threads = (threads > 0).then_some(threads);
        self
    }

    /// Replaces the worker-thread count in place.
    pub fn set_threads(&mut self, threads: usize) {
        self.threads = (threads > 0).then_some(threads);
    }

    /// The worker-thread count a first scan will use.
    fn thread_count(&self) -> usize {
        self.threads.unwrap_or_else(|| {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
        })
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

    /// Whether a first scan has completed, i.e. whether a next scan is valid.
    pub fn has_scanned(&self) -> bool {
        self.has_scanned
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
        self.first_scan_with(compare, needle, &mut NoObserver)
    }

    /// [`Scanner::first_scan`] with progress reporting and cooperative
    /// cancellation. An aborted scan leaves the current generation untouched.
    pub fn first_scan_with(
        &mut self,
        compare: ScanCompareType,
        needle: Option<Needle>,
        observer: &mut dyn ScanObserver,
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
        self.truncated = false;

        // An estimate, since a region may read short: the walked span divided by
        // the candidate step. Good enough to drive a bar, and the only number
        // available before the walk starts.
        let align = self.alignment();
        let total: usize = regions.iter().map(|r| r.size / align).sum();
        let span: usize = regions.iter().map(|r| r.size).sum();

        // Shard the address space across workers once it is big enough to be
        // worth the threads. ReClass.NET's parallel pool was deliberately not
        // ported when this engine was written; a first scan over a real working
        // set is entirely memory-read-bound and shards cleanly.
        let shards = self.shard_regions(&regions, stride);
        let workers = self.thread_count().min(shards.len()).max(1);
        let (results, scanned, skipped, truncated) =
            if workers > 1 && span >= PARALLEL_THRESHOLD {
                self.first_scan_sharded(
                    &shards, compare, needle.as_ref(), stride, observer, total, workers,
                )?
            } else {
                self.first_scan_serial(&regions, compare, needle.as_ref(), stride, observer, total)?
            };
        self.truncated = truncated;

        self.last_stats = ScanStats {
            scanned,
            matched: results.len(),
            unreadable: 0,
            skipped_bytes: skipped,
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
        self.next_scan_with(compare, needle, &mut NoObserver)
    }

    /// [`Scanner::next_scan`] with progress reporting and cooperative
    /// cancellation. An aborted scan leaves the current generation untouched.
    pub fn next_scan_with(
        &mut self,
        compare: ScanCompareType,
        needle: Option<Needle>,
        observer: &mut dyn ScanObserver,
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

        // Borrowed, not cloned. The previous generation is
        // `len * (8 + 3 * stride)` bytes — around 100 MB at the default
        // five-million cap for an `i32` — and it was duplicated on every single
        // narrowing pass purely to satisfy the borrow checker.
        let previous = std::mem::take(self.history.last_mut().expect("has_scanned"));
        let outcome = self.run_next_scan(&previous, compare, needle.as_ref(), stride, observer);
        // Put it back before anything can return: this generation is the user's
        // current result set until a new one replaces it, and an error or a
        // cancellation must leave it exactly where it was.
        if let Some(slot) = self.history.last_mut() {
            *slot = previous;
        }
        let (results, unreadable, last_err) = outcome?;
        let previous_len = self.results().len();

        // Everything gone is not a narrowing — it is a dead target. Report it
        // and leave the current generation intact rather than handing back an
        // empty result set that reads as "your value isn't there any more".
        if unreadable == previous_len && previous_len > 0 {
            return Err(ScanError::TargetUnreadable(
                last_err.unwrap_or(nemclass_core::Error::ProcessNotFound),
            ));
        }

        self.last_stats = ScanStats {
            scanned: previous_len,
            matched: results.len(),
            unreadable,
            // A next scan reads only known result addresses, so there is no
            // region span to skip — unreadable results are counted individually.
            skipped_bytes: 0,
        };
        self.push_generation(results);
        Ok(self.results())
    }

    /// Splits `regions` into work units of at most [`SHARD_SPAN`].
    ///
    /// A shard's span is extended by `stride - 1` so a value straddling the cut
    /// is still read, while the shard's *positions* stop short of the next
    /// shard's start — the walk stops once fewer than `stride` bytes remain, and
    /// both ends sit on the alignment lattice, so no position is tested twice.
    fn shard_regions(&self, regions: &[Region], stride: usize) -> Vec<Region> {
        let align = self.alignment();
        let mut out = Vec::new();
        for region in regions {
            if region.size <= SHARD_SPAN {
                out.push(region.clone());
                continue;
            }
            let end = region.end();
            let mut start = region.base;
            while start < end {
                // Cut on the lattice, so the next shard's first candidate is
                // exactly one step past this shard's last.
                let mut cut = Self::align_up(start.saturating_add(SHARD_SPAN), align).min(end);
                if cut <= start {
                    cut = end;
                }
                let read_end = cut.saturating_add(stride - 1).min(end);
                out.push(Region::new(start, read_end - start));
                start = cut;
            }
        }
        out
    }

    /// The single-threaded region walk.
    fn first_scan_serial(
        &self,
        regions: &[Region],
        compare: ScanCompareType,
        needle: Option<&Needle>,
        stride: usize,
        observer: &mut dyn ScanObserver,
        total: usize,
    ) -> Result<(ScanResults, usize, usize, bool)> {
        let mut results = ScanResults::with_stride(stride);
        let mut buf = vec![0u8; CHUNK_SIZE.max(stride)];
        let mut scanned = 0usize;
        let mut skipped = 0usize;
        let mut truncated = false;

        for region in regions {
            let outcome = self.scan_region_first(
                region, compare, needle, stride, &mut buf, &mut results, observer, &mut scanned,
                &mut skipped, total,
            )?;
            if outcome == WalkOutcome::Cancelled {
                // Deliberately before `push_generation`: a stopped scan must
                // leave the previous results exactly as they were.
                return Err(ScanError::Cancelled);
            }
            if results.len() >= self.result_limit {
                truncated = true;
                break;
            }
        }
        Ok((results, scanned, skipped, truncated))
    }

    /// The sharded region walk: `workers` threads over `shards`.
    ///
    /// Each shard's matches are collected separately and concatenated in shard
    /// order, so the result set is still ascending by address regardless of the
    /// order the threads finish in.
    #[allow(clippy::too_many_arguments)]
    fn first_scan_sharded(
        &self,
        shards: &[Region],
        compare: ScanCompareType,
        needle: Option<&Needle>,
        stride: usize,
        observer: &mut dyn ScanObserver,
        total: usize,
        workers: usize,
    ) -> Result<(ScanResults, usize, usize, bool)> {
        let next_shard = AtomicUsize::new(0);
        let scanned = AtomicUsize::new(0);
        let skipped = AtomicUsize::new(0);
        let matched = AtomicUsize::new(0);
        let cancelled = AtomicBool::new(false);
        // One slot per shard so the join order does not decide the address
        // order of the results.
        let slots: Vec<std::sync::Mutex<ScanResults>> =
            (0..shards.len()).map(|_| std::sync::Mutex::new(ScanResults::with_stride(stride))).collect();
        // The observer is `&mut` and cannot be shared, so ticks funnel through
        // one lock. They happen once every PROGRESS_INTERVAL candidates, so the
        // contention is nowhere near the read cost.
        let observer = std::sync::Mutex::new(observer);

        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    let mut buf = vec![0u8; CHUNK_SIZE.max(stride)];
                    loop {
                        if cancelled.load(Ordering::Relaxed)
                            || matched.load(Ordering::Relaxed) >= self.result_limit
                        {
                            return;
                        }
                        let index = next_shard.fetch_add(1, Ordering::Relaxed);
                        let Some(shard) = shards.get(index) else { return };

                        let mut local = ScanResults::with_stride(stride);
                        let mut local_scanned = 0usize;
                        let mut local_skipped = 0usize;

                        // The per-shard walk reports through a closure that
                        // folds this thread's progress into the shared counters
                        // and relays the observer's verdict.
                        let mut relay = |progress: ScanProgress| -> bool {
                            if cancelled.load(Ordering::Relaxed) {
                                return false;
                            }
                            let done = scanned.load(Ordering::Relaxed) + progress.done;
                            let go = observer
                                .lock()
                                .map(|mut o| {
                                    o.tick(ScanProgress {
                                        done,
                                        total,
                                        matches: matched.load(Ordering::Relaxed) + progress.matches,
                                    })
                                })
                                .unwrap_or(true);
                            if !go {
                                cancelled.store(true, Ordering::Relaxed);
                            }
                            go
                        };

                        let outcome = self.scan_region_first(
                            shard, compare, needle, stride, &mut buf, &mut local, &mut relay,
                            &mut local_scanned, &mut local_skipped, total,
                        );
                        match outcome {
                            Ok(WalkOutcome::Cancelled) => {
                                cancelled.store(true, Ordering::Relaxed);
                                return;
                            }
                            Ok(WalkOutcome::Completed) => {}
                            Err(_) => {
                                cancelled.store(true, Ordering::Relaxed);
                                return;
                            }
                        }

                        scanned.fetch_add(local_scanned, Ordering::Relaxed);
                        skipped.fetch_add(local_skipped, Ordering::Relaxed);
                        matched.fetch_add(local.len(), Ordering::Relaxed);
                        if let Ok(mut slot) = slots[index].lock() {
                            *slot = local;
                        }
                    }
                });
            }
        });

        if cancelled.load(Ordering::Relaxed) {
            return Err(ScanError::Cancelled);
        }

        let mut results = ScanResults::with_stride(stride);
        results.reserve(matched.load(Ordering::Relaxed));
        let mut truncated = false;
        for slot in slots {
            let mut part = slot.into_inner().unwrap_or_else(|e| e.into_inner());
            results.append(&mut part);
            if results.len() >= self.result_limit {
                truncated = true;
                break;
            }
        }

        Ok((
            results,
            scanned.load(Ordering::Relaxed),
            skipped.load(Ordering::Relaxed),
            truncated,
        ))
    }

    /// The next-scan core: re-read every previous result in batches and
    /// re-compare.
    ///
    /// Returns the new generation, how many addresses could not be read, and the
    /// last read error (for the "everything is gone" diagnosis).
    fn run_next_scan(
        &self,
        previous: &ScanResults,
        compare: ScanCompareType,
        needle: Option<&Needle>,
        stride: usize,
        observer: &mut dyn ScanObserver,
    ) -> Result<(ScanResults, usize, Option<nemclass_core::Error>)> {
        let mut results = ScanResults::with_stride(stride);
        results.reserve(previous.len());
        let mut unreadable = 0usize;
        let mut last_err = None;

        // One vectored read per batch instead of one syscall per result. At the
        // five-million default cap that is the difference between five million
        // syscalls and about five thousand.
        let batch = self.target.batch_size().clamp(1, 4096);
        let mut bytes = vec![0u8; batch * stride];
        let mut statuses: Vec<core::result::Result<usize, nemclass_core::Error>> =
            Vec::with_capacity(batch);

        let mut index = 0usize;
        while index < previous.len() {
            let count = batch.min(previous.len() - index);

            if !observer.tick(ScanProgress {
                done: index,
                total: previous.len(),
                matches: results.len(),
            }) {
                // The caller puts the previous generation back, so a stopped
                // narrowing leaves the user's result set exactly as it was.
                return Err(ScanError::Cancelled);
            }

            statuses.clear();
            statuses.resize_with(count, || Ok(0));
            {
                let mut spans: Vec<(usize, &mut [u8])> = bytes[..count * stride]
                    .chunks_mut(stride)
                    .enumerate()
                    .map(|(i, chunk)| {
                        (previous.get(index + i).expect("in range").address, chunk)
                    })
                    .collect();
                self.target.read_batch(&mut spans, &mut statuses);
            }

            for i in 0..count {
                // An address that has since been freed or unmapped drops just
                // that result: a long-running target recycles memory constantly,
                // and aborting the whole pass would make every scan session die
                // the first time one candidate went away.
                match std::mem::replace(&mut statuses[i], Ok(0)) {
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
                let prev = previous.get(index + i).expect("in range");
                let cur = &bytes[i * stride..(i + 1) * stride];
                let matched = match needle {
                    Some(n) => {
                        n.compare_next_with_first(cur, 0, compare, prev.current, prev.first)
                    }
                    None if compare.needs_first() => {
                        self.value_type.compare_change(compare, cur, prev.first)
                    }
                    None => self.value_type.compare_change(compare, cur, prev.current),
                };
                if matched {
                    // This generation's `previous` is the *previous* generation's
                    // current — the value the user last saw, which is what a Cheat
                    // Engine "Previous" column shows. `first` rides along
                    // untouched so a later "same as first scan" still has the
                    // original.
                    results.push_with_first(prev.address, cur, prev.current, prev.first);
                }
            }

            index += count;
        }

        Ok((results, unreadable, last_err))
    }

    /// Walks one region in overlapping [`CHUNK_SIZE`] windows, comparing every
    /// aligned position, and appends matches (ascending address).
    ///
    /// `scanned` accumulates across regions so progress is reported against the
    /// whole pass, not per region.
    ///
    /// A region that faults part-way through does **not** abort the pass. The
    /// maps snapshot is taken once and the target keeps running, so an
    /// `munmap`, a `PROT_NONE` guard page inside a merged mapping, or a
    /// `ptrace_scope` change routinely makes part of a "readable" region
    /// unreadable. Those spans are stepped over a page at a time and their size
    /// accumulated into `skipped`; only a region that faults repeatedly is
    /// abandoned wholesale.
    #[allow(clippy::too_many_arguments)]
    fn scan_region_first(
        &self,
        region: &Region,
        compare: ScanCompareType,
        needle: Option<&Needle>,
        stride: usize,
        buf: &mut [u8],
        out: &mut ScanResults,
        observer: &mut dyn ScanObserver,
        scanned: &mut usize,
        skipped: &mut usize,
        total: usize,
    ) -> Result<WalkOutcome> {
        let align = self.alignment();
        // Start on an aligned address so every candidate in this region sits on
        // the same lattice, independent of where the region happens to begin.
        let mut addr = Self::align_up(region.base, align);
        let region_end = region.end();
        // Candidates since the last observer tick, so the check itself costs
        // nothing per position.
        let mut since_tick = 0usize;
        // Consecutive failed windows. A region that is entirely gone would
        // otherwise cost one syscall per page for its whole span.
        let mut consecutive_faults = 0usize;

        while addr < region_end {
            // Never read past the region: cap the request to what remains.
            let remaining = region_end - addr;
            if remaining < stride {
                // The region tail is too short to hold even one value. This is
                // the ordinary way the walk ends, not a fault.
                break;
            }
            let want = buf.len().min(remaining);
            let read = match self.target.read(addr, &mut buf[..want]) {
                Ok(n) => {
                    consecutive_faults = 0;
                    n
                }
                Err(_) => {
                    // `addr` itself is unreadable. Step over the page it sits in
                    // and try the next one; a hole is usually a page or two.
                    consecutive_faults += 1;
                    if consecutive_faults > MAX_CONSECUTIVE_FAULTS {
                        *skipped += remaining;
                        break;
                    }
                    let next = Self::next_page(addr).min(region_end);
                    *skipped += next - addr;
                    addr = Self::align_up(next, align);
                    continue;
                }
            };
            if read < stride {
                // A hole starts inside this window before a whole value fits.
                // Resume after the faulting page rather than abandoning the
                // rest of the region.
                let next = Self::next_page(addr.saturating_add(read)).min(region_end);
                *skipped += next - addr;
                addr = Self::align_up(next, align);
                continue;
            }
            // A short read (`read < want`) is *not* accounted as skipped here:
            // the advance below resumes at `addr + read - (stride - 1)`, the
            // next iteration faults, and the page-skip path above counts the
            // hole exactly once. Counting the window remainder as well would
            // double-count every byte past the hole that is scanned normally.

            // The last position where a full stride still fits in what we read.
            let last = read - stride;
            // A literal byte/string needle almost never matches, and testing
            // every position to discover that is the whole cost of an AOB scan.
            // `memchr` finds the occurrences of the needle's first byte with SIMD
            // and the walk visits only those, which is typically two orders of
            // magnitude fewer positions.
            let prefix = match (needle, compare) {
                (Some(n), ScanCompareType::Exact) => n.literal_prefix(),
                _ => None,
            };
            let candidates: Box<dyn Iterator<Item = usize>> = match prefix {
                Some(byte) => Box::new(
                    memchr::memchr_iter(byte, &buf[..read])
                        // Keep the alignment lattice: a prefiltered position that
                        // is not on it was never a candidate.
                        .filter(move |off| off % align == 0)
                        .take_while(move |off| *off <= last),
                ),
                None => Box::new((0..=last).step_by(align)),
            };
            // `scanned` still counts lattice positions, not prefiltered hits:
            // it drives the progress bar against a total computed from the span,
            // and counting only the hits would make the bar stall at zero.
            let mut lattice_positions = last / align + 1;
            for off in candidates {
                lattice_positions = lattice_positions.saturating_sub(1);
                *scanned += 1;
                since_tick += 1;
                if since_tick >= PROGRESS_INTERVAL {
                    since_tick = 0;
                    let go = observer.tick(ScanProgress {
                        done: *scanned,
                        total,
                        matches: out.len(),
                    });
                    if !go {
                        return Ok(WalkOutcome::Cancelled);
                    }
                }
                let matched = match needle {
                    Some(n) => n.compare_first(&buf[..read], off, compare),
                    None => matches!(compare, ScanCompareType::Unknown),
                };
                if matched {
                    // Nothing came before a first scan, so the value is its own
                    // previous — Cheat Engine shows it in both columns rather
                    // than leaving Previous blank.
                    let value = &buf[off..off + stride];
                    out.push(addr + off, value, value);
                    if out.len() >= self.result_limit {
                        return Ok(WalkOutcome::Completed);
                    }
                }
            }

            // Positions the prefilter skipped were still examined, as far as
            // "how much of the span is done" is concerned.
            *scanned += lattice_positions;

            // Advance so the next window overlaps by `stride - 1`, guaranteeing a
            // value straddling the previous chunk boundary is still tested, then
            // round back up to the alignment lattice so candidates stay on it.
            // Advance by at least `align` to make progress even in the degenerate
            // `read == stride` case. Saturating throughout: a region abutting the
            // top of the address space would otherwise overflow here, which
            // panics in debug and silently wraps to 0 in release.
            let step = (read - (stride - 1)).max(1);
            let floor = addr.saturating_add(align);
            addr = Self::align_up(addr.saturating_add(step), align).max(floor);
        }
        Ok(WalkOutcome::Completed)
    }

    /// The start of the page after the one containing `addr`, saturating at the
    /// top of the address space.
    fn next_page(addr: usize) -> usize {
        match addr.checked_add(PAGE_SIZE) {
            // `addr & !(PAGE_SIZE - 1)` is the page base; + one page is the next.
            Some(_) => (addr & !(PAGE_SIZE - 1)).saturating_add(PAGE_SIZE),
            None => usize::MAX,
        }
    }

    /// `addr` rounded up to a multiple of `align`, saturating instead of
    /// panicking on overflow (`usize::next_multiple_of` panics in debug).
    fn align_up(addr: usize, align: usize) -> usize {
        debug_assert!(align > 0);
        match addr.checked_next_multiple_of(align) {
            Some(v) => v,
            None => usize::MAX,
        }
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
                // A `Between` with no upper bound used to degrade silently to
                // `value > lower`, which is a different search returning far
                // more results than were asked for — and no way to tell.
                if compare.needs_upper_bound() && !n.has_upper_bound() {
                    return Err(ScanError::BetweenNeedsUpperBound);
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
            threads: self.threads,
            truncated: self.truncated,
            history: self.history.clone(),
            has_scanned: self.has_scanned,
            last_stats: self.last_stats,
        }
    }
}

/// A shared empty result set for [`Scanner::results`] before the first scan.
static EMPTY_RESULTS: ScanResults = ScanResults::new_const();

