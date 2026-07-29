//! The scan-target seam: what the [`crate::Scanner`] needs from a source of
//! memory, kept abstract so the engine is platform-neutral and mock-testable.
//!
//! [`ScanTarget`] enumerates readable [`Region`]s and reads bytes at absolute
//! addresses; [`WriteTarget`] adds the write half a [`crate::FreezeSet`] needs.
//! Tests drive the scanner through [`MockTarget`] (an in-memory buffer plus
//! fabricated regions); a live Linux target uses [`ProcessTarget`], backed by
//! `nemclass_core::{Process, ProviderRegistry}`.

use nemclass_core::Result;
use std::sync::Mutex;

/// One contiguous, readable span of the target's address space that the scanner
/// may walk. Platform-neutral (mirrors the useful part of
/// `nemclass_core::Section`) so a mock can fabricate regions freely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    /// Start address of the region.
    pub base: usize,
    /// Length of the region in bytes.
    pub size: usize,
}

impl Region {
    /// A region from a base and size.
    pub fn new(base: usize, size: usize) -> Self {
        Self { base, size }
    }

    /// The (exclusive) end address of the region.
    pub fn end(&self) -> usize {
        self.base.saturating_add(self.size)
    }
}

/// Which parts of a target's address space a first scan may walk: a half-open
/// window `[start, stop)` intersected with an optional allowlist of spans.
///
/// Purely an address-space policy — platform-neutral and side-effect free, so it
/// drives a [`MockTarget`] scan identically to a live one. It lives on the
/// [`crate::Scanner`] rather than on the target because [`ScanTarget::regions`]
/// answers "what can I read", not "what do I want to read this time": baking a
/// window into the target would silently truncate anything else that asks it for
/// regions (notably [`crate::pointer_scan`]).
///
/// [`Default`] is unrestricted, so an unconfigured scanner behaves exactly as it
/// did before this type existed.
///
/// Note that clamping *truncates* a region at `start`/`stop`, so a value that
/// straddles the boundary (an `i32` at `start - 2`) is not found. This matches
/// ReClass.NET's `Scanner.GetSearchableSections` and is intentional.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionFilter {
    /// Inclusive lower bound of the window.
    pub start: usize,
    /// Exclusive upper bound of the window.
    pub stop: usize,
    /// Spans to restrict the scan to, typically module images. Empty means "no
    /// allowlist" — i.e. the whole window — **not** "nothing".
    pub include: Vec<Region>,
}

impl Default for RegionFilter {
    fn default() -> Self {
        Self { start: 0, stop: usize::MAX, include: Vec::new() }
    }
}

impl RegionFilter {
    /// A filter restricted to the half-open window `[start, stop)`.
    pub fn window(start: usize, stop: usize) -> Self {
        Self { start, stop, ..Self::default() }
    }

    /// Restricts the filter to an allowlist of spans.
    pub fn with_include(mut self, include: Vec<Region>) -> Self {
        self.include = include;
        self
    }

    /// Whether [`Self::apply`] would return its input unchanged.
    pub fn is_unrestricted(&self) -> bool {
        self.start == 0 && self.stop == usize::MAX && self.include.is_empty()
    }

    /// Clamps `regions` to the window and intersects them with the allowlist.
    ///
    /// The result is ascending by base, disjoint, and never contains a
    /// zero-sized region. One input region straddling several allowlist spans
    /// yields one output region per span.
    pub fn apply(&self, regions: &[Region]) -> Vec<Region> {
        if self.is_unrestricted() {
            return regions.to_vec();
        }
        if self.start >= self.stop {
            return Vec::new();
        }
        let include = self.merged_include();
        let mut out = Vec::with_capacity(regions.len());
        for r in regions {
            // Window clamp. Both bounds are computed from the originals rather
            // than mutated in place — ReClass.NET's `Scanner.cs` clamp re-tests
            // an already-moved `start` against the original `end`.
            let lo = r.base.max(self.start);
            let hi = r.end().min(self.stop);
            if lo >= hi {
                continue;
            }
            if include.is_empty() {
                out.push(Region::new(lo, hi - lo));
                continue;
            }
            for inc in &include {
                let a = lo.max(inc.base);
                let b = hi.min(inc.end());
                if a < b {
                    out.push(Region::new(a, b - a));
                }
            }
        }
        out.sort_by_key(|r| r.base);
        out
    }

    /// The allowlist, sorted and coalesced.
    ///
    /// Two selected modules with overlapping or abutting spans would otherwise
    /// each intersect the same source region, emitting overlapping output
    /// regions — the same address matched twice, giving duplicate results and an
    /// inflated count.
    fn merged_include(&self) -> Vec<Region> {
        let mut spans: Vec<Region> =
            self.include.iter().filter(|r| r.size > 0).cloned().collect();
        spans.sort_by_key(|r| r.base);
        let mut merged: Vec<Region> = Vec::with_capacity(spans.len());
        for r in spans {
            match merged.last_mut() {
                // Overlapping or exactly abutting: extend the previous span.
                Some(last) if r.base <= last.end() => {
                    let end = last.end().max(r.end());
                    last.size = end - last.base;
                }
                _ => merged.push(r),
            }
        }
        merged
    }
}

/// A tri-state predicate over one protection flag — ReClass.NET's `SettingState`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FilterState {
    /// The section must have the flag.
    Yes,
    /// The section must not have the flag.
    No,
    /// Don't care.
    #[default]
    Any,
}

impl FilterState {
    /// Whether a section that does (or doesn't) have the flag passes.
    pub const fn accepts(self, has: bool) -> bool {
        match self {
            Self::Yes => has,
            Self::No => !has,
            Self::Any => true,
        }
    }
}

/// Which sections of a live process are offered to a scan: the protection and
/// memory-type half of the scan scope, mirroring ReClass.NET's `ScanSettings`.
///
/// Unlike [`RegionFilter`] this needs `Section::{prot, kind}` and so can only be
/// applied where sections exist — inside [`ProcessTarget`]. That is not new
/// policy in the target: `regions()` has always hardcoded "writable only", and
/// this makes that choice configurable.
///
/// [`Default`] reproduces both the previous hardcoded behaviour and
/// ReClass.NET's defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionFilter {
    /// Whether the section must be writable. Default [`FilterState::Yes`].
    pub writable: FilterState,
    /// Whether the section must be executable. Default [`FilterState::Any`].
    pub executable: FilterState,
    /// Whether the section must be copy-on-write. Default [`FilterState::No`].
    pub copy_on_write: FilterState,
    /// Scan anonymous private memory (heap, stacks). Default `true`.
    pub scan_private: bool,
    /// Scan module image mappings. Default `true`.
    pub scan_image: bool,
    /// Scan shared mappings. Default `false`.
    pub scan_mapped: bool,
}

impl Default for SectionFilter {
    fn default() -> Self {
        Self {
            writable: FilterState::Yes,
            executable: FilterState::Any,
            copy_on_write: FilterState::No,
            scan_private: true,
            scan_image: true,
            scan_mapped: false,
        }
    }
}

impl SectionFilter {
    /// Whether this section's memory type and protection pass the filter.
    ///
    /// Platform-neutral, so it is unit-testable against hand-built sections with
    /// no live process.
    pub fn keep(&self, s: &nemclass_core::Section) -> bool {
        use nemclass_core::SectionType;
        let type_ok = match s.kind {
            SectionType::Private => self.scan_private,
            SectionType::Image => self.scan_image,
            SectionType::Mapped => self.scan_mapped,
            // An unclassifiable mapping is never scanned, as in ReClass.NET.
            SectionType::Unknown => false,
        };
        type_ok
            && self.writable.accepts(s.prot.write())
            && self.executable.accepts(s.prot.execute())
            && self.copy_on_write.accepts(s.prot.copy_on_write())
    }
}

/// A readable source of target memory the [`crate::Scanner`] walks.
///
/// The scanner only ever reads within a [`Region`] returned by [`Self::regions`]
/// and never assumes a read is complete — it uses the returned length — so a
/// short read at a region tail is handled gracefully.
///
/// `Send + Sync` because a first scan shards its regions across threads and
/// reads through `&self` from all of them.
pub trait ScanTarget: Send + Sync {
    /// The readable regions to scan, in ascending address order.
    fn regions(&self) -> Result<Vec<Region>>;

    /// Reads up to `buf.len()` bytes starting at `addr`, returning the number of
    /// bytes actually read (which may be short if the tail is unmapped).
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize>;

    /// Reads many spans at once, filling `out[i]` with the result for
    /// `spans[i]`.
    ///
    /// The default fans out to [`Self::read`], which is what the mock and any
    /// simple target want. A live target overrides it with a vectored read: a
    /// next scan re-reads every surviving result, and at the five-million
    /// default cap that is five million syscalls where one `process_vm_readv`
    /// can carry a thousand spans.
    ///
    /// `out` is per-span so one unreadable address drops one result rather than
    /// the whole batch — a long-running target recycles memory constantly.
    fn read_batch(&self, spans: &mut [(usize, &mut [u8])], out: &mut [Result<usize>]) {
        for (i, (addr, buf)) in spans.iter_mut().enumerate() {
            if let Some(slot) = out.get_mut(i) {
                *slot = self.read(*addr, buf);
            }
        }
    }

    /// How many spans [`Self::read_batch`] should be given at a time.
    ///
    /// The default is 1 — no batching — so a target that has not overridden
    /// `read_batch` is not asked to build batch buffers for nothing.
    fn batch_size(&self) -> usize {
        1
    }
}

/// Merges regions that touch or overlap, so a value straddling the boundary
/// between two adjacent mappings is still found.
///
/// `/proc/<pid>/maps` splits a single `mmap` the moment part of it gets
/// different protection, and the heap routinely appears as several abutting
/// `rw-p` entries. The scan walk stops at each region's end, so an `i32` with
/// two bytes either side of such a boundary was never tested — a value that is
/// genuinely there and genuinely writable simply could not be found.
pub fn coalesce_regions(mut regions: Vec<Region>) -> Vec<Region> {
    regions.retain(|r| r.size > 0);
    regions.sort_by_key(|r| r.base);
    let mut merged: Vec<Region> = Vec::with_capacity(regions.len());
    for r in regions {
        match merged.last_mut() {
            Some(last) if r.base <= last.end() => {
                let end = last.end().max(r.end());
                last.size = end - last.base;
            }
            _ => merged.push(r),
        }
    }
    merged
}

/// The write half of a target: what a [`crate::FreezeSet`] needs to keep frozen
/// values pinned. Split from [`ScanTarget`] so a read-only source (a snapshot,
/// a dump file) can still be scanned without implementing writes.
pub trait WriteTarget {
    /// Writes `buf` starting at `addr`, returning the number of bytes written.
    fn write(&self, addr: usize, buf: &[u8]) -> Result<usize>;
}

/// An in-memory scan target for tests: a flat byte buffer mapped at a chosen
/// base address, exposed as one or more fabricated [`Region`]s.
///
/// Addresses passed to [`ScanTarget::read`] are absolute (base-relative into the
/// buffer). Reads and writes clamp to the buffer, mirroring a real target's
/// short transfer at a region edge. This is the sole test double the scanner is
/// exercised through — no live process required.
#[derive(Debug)]
pub struct MockTarget {
    base: usize,
    /// Behind a `Mutex` so [`WriteTarget::write`], which takes `&self`, can
    /// actually store bytes. A test double that accepted writes and silently
    /// discarded them would let freeze/write code pass its tests having written
    /// nothing.
    buf: Mutex<Vec<u8>>,
    regions: Vec<Region>,
    /// Absolute address ranges that fail to read, so a test can reproduce a
    /// target that unmapped part of a nominally readable region mid-scan.
    holes: Vec<(usize, usize)>,
}

impl Clone for MockTarget {
    fn clone(&self) -> Self {
        Self {
            base: self.base,
            buf: Mutex::new(self.buf_lock().clone()),
            regions: self.regions.clone(),
            holes: self.holes.clone(),
        }
    }
}

impl MockTarget {
    /// A target whose whole buffer is one region starting at `base`.
    pub fn new(base: usize, buf: Vec<u8>) -> Self {
        let regions = vec![Region::new(base, buf.len())];
        Self::with_regions(base, buf, regions)
    }

    /// A target with explicit, possibly-partial [`Region`]s over the buffer.
    /// Regions are given as absolute address ranges; the scanner will only read
    /// within them, so this exercises region-boundary behaviour.
    pub fn with_regions(base: usize, buf: Vec<u8>, regions: Vec<Region>) -> Self {
        Self {
            base,
            buf: Mutex::new(buf),
            regions,
            holes: Vec::new(),
        }
    }

    /// Marks `[start, end)` unreadable: reads that begin inside it fail, and
    /// reads that run into it stop short — exactly how `process_vm_readv`
    /// behaves against an unmapped page inside a listed region.
    pub fn with_hole(mut self, start: usize, end: usize) -> Self {
        self.holes.push((start, end));
        self
    }

    /// The base address the buffer is mapped at.
    pub fn base(&self) -> usize {
        self.base
    }

    /// Mutable access to the backing buffer, so a test can mutate the target
    /// between a first and next scan.
    pub fn buf_mut(&mut self) -> &mut [u8] {
        self.buf.get_mut().expect("mock target buffer poisoned")
    }

    /// Reads the current bytes at absolute `addr` for `len` bytes, for test
    /// assertions. Returns `None` if out of range.
    pub fn peek(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        let start = addr.checked_sub(self.base)?;
        let end = start.checked_add(len)?;
        self.buf_lock().get(start..end).map(<[u8]>::to_vec)
    }

    fn buf_lock(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
        self.buf.lock().expect("mock target buffer poisoned")
    }

    /// Translates an absolute address into a buffer offset, if in range.
    fn offset_of(&self, addr: usize, len: usize) -> Option<usize> {
        addr.checked_sub(self.base).filter(|&o| o <= len)
    }

    /// How many bytes are readable starting at `addr` before the first hole.
    fn readable_from(&self, addr: usize) -> Option<usize> {
        if self.holes.iter().any(|&(s, e)| addr >= s && addr < e) {
            return None;
        }
        Some(
            self.holes
                .iter()
                .filter(|&&(s, _)| s > addr)
                .map(|&(s, _)| s - addr)
                .min()
                .unwrap_or(usize::MAX),
        )
    }
}

impl ScanTarget for MockTarget {
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(self.regions.clone())
    }

    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize> {
        let Some(until_hole) = self.readable_from(addr) else {
            return Err(nemclass_core::Error::InvalidAddress);
        };
        let src = self.buf_lock();
        let Some(offset) = self.offset_of(addr, src.len()) else {
            return Ok(0);
        };
        let available = src.len() - offset;
        let n = available.min(buf.len()).min(until_hole);
        buf[..n].copy_from_slice(&src[offset..offset + n]);
        Ok(n)
    }
}

impl WriteTarget for MockTarget {
    fn write(&self, addr: usize, buf: &[u8]) -> Result<usize> {
        // A hole is unmapped, so it fails writes exactly as it fails reads.
        let Some(until_hole) = self.readable_from(addr) else {
            return Err(nemclass_core::Error::InvalidAddress);
        };
        let mut dst = self.buf_lock();
        let Some(offset) = self.offset_of(addr, dst.len()) else {
            return Ok(0);
        };
        let available = dst.len() - offset;
        let n = available.min(buf.len()).min(until_hole);
        dst[offset..offset + n].copy_from_slice(&buf[..n]);
        Ok(n)
    }
}

// The live Linux target: regions from `enumerate_sections_and_modules`
// (writable, committed), reads via `Process::read_buf`, writes via
// `Process::write`. Linux-only; the scan engine above is platform-neutral.
#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Arc;

    use super::{Region, ScanTarget, SectionFilter, WriteTarget};
    use nemclass_core::{Process, ProviderRegistry, Result};

    /// A live Linux scan target backed by an opened [`Process`].
    ///
    /// Regions come from the provider's `enumerate_sections_and_modules`, kept
    /// or dropped by a [`SectionFilter`] whose default is the writable-only
    /// policy a value scan wants (Cheat Engine's default). Reads go through
    /// [`Process::read_buf`] (one `process_vm_readv`), writes through
    /// [`Process::write_buf`].
    ///
    /// The handle is an `Arc` so a caller that already has one — the UI holds
    /// `Arc<Process>` precisely so background workers can share it — can pass it
    /// in rather than opening a second one. That matters beyond saving a syscall:
    /// [`Self::attach`] always opens the *native* provider, so a scanner built
    /// that way reads through a different backend than an app attached via the
    /// kernel module, and the two can disagree about what is at an address.
    pub struct ProcessTarget {
        process: Arc<Process>,
        pid: nemclass_core::Pid,
        filter: SectionFilter,
    }

    impl ProcessTarget {
        /// Attaches to `pid` via the default native (`"linux-native"`) provider.
        pub fn attach(pid: nemclass_core::Pid) -> Result<Self> {
            Ok(Self::from_shared(Arc::new(Process::attach(pid)?)))
        }

        /// Wraps an already-opened process handle, sharing whichever backend it
        /// was opened with. Preferred over [`Self::attach`] whenever the caller
        /// has one.
        pub fn from_shared(process: Arc<Process>) -> Self {
            let pid = process.pid();
            Self { process, pid, filter: SectionFilter::default() }
        }

        /// Opens `pid` through a named provider in `registry` (e.g.
        /// `"linux-native"` or the privileged `"linux-kernel"`).
        pub fn open_with(
            registry: &ProviderRegistry,
            provider: &str,
            pid: nemclass_core::Pid,
        ) -> Result<Self> {
            let provider = registry
                .get(provider)
                .ok_or(nemclass_core::Error::ProcessNotFound)?;
            Ok(Self::from_shared(Arc::new(provider.open(pid)?)))
        }

        /// Restricts which sections [`ScanTarget::regions`] offers.
        pub fn with_section_filter(mut self, filter: SectionFilter) -> Self {
            self.filter = filter;
            self
        }

        /// Replaces the section filter in place.
        pub fn set_section_filter(&mut self, filter: SectionFilter) {
            self.filter = filter;
        }

        /// The active section filter.
        pub fn section_filter(&self) -> &SectionFilter {
            &self.filter
        }

        /// The opened process handle, for direct typed reads/writes.
        pub fn process(&self) -> &Process {
            &self.process
        }
    }

    impl ScanTarget for ProcessTarget {
        fn read_batch(
            &self,
            spans: &mut [(usize, &mut [u8])],
            out: &mut [Result<usize>],
        ) {
            // One `process_vm_readv` for the whole batch. It reports a total
            // rather than a per-span length, and it stops at the first span it
            // cannot read — so a partial result has to be resolved per span
            // before anything is trusted.
            let total = self.process.read_buf_batch(spans);
            let wanted: usize = spans.iter().map(|(_, b)| b.len()).sum();
            match total {
                Ok(n) if n == wanted => {
                    for (i, (_, buf)) in spans.iter().enumerate() {
                        if let Some(slot) = out.get_mut(i) {
                            *slot = Ok(buf.len());
                        }
                    }
                }
                // Short or failed: fall back to one read per span so the caller
                // learns exactly which addresses are gone. This costs a syscall
                // per span for that batch only, which is the old behaviour — and
                // it is rare, because a batch is short only when the target has
                // just freed something.
                _ => {
                    for (i, (addr, buf)) in spans.iter_mut().enumerate() {
                        if let Some(slot) = out.get_mut(i) {
                            *slot = self.process.read_buf(*addr, buf);
                        }
                    }
                }
            }
        }

        fn batch_size(&self) -> usize {
            // `process_vm_readv` takes at most IOV_MAX (1024) iovecs per call,
            // and `read_buf_batch` already chunks to that. Matching it keeps one
            // batch to one syscall.
            1024
        }

        fn regions(&self) -> Result<Vec<Region>> {
            // Enumerate through the native provider and keep the non-empty
            // sections the filter accepts.
            //
            // `LinuxProvider` is deliberate rather than the provider the process
            // was opened with: `KernelProvider` labels every section
            // `SectionType::Mapped` with no module name (see its
            // `enumerate_sections_and_modules`), which the memory-type filters
            // would reject wholesale. Classification has to come from
            // `/proc/<pid>/maps`.
            let provider = nemclass_core::LinuxProvider;
            // Sections only: the module list was enumerated and immediately
            // discarded on every scan and every pointer-map build, and building
            // it means opening a second handle and reading a PE header out of
            // the target for each Wine module.
            let sections =
                nemclass_core::ProcessProvider::enumerate_sections(&provider, self.pid)?;
            Ok(super::coalesce_regions(
                sections
                    .into_iter()
                    .filter(|s| s.size > 0 && self.filter.keep(s))
                    .map(|s| Region::new(s.base, s.size))
                    .collect(),
            ))
        }

        fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize> {
            self.process.read_buf(addr, buf)
        }
    }

    impl WriteTarget for ProcessTarget {
        fn write(&self, addr: usize, buf: &[u8]) -> Result<usize> {
            // One `process_vm_writev` for the whole span. This used to loop
            // `write::<u8>`, i.e. one syscall per byte per freeze entry, every
            // 200 ms.
            self.process.write_buf(addr, buf)
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::ProcessTarget;

// The Windows target. Structurally the same as the Linux one — the seams are
// platform-neutral, which is the whole point of having them — but it enumerates
// through `WindowsProvider` (`VirtualQueryEx`) and reads through
// `ReadProcessMemory`. There was previously no Windows `ScanTarget` at all, so
// the scanner, the pointer scan and the spider could not run there even though
// every layer beneath them could.
#[cfg(windows)]
mod win {
    use std::sync::Arc;

    use super::{Region, ScanTarget, SectionFilter, WriteTarget, coalesce_regions};
    use nemclass_core::{Process, ProviderRegistry, Result};

    /// A live Windows scan target backed by an opened [`Process`].
    pub struct ProcessTarget {
        process: Arc<Process>,
        pid: nemclass_core::Pid,
        filter: SectionFilter,
    }

    impl ProcessTarget {
        /// Opens `pid` through the native (`"windows-native"`) provider.
        pub fn attach(pid: nemclass_core::Pid) -> Result<Self> {
            use nemclass_core::ProcessProvider;
            let provider = nemclass_core::WindowsProvider;
            Ok(Self::from_shared(Arc::new(provider.open(pid)?)))
        }

        /// Wraps an already-opened process handle.
        pub fn from_shared(process: Arc<Process>) -> Self {
            let pid = process.pid();
            Self { process, pid, filter: SectionFilter::default() }
        }

        /// Opens `pid` through a named provider in `registry`.
        pub fn open_with(
            registry: &ProviderRegistry,
            provider: &str,
            pid: nemclass_core::Pid,
        ) -> Result<Self> {
            let provider = registry
                .get(provider)
                .ok_or(nemclass_core::Error::ProcessNotFound)?;
            Ok(Self::from_shared(Arc::new(provider.open(pid)?)))
        }

        pub fn with_section_filter(mut self, filter: SectionFilter) -> Self {
            self.filter = filter;
            self
        }

        pub fn set_section_filter(&mut self, filter: SectionFilter) {
            self.filter = filter;
        }

        pub fn section_filter(&self) -> &SectionFilter {
            &self.filter
        }

        pub fn process(&self) -> &Process {
            &self.process
        }
    }

    impl ScanTarget for ProcessTarget {
        fn regions(&self) -> Result<Vec<Region>> {
            use nemclass_core::ProcessProvider;
            let provider = nemclass_core::WindowsProvider;
            let sections = provider.enumerate_sections(self.pid)?;
            Ok(coalesce_regions(
                sections
                    .into_iter()
                    .filter(|s| s.size > 0 && self.filter.keep(s))
                    .map(|s| Region::new(s.base, s.size))
                    .collect(),
            ))
        }

        fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize> {
            self.process.read_buf(addr, buf)
        }

        fn read_batch(
            &self,
            spans: &mut [(usize, &mut [u8])],
            out: &mut [Result<usize>],
        ) {
            // `ReadProcessMemory` has no vectored form, so the batch is a loop —
            // but going through the same entry point keeps the scan engine's
            // batching path identical on both platforms rather than special-cased.
            for (i, (addr, buf)) in spans.iter_mut().enumerate() {
                if let Some(slot) = out.get_mut(i) {
                    *slot = self.process.read_buf(*addr, buf);
                }
            }
        }
    }

    impl WriteTarget for ProcessTarget {
        fn write(&self, addr: usize, buf: &[u8]) -> Result<usize> {
            self.process.write_buf(addr, buf)
        }
    }
}

#[cfg(windows)]
pub use win::ProcessTarget;
