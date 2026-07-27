//! The scan-target seam: what the [`crate::Scanner`] needs from a source of
//! memory, kept abstract so the engine is platform-neutral and mock-testable.
//!
//! [`ScanTarget`] enumerates readable [`Region`]s and reads bytes at absolute
//! addresses; [`WriteTarget`] adds the write half a [`crate::FreezeSet`] needs.
//! Tests drive the scanner through [`MockTarget`] (an in-memory buffer plus
//! fabricated regions); a live Linux target uses [`ProcessTarget`], backed by
//! `nemclass_core::{Process, ProviderRegistry}`.

use nemclass_core::Result;

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
pub trait ScanTarget {
    /// The readable regions to scan, in ascending address order.
    fn regions(&self) -> Result<Vec<Region>>;

    /// Reads up to `buf.len()` bytes starting at `addr`, returning the number of
    /// bytes actually read (which may be short if the tail is unmapped).
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize>;
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
#[derive(Debug, Clone)]
pub struct MockTarget {
    base: usize,
    buf: Vec<u8>,
    regions: Vec<Region>,
}

impl MockTarget {
    /// A target whose whole buffer is one region starting at `base`.
    pub fn new(base: usize, buf: Vec<u8>) -> Self {
        let regions = vec![Region::new(base, buf.len())];
        Self { base, buf, regions }
    }

    /// A target with explicit, possibly-partial [`Region`]s over the buffer.
    /// Regions are given as absolute address ranges; the scanner will only read
    /// within them, so this exercises region-boundary behaviour.
    pub fn with_regions(base: usize, buf: Vec<u8>, regions: Vec<Region>) -> Self {
        Self { base, buf, regions }
    }

    /// The base address the buffer is mapped at.
    pub fn base(&self) -> usize {
        self.base
    }

    /// Mutable access to the backing buffer, so a test can mutate the target
    /// between a first and next scan.
    pub fn buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Reads the current bytes at absolute `addr` for `len` bytes, for test
    /// assertions. Returns `None` if out of range.
    pub fn peek(&self, addr: usize, len: usize) -> Option<&[u8]> {
        let start = addr.checked_sub(self.base)?;
        self.buf.get(start..start + len)
    }

    /// Translates an absolute address into a buffer offset, if in range.
    fn offset_of(&self, addr: usize) -> Option<usize> {
        addr.checked_sub(self.base).filter(|&o| o <= self.buf.len())
    }
}

impl ScanTarget for MockTarget {
    fn regions(&self) -> Result<Vec<Region>> {
        Ok(self.regions.clone())
    }

    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize> {
        let Some(offset) = self.offset_of(addr) else {
            return Ok(0);
        };
        let available = self.buf.len() - offset;
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&self.buf[offset..offset + n]);
        Ok(n)
    }
}

impl WriteTarget for MockTarget {
    fn write(&self, _addr: usize, _buf: &[u8]) -> Result<usize> {
        // Interior mutability is intentionally not offered on the shared-ref
        // `MockTarget`; freeze-write tests use a `&mut` helper instead (see the
        // crate tests). A shared-ref write would need a `Cell`/`Mutex` wrapper.
        Ok(0)
    }
}

// The live Linux target: regions from `enumerate_sections_and_modules`
// (writable, committed), reads via `Process::read_buf`, writes via
// `Process::write`. Linux-only; the scan engine above is platform-neutral.
#[cfg(target_os = "linux")]
mod linux {
    use super::{Region, ScanTarget, SectionFilter, WriteTarget};
    use nemclass_core::{Process, ProviderRegistry, Result};

    /// A live Linux scan target backed by an opened [`Process`].
    ///
    /// Regions come from the provider's `enumerate_sections_and_modules`, kept
    /// or dropped by a [`SectionFilter`] whose default is the writable-only
    /// policy a value scan wants (Cheat Engine's default). Reads go through
    /// [`Process::read_buf`] (one `process_vm_readv`), writes through
    /// [`Process::write`].
    pub struct ProcessTarget {
        process: Process,
        pid: nemclass_core::Pid,
        filter: SectionFilter,
    }

    impl ProcessTarget {
        /// Attaches to `pid` via the default native (`"linux-native"`) provider.
        pub fn attach(pid: nemclass_core::Pid) -> Result<Self> {
            let process = Process::attach(pid)?;
            Ok(Self { process, pid, filter: SectionFilter::default() })
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
            let process = provider.open(pid)?;
            Ok(Self { process, pid, filter: SectionFilter::default() })
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
            let (sections, _modules) =
                nemclass_core::ProcessProvider::enumerate_sections_and_modules(&provider, self.pid)?;
            Ok(sections
                .into_iter()
                .filter(|s| s.size > 0 && self.filter.keep(s))
                .map(|s| Region::new(s.base, s.size))
                .collect())
        }

        fn read(&self, addr: usize, buf: &mut [u8]) -> Result<usize> {
            self.process.read_buf(addr, buf)
        }
    }

    impl WriteTarget for ProcessTarget {
        fn write(&self, addr: usize, buf: &[u8]) -> Result<usize> {
            // `Process` exposes a typed `write<T>` but no raw-buffer write, so a
            // freeze span is written a byte at a time (`write::<u8>`). Freeze
            // entries are only a handful of bytes and written periodically, so
            // the per-byte cost is negligible; a bulk `Process::write_buf` in
            // core would let this become a single `process_vm_writev`.
            for (i, &b) in buf.iter().enumerate() {
                self.process.write::<u8>(addr + i, b)?;
            }
            Ok(buf.len())
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::ProcessTarget;
