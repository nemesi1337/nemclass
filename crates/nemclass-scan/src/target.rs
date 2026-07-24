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
    use super::{Region, ScanTarget, WriteTarget};
    use nemclass_core::{Process, ProviderRegistry, Result};

    /// A live Linux scan target backed by an opened [`Process`].
    ///
    /// Regions come from the provider's `enumerate_sections_and_modules`,
    /// filtered to writable, non-zero sections — the ones a value scan cares
    /// about (Cheat Engine's default "writable" filter). Reads go through
    /// [`Process::read_buf`] (one `process_vm_readv`), writes through
    /// [`Process::write`].
    pub struct ProcessTarget {
        process: Process,
        pid: nemclass_core::Pid,
    }

    impl ProcessTarget {
        /// Attaches to `pid` via the default native (`"linux-native"`) provider.
        pub fn attach(pid: nemclass_core::Pid) -> Result<Self> {
            let process = Process::attach(pid)?;
            Ok(Self { process, pid })
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
            Ok(Self { process, pid })
        }

        /// The opened process handle, for direct typed reads/writes.
        pub fn process(&self) -> &Process {
            &self.process
        }
    }

    impl ScanTarget for ProcessTarget {
        fn regions(&self) -> Result<Vec<Region>> {
            // Enumerate through the native provider; keep writable, committed
            // sections (a value scan only cares about mutable memory).
            let provider = nemclass_core::LinuxProvider;
            let (sections, _modules) =
                nemclass_core::ProcessProvider::enumerate_sections_and_modules(&provider, self.pid)?;
            Ok(sections
                .into_iter()
                .filter(|s| s.prot.write() && s.size > 0)
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
