use crate::internal::process::Protection;

/// A platform-neutral process id, used across the [`crate::ProcessProvider`] /
/// [`crate::Process`] seam so the trait signatures don't hard-depend on
/// `libc::pid_t` (which `libc` only defines on unix, not on Windows).
///
/// On unix this is exactly `libc::pid_t` (an `i32`), so existing callers that
/// pass a `libc::pid_t` keep type-checking unchanged. On Windows it is an `i32`
/// as well — wide enough to hold any real process id (a Win32 `DWORD` pid) — so
/// the same providers/handles compile there with no signature churn.
#[cfg(unix)]
pub type Pid = libc::pid_t;

/// See the unix definition above. Windows process ids are `DWORD` (`u32`) but the
/// neutral seam keeps a single signed `i32` type; every real pid fits.
#[cfg(not(unix))]
pub type Pid = i32;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Start
    pub from: usize,
    /// End
    pub to: usize,
    /// Prtection
    pub prot: Protection,
    /// Mapping name/path as reported by the OS — a backing file path, or a
    /// pseudo-name like `[heap]`/`[stack]` on Linux. `None` for anonymous
    /// mappings and backends that don't expose one (e.g. Windows).
    pub name: Option<String>,
}

#[derive(Debug)]
/// Single process
pub struct ProcessEntry {
    /// Id of the process.
    pub id: u32,
    /// Name of the process.
    pub name: String,
    /// Id of the parent process.
    pub parent_id: u32,
}

#[derive(Debug, Clone)]
pub struct ModuleInfoWithName {
    /// Module's base
    pub base: usize,
    /// Module's size
    pub size: usize,
    /// Module's name
    pub name: String,
}

/// A module in a target: a loaded image with a base, size and name. Alias of
/// [`ModuleInfoWithName`] so the [`crate::ProcessProvider`] vocabulary
/// (`Section`/`Module`) reads cleanly without duplicating the type.
pub type Module = ModuleInfoWithName;

/// Origin of a memory [`Section`] — mirrors ReClass.NET's `SectionType`, telling
/// an image mapping (backed by a file / inode) apart from a shared mapping and
/// from plain anonymous private memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// Backed by a mapped file (has an inode) — part of a module image.
    Image,
    /// A shared mapping: file- or shm-backed and visible to other processes
    /// (Windows `MEM_MAPPED`, Linux's `s` sharing flag).
    Mapped,
    /// Anonymous, process-private memory — the heap, thread stacks and plain
    /// anonymous mappings (Windows `MEM_PRIVATE`). This is where a value scan
    /// finds most of what it is looking for.
    Private,
    /// Origin could not be determined.
    Unknown,
}

/// One contiguous mapping in the target's address space: an address range, its
/// protection, and — for file-backed mappings — the backing module's name.
///
/// This is the per-mapping "section" a [`crate::ProcessProvider`] enumerates
/// (ReClass.NET's `EnumerateRemoteSectionData`). Distinct from [`Module`], which
/// aggregates the sections of one image into a single base/size/name.
#[derive(Debug, Clone)]
pub struct Section {
    /// Start address of the mapping.
    pub base: usize,
    /// Size of the mapping in bytes.
    pub size: usize,
    /// Protection flags for the mapping.
    pub prot: Protection,
    /// Whether the mapping is file-backed (image) or anonymous.
    pub kind: SectionType,
    /// Backing module file name for image sections; `None` for anonymous ones.
    pub module: Option<String>,
}

/// One module aggregated from `/proc/<pid>/maps`: its file name, image base and
/// the end of its last mapping. Linux-only (the `maps`-parsing internal type).
#[cfg(target_os = "linux")]
pub struct RawModule {
    pub name: String,
    pub base: usize,
    pub end: usize,
}