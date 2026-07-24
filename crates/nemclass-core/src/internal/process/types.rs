use crate::internal::process::Protection;

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
/// an image mapping (backed by a file / inode) apart from an anonymous mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    /// Backed by a mapped file (has an inode) — part of a module image.
    Image,
    /// An anonymous mapping (heap, stack, private, ...).
    Mapped,
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
/// the end of its last mapping.
pub struct RawModule {
    pub name: String,
    pub base: usize,
    pub end: usize,
}