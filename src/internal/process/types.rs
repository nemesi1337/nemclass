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

/// One module aggregated from `/proc/<pid>/maps`: its file name, image base and
/// the end of its last mapping.
pub struct RawModule {
    pub name: String,
    pub base: usize,
    pub end: usize,
}