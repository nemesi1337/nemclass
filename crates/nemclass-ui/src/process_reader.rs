//! `ProcessReader` — orphan-safe newtype wrapping `nemclass_core::Process` so
//! the UI crate can implement the model's `MemoryReader` and `ModuleResolver`
//! traits without violating the orphan rule (which forbids `impl ForeignTrait
//! for ForeignType` in a third crate).

use nemclass_core::{ModuleInfoWithName, Process};
use nemclass_model::{MemoryReader, ModuleResolver};

/// A thin, non-owning wrapper around a `Process` reference.
///
/// - Implements `MemoryReader` by reading a `usize` through `Process::read`.
/// - Implements `ModuleResolver` via the cached module list baked in at
///   construction time (avoids re-reading `/proc/<pid>/maps` every frame for
///   every formula evaluation; the caller refreshes the cache as needed).
pub struct ProcessReader<'a> {
    process: &'a Process,
    modules: Vec<ModuleInfoWithName>,
}

impl<'a> ProcessReader<'a> {
    /// Creates a wrapper.  The `modules` slice is collected once from
    /// `process.modules()` by the caller; passing it here keeps this type
    /// zero-allocation on the hot path.
    pub fn new(process: &'a Process, modules: Vec<ModuleInfoWithName>) -> Self {
        Self { process, modules }
    }
}

impl MemoryReader for ProcessReader<'_> {
    fn read_usize(&self, addr: usize) -> nemclass_model::Result<usize> {
        self.process
            .read::<usize>(addr)
            .map_err(|e| nemclass_model::ModelError::ResolveError(e.to_string()))
    }
}

impl ModuleResolver for ProcessReader<'_> {
    fn resolve_module(&self, name: &str) -> Option<usize> {
        self.modules
            .iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .map(|m| m.base)
    }
}
