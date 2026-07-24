mod decoder;
mod process;

// Re-export the curated public surface from the platform-specific submodules so
// `lib.rs` can lift it to the crate root. The `process` module tree itself stays
// private — callers use these names, not `internal::process::…` paths.
pub use process::{
    LinuxProvider, MemoryBackend, MemoryRegion, Module, ModuleInfoWithName, Process, ProcessEntry,
    ProcessIterator, ProcessProvider, Protection, ProviderRegistry, Section, SectionType, pe,
};

// Disassembler wrapper (iced-x86) — consumed by the future scanner/host APIs.
pub use decoder::{InstructionData, disassemble_instructions};
