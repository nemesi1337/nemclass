mod decoder;
mod process;

// Memory-dissection analysis (M5.1): region classification, string detection,
// pointer/vtable classification, and (Linux) live-process function walks. Layers
// on top of `decoder` + `process`; its pure core is platform-neutral.
mod analysis;

// Re-export the curated public surface from the platform-specific submodules so
// `lib.rs` can lift it to the crate root. The `process` module tree itself stays
// private — callers use these names, not `internal::process::…` paths.
pub use process::{
    MemoryBackend, MemoryRegion, Module, ModuleInfoWithName, Pid, Process, ProcessEntry,
    ProcessIterator, ProcessProvider, Protection, ProviderRegistry, Section, SectionType, Symbol,
    pe, symbols,
};

// On-disk symbolication (M5.2). Behind the optional `symbols` feature so the base
// build never references addr2line/object/pdb.
#[cfg(feature = "symbols")]
pub use process::{SymbolResolver, symbol_resolver};

// Native Linux provider (`process_vm_readv` backend + `/proc` enumeration) plus
// the backend-name constants a UI backend picker keys off of.
#[cfg(target_os = "linux")]
pub use process::{LINUX_KERNEL, LINUX_NATIVE, LinuxProvider};

// Native Windows backend + provider (`ReadProcessMemory`/`OpenProcess`/...),
// the `#[cfg(windows)]` mirror of `LinuxProvider`.
#[cfg(windows)]
pub use process::{WINDOWS_NATIVE, WindowsBackend, WindowsProvider};

// Kernel-device client + privileged backend/provider (Linux-only). Speaks the
// `nemclass_mod` ioctl ABI over `/proc/nemclass/attach` for ptrace-free memory IO and
// the non-ptrace debugger; the `kernel` module holds the `#[repr(C)]` ABI and
// the `Debugger` controller layered over the client.
#[cfg(target_os = "linux")]
pub use process::{
    Breakpoint, BreakpointId, BreakpointSpec, DebugEvent, Debugger, Event, KernelBackend,
    KernelClient, KernelProvider, PtraceStatus, Registers, kernel,
};

// Disassembler wrapper (iced-x86) — consumed by the future scanner/host APIs.
// `FlowKind` is the coarse control-flow class carried on each `InstructionData`.
pub use decoder::{FlowKind, InstructionData, disassemble_instructions};

// Memory-dissection analysis surface (M5.1). The `analysis` module tree stays
// private; callers use these curated names. `disasm`'s live-process walk and the
// `from_pid`/`classify_in_process` conveniences are Linux-only.
pub use analysis::{
    AddrClass, PointerClass, RegionIndex, StrKind, StringRun, classify_value, detect_strings,
    string_at,
};
#[cfg(target_os = "linux")]
pub use analysis::{
    DissectResult, FunctionDisasm, classify_in_process, disassemble_function, disassemble_range,
    dissect_regions, module_exec_regions,
};
