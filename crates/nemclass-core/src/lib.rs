use core::result;

pub mod internal;

// Curated crate-root API. The `internal` module tree stays private in spirit
// (it holds the platform-specific machinery); everything the model/ui/script
// layers build on is re-exported here so they never reach through `internal::`.
pub use internal::{
    // Backend seam (raw IO) + platform provider seam.
    MemoryBackend,
    ProcessProvider,
    ProviderRegistry,
    // Process handle + typed IO.
    Process,
    // Platform-neutral value types.
    Pid,
    ProcessEntry,
    ModuleInfoWithName,
    MemoryRegion,
    Protection,
    Section,
    SectionType,
    Module,
    // Process enumeration.
    ProcessIterator,
    // Disassembler wrapper (iced-x86).
    InstructionData,
    disassemble_instructions,
    // PE utilities (shared between Wine detection and a future Windows backend).
    pe,
    // Exported-symbol resolution (PE export directory / ELF `.dynsym`).
    Symbol,
    symbols,
};

// Native Linux provider (`process_vm_readv` + `/proc`), Linux-only.
#[cfg(target_os = "linux")]
pub use internal::LinuxProvider;

// Native Windows backend + provider, the `#[cfg(windows)]` mirror of the Linux
// native provider. Gated so non-Windows builds never pull in `windows-sys`.
#[cfg(windows)]
pub use internal::{WindowsBackend, WindowsProvider};

// Kernel-module client, privileged backend/provider, and debugger types
// (Linux-only): ptrace-free memory IO plus hardware breakpoints/uprobes over
// the `nemclass_mod` char device. The `Debugger` controller (attach → auth →
// set bp → wait → inspect → clear) sits on top of `KernelClient`. Gated so
// non-Linux builds stay clean.
#[cfg(target_os = "linux")]
pub use internal::{
    Breakpoint, BreakpointId, BreakpointSpec, DebugEvent, Debugger, Event, KernelBackend,
    KernelClient, KernelProvider, PtraceStatus, Registers, kernel,
};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The address could not be translated / was outside a valid mapping.
    #[error("invalid address")]
    InvalidAddress,
    /// A wrapped `std::io::Error` (e.g. failure reading `/proc`).
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// A raw OS errno from a failing syscall (e.g. `process_vm_readv`).
    #[cfg(unix)]
    #[error("os error {0}: {msg}", msg = os_error_message(*.0))]
    Errno(i32),
    /// A Win32 error code from a failing Windows API call (the value of
    /// `GetLastError`, e.g. after a failed `OpenProcess`/`ReadProcessMemory`).
    /// The `Errno` counterpart on the unix side.
    #[cfg(windows)]
    #[error("win32 error {code}: {msg}", msg = os_error_message(*code))]
    WinApi { code: u32 },
    /// Specified process was not found.
    #[error("process not found")]
    ProcessNotFound,
    /// Specified module was not found.
    #[error("module not found")]
    ModuleNotFound,
    /// No threads running in the process.
    #[error("no threads in process")]
    NoThreads,
    /// String read was not a valid UTF-8 or UTF-16 byte sequence.
    #[error("invalid string")]
    InvalidString,
    /// Process has died and is no longer available.
    #[error("process died")]
    ProcessDied,
    /// A short transfer: fewer bytes were read/written than requested.
    #[error("partial memory transfer: {actual} of {requested} bytes")]
    PartialTransfer { requested: usize, actual: usize },
    /// The `nemclass` kernel char device (`/dev/nemclass`) could not be opened —
    /// the module is not loaded, or the caller lacks permission on the node.
    #[error("kernel device unavailable: {0}")]
    DeviceUnavailable(String),
    /// The kernel module reports an ABI revision this client does not speak.
    #[error("kernel ABI mismatch: module reports {found}, client expects {expected}")]
    AbiMismatch { expected: u32, found: u32 },
    /// A caller supplied an argument the API rejects before any syscall (e.g. a
    /// hardware-breakpoint length that is not 1/2/4/8, or clearing a breakpoint
    /// id that was never armed). Distinct from an OS [`Error::Errno`]: this is
    /// caught client-side so the caller learns of the misuse without a round-trip.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

/// Renders an errno to its libc message for the `Display` impl above.
#[cfg(unix)]
fn os_error_message(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// Renders a Win32 error code to its system message for the `Display` impl
/// above. `std::io` knows how to format a raw Windows error code.
#[cfg(windows)]
fn os_error_message(code: u32) -> String {
    std::io::Error::from_raw_os_error(code as i32).to_string()
}

#[allow(missing_docs)]
pub type Result<T> = result::Result<T, Error>;

impl Error {
    /// Captures the current thread's `errno` as an [`Error::Errno`].
    // Gated on `unix` only (not the `std` feature): the callers in the iovec
    // backend are `cfg(unix)`, so gating this on `feature = "std"` broke
    // `--no-default-features` builds (the `alloc`-only tier the crate advertises).
    #[cfg(unix)]
    pub(crate) fn last<T>() -> Result<T> {
        // SAFETY: `__errno_location` returns a valid, thread-local `*mut i32`
        // that libc guarantees is live for the current thread; we only read it.
        unsafe { Err(Error::Errno(*libc::__errno_location())) }
    }

    /// Captures the current thread's Win32 last-error as an [`Error::WinApi`].
    /// The Windows counterpart of [`Error::last`].
    #[cfg(windows)]
    pub(crate) fn last_win32<T>() -> Result<T> {
        // SAFETY: `GetLastError` is a thread-local read of the calling thread's
        // last-error code; it has no preconditions and cannot fault.
        let code = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        Err(Error::WinApi { code })
    }
}
