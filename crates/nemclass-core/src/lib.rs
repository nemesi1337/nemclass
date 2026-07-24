use core::result;

pub mod internal;

// Curated crate-root API. The `internal` module tree stays private in spirit
// (it holds the platform-specific machinery); everything the model/ui/script
// layers build on is re-exported here so they never reach through `internal::`.
pub use internal::{
    // Backend seam (raw IO) + platform provider seam.
    MemoryBackend,
    ProcessProvider,
    LinuxProvider,
    ProviderRegistry,
    // Process handle + typed IO.
    Process,
    // Platform-neutral value types.
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
}

/// Renders an errno to its libc message for the `Display` impl above.
#[cfg(unix)]
fn os_error_message(errno: i32) -> String {
    std::io::Error::from_raw_os_error(errno).to_string()
}

#[allow(missing_docs)]
pub type Result<T> = result::Result<T, Error>;

impl Error {
    /// Captures the current thread's `errno` as an [`Error::Errno`].
    #[cfg(all(unix, feature = "std"))]
    pub(crate) fn last<T>() -> Result<T> {
        // SAFETY: `__errno_location` returns a valid, thread-local `*mut i32`
        // that libc guarantees is live for the current thread; we only read it.
        unsafe { Err(Error::Errno(*libc::__errno_location())) }
    }
}
