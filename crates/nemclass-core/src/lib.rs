use core::result;

pub mod internal;

pub enum Error {
    InvalidAddress,
    IoError(std::io::Error),
    #[cfg(unix)]
    Errno(i32),
    /// Specified process was not found
    ProcessNotFound,
    /// Specified module was not found
    ModuleNotFound,
    /// No threads running in the process
    NoThreads,
    /// String read was not valid UTF-8 or UTF-16 byte sequence
    InvalidString,
    /// Process has died and is no longer available
    ProcessDied,
}

#[allow(missing_docs)]
pub type Result<T> = result::Result<T, Error>;

#[allow(dead_code)]
impl Error {
    #[cfg(all(unix, feature = "std"))]
    pub(crate) fn last<T>() -> Result<T> {
        unsafe { Err(Error::Errno(*libc::__errno_location())) }
    }
}
