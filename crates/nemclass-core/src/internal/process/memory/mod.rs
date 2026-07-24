// The `process_vm_readv`/`writev` backend is Linux-only; on Windows the native
// backend lives in `super::win_backend`. Gating the module keeps `libc::iovec`
// and the `process_vm_*` syscalls out of the Windows build entirely.
#[cfg(target_os = "linux")]
mod iovec;

#[cfg(target_os = "linux")]
pub use iovec::*;

/// Raw read/write IO on an already-opened target process.
///
/// This is the lower of the two backend seams: it deals only in byte buffers at
/// absolute addresses and knows nothing about process lifecycle, sections, or
/// modules (that is [`crate::ProcessProvider`]'s job). Implementors: the Linux
/// `IovecProcessMemoryBackend` (via `process_vm_readv` / `process_vm_writev`),
/// and — later — a leechcore backend and a native Windows backend.
///
/// The `*_batch` variants exist so a caller reading/writing many small,
/// scattered regions pays a single syscall (per `IOV_MAX` chunk) instead of one
/// per region.
pub trait MemoryBackend {
    /// Reads into `buf` starting at `address`. Returns the number of bytes read.
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize>;

    /// Reads a batch of `(address, buffer)` regions. Returns the total number of
    /// bytes read across all regions.
    fn read_buf_batch(&self, regions: &mut [(usize, &mut [u8])]) -> crate::Result<usize>;

    /// Writes `buf` to the target starting at `address`. Returns the number of
    /// bytes written.
    fn write_buf(&self, address: usize, buf: &[u8]) -> crate::Result<usize>;

    /// Writes a batch of `(address, buffer)` regions. Returns the total number of
    /// bytes written across all regions.
    fn write_buf_batch(&self, regions: &[(usize, &[u8])]) -> crate::Result<usize>;
}
