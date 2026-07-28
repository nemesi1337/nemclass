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
///
/// `Send + Sync` so an [`super::Process`] can be shared as `Arc<Process>` across
/// threads: the UI runs heavy reads (dissect, scans) on a `spawn_blocking` worker
/// off the eframe frame. All backends are thread-agnostic — the Linux backend
/// holds a pid, the kernel backend a device fd, and the Windows backend an
/// `OpenProcess` handle (a process-scoped kernel object with no thread affinity;
/// see `win_backend::SendHandle`). All access is through `&self`, so concurrent
/// reads are sound.
pub trait MemoryBackend: Send + Sync {
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

/// An in-memory [`MemoryBackend`] over a single contiguous `[base, base+len)`
/// buffer, for tests. Reads/writes that fall outside the buffer are clamped
/// (short) exactly like the real backends do on a partial mapping — a read
/// starting past the end returns `Ok(0)` rather than erroring.
///
/// Interior mutability (a `Mutex`) keeps it `Send + Sync` and lets a test mutate
/// the backing bytes through the `&self` a [`super::Process`] hands out, so
/// change-detection paths (e.g. the hex viewer's red-tint) can be driven between
/// frames.
#[cfg(feature = "test-util")]
pub struct MockMemoryBackend {
    base: usize,
    buf: std::sync::Mutex<Vec<u8>>,
}

#[cfg(feature = "test-util")]
impl MockMemoryBackend {
    /// Creates a backend serving `bytes` at virtual address `base`.
    pub fn new(base: usize, bytes: Vec<u8>) -> Self {
        Self {
            base,
            buf: std::sync::Mutex::new(bytes),
        }
    }

    /// The virtual base address the buffer is mapped at.
    pub fn base(&self) -> usize {
        self.base
    }

    /// Overwrites the backing bytes at `address` (clamped to the buffer), so a
    /// test can simulate the target mutating memory between reads.
    pub fn poke(&self, address: usize, bytes: &[u8]) {
        let mut data = self.buf.lock().unwrap();
        if let Some(off) = address.checked_sub(self.base)
            && off < data.len() {
            let n = bytes.len().min(data.len() - off);
            data[off..off + n].copy_from_slice(&bytes[..n]);
        }
    }

    /// Byte count within `[address, address+want)` that overlaps the buffer.
    fn overlap(&self, data_len: usize, address: usize, want: usize) -> Option<(usize, usize)> {
        let off = address.checked_sub(self.base)?;
        if off >= data_len {
            return None;
        }
        Some((off, want.min(data_len - off)))
    }
}

#[cfg(feature = "test-util")]
impl MemoryBackend for MockMemoryBackend {
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize> {
        let data = self.buf.lock().unwrap();
        match self.overlap(data.len(), address, buf.len()) {
            Some((off, n)) => {
                buf[..n].copy_from_slice(&data[off..off + n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    fn read_buf_batch(&self, regions: &mut [(usize, &mut [u8])]) -> crate::Result<usize> {
        let data = self.buf.lock().unwrap();
        let mut total = 0;
        for (address, buf) in regions.iter_mut() {
            if let Some((off, n)) = self.overlap(data.len(), *address, buf.len()) {
                buf[..n].copy_from_slice(&data[off..off + n]);
                total += n;
            }
        }
        Ok(total)
    }

    fn write_buf(&self, address: usize, buf: &[u8]) -> crate::Result<usize> {
        let mut data = self.buf.lock().unwrap();
        match self.overlap(data.len(), address, buf.len()) {
            Some((off, n)) => {
                data[off..off + n].copy_from_slice(&buf[..n]);
                Ok(n)
            }
            None => Ok(0),
        }
    }

    fn write_buf_batch(&self, regions: &[(usize, &[u8])]) -> crate::Result<usize> {
        let mut data = self.buf.lock().unwrap();
        let mut total = 0;
        for (address, buf) in regions.iter() {
            if let Some((off, n)) = self.overlap(data.len(), *address, buf.len()) {
                data[off..off + n].copy_from_slice(&buf[..n]);
                total += n;
            }
        }
        Ok(total)
    }
}

#[cfg(all(test, feature = "test-util"))]
mod mock_tests {
    use super::{MemoryBackend, MockMemoryBackend};

    #[test]
    fn reads_and_writes_within_buffer() {
        let be = MockMemoryBackend::new(0x1000, vec![0u8; 8]);
        assert_eq!(be.write_buf(0x1002, &[0xaa, 0xbb]).unwrap(), 2);
        let mut buf = [0u8; 4];
        assert_eq!(be.read_buf(0x1000, &mut buf).unwrap(), 4);
        assert_eq!(buf, [0x00, 0x00, 0xaa, 0xbb]);
    }

    #[test]
    fn reads_are_short_at_the_boundary() {
        let be = MockMemoryBackend::new(0x1000, vec![7u8; 4]);
        // Reading 8 bytes starting 2 past the base only yields the 2 in range.
        let mut buf = [0u8; 8];
        assert_eq!(be.read_buf(0x1002, &mut buf).unwrap(), 2);
        // Reads entirely outside the buffer return 0, not an error.
        assert_eq!(be.read_buf(0x9000, &mut buf).unwrap(), 0);
        assert_eq!(be.read_buf(0x0100, &mut buf).unwrap(), 0);
    }

    #[test]
    fn poke_mutates_backing_bytes() {
        let be = MockMemoryBackend::new(0, vec![0u8; 4]);
        be.poke(1, &[0xde, 0xad]);
        let mut buf = [0u8; 4];
        be.read_buf(0, &mut buf).unwrap();
        assert_eq!(buf, [0x00, 0xde, 0xad, 0x00]);
    }
}
