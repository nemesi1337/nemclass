use crate::Error;
use crate::internal::process::MemoryBackend;

/// Linux `MemoryBackend` backed by `process_vm_readv` / `process_vm_writev`.
///
/// These syscalls move bytes between the caller's address space and the
/// target's without stopping it (unlike `PTRACE_PEEKDATA`), which is why they
/// are the fast path ReClass.NET's Unix native core also uses. They require
/// `CAP_SYS_PTRACE` or a matching `ptrace_scope`; a lack of permission surfaces
/// as `EPERM` from the syscall (see [`Error::Errno`]).
pub struct IovecProcessMemoryBackend {
    pid: libc::pid_t,
}

/// Linux caps one `process_vm_{readv,writev}` at `UIO_MAXIOV` (`IOV_MAX`, 1024)
/// iovecs; longer batches are split into this many entries per syscall.
const MAX_IOV: usize = 1024;

impl IovecProcessMemoryBackend {
    pub fn new(pid: libc::pid_t) -> Self {
        IovecProcessMemoryBackend { pid }
    }
}

impl MemoryBackend for IovecProcessMemoryBackend {
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize> {
        // SAFETY: `buf` is a valid, uniquely-borrowed local slice, so the local
        // iovec points at `buf.len()` writable bytes. The remote iovec is only
        // dereferenced by the kernel in the target's address space; a bad remote
        // range fails the syscall with an errno rather than faulting us. Both
        // counts are `1`, matching the single iovec passed for each side.
        unsafe {
            let read = libc::process_vm_readv(
                self.pid as _,
                &libc::iovec {
                    iov_base: buf.as_mut_ptr() as _,
                    iov_len: buf.len(),
                },
                1,
                &libc::iovec {
                    iov_base: address as _,
                    iov_len: buf.len(),
                },
                1,
                0,
            );

            if read == -1 {
                Error::last()
            } else {
                Ok(read as usize)
            }
        }
    }

    fn read_buf_batch(&self, regions: &mut [(usize, &mut [u8])]) -> crate::Result<usize> {
        let mut total = 0;
        for chunk in regions.chunks_mut(MAX_IOV) {
            let local: Vec<libc::iovec> = chunk
                .iter_mut()
                .map(|(_, buf)| libc::iovec {
                    iov_base: buf.as_mut_ptr() as _,
                    iov_len: buf.len(),
                })
                .collect();
            let remote: Vec<libc::iovec> = chunk
                .iter()
                .map(|(address, buf)| libc::iovec {
                    iov_base: *address as _,
                    iov_len: buf.len(),
                })
                .collect();

            // SAFETY: `local`/`remote` are non-empty (each chunk holds at least
            // one region), have equal length, and stay alive for the call. Each
            // local iovec points into a live, uniquely-borrowed buffer in
            // `chunk`; the remote iovecs are only dereferenced in the target, so
            // an invalid remote range fails with an errno rather than faulting.
            let read = unsafe {
                libc::process_vm_readv(
                    self.pid as _,
                    local.as_ptr(),
                    local.len() as _,
                    remote.as_ptr(),
                    remote.len() as _,
                    0,
                )
            };

            if read == -1 {
                return Error::last();
            }
            total += read as usize;
        }

        Ok(total)
    }

    fn write_buf(&self, address: usize, buf: &[u8]) -> crate::Result<usize> {
        // SAFETY: `buf` is a valid, live local slice, so the local iovec points
        // at `buf.len()` readable bytes. The remote iovec is only dereferenced by
        // the kernel in the target's address space; a bad or read-only remote
        // range fails the syscall with an errno rather than faulting us. Both
        // counts are `1`, matching the single iovec passed for each side.
        unsafe {
            let written = libc::process_vm_writev(
                self.pid as _,
                &libc::iovec {
                    iov_base: buf.as_ptr() as _,
                    iov_len: buf.len(),
                },
                1,
                &libc::iovec {
                    iov_base: address as _,
                    iov_len: buf.len(),
                },
                1,
                0,
            );

            if written == -1 {
                Error::last()
            } else {
                Ok(written as usize)
            }
        }
    }

    fn write_buf_batch(&self, regions: &[(usize, &[u8])]) -> crate::Result<usize> {
        let mut total = 0;
        for chunk in regions.chunks(MAX_IOV) {
            let local: Vec<libc::iovec> = chunk
                .iter()
                .map(|(_, buf)| libc::iovec {
                    iov_base: buf.as_ptr() as _,
                    iov_len: buf.len(),
                })
                .collect();
            let remote: Vec<libc::iovec> = chunk
                .iter()
                .map(|(address, buf)| libc::iovec {
                    iov_base: *address as _,
                    iov_len: buf.len(),
                })
                .collect();

            // SAFETY: `local`/`remote` are non-empty (each chunk holds at least
            // one region), have equal length, and stay alive for the call. Each
            // local iovec points into a live, borrowed buffer in `chunk`; the
            // remote iovecs are only dereferenced in the target, so an invalid or
            // read-only remote range fails with an errno rather than faulting.
            let written = unsafe {
                libc::process_vm_writev(
                    self.pid as _,
                    local.as_ptr(),
                    local.len() as _,
                    remote.as_ptr(),
                    remote.len() as _,
                    0,
                )
            };

            if written == -1 {
                return Error::last();
            }
            total += written as usize;
        }

        Ok(total)
    }
}
