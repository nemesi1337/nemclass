use crate::Error;
use crate::internal::process::ProcessMemoryBackend;

pub struct IovecProcessMemoryBackend {
    pid: libc::pid_t,
}

impl IovecProcessMemoryBackend {
    pub fn new(pid: libc::pid_t) -> Self {
        IovecProcessMemoryBackend { pid }
    }
}

impl ProcessMemoryBackend for IovecProcessMemoryBackend {
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize> {
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
        // Linux caps one process_vm_readv at UIO_MAXIOV (IOV_MAX) iovecs.
        const MAX_IOV: usize = 1024;

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
}
