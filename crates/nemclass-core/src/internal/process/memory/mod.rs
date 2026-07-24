mod iovec;

pub use iovec::*;

pub trait ProcessMemoryBackend {
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize>;

    fn read_buf_batch(&self, regions: &mut [(usize, &mut [u8])]) -> crate::Result<usize>;
}