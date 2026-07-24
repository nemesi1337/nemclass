//! Userspace client for the `nemclass_mod` char device (`/dev/nemclass`).
//!
//! [`KernelClient`] opens the device and drives its ioctl ABI (see [`super::abi`])
//! to provide two capabilities that bypass ptrace/Yama:
//!
//! 1. **Kernel-mediated memory access** — [`KernelClient::read_mem`] /
//!    [`KernelClient::write_mem`] move bytes to/from a target `pid` through the
//!    module (which uses `access_process_vm` in ring 0), so it works where
//!    `process_vm_readv` is denied. [`KernelBackend`] adapts this to the crate's
//!    [`MemoryBackend`] seam.
//! 2. **A non-ptrace debugger** ("GD"-style, like Cheat Engine's DBK global
//!    debug) — hardware breakpoints/watchpoints and uprobes that deliver
//!    register-snapshot [`Event`]s via [`KernelClient::wait_event`] without
//!    halting the target.
//!
//! Every ioctl goes through the private [`KernelClient::ioctl`] helper, which
//! contains the single `unsafe` FFI block; the errno of a failing call is
//! surfaced through the crate's existing [`Error::Errno`] via `Error::last`.

use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};

use crate::Error;
use crate::internal::process::MemoryBackend;
use crate::internal::process::kernel::abi;
use crate::internal::process::{MemoryRegion, Protection};

/// Default device node created by the module.
pub const NEMCLASS_DEVICE: &str = "/dev/nemclass";

/// A register-snapshot delivered when a breakpoint/uprobe fires. A
/// platform-neutral view of [`abi::nemclass_event`]; the target is **not**
/// halted, so this reports "what executed/accessed here" after the fact.
#[derive(Debug, Clone, Copy)]
pub struct Event {
    /// Slot id of the breakpoint that fired (from [`KernelClient::set_hw_breakpoint`]
    /// / [`KernelClient::set_uprobe`]).
    pub slot: i32,
    /// Process the hit occurred in.
    pub pid: i32,
    /// Thread the hit occurred in.
    pub tid: i32,
    /// Which kind of breakpoint fired, if recognised.
    pub kind: Option<abi::BreakpointKind>,
    /// The watched / probe address the breakpoint was set on.
    pub addr: u64,
    /// Instruction pointer at the hit (`RIP`).
    pub ip: u64,
    /// Stack pointer at the hit (`RSP`).
    pub sp: u64,
    /// `RFLAGS` at the hit.
    pub flags: u64,
    /// General-purpose registers at the hit, in the ABI's order:
    /// `[ax, bx, cx, dx, si, di, bp, r8..=r15]`.
    pub gpr: [u64; 15],
}

impl From<abi::nemclass_event> for Event {
    fn from(e: abi::nemclass_event) -> Self {
        Event {
            slot: e.slot,
            pid: e.pid,
            tid: e.tid,
            kind: abi::BreakpointKind::from_raw(e.kind),
            addr: e.addr,
            ip: e.ip,
            sp: e.sp,
            flags: e.flags,
            gpr: [
                e.ax, e.bx, e.cx, e.dx, e.si, e.di, e.bp, e.r8, e.r9, e.r10, e.r11, e.r12, e.r13,
                e.r14, e.r15,
            ],
        }
    }
}

/// Result of a [`KernelClient::ptrace_query`]: whether a target is currently
/// ptraced, and by whom.
#[derive(Debug, Clone, Copy)]
pub struct PtraceStatus {
    /// Whether `pid` is currently being ptraced by some tracer.
    pub traced: bool,
    /// The tracer's pid (`0` when not traced).
    pub tracer_pid: i32,
}

/// A handle to the `nemclass` kernel char device.
///
/// Holds the open [`File`] (RAII closes the fd on drop) and its [`RawFd`] for
/// ioctl. Constructing one only opens the node; call [`KernelClient::auth`]
/// before privileged operations if the module requires it.
pub struct KernelClient {
    // Kept alive so the fd stays valid; the module scopes debugger slots and
    // the event queue to this fd, so dropping it releases them.
    file: File,
    fd: RawFd,
}

impl KernelClient {
    /// Opens [`NEMCLASS_DEVICE`] read/write.
    ///
    /// Fails with [`Error::DeviceUnavailable`] if the module is not loaded or the
    /// caller lacks permission on the node (the usual case when unprivileged).
    pub fn open() -> crate::Result<Self> {
        Self::open_path(NEMCLASS_DEVICE)
    }

    /// Opens a specific device path (useful for tests / non-default nodes).
    pub fn open_path(path: &str) -> crate::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| Error::DeviceUnavailable(format!("{path}: {e}")))?;
        let fd = file.as_raw_fd();
        Ok(KernelClient { file, fd })
    }

    /// Issues one ioctl with `arg` as the argument pointer, mapping a `-1`
    /// return to the current errno. Returns the raw non-negative ioctl result
    /// (some commands, e.g. `BP_SET` in other ABIs, encode a value there — this
    /// ABI returns `0` on success and reports its outputs in the struct).
    ///
    /// `arg` must point at a valid, correctly-sized argument struct for
    /// `request` for the duration of the call; callers pass a `&mut` to a local.
    fn ioctl<T>(&self, request: libc::c_ulong, arg: *mut T) -> crate::Result<libc::c_int> {
        // SAFETY: `self.fd` is a live fd owned by `self.file`. `request` is one
        // of the `NEMCLASS_IOC_*` codes whose encoded size matches `T` (the
        // struct is chosen per command), and `arg` points at a live, uniquely
        // borrowed `T` that outlives the call. The kernel reads/writes only that
        // struct (and, for READ/WRITE/ENUM/WAIT, the separate userspace buffer
        // whose address is carried *inside* the struct as a `u64`, kept alive by
        // the caller). A bad target address fails with an errno, not a fault.
        let ret = unsafe { libc::ioctl(self.fd, request, arg as *mut libc::c_void) };
        if ret == -1 {
            Error::last()
        } else {
            Ok(ret)
        }
    }

    /// Authenticates this fd with the module's symmetric key.
    ///
    /// The key is truncated to [`abi::NEMCLASS_KEY_MAX`] bytes (the ABI cap).
    /// Modules that don't require auth will still accept this.
    pub fn auth(&self, key: &[u8]) -> crate::Result<()> {
        let mut arg = abi::nemclass_auth {
            key: [0u8; abi::NEMCLASS_KEY_MAX],
            key_len: 0,
            _pad: 0,
        };
        let n = key.len().min(abi::NEMCLASS_KEY_MAX);
        arg.key[..n].copy_from_slice(&key[..n]);
        arg.key_len = n as u32;
        self.ioctl(abi::NEMCLASS_IOC_AUTH, &mut arg)?;
        Ok(())
    }

    /// Queries the module's ABI revision (`NEMCLASS_IOC_VERSION`).
    pub fn version(&self) -> crate::Result<u32> {
        let mut arg = abi::nemclass_version { abi: 0, _pad: 0 };
        self.ioctl(abi::NEMCLASS_IOC_VERSION, &mut arg)?;
        Ok(arg.abi)
    }

    /// Verifies the module speaks [`abi::NEMCLASS_ABI_VERSION`], returning
    /// [`Error::AbiMismatch`] otherwise.
    pub fn check_abi(&self) -> crate::Result<()> {
        let found = self.version()?;
        if found != abi::NEMCLASS_ABI_VERSION {
            return Err(Error::AbiMismatch {
                expected: abi::NEMCLASS_ABI_VERSION,
                found,
            });
        }
        Ok(())
    }

    // --- memory access ----------------------------------------------------

    /// Reads `[addr, addr+buf.len())` of target `pid` into `buf` via the module.
    ///
    /// Returns the number of bytes read; a short count means the transfer hit an
    /// unmapped page (the module reports `done < len`). Large reads are chunked
    /// so a single unreadable page doesn't sink the whole request.
    pub fn read_mem(&self, pid: libc::pid_t, addr: usize, buf: &mut [u8]) -> crate::Result<usize> {
        let mut total = 0usize;
        while total < buf.len() {
            let chunk = &mut buf[total..];
            let mut arg = abi::nemclass_rw {
                pid,
                _pad: 0,
                addr: (addr + total) as u64,
                len: chunk.len() as u64,
                ubuf: chunk.as_mut_ptr() as u64,
                done: 0,
            };
            self.ioctl(abi::NEMCLASS_IOC_READ, &mut arg)?;
            let done = arg.done as usize;
            total += done;
            // A short transfer means we hit a boundary; stop and let the caller
            // (Process::read) decide, matching the iovec backend's semantics.
            if done < chunk.len() {
                break;
            }
        }
        Ok(total)
    }

    /// Writes `buf` to `[addr, addr+buf.len())` of target `pid` via the module.
    /// Returns the number of bytes written; a short count means a boundary.
    pub fn write_mem(&self, pid: libc::pid_t, addr: usize, buf: &[u8]) -> crate::Result<usize> {
        let mut total = 0usize;
        while total < buf.len() {
            let chunk = &buf[total..];
            let mut arg = abi::nemclass_rw {
                pid,
                _pad: 0,
                addr: (addr + total) as u64,
                len: chunk.len() as u64,
                // The kernel only reads from `ubuf` for a WRITE; casting away
                // const is sound because the module never writes through it.
                ubuf: chunk.as_ptr() as u64,
                done: 0,
            };
            self.ioctl(abi::NEMCLASS_IOC_WRITE, &mut arg)?;
            let done = arg.done as usize;
            total += done;
            if done < chunk.len() {
                break;
            }
        }
        Ok(total)
    }

    /// Enumerates target `pid`'s memory regions (VMAs) through the module.
    ///
    /// Two-pass: a probe with `max = 0` learns the region count, then a sized
    /// pass fills the buffer (retried once if the count grew between passes).
    /// Regions map to the crate's platform-neutral [`MemoryRegion`]; the ABI
    /// record carries no name, so `name` is always `None`.
    pub fn enum_regions(&self, pid: libc::pid_t) -> crate::Result<Vec<MemoryRegion>> {
        // Probe pass: no buffer, just read `total`.
        let mut probe = abi::nemclass_enum_regions {
            pid,
            max: 0,
            ubuf: 0,
            count: 0,
            total: 0,
        };
        self.ioctl(abi::NEMCLASS_IOC_ENUM_REGIONS, &mut probe)?;

        // Over-allocate a little so regions racing in between passes still fit;
        // if `total` is somehow reported as 0 we still make one bounded attempt.
        let mut cap = (probe.total as usize).saturating_add(16).max(16);
        // Bound the retry loop so a pathological, ever-growing target can't spin.
        for _ in 0..4 {
            let mut records = vec![
                abi::nemclass_region {
                    start: 0,
                    end: 0,
                    file_off: 0,
                    prot: 0,
                    _pad: 0,
                };
                cap
            ];
            let mut arg = abi::nemclass_enum_regions {
                pid,
                max: cap as u32,
                ubuf: records.as_mut_ptr() as u64,
                count: 0,
                total: 0,
            };
            self.ioctl(abi::NEMCLASS_IOC_ENUM_REGIONS, &mut arg)?;

            if arg.total as usize > cap {
                // Grew past our buffer; size to the new total and try again.
                cap = (arg.total as usize).saturating_add(16);
                continue;
            }

            records.truncate(arg.count as usize);
            return Ok(records
                .into_iter()
                .map(|r| MemoryRegion {
                    from: r.start as usize,
                    to: r.end as usize,
                    prot: Protection::from_bits_truncate(r.prot as u8),
                    name: None,
                })
                .collect());
        }
        // Fell out of the retry loop: report a stale/short read as a partial.
        Err(Error::PartialTransfer {
            requested: probe.total as usize,
            actual: cap,
        })
    }

    // --- debugger (GD interop) --------------------------------------------

    /// Registers a hardware breakpoint / watchpoint on target `pid` at `addr`.
    ///
    /// `len` is the watch size in bytes (`1`/`2`/`4`/`8`); `ty` selects the
    /// trigger condition (execute / read / write / read-write). Returns the
    /// opaque slot id to pass to [`KernelClient::clear_breakpoint`].
    pub fn set_hw_breakpoint(
        &self,
        pid: libc::pid_t,
        addr: u64,
        len: u32,
        ty: abi::HwBreakpointType,
    ) -> crate::Result<i32> {
        let mut arg = abi::nemclass_bp_set {
            pid,
            kind: abi::BreakpointKind::Hardware.to_raw(),
            addr,
            len,
            type_: ty.to_raw(),
            slot: -1,
            _pad: 0,
        };
        self.ioctl(abi::NEMCLASS_IOC_BP_SET, &mut arg)?;
        Ok(arg.slot)
    }

    /// Registers a software execute breakpoint (uprobe) on target `pid` at
    /// `addr`. The module resolves the backing inode + file offset from the
    /// target's VMA covering `addr`. Returns the opaque slot id.
    pub fn set_uprobe(&self, pid: libc::pid_t, addr: u64) -> crate::Result<i32> {
        let mut arg = abi::nemclass_bp_set {
            pid,
            kind: abi::BreakpointKind::Uprobe.to_raw(),
            addr,
            // Unused for uprobes, but zeroed for a clean, reproducible struct.
            len: 0,
            type_: abi::NEMCLASS_BP_X,
            slot: -1,
            _pad: 0,
        };
        self.ioctl(abi::NEMCLASS_IOC_BP_SET, &mut arg)?;
        Ok(arg.slot)
    }

    /// Removes a breakpoint previously assigned to `slot`.
    pub fn clear_breakpoint(&self, slot: i32) -> crate::Result<()> {
        let mut arg = abi::nemclass_bp_clear { slot, _pad: 0 };
        self.ioctl(abi::NEMCLASS_IOC_BP_CLEAR, &mut arg)?;
        Ok(())
    }

    /// Waits for the next breakpoint/uprobe hit on this fd.
    ///
    /// `timeout_ms`: `< 0` blocks forever, `0` polls (non-blocking), `> 0` waits
    /// that many milliseconds. Returns `Ok(None)` on timeout (`ETIMEDOUT`) or an
    /// empty non-blocking poll (`EAGAIN`), and `Ok(Some(event))` on a hit.
    pub fn wait_event(&self, timeout_ms: i32) -> crate::Result<Option<Event>> {
        let mut event = abi::nemclass_event {
            slot: 0,
            pid: 0,
            tid: 0,
            kind: 0,
            addr: 0,
            ip: 0,
            sp: 0,
            flags: 0,
            ax: 0,
            bx: 0,
            cx: 0,
            dx: 0,
            si: 0,
            di: 0,
            bp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };
        let mut arg = abi::nemclass_wait {
            ubuf: (&mut event as *mut abi::nemclass_event) as u64,
            timeout_ms,
            _pad: 0,
        };
        match self.ioctl(abi::NEMCLASS_IOC_WAIT_EVENT, &mut arg) {
            Ok(_) => Ok(Some(Event::from(event))),
            // A timeout / empty poll is an expected non-hit, not an error.
            Err(Error::Errno(e))
                if e == libc::ETIMEDOUT || e == libc::EAGAIN || e == libc::EWOULDBLOCK =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    // --- ptrace interop ---------------------------------------------------

    /// Queries whether target `pid` is currently ptraced, and by whom.
    pub fn ptrace_query(&self, pid: libc::pid_t) -> crate::Result<PtraceStatus> {
        let mut arg = abi::nemclass_ptrace {
            pid,
            tracer_pid: 0,
            traced: 0,
            _pad: [0u8; 7],
        };
        self.ioctl(abi::NEMCLASS_IOC_PTRACE_QUERY, &mut arg)?;
        Ok(PtraceStatus {
            traced: arg.traced != 0,
            tracer_pid: arg.tracer_pid,
        })
    }

    /// Asks the module to hide any ptrace relationship on target `pid`
    /// (anti-anti-debug). Uses `pid` only.
    pub fn ptrace_hide(&self, pid: libc::pid_t) -> crate::Result<()> {
        let mut arg = abi::nemclass_ptrace {
            pid,
            tracer_pid: 0,
            traced: 0,
            _pad: [0u8; 7],
        };
        self.ioctl(abi::NEMCLASS_IOC_PTRACE_HIDE, &mut arg)?;
        Ok(())
    }

    /// Consumes the client, returning the owned [`File`] (its fd). The debugger
    /// slots / event queue scoped to this fd live as long as the returned file.
    pub fn into_file(self) -> File {
        self.file
    }
}

/// A [`MemoryBackend`] that routes reads/writes through the kernel module for a
/// fixed target `pid`. Slots into the same seam as `IovecProcessMemoryBackend`,
/// so a [`crate::Process`] backed by this transparently uses the privileged
/// path. Wrap the shared client in an `Arc`-free single owner: one backend owns
/// its own fd (the module scopes state per-fd), so cloning is not offered.
pub struct KernelBackend {
    client: KernelClient,
    pid: libc::pid_t,
}

impl KernelBackend {
    /// Opens the device and binds this backend to `pid`.
    pub fn open(pid: libc::pid_t) -> crate::Result<Self> {
        Ok(KernelBackend {
            client: KernelClient::open()?,
            pid,
        })
    }

    /// Binds a backend to `pid` over an already-opened (and possibly
    /// authenticated) client.
    pub fn with_client(client: KernelClient, pid: libc::pid_t) -> Self {
        KernelBackend { client, pid }
    }

    /// The underlying client, for debugger operations alongside memory IO.
    pub fn client(&self) -> &KernelClient {
        &self.client
    }
}

impl MemoryBackend for KernelBackend {
    fn read_buf(&self, address: usize, buf: &mut [u8]) -> crate::Result<usize> {
        self.client.read_mem(self.pid, address, buf)
    }

    fn read_buf_batch(&self, regions: &mut [(usize, &mut [u8])]) -> crate::Result<usize> {
        // The ABI has no scatter/gather read; issue one ioctl per region. The
        // module still avoids the ptrace stop cost, so this stays the fast path
        // where `process_vm_readv` is denied.
        let mut total = 0;
        for (address, buf) in regions.iter_mut() {
            total += self.client.read_mem(self.pid, *address, buf)?;
        }
        Ok(total)
    }

    fn write_buf(&self, address: usize, buf: &[u8]) -> crate::Result<usize> {
        self.client.write_mem(self.pid, address, buf)
    }

    fn write_buf_batch(&self, regions: &[(usize, &[u8])]) -> crate::Result<usize> {
        let mut total = 0;
        for (address, buf) in regions.iter() {
            total += self.client.write_mem(self.pid, *address, buf)?;
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The module is not loaded in CI/dev, so opening the device is expected to
    /// fail with a clear [`Error::DeviceUnavailable`] rather than panic. This is
    /// the one client behaviour we can check without the device.
    #[test]
    fn open_without_module_is_device_unavailable() {
        match KernelClient::open() {
            Err(Error::DeviceUnavailable(_)) => {}
            Err(other) => panic!("expected DeviceUnavailable, got {other:?}"),
            Ok(_) => {
                // On a host that actually has the module loaded this is fine;
                // don't fail the suite there.
                eprintln!("SKIP: /dev/nemclass is present on this host");
            }
        }
    }

    /// Exercises the full memory path (read + write round-trip and region
    /// enumeration) against our own pid. Requires the module; ignored by
    /// default because it cannot run without `/dev/nemclass`.
    #[test]
    #[ignore = "requires the nemclass kernel module loaded at /dev/nemclass"]
    fn kernel_backend_self_round_trip() {
        let pid = std::process::id() as libc::pid_t;
        let backend = KernelBackend::open(pid).expect("open device");

        let cell = Box::new(0xA5A5_5A5A_1234_5678u64);
        let addr = cell.as_ref() as *const u64 as usize;

        let mut buf = [0u8; 8];
        let n = backend.read_buf(addr, &mut buf).expect("read");
        assert_eq!(n, 8);
        assert_eq!(u64::from_ne_bytes(buf), 0xA5A5_5A5A_1234_5678u64);

        let new = 0x0102_0304_0506_0708u64;
        backend.write_buf(addr, &new.to_ne_bytes()).expect("write");
        assert_eq!(*cell, new);

        let regions = backend.client().enum_regions(pid).expect("enum");
        assert!(!regions.is_empty());
    }
}
