//! Userspace mirror of the `nemclass_mod` char-device ABI.
//!
//! This is a byte-for-byte Rust translation of the kernel UAPI header
//! `linux/nemclass_mod/include/uapi/nemclass.h`. Every struct is `#[repr(C)]`
//! with the fields in header order so its size and layout match the kernel's
//! exactly, and the ioctl request codes are recomputed here with the same
//! `_IOC` encoding the header's `_IOW`/`_IOR`/`_IOWR` macros use. The
//! compile-time `assert!`s at the bottom lock the sizes so an accidental field
//! or padding change fails the build rather than corrupting an ioctl.
//!
//! Buffers cross the ABI as `u64` addresses (never native pointers), so the
//! layout is identical for 32- and 64-bit callers — the client fills these in
//! by casting a local buffer pointer to `u64`.

#![allow(non_camel_case_types)]

use core::mem::size_of;

/// ABI revision this client speaks; must match the module's
/// `NEMCLASS_ABI_VERSION`. Surfaced by [`super::client::KernelClient::version`].
pub const NEMCLASS_ABI_VERSION: u32 = 1;

/// ioctl "magic" / type byte (`'N'`) shared by every nemclass request code.
pub const NEMCLASS_IOC_MAGIC: u32 = b'N' as u32;

/// Maximum symmetric-key length accepted by [`NEMCLASS_IOC_AUTH`].
pub const NEMCLASS_KEY_MAX: usize = 64;

// --- Breakpoint kinds (`nemclass_bp_set.kind`) ---------------------------

/// Hardware breakpoint / watchpoint (debug-register backed, per-thread).
pub const NEMCLASS_BP_KIND_HW: u32 = 0;
/// Software execute breakpoint implemented with a uprobe.
pub const NEMCLASS_BP_KIND_UPROBE: u32 = 1;

// --- Hardware breakpoint trigger types (`nemclass_bp_set.type`) ----------

/// Execute.
pub const NEMCLASS_BP_X: u32 = 0;
/// Data write.
pub const NEMCLASS_BP_W: u32 = 1;
/// Data read or write.
pub const NEMCLASS_BP_RW: u32 = 2;
/// Data read.
pub const NEMCLASS_BP_R: u32 = 3;

/// Breakpoint kind selector for [`super::client::KernelClient`] debugger calls,
/// mapping to `NEMCLASS_BP_KIND_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointKind {
    /// Debug-register hardware breakpoint / watchpoint.
    Hardware,
    /// uprobe-backed software execute breakpoint.
    Uprobe,
}

impl BreakpointKind {
    /// The wire value for `nemclass_bp_set.kind`.
    pub const fn to_raw(self) -> u32 {
        match self {
            BreakpointKind::Hardware => NEMCLASS_BP_KIND_HW,
            BreakpointKind::Uprobe => NEMCLASS_BP_KIND_UPROBE,
        }
    }

    /// Reconstructs a kind from a `nemclass_event.kind` wire value, if known.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            NEMCLASS_BP_KIND_HW => Some(BreakpointKind::Hardware),
            NEMCLASS_BP_KIND_UPROBE => Some(BreakpointKind::Uprobe),
            _ => None,
        }
    }
}

/// Hardware watchpoint trigger condition, mapping to `NEMCLASS_BP_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HwBreakpointType {
    /// Trigger on instruction execution at the address.
    Execute,
    /// Trigger on a data write to the address.
    Write,
    /// Trigger on a data read or write to the address.
    ReadWrite,
    /// Trigger on a data read from the address.
    Read,
}

impl HwBreakpointType {
    /// The wire value for `nemclass_bp_set.type`.
    pub const fn to_raw(self) -> u32 {
        match self {
            HwBreakpointType::Execute => NEMCLASS_BP_X,
            HwBreakpointType::Write => NEMCLASS_BP_W,
            HwBreakpointType::ReadWrite => NEMCLASS_BP_RW,
            HwBreakpointType::Read => NEMCLASS_BP_R,
        }
    }
}

// --- ioctl argument structs ----------------------------------------------
//
// Field order and types mirror the C header exactly. `_pad` fields are kept
// (not elided) so `size_of` matches the kernel's `sizeof(struct ...)` and the
// `_IOC` size component of each request code below comes out identical.

/// Argument for [`NEMCLASS_IOC_AUTH`]: a symmetric key (`key_len` valid bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_auth {
    /// Key material; only the first `key_len` bytes are significant.
    pub key: [u8; NEMCLASS_KEY_MAX],
    /// Number of valid bytes in `key` (`<= NEMCLASS_KEY_MAX`).
    pub key_len: u32,
    /// Padding to a natural boundary; must be zero.
    pub _pad: u32,
}

/// Argument for [`NEMCLASS_IOC_VERSION`]: reports the module's ABI revision.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_version {
    /// Out: the module's `NEMCLASS_ABI_VERSION`.
    pub abi: u32,
    /// Padding; must be zero.
    pub _pad: u32,
}

/// Argument for [`NEMCLASS_IOC_READ`] / [`NEMCLASS_IOC_WRITE`]: transfer
/// `[addr, addr+len)` of target `pid` to/from the userspace buffer `ubuf`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_rw {
    /// Target process id.
    pub pid: i32,
    /// Padding; must be zero.
    pub _pad: u32,
    /// Target virtual address of the transfer.
    pub addr: u64,
    /// Requested byte count.
    pub len: u64,
    /// Userspace buffer address (this client casts a local pointer to `u64`).
    pub ubuf: u64,
    /// Out: bytes actually transferred (may be short at a mapping boundary).
    pub done: u64,
}

/// One VMA record produced by [`NEMCLASS_IOC_ENUM_REGIONS`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_region {
    /// Inclusive start address of the mapping.
    pub start: u64,
    /// Exclusive end address of the mapping.
    pub end: u64,
    /// Backing-file offset, `0` for anonymous mappings.
    pub file_off: u64,
    /// Protection bits: `bit0=r bit1=w bit2=x` — matches [`crate::Protection`].
    pub prot: u32,
    /// Padding; must be zero.
    pub _pad: u32,
}

/// Argument for [`NEMCLASS_IOC_ENUM_REGIONS`]: enumerate `pid`'s VMAs into the
/// userspace array at `ubuf` (`max` records of capacity).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_enum_regions {
    /// Target process id.
    pub pid: i32,
    /// Capacity of the `ubuf` array, in [`nemclass_region`] records.
    pub max: u32,
    /// Userspace array address of [`nemclass_region`].
    pub ubuf: u64,
    /// Out: records actually written (`<= max`).
    pub count: u32,
    /// Out: total regions available (may exceed `max` — retry with a bigger buf).
    pub total: u32,
}

/// Argument for [`NEMCLASS_IOC_BP_SET`]: register a breakpoint on target `pid`.
///
/// The C field named `type` is spelled `type_` here (a Rust keyword).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_bp_set {
    /// Target process id.
    pub pid: i32,
    /// Breakpoint kind: `NEMCLASS_BP_KIND_*`.
    pub kind: u32,
    /// Target virtual address to watch / probe.
    pub addr: u64,
    /// HW watchpoint length in bytes (`1`/`2`/`4`/`8`); ignored for uprobes.
    pub len: u32,
    /// HW trigger type `NEMCLASS_BP_*` (C field `type`); ignored for uprobes.
    pub type_: u32,
    /// Out: opaque slot id assigned to this breakpoint (`>= 0`).
    pub slot: i32,
    /// Padding; must be zero.
    pub _pad: u32,
}

/// Argument for [`NEMCLASS_IOC_BP_CLEAR`]: remove a previously assigned slot.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_bp_clear {
    /// Slot id returned by a prior [`nemclass_bp_set`].
    pub slot: i32,
    /// Padding; must be zero.
    pub _pad: u32,
}

/// A breakpoint/uprobe hit: an x86_64 register snapshot. Execution is **not**
/// halted — this records "what accessed/executed here" and continues.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_event {
    /// Slot id of the breakpoint that fired.
    pub slot: i32,
    /// Process id the hit occurred in.
    pub pid: i32,
    /// Thread id the hit occurred in.
    pub tid: i32,
    /// Breakpoint kind: `NEMCLASS_BP_KIND_*`.
    pub kind: u32,
    /// Watched / probe address.
    pub addr: u64,
    /// Instruction pointer at the hit (`RIP`).
    pub ip: u64,
    /// Stack pointer at the hit (`RSP`).
    pub sp: u64,
    /// `RFLAGS` at the hit.
    pub flags: u64,
    /// `RAX`.
    pub ax: u64,
    /// `RBX`.
    pub bx: u64,
    /// `RCX`.
    pub cx: u64,
    /// `RDX`.
    pub dx: u64,
    /// `RSI`.
    pub si: u64,
    /// `RDI`.
    pub di: u64,
    /// `RBP`.
    pub bp: u64,
    /// `R8`.
    pub r8: u64,
    /// `R9`.
    pub r9: u64,
    /// `R10`.
    pub r10: u64,
    /// `R11`.
    pub r11: u64,
    /// `R12`.
    pub r12: u64,
    /// `R13`.
    pub r13: u64,
    /// `R14`.
    pub r14: u64,
    /// `R15`.
    pub r15: u64,
}

/// Argument for [`NEMCLASS_IOC_WAIT_EVENT`]: block until the next hit for this
/// fd is delivered into the [`nemclass_event`] at `ubuf`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_wait {
    /// Userspace [`nemclass_event`] address to fill.
    pub ubuf: u64,
    /// `< 0` block forever, `0` non-blocking, `> 0` timeout in milliseconds.
    pub timeout_ms: i32,
    /// Padding; must be zero.
    pub _pad: u32,
}

/// Argument for [`NEMCLASS_IOC_PTRACE_QUERY`] (fills the out fields) and
/// [`NEMCLASS_IOC_PTRACE_HIDE`] (uses `pid` only).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct nemclass_ptrace {
    /// Target process id.
    pub pid: i32,
    /// Out: the tracer's pid, or `0` if none.
    pub tracer_pid: i32,
    /// Out: nonzero if `pid` is currently ptraced.
    pub traced: u8,
    /// Padding; must be zero.
    pub _pad: [u8; 7],
}

// --- ioctl request codes -------------------------------------------------
//
// Recomputed with the Linux asm-generic `_IOC` encoding (verified against
// /usr/include/asm-generic/ioctl.h): a request is a 32-bit word packing
// [dir:2][size:14][type:8][nr:8]. We build them as `c_ulong` because that is
// the request-argument type of `libc::ioctl` on Linux.

/// `_IOC_NRBITS` — width of the command-number field.
const IOC_NRBITS: u32 = 8;
/// `_IOC_TYPEBITS` — width of the magic/type field.
const IOC_TYPEBITS: u32 = 8;
/// `_IOC_SIZEBITS` — width of the argument-size field.
const IOC_SIZEBITS: u32 = 14;

/// `_IOC_NRSHIFT`.
const IOC_NRSHIFT: u32 = 0;
/// `_IOC_TYPESHIFT`.
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
/// `_IOC_SIZESHIFT`.
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
/// `_IOC_DIRSHIFT`.
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

/// `_IOC_NONE` — no data transfer. Kept for a complete encoding; none of the
/// nemclass codes are `_IO` (all carry a struct), so it is currently unused.
const _IOC_NONE: u32 = 0;
/// `_IOC_WRITE` — userland writes, kernel reads.
const IOC_WRITE: u32 = 1;
/// `_IOC_READ` — userland reads, kernel writes.
const IOC_READ: u32 = 2;

/// The `_IOC(dir, type, nr, size)` macro, as a `const fn`. `size` is masked to
/// `_IOC_SIZEBITS` exactly as the kernel does; all our struct sizes fit.
const fn ioc(dir: u32, ty: u32, nr: u32, size: u32) -> libc::c_ulong {
    (((dir & 0x3) << IOC_DIRSHIFT)
        | (ty << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | ((size & ((1 << IOC_SIZEBITS) - 1)) << IOC_SIZESHIFT)) as libc::c_ulong
}

/// `_IOW(magic, nr, T)`.
const fn iow<T>(nr: u32) -> libc::c_ulong {
    ioc(IOC_WRITE, NEMCLASS_IOC_MAGIC, nr, size_of::<T>() as u32)
}

/// `_IOR(magic, nr, T)`.
const fn ior<T>(nr: u32) -> libc::c_ulong {
    ioc(IOC_READ, NEMCLASS_IOC_MAGIC, nr, size_of::<T>() as u32)
}

/// `_IOWR(magic, nr, T)`.
const fn iowr<T>(nr: u32) -> libc::c_ulong {
    ioc(
        IOC_READ | IOC_WRITE,
        NEMCLASS_IOC_MAGIC,
        nr,
        size_of::<T>() as u32,
    )
}

/// `NEMCLASS_IOC_AUTH` — `_IOW('N', 0x01, struct nemclass_auth)`.
pub const NEMCLASS_IOC_AUTH: libc::c_ulong = iow::<nemclass_auth>(0x01);
/// `NEMCLASS_IOC_VERSION` — `_IOR('N', 0x02, struct nemclass_version)`.
pub const NEMCLASS_IOC_VERSION: libc::c_ulong = ior::<nemclass_version>(0x02);

/// `NEMCLASS_IOC_READ` — `_IOWR('N', 0x10, struct nemclass_rw)`.
pub const NEMCLASS_IOC_READ: libc::c_ulong = iowr::<nemclass_rw>(0x10);
/// `NEMCLASS_IOC_WRITE` — `_IOWR('N', 0x11, struct nemclass_rw)`.
pub const NEMCLASS_IOC_WRITE: libc::c_ulong = iowr::<nemclass_rw>(0x11);
/// `NEMCLASS_IOC_ENUM_REGIONS` — `_IOWR('N', 0x12, struct nemclass_enum_regions)`.
pub const NEMCLASS_IOC_ENUM_REGIONS: libc::c_ulong = iowr::<nemclass_enum_regions>(0x12);

/// `NEMCLASS_IOC_BP_SET` — `_IOWR('N', 0x20, struct nemclass_bp_set)`.
pub const NEMCLASS_IOC_BP_SET: libc::c_ulong = iowr::<nemclass_bp_set>(0x20);
/// `NEMCLASS_IOC_BP_CLEAR` — `_IOW('N', 0x21, struct nemclass_bp_clear)`.
pub const NEMCLASS_IOC_BP_CLEAR: libc::c_ulong = iow::<nemclass_bp_clear>(0x21);
/// `NEMCLASS_IOC_WAIT_EVENT` — `_IOWR('N', 0x22, struct nemclass_wait)`.
pub const NEMCLASS_IOC_WAIT_EVENT: libc::c_ulong = iowr::<nemclass_wait>(0x22);

/// `NEMCLASS_IOC_PTRACE_QUERY` — `_IOWR('N', 0x30, struct nemclass_ptrace)`.
pub const NEMCLASS_IOC_PTRACE_QUERY: libc::c_ulong = iowr::<nemclass_ptrace>(0x30);
/// `NEMCLASS_IOC_PTRACE_HIDE` — `_IOW('N', 0x31, struct nemclass_ptrace)`.
pub const NEMCLASS_IOC_PTRACE_HIDE: libc::c_ulong = iow::<nemclass_ptrace>(0x31);

// --- ABI locks -----------------------------------------------------------
//
// If a field, type, or padding ever drifts from the C header these fail the
// build. Sizes computed from the header: naturally aligned, no unexpected
// padding (largest scalar in each struct is <= 8 bytes).

const _: () = assert!(size_of::<nemclass_auth>() == 72);
const _: () = assert!(size_of::<nemclass_version>() == 8);
const _: () = assert!(size_of::<nemclass_rw>() == 40);
const _: () = assert!(size_of::<nemclass_region>() == 32);
const _: () = assert!(size_of::<nemclass_enum_regions>() == 24);
const _: () = assert!(size_of::<nemclass_bp_set>() == 32);
const _: () = assert!(size_of::<nemclass_bp_clear>() == 8);
const _: () = assert!(size_of::<nemclass_event>() == 168);
const _: () = assert!(size_of::<nemclass_wait>() == 16);
const _: () = assert!(size_of::<nemclass_ptrace>() == 16);

#[cfg(test)]
mod tests {
    use super::*;

    /// Reproduces the header's ioctl codes numerically (independent of the
    /// `const fn` path above) so a mistake in either surfaces. Values are the
    /// asm-generic encoding: `(dir << 30) | (size << 16) | ('N' << 8) | nr`.
    #[test]
    fn ioctl_codes_match_header_encoding() {
        const N: u64 = b'N' as u64;
        let expect = |dir: u64, nr: u64, size: u64| (dir << 30) | (size << 16) | (N << 8) | nr;

        // _IOW = dir 1, _IOR = dir 2, _IOWR = dir 3.
        assert_eq!(NEMCLASS_IOC_AUTH, expect(1, 0x01, 72));
        assert_eq!(NEMCLASS_IOC_VERSION, expect(2, 0x02, 8));
        assert_eq!(NEMCLASS_IOC_READ, expect(3, 0x10, 40));
        assert_eq!(NEMCLASS_IOC_WRITE, expect(3, 0x11, 40));
        assert_eq!(NEMCLASS_IOC_ENUM_REGIONS, expect(3, 0x12, 24));
        assert_eq!(NEMCLASS_IOC_BP_SET, expect(3, 0x20, 32));
        assert_eq!(NEMCLASS_IOC_BP_CLEAR, expect(1, 0x21, 8));
        assert_eq!(NEMCLASS_IOC_WAIT_EVENT, expect(3, 0x22, 16));
        assert_eq!(NEMCLASS_IOC_PTRACE_QUERY, expect(3, 0x30, 16));
        assert_eq!(NEMCLASS_IOC_PTRACE_HIDE, expect(1, 0x31, 16));
    }

    #[test]
    fn bp_kind_and_type_round_trip() {
        assert_eq!(BreakpointKind::Hardware.to_raw(), NEMCLASS_BP_KIND_HW);
        assert_eq!(BreakpointKind::Uprobe.to_raw(), NEMCLASS_BP_KIND_UPROBE);
        assert_eq!(
            BreakpointKind::from_raw(NEMCLASS_BP_KIND_UPROBE),
            Some(BreakpointKind::Uprobe)
        );
        assert_eq!(BreakpointKind::from_raw(999), None);

        assert_eq!(HwBreakpointType::Execute.to_raw(), NEMCLASS_BP_X);
        assert_eq!(HwBreakpointType::Read.to_raw(), NEMCLASS_BP_R);
    }
}
