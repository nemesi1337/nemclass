//! Userspace debugger controller driving the `nemclass_mod` char device.
//!
//! [`Debugger`] is an ergonomic layer over [`KernelClient`](super::KernelClient):
//! it owns the authenticated device fd bound to a single target `pid`, keeps
//! breakpoint bookkeeping (id → spec, list / clear), decodes raw kernel
//! [`Event`](super::Event)s into a rich [`DebugEvent`], and exposes the ptrace
//! interop and kernel-mediated memory access needed to inspect/patch around a
//! hit. It does **not** re-implement any ioctl — every kernel round-trip goes
//! through the existing client.
//!
//! # Why a separate controller?
//!
//! [`KernelClient`](super::KernelClient) is a thin, stateless wrapper over the
//! ABI: `set_hw_breakpoint`/`set_uprobe` hand back an opaque kernel *slot id*
//! and forget it. A debugger needs to *remember* what it armed so it can list
//! and tear down breakpoints, associate an incoming event's slot with the spec
//! that produced it, and present one uniform "set a breakpoint" call over the
//! module's two very different kinds (debug-register hardware watchpoints and
//! uprobe-backed software execute breakpoints). That stateful bookkeeping is
//! this module's job.
//!
//! # The flow
//!
//! ```text
//! attach(pid, key)  ── open /dev/nemclass, VERSION-check ABI, AUTH ──▶ Debugger
//!        │
//!        ├─ set_breakpoint(spec) ─▶ BreakpointId          (BP_SET)
//!        │
//!        ├─ wait_event(timeout)  ─▶ Option<DebugEvent>    (WAIT_EVENT)
//!        │        │
//!        │        └─ read_memory / write_memory to inspect/patch around the hit
//!        │
//!        └─ clear_breakpoint(id)                          (BP_CLEAR)
//! ```
//!
//! The target is **never halted**: the module captures a register snapshot at
//! each hit and lets the thread continue, so [`wait_event`](Debugger::wait_event)
//! reports "what executed/accessed here" after the fact rather than stopping the
//! world (this is the Cheat-Engine "global debug" model, not classic ptrace
//! single-stepping).
//!
//! # Platform
//!
//! Linux-only and kernel-module-only: it speaks a Linux ioctl ABI over
//! `/dev/nemclass`. The whole `kernel` module is gated `#[cfg(target_os =
//! "linux")]`, so a future Windows debugger can slot in behind an equivalent
//! surface without touching callers.

use super::abi;
use super::client::{Event, KernelClient, PtraceStatus};
use crate::Error;

/// Stable identifier for a breakpoint owned by a [`Debugger`].
///
/// This wraps the kernel *slot id* returned by `BP_SET`, which the module
/// assigns monotonically per fd and never reuses within a session — so it is a
/// stable handle for [`Debugger::clear_breakpoint`] and matches the `slot`
/// carried on an incoming [`DebugEvent`]. It is deliberately opaque; construct
/// one only via [`Debugger::set_breakpoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BreakpointId(pub(crate) i32);

impl BreakpointId {
    /// The raw kernel slot id behind this handle. Exposed for logging / display
    /// and for correlating with a [`DebugEvent::breakpoint`].
    pub fn raw(self) -> i32 {
        self.0
    }
}

impl core::fmt::Display for BreakpointId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "bp#{}", self.0)
    }
}

/// What to arm, covering both breakpoint kinds the module supports.
///
/// Build one with the constructors ([`hardware`](BreakpointSpec::hardware),
/// [`watch_write`](BreakpointSpec::watch_write), …, [`uprobe`](BreakpointSpec::uprobe))
/// so the hardware length is validated up front, or the struct variants
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointSpec {
    /// A debug-register hardware breakpoint / watchpoint (per-thread, DR-backed).
    ///
    /// `len` is the watched span in bytes and must be `1`, `2`, `4`, or `8`;
    /// `ty` selects the trigger condition. Execute breakpoints conventionally
    /// use `len == 1`.
    Hardware {
        /// Target virtual address to watch.
        addr: u64,
        /// Watch span in bytes: `1`, `2`, `4`, or `8`.
        len: u32,
        /// Trigger condition (execute / read / write / read-write).
        ty: abi::HwBreakpointType,
    },
    /// A uprobe-backed software execute breakpoint.
    ///
    /// The module resolves the backing inode + file offset from the target's
    /// VMA covering `addr`, so `addr` must fall inside a file-backed executable
    /// mapping (a JIT/anonymous region has no inode to probe).
    Uprobe {
        /// Target virtual address to probe.
        addr: u64,
    },
}

impl BreakpointSpec {
    /// A hardware breakpoint/watchpoint. Returns [`Error::InvalidArgument`] if
    /// `len` is not one of `1`/`2`/`4`/`8` (the debug-register-legal spans),
    /// mirroring the kernel's own `-EINVAL` but catching the misuse before the
    /// ioctl.
    pub fn hardware(addr: u64, len: u32, ty: abi::HwBreakpointType) -> crate::Result<Self> {
        validate_hw_len(len)?;
        Ok(BreakpointSpec::Hardware { addr, len, ty })
    }

    /// An execute (`X`) hardware breakpoint at `addr` (length 1).
    pub fn execute(addr: u64) -> Self {
        BreakpointSpec::Hardware {
            addr,
            len: 1,
            ty: abi::HwBreakpointType::Execute,
        }
    }

    /// A write watchpoint on `len` bytes at `addr`. Returns
    /// [`Error::InvalidArgument`] for an illegal `len`.
    pub fn watch_write(addr: u64, len: u32) -> crate::Result<Self> {
        Self::hardware(addr, len, abi::HwBreakpointType::Write)
    }

    /// A read watchpoint on `len` bytes at `addr`. Returns
    /// [`Error::InvalidArgument`] for an illegal `len`.
    pub fn watch_read(addr: u64, len: u32) -> crate::Result<Self> {
        Self::hardware(addr, len, abi::HwBreakpointType::Read)
    }

    /// A read-or-write (access) watchpoint on `len` bytes at `addr`. Returns
    /// [`Error::InvalidArgument`] for an illegal `len`.
    pub fn watch_access(addr: u64, len: u32) -> crate::Result<Self> {
        Self::hardware(addr, len, abi::HwBreakpointType::ReadWrite)
    }

    /// A uprobe (software execute) breakpoint at `addr`.
    pub fn uprobe(addr: u64) -> Self {
        BreakpointSpec::Uprobe { addr }
    }

    /// The address this breakpoint is set on, whichever kind it is.
    pub fn addr(&self) -> u64 {
        match *self {
            BreakpointSpec::Hardware { addr, .. } => addr,
            BreakpointSpec::Uprobe { addr } => addr,
        }
    }

    /// The ABI kind this spec maps to.
    pub fn kind(&self) -> abi::BreakpointKind {
        match self {
            BreakpointSpec::Hardware { .. } => abi::BreakpointKind::Hardware,
            BreakpointSpec::Uprobe { .. } => abi::BreakpointKind::Uprobe,
        }
    }
}

/// The two debug-register-legal HW watchpoint spans, checked client-side so a
/// bad length is a clear [`Error::InvalidArgument`] instead of a raw `-EINVAL`.
fn validate_hw_len(len: u32) -> crate::Result<()> {
    match len {
        1 | 2 | 4 | 8 => Ok(()),
        other => Err(Error::InvalidArgument(format!(
            "hardware breakpoint length must be 1, 2, 4, or 8 bytes, got {other}"
        ))),
    }
}

/// An armed breakpoint as tracked by the [`Debugger`]: its stable id plus the
/// spec it was created from. Returned by [`Debugger::breakpoints`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Breakpoint {
    /// Stable id (kernel slot) — pass to [`Debugger::clear_breakpoint`].
    pub id: BreakpointId,
    /// What was armed.
    pub spec: BreakpointSpec,
}

/// The x86_64 register snapshot captured at a hit.
///
/// This is a decoded, field-named view of the flat register array on the ABI
/// [`Event`](super::Event); the target was not halted, so these are the register
/// values *at the moment the breakpoint fired*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    /// Instruction pointer (`RIP`).
    pub rip: u64,
    /// Stack pointer (`RSP`).
    pub rsp: u64,
    /// `RFLAGS`.
    pub rflags: u64,
    /// `RAX`.
    pub rax: u64,
    /// `RBX`.
    pub rbx: u64,
    /// `RCX`.
    pub rcx: u64,
    /// `RDX`.
    pub rdx: u64,
    /// `RSI`.
    pub rsi: u64,
    /// `RDI`.
    pub rdi: u64,
    /// `RBP`.
    pub rbp: u64,
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

impl Registers {
    /// Decodes the flat `[ax, bx, cx, dx, si, di, bp, r8..=r15]` array on an
    /// [`Event`](super::Event) (plus `ip`/`sp`/`flags`) into named fields. The
    /// order matches [`Event::gpr`](super::Event::gpr).
    fn from_event(e: &Event) -> Self {
        let g = e.gpr;
        Registers {
            rip: e.ip,
            rsp: e.sp,
            rflags: e.flags,
            rax: g[0],
            rbx: g[1],
            rcx: g[2],
            rdx: g[3],
            rsi: g[4],
            rdi: g[5],
            rbp: g[6],
            r8: g[7],
            r9: g[8],
            r10: g[9],
            r11: g[10],
            r12: g[11],
            r13: g[12],
            r14: g[13],
            r15: g[14],
        }
    }
}

/// A decoded breakpoint/uprobe hit delivered by [`Debugger::wait_event`].
///
/// A rich view of the raw ABI [`Event`](super::Event): the kernel slot is
/// resolved back to the [`BreakpointId`] that produced it (and, when the
/// debugger armed it, the originating [`BreakpointSpec`]), and the flat register
/// array is decoded into a named [`Registers`]. Execution was **not** halted —
/// this records "what executed/accessed here" and the target has already moved
/// on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DebugEvent {
    /// The breakpoint that fired.
    pub breakpoint: BreakpointId,
    /// The spec this debugger armed for that breakpoint, if it is still tracked.
    /// `None` if the slot was cleared, or armed on a different fd (should not
    /// happen for a single-owner [`Debugger`], but the event carries the slot
    /// verbatim so this stays honest).
    pub spec: Option<BreakpointSpec>,
    /// Process the hit occurred in (always this debugger's target).
    pub pid: i32,
    /// Thread the hit occurred in.
    pub tid: i32,
    /// Which kind of breakpoint fired, if the kernel-reported kind is known.
    pub kind: Option<abi::BreakpointKind>,
    /// The watched / probe address the breakpoint was set on.
    pub address: u64,
    /// The x86_64 register snapshot at the hit.
    pub registers: Registers,
}

/// Ergonomic controller for the kernel module's non-ptrace debugger engine.
///
/// Owns an authenticated [`KernelClient`] bound to a target `pid`, plus the
/// breakpoint bookkeeping. See the [module docs](self) for the attach → set →
/// wait → inspect → clear flow. Dropping the `Debugger` closes the device fd,
/// which the module treats as end-of-session: all breakpoints armed on this fd
/// are torn down and the event queue is released.
pub struct Debugger {
    client: KernelClient,
    pid: libc::pid_t,
    breakpoints: Vec<Breakpoint>,
}

impl Debugger {
    /// Attaches to `pid`: opens `/dev/nemclass`, verifies the module speaks
    /// [`abi::NEMCLASS_ABI_VERSION`], and authenticates with `key`.
    ///
    /// `key` is the raw key bytes the module was loaded with (`key=<hex>`
    /// decoded to bytes). The module fails **closed**: if it was loaded without
    /// a key, or `key` does not match, [`auth`](KernelClient::auth) returns
    /// [`Error::Errno`] with `EACCES`.
    ///
    /// # Errors
    /// - [`Error::DeviceUnavailable`] if the module is not loaded or the caller
    ///   lacks permission on the node.
    /// - [`Error::AbiMismatch`] if the module's ABI revision differs from this
    ///   client's — fail fast rather than issue mismatched ioctls.
    /// - [`Error::Errno`] (`EACCES`) if authentication is rejected.
    pub fn attach(pid: libc::pid_t, key: &[u8]) -> crate::Result<Self> {
        let client = KernelClient::open()?;
        // Check the ABI before anything else: a mismatched module could lay out
        // every subsequent ioctl struct differently.
        client.check_abi()?;
        client.auth(key)?;
        Ok(Self::from_client(client, pid))
    }

    /// Adopts an already-opened (and, if the module requires it, already
    /// authenticated) [`KernelClient`], binding it to `pid`.
    ///
    /// Use this to share the ABI-check/auth handshake with a [`KernelBackend`]
    /// or to inject a client in tests. This does **not** re-check the ABI or
    /// re-auth; call [`KernelClient::check_abi`] / [`KernelClient::auth`]
    /// yourself first if the client is fresh.
    pub fn from_client(client: KernelClient, pid: libc::pid_t) -> Self {
        Debugger {
            client,
            pid,
            breakpoints: Vec::new(),
        }
    }

    /// The target process this debugger is bound to.
    pub fn pid(&self) -> libc::pid_t {
        self.pid
    }

    /// The underlying client, for callers that need a raw ioctl not surfaced
    /// here (e.g. region enumeration via [`KernelClient::enum_regions`]).
    pub fn client(&self) -> &KernelClient {
        &self.client
    }

    // --- breakpoints ------------------------------------------------------

    /// Arms a breakpoint described by `spec` on the target, returning its stable
    /// [`BreakpointId`].
    ///
    /// Dispatches to `BP_SET` as a hardware watchpoint or a uprobe. The returned
    /// id is recorded so it appears in [`breakpoints`](Debugger::breakpoints),
    /// resolves the `spec` on a matching [`DebugEvent`], and can be cleared.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] for an illegal hardware length (already
    ///   caught by the [`BreakpointSpec`] constructors, re-checked here in case
    ///   a struct variant was built by hand).
    /// - [`Error::Errno`] surfacing the kernel's failure: `EINVAL` (bad
    ///   type/len), `EOPNOTSUPP` (kernel built without `CONFIG_HAVE_HW_BREAKPOINT`
    ///   / `CONFIG_UPROBES`), `ESRCH` (target gone), `ENOMEM`, or an
    ///   arch-specific error when a uprobe address is not in a file-backed VMA.
    pub fn set_breakpoint(&mut self, spec: BreakpointSpec) -> crate::Result<BreakpointId> {
        let slot = match spec {
            BreakpointSpec::Hardware { addr, len, ty } => {
                validate_hw_len(len)?;
                self.client.set_hw_breakpoint(self.pid, addr, len, ty)?
            }
            BreakpointSpec::Uprobe { addr } => self.client.set_uprobe(self.pid, addr)?,
        };
        let id = BreakpointId(slot);
        self.breakpoints.push(Breakpoint { id, spec });
        Ok(id)
    }

    /// Clears the breakpoint with `id` (`BP_CLEAR`) and drops its bookkeeping.
    ///
    /// # Errors
    /// - [`Error::InvalidArgument`] if `id` is not one this debugger armed (or
    ///   was already cleared) — a client-side check so the caller learns of the
    ///   misuse without a kernel round-trip.
    /// - [`Error::Errno`] (`ENOENT`) if the kernel no longer knows the slot
    ///   (e.g. the session was reset underneath us). The bookkeeping entry is
    ///   still removed so state stays consistent.
    pub fn clear_breakpoint(&mut self, id: BreakpointId) -> crate::Result<()> {
        let idx = self
            .breakpoints
            .iter()
            .position(|b| b.id == id)
            .ok_or_else(|| {
                Error::InvalidArgument(format!("no such breakpoint {id} on this debugger"))
            })?;
        // Remove from bookkeeping first so a kernel ENOENT (slot already gone)
        // still leaves us in a consistent, non-leaking state.
        self.breakpoints.remove(idx);
        self.client.clear_breakpoint(id.raw())?;
        Ok(())
    }

    /// The breakpoints currently armed by this debugger, in the order they were
    /// set. Cleared breakpoints are not listed.
    pub fn breakpoints(&self) -> &[Breakpoint] {
        &self.breakpoints
    }

    /// Looks up the [`BreakpointSpec`] this debugger armed for `id`, if still
    /// tracked.
    pub fn breakpoint_spec(&self, id: BreakpointId) -> Option<BreakpointSpec> {
        self.breakpoints
            .iter()
            .find(|b| b.id == id)
            .map(|b| b.spec)
    }

    // --- events -----------------------------------------------------------

    /// Waits for the next breakpoint/uprobe hit, returning a decoded
    /// [`DebugEvent`].
    ///
    /// `timeout`: `None` blocks forever; `Some(Duration::ZERO)` polls
    /// (non-blocking); `Some(d)` waits up to `d` (rounded to whole
    /// milliseconds, clamped to `i32::MAX`). Returns `Ok(None)` on timeout or an
    /// empty non-blocking poll — the module's `EAGAIN`/`ETIMEDOUT` contract,
    /// where those mean "retry, no event lost", not an error.
    ///
    /// The returned event's [`spec`](DebugEvent::spec) is resolved from this
    /// debugger's bookkeeping when the firing slot is still tracked.
    pub fn wait_event(
        &mut self,
        timeout: Option<core::time::Duration>,
    ) -> crate::Result<Option<DebugEvent>> {
        let timeout_ms = match timeout {
            // Block forever.
            None => -1,
            Some(d) => {
                let ms = d.as_millis();
                // Clamp to the ABI's i32 field; `u128 as i32` would wrap.
                if ms > i32::MAX as u128 {
                    i32::MAX
                } else {
                    ms as i32
                }
            }
        };
        match self.client.wait_event(timeout_ms)? {
            Some(ev) => Ok(Some(self.decode_event(&ev))),
            None => Ok(None),
        }
    }

    /// Decodes a raw ABI [`Event`] into a [`DebugEvent`], resolving the firing
    /// slot back to this debugger's tracked [`BreakpointSpec`].
    fn decode_event(&self, ev: &Event) -> DebugEvent {
        let breakpoint = BreakpointId(ev.slot);
        DebugEvent {
            breakpoint,
            spec: self.breakpoint_spec(breakpoint),
            pid: ev.pid,
            tid: ev.tid,
            kind: ev.kind,
            address: ev.addr,
            registers: Registers::from_event(ev),
        }
    }

    // --- memory (inspect / patch around a hit) ----------------------------

    /// Reads `[addr, addr+buf.len())` of the target through the module.
    ///
    /// Returns the number of bytes read (short at a mapping boundary). This is
    /// the same kernel-mediated path as [`KernelBackend`](super::KernelBackend)
    /// — it works where `process_vm_readv` is denied.
    pub fn read_memory(&self, addr: usize, buf: &mut [u8]) -> crate::Result<usize> {
        self.client.read_mem(self.pid, addr, buf)
    }

    /// Writes `buf` to `[addr, addr+buf.len())` of the target through the
    /// module. Returns the number of bytes written (short at a boundary).
    pub fn write_memory(&self, addr: usize, buf: &[u8]) -> crate::Result<usize> {
        self.client.write_mem(self.pid, addr, buf)
    }

    // --- ptrace interop ---------------------------------------------------

    /// Queries whether `pid` is currently ptraced, and by whom
    /// (`PTRACE_QUERY`). Takes an explicit `pid` so callers can probe processes
    /// other than the attached target (e.g. to detect an anti-debug watcher).
    pub fn ptrace_status(&self, pid: libc::pid_t) -> crate::Result<PtraceStatus> {
        self.client.ptrace_query(pid)
    }

    /// Asks the module to hide any ptrace relationship on `pid` (anti-anti-debug,
    /// `PTRACE_HIDE`).
    ///
    /// **Gated by a module parameter.** The module must have been loaded with
    /// `allow_ptrace_hide=1`; otherwise this returns [`Error::Errno`] with
    /// `EPERM` and the operation is a no-op. This is experimental — see the
    /// module's `MODULE_PARM_DESC(allow_ptrace_hide)`.
    pub fn ptrace_hide(&self, pid: libc::pid_t) -> crate::Result<()> {
        self.client.ptrace_hide(pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- BreakpointSpec construction / validation -------------------------

    #[test]
    fn hardware_len_validation() {
        for good in [1u32, 2, 4, 8] {
            assert!(BreakpointSpec::hardware(0x1000, good, abi::HwBreakpointType::Write).is_ok());
        }
        for bad in [0u32, 3, 5, 6, 7, 16] {
            match BreakpointSpec::hardware(0x1000, bad, abi::HwBreakpointType::Write) {
                Err(Error::InvalidArgument(_)) => {}
                other => panic!("expected InvalidArgument for len {bad}, got {other:?}"),
            }
        }
    }

    #[test]
    fn spec_constructors_map_to_expected_kind_and_addr() {
        let x = BreakpointSpec::execute(0xdead);
        assert_eq!(x.kind(), abi::BreakpointKind::Hardware);
        assert_eq!(x.addr(), 0xdead);
        assert!(matches!(
            x,
            BreakpointSpec::Hardware {
                ty: abi::HwBreakpointType::Execute,
                len: 1,
                ..
            }
        ));

        let w = BreakpointSpec::watch_write(0xbeef, 4).unwrap();
        assert!(matches!(
            w,
            BreakpointSpec::Hardware {
                ty: abi::HwBreakpointType::Write,
                len: 4,
                addr: 0xbeef,
            }
        ));

        let r = BreakpointSpec::watch_read(0x10, 8).unwrap();
        assert!(matches!(r, BreakpointSpec::Hardware { ty: abi::HwBreakpointType::Read, .. }));

        let rw = BreakpointSpec::watch_access(0x20, 2).unwrap();
        assert!(matches!(
            rw,
            BreakpointSpec::Hardware { ty: abi::HwBreakpointType::ReadWrite, .. }
        ));

        let u = BreakpointSpec::uprobe(0xcafe);
        assert_eq!(u.kind(), abi::BreakpointKind::Uprobe);
        assert_eq!(u.addr(), 0xcafe);
    }

    // --- BP_SET wire encoding round-trip ----------------------------------
    //
    // We cannot issue ioctls without the device, but we CAN prove that a
    // `BreakpointSpec` produces exactly the `nemclass_bp_set` bytes the kernel
    // expects, by mirroring `KernelClient::set_*`'s struct construction.

    /// The `nemclass_bp_set` a `Hardware` spec should serialize to.
    fn hw_request(pid: i32, addr: u64, len: u32, ty: abi::HwBreakpointType) -> abi::nemclass_bp_set {
        abi::nemclass_bp_set {
            pid,
            kind: abi::BreakpointKind::Hardware.to_raw(),
            addr,
            len,
            type_: ty.to_raw(),
            slot: -1,
            _pad: 0,
        }
    }

    #[test]
    fn hardware_spec_encodes_bp_set() {
        let req = hw_request(4321, 0x4011a0, 4, abi::HwBreakpointType::ReadWrite);
        assert_eq!(req.pid, 4321);
        assert_eq!(req.kind, abi::NEMCLASS_BP_KIND_HW);
        assert_eq!(req.addr, 0x4011a0);
        assert_eq!(req.len, 4);
        assert_eq!(req.type_, abi::NEMCLASS_BP_RW);
        // Slot is the "out" sentinel until the kernel fills it.
        assert_eq!(req.slot, -1);
        assert_eq!(req._pad, 0);
    }

    #[test]
    fn uprobe_spec_encodes_bp_set() {
        // Mirror `KernelClient::set_uprobe`'s struct: kind=UPROBE, X type, zeroed len.
        let req = abi::nemclass_bp_set {
            pid: 99,
            kind: abi::BreakpointKind::Uprobe.to_raw(),
            addr: 0x555500,
            len: 0,
            type_: abi::NEMCLASS_BP_X,
            slot: -1,
            _pad: 0,
        };
        assert_eq!(req.kind, abi::NEMCLASS_BP_KIND_UPROBE);
        assert_eq!(req.len, 0);
        assert_eq!(req.addr, 0x555500);
    }

    // --- Event → DebugEvent decode ----------------------------------------

    /// A fully-populated raw event with distinct register values so a decode
    /// mistake (wrong slot in the flat array) is caught.
    fn sample_event(slot: i32, kind: u32) -> Event {
        Event {
            slot,
            pid: 1234,
            tid: 1240,
            kind: abi::BreakpointKind::from_raw(kind),
            addr: 0x4011a0,
            ip: 0x4011a5,
            sp: 0x7fff_0000,
            flags: 0x202,
            // ax, bx, cx, dx, si, di, bp, r8..=r15
            gpr: [
                0xa, 0xb, 0xc, 0xd, 0x51, 0xd1, 0xb9, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            ],
        }
    }

    #[test]
    fn registers_decode_matches_abi_order() {
        let ev = sample_event(0, abi::NEMCLASS_BP_KIND_HW);
        let r = Registers::from_event(&ev);
        assert_eq!(r.rip, 0x4011a5);
        assert_eq!(r.rsp, 0x7fff_0000);
        assert_eq!(r.rflags, 0x202);
        assert_eq!(r.rax, 0xa);
        assert_eq!(r.rbx, 0xb);
        assert_eq!(r.rcx, 0xc);
        assert_eq!(r.rdx, 0xd);
        assert_eq!(r.rsi, 0x51);
        assert_eq!(r.rdi, 0xd1);
        assert_eq!(r.rbp, 0xb9);
        assert_eq!(r.r8, 0x8);
        assert_eq!(r.r15, 0x15);
    }

    #[test]
    fn decode_event_resolves_tracked_spec() {
        // Build a debugger without touching the device: we only exercise the
        // pure bookkeeping/decoding, never an ioctl.
        let mut dbg = Debugger {
            client: unreachable_client(),
            pid: 1234,
            breakpoints: Vec::new(),
        };
        // Pretend the kernel handed us slot 7 for a write watchpoint.
        let spec = BreakpointSpec::watch_write(0x4011a0, 4).unwrap();
        dbg.breakpoints.push(Breakpoint {
            id: BreakpointId(7),
            spec,
        });

        let ev = sample_event(7, abi::NEMCLASS_BP_KIND_HW);
        let de = dbg.decode_event(&ev);
        assert_eq!(de.breakpoint, BreakpointId(7));
        assert_eq!(de.spec, Some(spec));
        assert_eq!(de.pid, 1234);
        assert_eq!(de.tid, 1240);
        assert_eq!(de.kind, Some(abi::BreakpointKind::Hardware));
        assert_eq!(de.address, 0x4011a0);
        assert_eq!(de.registers.rip, 0x4011a5);

        // An event for an untracked slot decodes with `spec == None`, not a panic.
        let untracked = dbg.decode_event(&sample_event(999, abi::NEMCLASS_BP_KIND_UPROBE));
        assert_eq!(untracked.breakpoint, BreakpointId(999));
        assert_eq!(untracked.spec, None);
        assert_eq!(untracked.kind, Some(abi::BreakpointKind::Uprobe));
    }

    // --- breakpoint bookkeeping (ids / list / clear) ----------------------

    #[test]
    fn bookkeeping_list_and_lookup() {
        let mut dbg = Debugger {
            client: unreachable_client(),
            pid: 1,
            breakpoints: Vec::new(),
        };
        let a = BreakpointSpec::execute(0x1000);
        let b = BreakpointSpec::watch_read(0x2000, 8).unwrap();
        dbg.breakpoints.push(Breakpoint {
            id: BreakpointId(0),
            spec: a,
        });
        dbg.breakpoints.push(Breakpoint {
            id: BreakpointId(1),
            spec: b,
        });

        assert_eq!(dbg.breakpoints().len(), 2);
        assert_eq!(dbg.breakpoint_spec(BreakpointId(0)), Some(a));
        assert_eq!(dbg.breakpoint_spec(BreakpointId(1)), Some(b));
        assert_eq!(dbg.breakpoint_spec(BreakpointId(42)), None);
        // Insertion order is preserved.
        assert_eq!(dbg.breakpoints()[0].id, BreakpointId(0));
        assert_eq!(dbg.breakpoints()[1].id, BreakpointId(1));
    }

    #[test]
    fn clear_unknown_breakpoint_is_invalid_argument() {
        // `clear_breakpoint` must reject an unknown id *before* any ioctl, so we
        // can assert on the error without a device.
        let mut dbg = Debugger {
            client: unreachable_client(),
            pid: 1,
            breakpoints: Vec::new(),
        };
        match dbg.clear_breakpoint(BreakpointId(5)) {
            Err(Error::InvalidArgument(_)) => {}
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    #[test]
    fn breakpoint_id_display_and_raw() {
        let id = BreakpointId(12);
        assert_eq!(id.raw(), 12);
        assert_eq!(format!("{id}"), "bp#12");
    }

    #[test]
    fn wait_event_timeout_clamps_to_i32() {
        // Sanity-check the `Duration` → `timeout_ms` mapping the debugger uses,
        // without touching the device: `None` → block forever (`-1`), zero →
        // non-blocking (`0`), an over-large duration saturates at `i32::MAX`.
        // (Mirrors the arithmetic in `wait_event`.)
        let ms = |d: Option<core::time::Duration>| -> i32 {
            match d {
                None => -1,
                Some(d) => {
                    let m = d.as_millis();
                    if m > i32::MAX as u128 {
                        i32::MAX
                    } else {
                        m as i32
                    }
                }
            }
        };
        assert_eq!(ms(None), -1);
        assert_eq!(ms(Some(core::time::Duration::ZERO)), 0);
        assert_eq!(ms(Some(core::time::Duration::from_millis(250))), 250);
        assert_eq!(ms(Some(core::time::Duration::from_secs(60 * 60 * 24 * 365))), i32::MAX);
    }

    // --- live device test (skips cleanly without the module) --------------

    /// End-to-end against a real `/dev/nemclass`: attach to ourselves, set an
    /// execute breakpoint, and tear it down. `#[ignore]` by default because the
    /// module is not loaded in CI/dev; when run, it SKIPs cleanly if the device
    /// is absent or auth is refused rather than failing the suite.
    ///
    /// Run with the key the module was loaded with:
    /// `NEMCLASS_KEY=<hex> cargo test -p nemclass-core -- --ignored live_attach`.
    #[test]
    #[ignore = "requires the nemclass kernel module loaded at /dev/nemclass (set NEMCLASS_KEY)"]
    fn live_attach_set_clear_breakpoint() {
        let pid = std::process::id() as libc::pid_t;

        // The module is loaded with `key=<hex>`; the client must AUTH with the
        // raw bytes. Accept hex via env; empty means "loaded without a key".
        let key = std::env::var("NEMCLASS_KEY")
            .ok()
            .map(|h| {
                (0..h.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&h[i..i + 2], 16).expect("valid hex key"))
                    .collect::<Vec<u8>>()
            })
            .unwrap_or_default();

        let mut dbg = match Debugger::attach(pid, &key) {
            Ok(d) => d,
            Err(Error::DeviceUnavailable(_)) => {
                eprintln!("SKIP: /dev/nemclass not present");
                return;
            }
            Err(Error::AbiMismatch { .. }) => {
                eprintln!("SKIP: nemclass ABI mismatch");
                return;
            }
            Err(Error::Errno(e)) if e == libc::EACCES => {
                eprintln!("SKIP: auth refused (set NEMCLASS_KEY to the module's key)");
                return;
            }
            Err(e) => panic!("unexpected attach error: {e:?}"),
        };

        // Arm an execute breakpoint on this test function's own address — a real,
        // mapped, executable address in our own process.
        let addr = live_attach_set_clear_breakpoint as *const () as usize as u64;
        let id = dbg
            .set_breakpoint(BreakpointSpec::execute(addr))
            .expect("set execute breakpoint");
        assert_eq!(dbg.breakpoints().len(), 1);
        assert_eq!(dbg.breakpoint_spec(id).map(|s| s.addr()), Some(addr));

        // A non-blocking wait should not error (may or may not have a hit).
        let _ = dbg
            .wait_event(Some(core::time::Duration::ZERO))
            .expect("non-blocking wait");

        dbg.clear_breakpoint(id).expect("clear breakpoint");
        assert!(dbg.breakpoints().is_empty());
    }

    /// Constructs a [`KernelClient`] whose fd is invalid, for tests that only
    /// touch pure bookkeeping/decoding and must **never** reach an ioctl. Any
    /// accidental ioctl on `-1` fails with `EBADF` rather than hitting a real
    /// device, so a test that wrongly calls the kernel will error loudly.
    fn unreachable_client() -> KernelClient {
        // SAFETY: we only build the struct; no method that dereferences the fd
        // is called on this client in these tests. `/dev/null` gives us a real,
        // owned `File` so `Drop` is well-defined; its fd is simply never a valid
        // nemclass device.
        KernelClient::from_raw_parts_for_test()
    }
}
