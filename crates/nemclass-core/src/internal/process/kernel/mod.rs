//! Client for the `nemclass_mod` Linux kernel char device (`/dev/nemclass`).
//!
//! The module exposes an ioctl ABI providing (a) kernel-side remote process
//! memory read/write that bypasses ptrace/Yama, and (b) a non-ptrace,
//! "global-debug"-style debugger (hardware breakpoints/watchpoints and uprobes
//! that deliver register-snapshot events). This module is the userspace half:
//!
//! - [`abi`] mirrors the C UAPI header byte-for-byte (`#[repr(C)]` structs +
//!   the `_IOC`-encoded request codes), with compile-time size assertions.
//! - [`client`] wraps the device fd and drives every ioctl, exposing the raw
//!   memory API, the low-level debugger calls, and the ptrace-interop queries.
//! - [`debugger`] is the ergonomic controller over [`client`]: it authenticates
//!   the fd, keeps breakpoint bookkeeping (id → spec, list / clear), and decodes
//!   raw events into a rich [`DebugEvent`] with named registers.
//!
//! Everything here is Linux-only (it speaks a Linux ioctl ABI over `/dev`), so
//! the whole module is gated at the `process` level with
//! `#[cfg(target_os = "linux")]`, keeping the shared [`crate::MemoryBackend`]
//! seam free of Linux specifics for a future Windows backend.

pub mod abi;
pub mod client;
pub mod debugger;

pub use client::{Event, KernelBackend, KernelClient, PtraceStatus, NEMCLASS_DEVICE};
pub use debugger::{Breakpoint, BreakpointId, BreakpointSpec, DebugEvent, Debugger, Registers};
