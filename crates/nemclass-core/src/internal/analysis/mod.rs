//! Memory-dissection analysis foundation (phase M5.1).
//!
//! This layer sits above the raw memory backend and the disassembler and turns
//! bytes into meaning for the memory viewer / dissector:
//!
//! - [`region_index`] — a sorted, non-overlapping view of a target's mappings
//!   that answers "what is at this address?" (unmapped / data / executable, and
//!   which module) in `O(log n)`.
//! - [`strings`] — printable ASCII / UTF-16LE run detection over a byte buffer.
//! - [`pointer`] — classify a machine word as null / not-a-pointer / data /
//!   code / vtable, using a [`region_index::RegionIndex`] and an injected reader.
//! - [`disasm`] — Linux-only linear disassembly of a single function from a live
//!   process (the ReClass.NET `DisassembleRemoteCode` analog).
//!
//! The pure pieces ([`region_index::RegionIndex::from_sections`],
//! [`strings::detect_strings`], [`pointer::classify_value`] with an injected
//! reader) are platform-neutral and unit-tested without a process; only the
//! `from_pid` / `classify_in_process` / [`disasm`] conveniences touch `/proc`
//! and are `#[cfg(target_os = "linux")]`.

pub mod pointer;
pub mod region_index;
pub mod strings;

// Live-process function walk — reads from a `Process`, so Linux-only.
#[cfg(target_os = "linux")]
pub mod disasm;

pub use pointer::{PointerClass, classify_value};
pub use region_index::{AddrClass, RegionIndex};
pub use strings::{StrKind, StringRun, detect_strings, string_at};

#[cfg(target_os = "linux")]
pub use disasm::{FunctionDisasm, disassemble_function};

#[cfg(target_os = "linux")]
pub use pointer::classify_in_process;
