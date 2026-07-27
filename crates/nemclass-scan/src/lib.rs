#![doc = include_str!("detailed_docs.md")]
//! Cheat-Engine-style memory scanner for nemclass.
//!
//! A faithful port of ReClass.NET's `MemoryScanner` (`ScanValueType`,
//! `ScanCompareType`, `Scanner`, and the per-type comparers), restructured
//! around a single [`ScanTarget`] seam so the scan engine is **platform-neutral
//! and mock-testable**. The live Linux target ([`ProcessTarget`], Linux-only)
//! is backed by `nemclass_core::{Process, ProviderRegistry}`; the engine itself
//! ([`Scanner`], [`ScanValueType`], [`ScanCompareType`], [`FreezeSet`]) depends
//! only on the trait and works against an in-memory [`MockTarget`].
//!
//! # Shape
//! - [`ScanValueType`] — the searchable value kinds (`I8`..`U64`, `F32`/`F64`,
//!   [`ScanValueType::Bytes`] AOB with `??` wildcards, and UTF-8/UTF-16
//!   strings). Each knows its stride and how to [`ScanValueType::parse_needle`].
//! - [`ScanCompareType`] — `Exact`/`NotEqual`/`GreaterThan`/`LessThan`/`Between`
//!   plus the change-relative kinds (`Unknown`, `Increased`, `IncreasedBy`,
//!   `Decreased`, `DecreasedBy`, `Changed`, `Unchanged`).
//! - [`Scanner`] — generic over [`ScanTarget`]:
//!   [`Scanner::first_scan`] walks regions in chunks; [`Scanner::next_scan`]
//!   re-reads only the previous match addresses; a bounded undo history backs
//!   [`Scanner::undo`].
//! - [`FreezeSet`] — periodically re-writes pinned values through a
//!   [`WriteTarget`].
//!
//! # Example
//! ```
//! use nemclass_scan::{MockTarget, Scanner, ScanValueType, ScanCompareType};
//!
//! let mut buf = vec![0u8; 32];
//! buf[8..12].copy_from_slice(&1337i32.to_le_bytes());
//! let target = MockTarget::new(0x1000, buf);
//!
//! let mut scanner = Scanner::new(target, ScanValueType::I32);
//! let needle = ScanValueType::I32.parse_needle("1337").unwrap();
//! let results = scanner.first_scan(ScanCompareType::Exact, Some(needle)).unwrap();
//! assert_eq!(results.len(), 1);
//! assert_eq!(results.iter().next().unwrap().address, 0x1008);
//! ```

mod compare;
mod freeze;
mod pattern;
mod pointerscan;
mod results;
mod scanner;
mod target;
mod signature;
mod value_type;

pub use compare::ScanCompareType;
pub use freeze::FreezeSet;
pub use pattern::{BytePattern, PatternByte, PatternError};
pub use pointerscan::{
    pointer_scan, PointerMap, PointerPath, PointerScanConfig, PointerScanResult,
};
pub use results::{ScanResult, ScanResults};
pub use signature::{format_signature, make_signature, SignatureConfig};
pub use scanner::{NoObserver, ScanError, ScanObserver, ScanProgress, ScanStats, Scanner};
pub use target::{
    FilterState, MockTarget, Region, RegionFilter, ScanTarget, SectionFilter, WriteTarget,
};
pub use value_type::{
    DEFAULT_FLOAT_TOLERANCE, Needle, NeedleParseError, ScanValueType,
};

// The live Linux scan target (`process_vm_readv`/`writev` regions + IO).
#[cfg(target_os = "linux")]
pub use target::ProcessTarget;

// Re-export the core error/result vocabulary so callers keep one `Result` type.
pub use nemclass_core::{Error, Result};

#[cfg(test)]
mod tests;
