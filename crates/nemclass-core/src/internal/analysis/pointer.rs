//! Classify a value read from a target's memory as a pointer (and what kind).
//!
//! When the dissector reads a machine word out of a struct, it wants to know:
//! is this a null, a plain integer, a pointer into data, a pointer into code, or
//! the pointer to a **vtable** (the tell-tale of a polymorphic C++ object)? This
//! module answers that using a [`RegionIndex`] for the "where does it point?"
//! part and an injected reader for the "what does it point at?" part — so it is
//! testable with a fake reader and works over any [`crate::MemoryBackend`].

use crate::internal::analysis::region_index::{AddrClass, RegionIndex};

/// The maximum number of leading table entries probed when testing a data
/// pointer for vtable-ness. A real vtable can be longer; we only need enough
/// consecutive code pointers to be confident and to report a useful count.
const MAX_VTABLE_PROBE: usize = 8;

/// The minimum number of consecutive executable entries a candidate table needs
/// before we call it a vtable. Two independent code pointers in a row is a
/// strong signal and rejects the common "one function pointer stored in a
/// struct" false positive.
const MIN_VTABLE_METHODS: usize = 2;

/// Size of a probed vtable entry, in bytes. Entries are read as `u64` (an
/// absolute code address) per the classifier's contract, independent of the
/// host's pointer width.
const ENTRY_SIZE: usize = core::mem::size_of::<u64>();

/// The classification of a machine-word value read from a target.
#[derive(Debug, Clone, PartialEq)]
pub enum PointerClass {
    /// The value is `0`.
    Null,
    /// The value does not point into any mapping — most likely a plain integer.
    NotPointer,
    /// The value points into a readable, non-executable mapping (data).
    DataPtr,
    /// The value points into an executable mapping (a function / code address).
    CodePtr,
    /// The value points at a table whose first `method_count` entries are
    /// themselves code pointers — i.e. a vtable. `method_count` is how many
    /// leading executable entries were found (`>= 2`, capped at the probe size).
    VTablePtr {
        /// Number of leading entries that classify as executable.
        method_count: usize,
    },
}

/// Classifies `value` using `index` for address lookups and `read` to probe
/// memory for vtable candidacy.
///
/// - `0` → [`PointerClass::Null`].
/// - not inside any mapping → [`PointerClass::NotPointer`].
/// - inside an executable mapping → [`PointerClass::CodePtr`].
/// - inside a data mapping → probe for a vtable: if `value` is pointer-aligned,
///   read up to [`MAX_VTABLE_PROBE`] consecutive `u64` entries starting at
///   `value` and count the leading ones that point into executable memory; if
///   at least [`MIN_VTABLE_METHODS`] do, return [`PointerClass::VTablePtr`],
///   otherwise [`PointerClass::DataPtr`].
///
/// The `read` closure has the same shape as [`crate::Process::read_buf`]
/// (`fn(address, &mut [u8]) -> Result<bytes_read>`), so it can be a real backend
/// or a fake for tests. A short or failing read simply ends the vtable probe;
/// the entries gathered so far still count.
pub fn classify_value(
    value: u64,
    index: &RegionIndex,
    read: impl Fn(usize, &mut [u8]) -> crate::Result<usize>,
) -> PointerClass {
    if value == 0 {
        return PointerClass::Null;
    }

    // `usize` is the host word width; a target address wider than the host can't
    // be dereferenced here, so treat it as a non-pointer rather than truncating.
    let Ok(addr) = usize::try_from(value) else {
        return PointerClass::NotPointer;
    };

    match index.classify(addr) {
        AddrClass::Unmapped => PointerClass::NotPointer,
        AddrClass::Executable { .. } => PointerClass::CodePtr,
        AddrClass::Data { .. } => {
            // A vtable pointer must itself be aligned; an unaligned data pointer
            // is never a vtable candidate (and probing it would misread entries).
            if addr % ENTRY_SIZE != 0 {
                return PointerClass::DataPtr;
            }

            let methods = count_leading_code_entries(addr, index, &read);
            if methods >= MIN_VTABLE_METHODS {
                PointerClass::VTablePtr {
                    method_count: methods,
                }
            } else {
                PointerClass::DataPtr
            }
        }
    }
}

/// Reads up to [`MAX_VTABLE_PROBE`] `u64` entries starting at `table` and counts
/// how many *leading* entries point into executable memory. Stops at the first
/// non-executable (or unreadable) entry — a vtable's method pointers are
/// contiguous, so the first gap ends the run.
fn count_leading_code_entries(
    table: usize,
    index: &RegionIndex,
    read: &impl Fn(usize, &mut [u8]) -> crate::Result<usize>,
) -> usize {
    let mut count = 0;
    for i in 0..MAX_VTABLE_PROBE {
        let Some(entry_addr) = table.checked_add(i * ENTRY_SIZE) else {
            break;
        };
        let mut bytes = [0u8; ENTRY_SIZE];
        // A short or failing read ends the probe; we count what we confirmed.
        match read(entry_addr, &mut bytes) {
            Ok(n) if n == ENTRY_SIZE => {}
            _ => break,
        }
        let entry = u64::from_le_bytes(bytes);
        match usize::try_from(entry) {
            Ok(a) if index.is_executable(a) => count += 1,
            _ => break,
        }
    }
    count
}

/// Linux convenience wrapper: classifies `value` by probing the given live
/// process. Threads [`crate::Process::read_buf`] into [`classify_value`].
#[cfg(target_os = "linux")]
pub fn classify_in_process(
    value: u64,
    index: &RegionIndex,
    process: &crate::Process,
) -> PointerClass {
    classify_value(value, index, |addr, buf| process.read_buf(addr, buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::process::{Protection, Section, SectionType};
    use std::collections::HashMap;

    const EXEC_BASE: usize = 0x1000; // [0x1000, 0x2000) executable
    const DATA_BASE: usize = 0x3000; // [0x3000, 0x4000) data

    fn index() -> RegionIndex {
        RegionIndex::from_sections(&[
            Section {
                base: EXEC_BASE,
                size: 0x1000,
                prot: Protection::RX,
                kind: SectionType::Image,
                module: Some("app.exe".to_owned()),
            },
            Section {
                base: DATA_BASE,
                size: 0x1000,
                prot: Protection::RW,
                kind: SectionType::Mapped,
                module: None,
            },
        ])
    }

    /// A fake memory: 8-byte little-endian words keyed by address. Any address
    /// not present reads as a short read (0 bytes), ending a probe.
    fn reader(mem: HashMap<usize, u64>) -> impl Fn(usize, &mut [u8]) -> crate::Result<usize> {
        move |addr: usize, buf: &mut [u8]| match mem.get(&addr) {
            Some(&word) if buf.len() >= 8 => {
                buf[..8].copy_from_slice(&word.to_le_bytes());
                Ok(8)
            }
            _ => Ok(0),
        }
    }

    #[test]
    fn null_value_is_null() {
        let idx = index();
        assert_eq!(
            classify_value(0, &idx, reader(HashMap::new())),
            PointerClass::Null
        );
    }

    #[test]
    fn unmapped_value_is_not_pointer() {
        let idx = index();
        assert_eq!(
            classify_value(0x9999, &idx, reader(HashMap::new())),
            PointerClass::NotPointer
        );
    }

    #[test]
    fn executable_value_is_code_ptr() {
        let idx = index();
        assert_eq!(
            classify_value(EXEC_BASE as u64, &idx, reader(HashMap::new())),
            PointerClass::CodePtr
        );
    }

    #[test]
    fn plain_data_value_is_data_ptr() {
        let idx = index();
        // A data slot whose contents are *not* code pointers (they read as 0 /
        // short) is a plain data pointer.
        assert_eq!(
            classify_value(DATA_BASE as u64, &idx, reader(HashMap::new())),
            PointerClass::DataPtr
        );
    }

    #[test]
    fn data_slot_pointing_at_code_table_is_vtable() {
        let idx = index();
        // The data slot at DATA_BASE holds a table of 3 code pointers, then a
        // non-code word — method_count should be 3.
        let mut mem = HashMap::new();
        mem.insert(DATA_BASE, (EXEC_BASE + 0x10) as u64);
        mem.insert(DATA_BASE + 8, (EXEC_BASE + 0x20) as u64);
        mem.insert(DATA_BASE + 16, (EXEC_BASE + 0x30) as u64);
        mem.insert(DATA_BASE + 24, 0x12345678); // not a code address → ends run
        assert_eq!(
            classify_value(DATA_BASE as u64, &idx, reader(mem)),
            PointerClass::VTablePtr { method_count: 3 }
        );
    }

    #[test]
    fn single_code_pointer_in_data_is_not_a_vtable() {
        let idx = index();
        // Only one leading code pointer (< MIN_VTABLE_METHODS) → plain data ptr.
        let mut mem = HashMap::new();
        mem.insert(DATA_BASE, (EXEC_BASE + 0x10) as u64);
        assert_eq!(
            classify_value(DATA_BASE as u64, &idx, reader(mem)),
            PointerClass::DataPtr
        );
    }

    #[test]
    fn unaligned_data_pointer_is_never_a_vtable() {
        let idx = index();
        // Even if the (unaligned) slot would point at code pointers, an unaligned
        // pointer is rejected as a vtable candidate up front.
        let mut mem = HashMap::new();
        mem.insert(DATA_BASE + 1, (EXEC_BASE + 0x10) as u64);
        mem.insert(DATA_BASE + 9, (EXEC_BASE + 0x20) as u64);
        assert_eq!(
            classify_value((DATA_BASE + 1) as u64, &idx, reader(mem)),
            PointerClass::DataPtr
        );
    }
}
