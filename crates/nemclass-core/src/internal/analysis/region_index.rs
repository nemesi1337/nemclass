//! Fast "what is at this address?" lookups over a target's memory map.
//!
//! [`RegionIndex`] pre-sorts a target's [`Section`]s into non-overlapping ranges
//! so a single address can be classified — unmapped / data / executable, and
//! which module it belongs to — in `O(log n)` via binary search. It is the
//! shared substrate the pointer classifier and the memory dissector build on:
//! given a pointer value read from memory, "does it point at code, at data, or
//! at nothing?" is exactly a [`RegionIndex::classify`] call.
//!
//! The pure [`RegionIndex::from_sections`] constructor is platform-neutral and
//! unit-tested without a live process; the [`RegionIndex::from_pid`] convenience
//! (which parses `/proc/<pid>/maps`) is Linux-gated.

use crate::internal::process::{Protection, Section};

/// What kind of memory a given address falls in, as answered by
/// [`RegionIndex::classify`].
///
/// The three cases mirror ReClass.NET's pointer heuristics: an address is either
/// outside every mapping ([`Unmapped`]), inside an executable mapping (likely a
/// code pointer / vtable entry), or inside a non-executable mapping (data).
///
/// [`Unmapped`]: AddrClass::Unmapped
#[derive(Debug, Clone, PartialEq)]
pub enum AddrClass {
    /// The address is not inside any known mapping.
    Unmapped,
    /// The address is inside a readable, non-executable mapping. `module` is the
    /// backing module file name for image mappings, `None` for anonymous ones.
    Data {
        /// Backing module file name, if the covering section is file-backed.
        module: Option<String>,
    },
    /// The address is inside an executable mapping (a code page). `module` as in
    /// [`AddrClass::Data`].
    Executable {
        /// Backing module file name, if the covering section is file-backed.
        module: Option<String>,
    },
}

/// One resolved, sorted mapping in the index: a half-open range `[start, end)`
/// with its protection and (for image mappings) its backing module name.
#[derive(Debug, Clone)]
struct Range {
    start: usize,
    end: usize,
    prot: Protection,
    module: Option<String>,
}

/// A sorted, non-overlapping view of a target's mappings for fast address
/// classification. Build one with [`RegionIndex::from_sections`] (pure) or
/// [`RegionIndex::from_pid`] (Linux, reads `/proc/<pid>/maps`).
#[derive(Debug, Clone, Default)]
pub struct RegionIndex {
    /// Ranges sorted by `start`. Zero-size sections are dropped on construction,
    /// so every range is a real half-open interval and binary search is exact.
    ranges: Vec<Range>,
}

impl RegionIndex {
    /// Builds an index from a slice of [`Section`]s. **Pure**: it only sorts and
    /// stores, so it is fully unit-testable without a process.
    ///
    /// Zero-size sections are skipped. Sections are sorted by base address; if
    /// the caller's sections overlap (they shouldn't for `/proc/<pid>/maps`,
    /// whose mappings are disjoint), the lower-`start` range wins a lookup on the
    /// overlap because [`classify`] returns the first covering range — but the
    /// binary search below relies on ranges being non-overlapping for its
    /// candidate step, so overlaps only ever *under*-report, never panic.
    ///
    /// [`classify`]: RegionIndex::classify
    pub fn from_sections(sections: &[Section]) -> Self {
        let mut ranges: Vec<Range> = sections
            .iter()
            .filter(|s| s.size != 0)
            .map(|s| Range {
                start: s.base,
                end: s.base.saturating_add(s.size),
                prot: s.prot,
                module: s.module.clone(),
            })
            .collect();

        ranges.sort_by_key(|r| r.start);

        RegionIndex { ranges }
    }

    /// Builds an index from a live process's memory map by parsing
    /// `/proc/<pid>/maps`. The Linux convenience wrapper around the pure
    /// [`RegionIndex::from_sections`] core.
    #[cfg(target_os = "linux")]
    pub fn from_pid(pid: crate::Pid) -> crate::Result<Self> {
        let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
            .map_err(|_| crate::Error::ProcessDied)?;
        Ok(Self::from_sections(&crate::internal::process::parse_maps_sections(&maps)))
    }

    /// Finds the range covering `addr`, if any, via binary search.
    ///
    /// Ranges are sorted by `start`, so `partition_point` gives the index one
    /// past the last range whose `start <= addr`; that candidate is the only
    /// range that can contain `addr` (ranges are non-overlapping). We then check
    /// `addr < end` to reject an address that sits in a gap after the candidate.
    fn covering(&self, addr: usize) -> Option<&Range> {
        let idx = self.ranges.partition_point(|r| r.start <= addr);
        if idx == 0 {
            return None;
        }
        let candidate = &self.ranges[idx - 1];
        (addr < candidate.end).then_some(candidate)
    }

    /// Classifies `addr` as unmapped, data, or executable — with the backing
    /// module name for mapped cases. `O(log n)` in the number of ranges.
    pub fn classify(&self, addr: usize) -> AddrClass {
        match self.covering(addr) {
            None => AddrClass::Unmapped,
            Some(r) if r.prot.execute() => AddrClass::Executable {
                module: r.module.clone(),
            },
            Some(r) => AddrClass::Data {
                module: r.module.clone(),
            },
        }
    }

    /// `true` if `addr` falls inside an executable mapping. Convenience over
    /// [`RegionIndex::classify`] for the common code-pointer check.
    pub fn is_executable(&self, addr: usize) -> bool {
        self.covering(addr).is_some_and(|r| r.prot.execute())
    }

    /// `true` if `addr` falls inside *any* mapping (i.e. is not
    /// [`AddrClass::Unmapped`]).
    pub fn is_mapped(&self, addr: usize) -> bool {
        self.covering(addr).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::process::SectionType;

    /// Builds a hand-made section for the tests. `exec` toggles the X bit on top
    /// of R so we exercise both the data and executable classification arms.
    fn section(base: usize, size: usize, exec: bool, module: Option<&str>) -> Section {
        Section {
            base,
            size,
            prot: if exec { Protection::RX } else { Protection::R },
            kind: if module.is_some() {
                SectionType::Image
            } else {
                SectionType::Mapped
            },
            module: module.map(str::to_owned),
        }
    }

    /// A synthetic map: an executable code section, a data section, and a gap in
    /// between plus tails on either side that must classify as unmapped.
    fn index() -> RegionIndex {
        RegionIndex::from_sections(&[
            // Deliberately out of order to prove the constructor sorts.
            section(0x3000, 0x1000, false, None),           // [0x3000, 0x4000) data
            section(0x1000, 0x1000, true, Some("app.exe")), // [0x1000, 0x2000) exec
        ])
    }

    #[test]
    fn classify_executable_range() {
        let idx = index();
        assert_eq!(
            idx.classify(0x1000),
            AddrClass::Executable {
                module: Some("app.exe".to_owned())
            }
        );
        // Mid-range and last byte are still executable.
        assert!(idx.is_executable(0x1800));
        assert!(idx.is_executable(0x1FFF));
        assert!(idx.is_mapped(0x1FFF));
    }

    #[test]
    fn classify_data_range() {
        let idx = index();
        assert_eq!(idx.classify(0x3000), AddrClass::Data { module: None });
        assert!(!idx.is_executable(0x3500));
        assert!(idx.is_mapped(0x3500));
    }

    #[test]
    fn classify_unmapped_below_between_and_above() {
        let idx = index();
        // Below the lowest range.
        assert_eq!(idx.classify(0x0), AddrClass::Unmapped);
        assert_eq!(idx.classify(0xFFF), AddrClass::Unmapped);
        // In the gap between the exec and data ranges.
        assert_eq!(idx.classify(0x2000), AddrClass::Unmapped);
        assert_eq!(idx.classify(0x2FFF), AddrClass::Unmapped);
        // Above the highest range.
        assert_eq!(idx.classify(0x4000), AddrClass::Unmapped);
        assert_eq!(idx.classify(0x9999), AddrClass::Unmapped);

        assert!(!idx.is_mapped(0x2000));
    }

    #[test]
    fn range_boundaries_are_half_open() {
        let idx = index();
        // start is inclusive ...
        assert!(idx.is_mapped(0x1000));
        // ... end is exclusive: 0x2000 is the first byte *past* the exec range.
        assert_eq!(idx.classify(0x2000), AddrClass::Unmapped);
    }

    #[test]
    fn zero_size_sections_are_dropped() {
        let idx = RegionIndex::from_sections(&[section(0x1000, 0, false, None)]);
        assert!(!idx.is_mapped(0x1000));
        assert_eq!(idx.classify(0x1000), AddrClass::Unmapped);
    }
}
