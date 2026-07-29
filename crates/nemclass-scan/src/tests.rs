//! Scanner proof via a mock target — no live process.
//!
//! Every test drives the engine through [`MockTarget`] (an in-memory buffer plus
//! fabricated regions), so the whole scan pipeline (first scan, next scan,
//! change-relative filtering, AOB wildcards, region-boundary safety, freeze)
//! runs deterministically on any platform.

use crate::{
    BytePattern, FilterState, FreezeSet, MockTarget, Region, RegionFilter, ScanCompareType,
    ScanValueType, Scanner, SectionFilter, WriteTarget,
};
use nemclass_core::{Protection, Section, SectionType};

/// Base address the mock buffer is mapped at (arbitrary, non-zero).
const BASE: usize = 0x1_0000;

/// Builds a 32-byte buffer with a little-endian `i32` written at `offset`.
fn buf_with_i32(offset: usize, value: i32) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    buf
}

/// Parses a needle for `ty` from `text`, panicking on a parse error.
fn needle(ty: ScanValueType, text: &str) -> crate::Needle {
    ty.parse_needle(text).expect("parse needle")
}

#[test]
fn first_scan_exact_i32_finds_address() {
    // 1337 at offset 8 and again at offset 20.
    let mut buf = buf_with_i32(8, 1337);
    buf[20..24].copy_from_slice(&1337i32.to_le_bytes());
    let target = MockTarget::new(BASE, buf);

    let mut scanner = Scanner::new(target, ScanValueType::I32);
    let results = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "1337")))
        .unwrap();

    let addrs: Vec<usize> = results.iter().map(|r| r.address).collect();
    assert_eq!(addrs, vec![BASE + 8, BASE + 20]);
    // The captured previous bytes are the value we searched for.
    assert_eq!(results.iter().next().unwrap().current, 1337i32.to_le_bytes());
}

#[test]
fn first_scan_no_matches_is_empty() {
    let target = MockTarget::new(BASE, vec![0u8; 32]);
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    let results = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "1337")))
        .unwrap();
    assert!(results.is_empty());
    assert_eq!(results.len(), 0);
}

#[test]
fn next_scan_changed_and_unchanged() {
    let buf = buf_with_i32(8, 100);
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::I32);

    // First scan: exact 100 -> one match at offset 8.
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "100")))
        .unwrap();
    assert_eq!(scanner.results().len(), 1);

    // Mutate the target: change the value at offset 8 to 250.
    scanner.target().peek(BASE + 8, 4).unwrap(); // sanity: readable
    let target = scanner_target_mut(&mut scanner);
    target.buf_mut()[8..12].copy_from_slice(&250i32.to_le_bytes());

    // next_scan `Unchanged` should now drop it (no needle needed).
    let mut unchanged = clone_scanner_after_first(&scanner);
    let r = unchanged.next_scan(ScanCompareType::Unchanged, None).unwrap();
    assert!(r.is_empty(), "value changed, so Unchanged filters it out");

    // next_scan `Changed` keeps it.
    let r = scanner.next_scan(ScanCompareType::Changed, None).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r.iter().next().unwrap().address, BASE + 8);
}

#[test]
fn next_scan_increased_and_decreased() {
    let buf = buf_with_i32(4, 50);
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "50")))
        .unwrap();

    // Increase the value 50 -> 75.
    scanner_target_mut(&mut scanner).buf_mut()[4..8].copy_from_slice(&75i32.to_le_bytes());

    // Decreased should drop it; Increased should keep it.
    let mut dec = clone_scanner_after_first(&scanner);
    assert!(dec.next_scan(ScanCompareType::Decreased, None).unwrap().is_empty());

    let r = scanner.next_scan(ScanCompareType::Increased, None).unwrap();
    assert_eq!(r.len(), 1);

    // IncreasedBy 25 (exact delta) from the *new* baseline: bump 75 -> 100.
    scanner_target_mut(&mut scanner).buf_mut()[4..8].copy_from_slice(&100i32.to_le_bytes());
    let r = scanner
        .next_scan(ScanCompareType::IncreasedBy, Some(needle(ScanValueType::I32, "25")))
        .unwrap();
    assert_eq!(r.len(), 1, "100 == 75 + 25");

    // DecreasedBy 40: 100 -> 60.
    scanner_target_mut(&mut scanner).buf_mut()[4..8].copy_from_slice(&60i32.to_le_bytes());
    let r = scanner
        .next_scan(ScanCompareType::DecreasedBy, Some(needle(ScanValueType::I32, "40")))
        .unwrap();
    assert_eq!(r.len(), 1, "60 == 100 - 40");
}

#[test]
fn next_scan_between_filters() {
    // Two candidates: 10 at offset 0, 100 at offset 8.
    let mut buf = vec![0u8; 16];
    buf[0..4].copy_from_slice(&10i32.to_le_bytes());
    buf[8..12].copy_from_slice(&100i32.to_le_bytes());
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::I32);

    // Unknown first scan (accept all) so every aligned slot is a candidate.
    scanner.first_scan(ScanCompareType::Unknown, None).unwrap();

    // Between (5, 50): only the 10 qualifies (5 < 10 < 50); 100 and the zeros
    // outside the range are dropped.
    let n = needle(ScanValueType::I32, "5").with_upper_bound("50").unwrap();
    let r = scanner.next_scan(ScanCompareType::Between, Some(n)).unwrap();
    let vals: Vec<usize> = r.iter().map(|x| x.address).collect();
    assert_eq!(vals, vec![BASE]);
}

#[test]
fn unknown_first_scan_then_decreased() {
    // Unknown initial scan accepts every 4-byte slot; then a decrease filters.
    let mut buf = vec![0u8; 16];
    buf[0..4].copy_from_slice(&500i32.to_le_bytes());
    buf[8..12].copy_from_slice(&10i32.to_le_bytes());
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::I32);

    let first = scanner.first_scan(ScanCompareType::Unknown, None).unwrap();
    // 16 bytes, stride 4, Fast Scan alignment 4 -> offsets 0/4/8/12.
    assert_eq!(first.len(), 4);

    // Decrease only the value at offset 0 (500 -> 400); everything else stays.
    scanner_target_mut(&mut scanner).buf_mut()[0..4].copy_from_slice(&400i32.to_le_bytes());
    let r = scanner.next_scan(ScanCompareType::Decreased, None).unwrap();
    // Offset 0 is the only slot that decreased.
    assert!(r.iter().any(|x| x.address == BASE));
    // The untouched offset-8 value (10) did not decrease, so it is gone.
    assert!(!r.iter().any(|x| x.address == BASE + 8));
}

#[test]
fn float_exact_within_and_without_tolerance() {
    // 2.50 stored as f32 at offset 4.
    let mut buf = vec![0u8; 16];
    buf[4..8].copy_from_slice(&2.50f32.to_le_bytes());
    let target = MockTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::F32);

    // Within default tolerance (0.01): 2.505 matches 2.50.
    let r = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::F32, "2.505")))
        .unwrap();
    assert_eq!(r.len(), 1, "2.505 within default 0.01 tolerance of 2.50");

    // Outside tolerance: 2.60 does not match 2.50.
    let mut scanner2 = Scanner::new(scanner.into_target(), ScanValueType::F32);
    let r = scanner2
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::F32, "2.60")))
        .unwrap();
    assert!(r.is_empty(), "2.60 outside tolerance of 2.50");
}

#[test]
fn aob_wildcard_scan() {
    // Buffer contains 48 8B 05 D5 C3 somewhere.
    let mut buf = vec![0u8; 16];
    buf[6..11].copy_from_slice(&[0x48, 0x8B, 0x05, 0xD5, 0xC3]);
    let target = MockTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::Bytes);

    // Pattern with a full and a nibble wildcard: 48 8B ?? D? C3.
    let n = needle(ScanValueType::Bytes, "48 8B ?? D? C3");
    let r = scanner.first_scan(ScanCompareType::Exact, Some(n)).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r.iter().next().unwrap().address, BASE + 6);

    // A pattern that does not fit fails to match.
    let mut scanner2 = Scanner::new(scanner.into_target(), ScanValueType::Bytes);
    let n = needle(ScanValueType::Bytes, "48 8B FF");
    assert!(scanner2.first_scan(ScanCompareType::Exact, Some(n)).unwrap().is_empty());
}

#[test]
fn string_utf8_exact() {
    let mut buf = vec![0u8; 32];
    let text = b"hello";
    buf[10..15].copy_from_slice(text);
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::StringUtf8);
    let n = needle(ScanValueType::StringUtf8, "hello");
    let r = scanner.first_scan(ScanCompareType::Exact, Some(n)).unwrap();
    assert_eq!(r.len(), 1);
    assert_eq!(r.iter().next().unwrap().address, BASE + 10);
}

#[test]
fn stride_at_region_boundary_does_not_read_past() {
    // 32-byte buffer, but the region only covers the first 10 bytes. A value at
    // offset 8 (spanning 8..12) straddles the region edge and must NOT match,
    // because bytes 10..12 are outside the region.
    let mut buf = vec![0u8; 32];
    buf[8..12].copy_from_slice(&0x1122_3344i32.to_le_bytes());
    // A clean, fully-in-region value at offset 2.
    buf[2..6].copy_from_slice(&0x1122_3344i32.to_le_bytes());

    let regions = vec![Region::new(BASE, 10)];
    let target = MockTarget::with_regions(BASE, buf, regions);
    // Alignment 1 so both offsets are candidates and the assertion below is
    // about the region edge rather than about the Fast Scan lattice (offset 2
    // is not 4-aligned).
    let mut scanner = Scanner::new(target, ScanValueType::I32).with_alignment(1);

    let n = needle(ScanValueType::I32, "0x11223344");
    let r = scanner.first_scan(ScanCompareType::Exact, Some(n)).unwrap();
    let addrs: Vec<usize> = r.iter().map(|x| x.address).collect();
    // Only the in-region value at offset 2 is found; offset 8 spills past the
    // 10-byte region and is not read.
    assert_eq!(addrs, vec![BASE + 2]);
}

#[test]
fn multi_region_scan_across_chunks() {
    // Two disjoint regions with a matching value in each.
    let mut buf = vec![0u8; 64];
    buf[4..8].copy_from_slice(&7i32.to_le_bytes());
    buf[40..44].copy_from_slice(&7i32.to_le_bytes());
    let regions = vec![Region::new(BASE, 16), Region::new(BASE + 32, 16)];
    let target = MockTarget::with_regions(BASE, buf, regions);
    let mut scanner = Scanner::new(target, ScanValueType::I32);

    let n = needle(ScanValueType::I32, "7");
    let r = scanner.first_scan(ScanCompareType::Exact, Some(n)).unwrap();
    let addrs: Vec<usize> = r.iter().map(|x| x.address).collect();
    assert_eq!(addrs, vec![BASE + 4, BASE + 40]);
}

#[test]
fn undo_history_restores_previous_generation() {
    let buf = buf_with_i32(4, 42);
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::I32);

    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "42")))
        .unwrap();
    let after_first = scanner.results().len();
    assert!(!scanner.can_undo(), "one generation -> nothing to undo");

    // A next scan for a value it no longer equals -> empties results.
    let r = scanner
        .next_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "999")))
        .unwrap();
    assert!(r.is_empty());
    assert!(scanner.can_undo());

    // Undo restores the first-scan generation.
    assert!(scanner.undo());
    assert_eq!(scanner.results().len(), after_first);
    assert!(!scanner.can_undo());
}

#[test]
fn misuse_errors() {
    let mut scanner = Scanner::new(MockTarget::new(BASE, vec![0u8; 16]), ScanValueType::I32);

    // A change-relative compare on a first scan is invalid.
    assert!(scanner.first_scan(ScanCompareType::Increased, None).is_err());
    // Exact without a needle is invalid.
    assert!(scanner.first_scan(ScanCompareType::Exact, None).is_err());
    // A next scan before any first scan is invalid.
    assert!(scanner.next_scan(ScanCompareType::Changed, None).is_err());
    // A needle of the wrong type is rejected.
    let wrong = needle(ScanValueType::I16, "5");
    assert!(scanner.first_scan(ScanCompareType::Exact, Some(wrong)).is_err());
}

#[test]
fn freeze_set_applies_to_write_target() {
    // A hand-rolled interior-mutable write target for the freeze test (the
    // shared-ref `MockTarget::write` is a no-op by design).
    let target = CellTarget::new(BASE, vec![0u8; 16]);

    let mut freeze = FreezeSet::new();
    freeze.set(BASE + 4, 99i32.to_le_bytes().to_vec());
    assert_eq!(freeze.len(), 1);

    let report = freeze.apply(&target);
    assert_eq!(report.written, 1);
    assert!(report.all_written());
    assert!(report.problem().is_none());
    assert_eq!(target.peek(BASE + 4, 4), 99i32.to_le_bytes());

    // Simulate the target changing the value, then re-apply pins it back.
    target.poke(BASE + 4, &0i32.to_le_bytes());
    assert_eq!(target.peek(BASE + 4, 4), 0i32.to_le_bytes());
    freeze.apply(&target);
    assert_eq!(target.peek(BASE + 4, 4), 99i32.to_le_bytes());

    // Removing the entry stops it being re-pinned.
    freeze.remove(BASE + 4);
    assert!(freeze.is_empty());
}

#[test]
fn aob_pattern_direct_api() {
    // The BytePattern parser is also usable directly.
    let p = BytePattern::parse("DE AD ?? EF").unwrap();
    assert_eq!(p.len(), 4);
    assert!(p.has_wildcards());
    assert!(p.matches_at(&[0xDE, 0xAD, 0x00, 0xEF], 0));
    assert!(p.matches_at(&[0xDE, 0xAD, 0xFF, 0xEF], 0));
    assert!(!p.matches_at(&[0xDE, 0xAD, 0xFF, 0xEE], 0));
}

// --- test helpers -------------------------------------------------------

/// Reaches the mutable `MockTarget` inside a `Scanner` for tests that mutate the
/// buffer between a first and next scan.
fn scanner_target_mut(scanner: &mut Scanner<MockTarget>) -> &mut MockTarget {
    scanner.target_mut()
}

/// Clones the scanner's current target and results into a fresh scanner sitting
/// at the same "after first scan" state, so a test can try two different next
/// scans from one baseline.
fn clone_scanner_after_first(scanner: &Scanner<MockTarget>) -> Scanner<MockTarget> {
    scanner.clone_for_test()
}

/// An interior-mutable target for the freeze test and for the change-relative
/// next-scan tests, which need to mutate the buffer *between* two scans through
/// the shared reference the `Scanner` holds.
///
/// A `Mutex`, not a `RefCell`: `ScanTarget` is `Sync` so a first scan can shard
/// its regions across threads, and a `RefCell` is precisely what that forbids.
struct CellTarget {
    base: usize,
    buf: std::sync::Mutex<Vec<u8>>,
}

impl Clone for CellTarget {
    fn clone(&self) -> Self {
        Self { base: self.base, buf: std::sync::Mutex::new(self.lock().clone()) }
    }
}

impl CellTarget {
    fn new(base: usize, buf: Vec<u8>) -> Self {
        Self {
            base,
            buf: std::sync::Mutex::new(buf),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<u8>> {
        self.buf.lock().expect("cell target buffer poisoned")
    }

    fn peek(&self, addr: usize, len: usize) -> Vec<u8> {
        let off = addr - self.base;
        self.lock()[off..off + len].to_vec()
    }

    fn poke(&self, addr: usize, bytes: &[u8]) {
        let off = addr - self.base;
        self.lock()[off..off + bytes.len()].copy_from_slice(bytes);
    }
}

impl crate::ScanTarget for CellTarget {
    fn regions(&self) -> crate::Result<Vec<Region>> {
        Ok(vec![Region::new(self.base, self.lock().len())])
    }

    fn read(&self, addr: usize, buf: &mut [u8]) -> crate::Result<usize> {
        let off = addr - self.base;
        let b = self.lock();
        let n = buf.len().min(b.len().saturating_sub(off));
        buf[..n].copy_from_slice(&b[off..off + n]);
        Ok(n)
    }
}

impl WriteTarget for CellTarget {
    fn write(&self, addr: usize, buf: &[u8]) -> crate::Result<usize> {
        let off = addr - self.base;
        let mut b = self.lock();
        let n = buf.len().min(b.len().saturating_sub(off));
        b[off..off + n].copy_from_slice(&buf[..n]);
        Ok(n)
    }
}

// ── region filter: address-space scope ─────────────────────────────────────
//
// `RegionFilter` is pure, so these need no target at all. The end-to-end cases
// below then prove `first_scan` actually honours it.

/// Shorthand for the `(base, size)` pairs an assertion cares about.
fn spans(regions: &[Region]) -> Vec<(usize, usize)> {
    regions.iter().map(|r| (r.base, r.size)).collect()
}

#[test]
fn region_filter_default_is_identity() {
    let filter = RegionFilter::default();
    assert!(filter.is_unrestricted());
    let regions = vec![Region::new(0x1000, 0x1000), Region::new(0x8000, 0x400)];
    assert_eq!(filter.apply(&regions), regions);
}

#[test]
fn region_filter_window_clamps_head_and_tail() {
    let regions = vec![Region::new(0x1000, 0x1000)];
    let out = RegionFilter::window(0x1400, 0x1C00).apply(&regions);
    assert_eq!(spans(&out), vec![(0x1400, 0x800)]);
}

#[test]
fn region_filter_drops_non_overlapping_and_touching_windows() {
    let regions = vec![Region::new(0x1000, 0x1000)];
    // Wholly below, wholly above.
    assert!(RegionFilter::window(0x100, 0x200).apply(&regions).is_empty());
    assert!(RegionFilter::window(0x9000, 0x9100).apply(&regions).is_empty());
    // The window is half-open, so `stop == region.base` selects nothing.
    assert!(RegionFilter::window(0x0, 0x1000).apply(&regions).is_empty());
    // ...and `start == region.end()` likewise.
    assert!(RegionFilter::window(0x2000, 0x3000).apply(&regions).is_empty());
}

#[test]
fn region_filter_inverted_window_is_empty() {
    let regions = vec![Region::new(0x1000, 0x1000)];
    assert!(RegionFilter::window(0x2000, 0x1000).apply(&regions).is_empty());
    // Equal bounds are an empty half-open range, not "everything".
    assert!(RegionFilter::window(0x1500, 0x1500).apply(&regions).is_empty());
}

#[test]
fn region_filter_include_splits_one_region_into_many() {
    let regions = vec![Region::new(0x1000, 0x1000)];
    let out = RegionFilter::default()
        .with_include(vec![Region::new(0x1100, 0x100), Region::new(0x1800, 0x100)])
        .apply(&regions);
    assert_eq!(spans(&out), vec![(0x1100, 0x100), (0x1800, 0x100)]);
}

#[test]
fn region_filter_include_outside_window_is_dropped() {
    let regions = vec![Region::new(0x1000, 0x1000)];
    let out = RegionFilter::window(0x1000, 0x1400)
        .with_include(vec![Region::new(0x1800, 0x100)])
        .apply(&regions);
    assert!(out.is_empty(), "an include span outside the window selects nothing");
}

#[test]
fn region_filter_overlapping_includes_do_not_duplicate() {
    // Two selected modules whose spans overlap must not make the same address
    // match twice — that would give duplicate rows and an inflated count.
    let regions = vec![Region::new(0x1000, 0x1000)];
    let out = RegionFilter::default()
        .with_include(vec![Region::new(0x1000, 0x400), Region::new(0x1200, 0x400)])
        .apply(&regions);
    assert_eq!(spans(&out), vec![(0x1000, 0x600)]);

    // Exactly abutting spans coalesce too, and order doesn't matter.
    let out = RegionFilter::default()
        .with_include(vec![Region::new(0x1400, 0x400), Region::new(0x1000, 0x400)])
        .apply(&regions);
    assert_eq!(spans(&out), vec![(0x1000, 0x800)]);
}

#[test]
fn region_filter_never_emits_zero_sized_regions() {
    let regions = vec![Region::new(0x1000, 0x1000), Region::new(0x4000, 0)];
    let out = RegionFilter::window(0x1000, 0x5000)
        .with_include(vec![
            Region::new(0x1000, 0),      // zero-size include span
            Region::new(0x2000, 0x100),  // starts exactly at the region's end
            Region::new(0x0F00, 0x100),  // ends exactly at the region's base
            Region::new(0x1100, 0x100),
        ])
        .apply(&regions);
    assert!(out.iter().all(|r| r.size > 0), "got a zero-sized region: {out:?}");
    assert_eq!(spans(&out), vec![(0x1100, 0x100)]);
}

#[test]
fn region_filter_saturates_at_top_of_address_space() {
    let regions = vec![Region::new(usize::MAX - 8, 16)];
    // Region::end() saturates, so the region is effectively [MAX-8, MAX).
    assert_eq!(spans(&RegionFilter::default().apply(&regions)), vec![(usize::MAX - 8, 16)]);
    let out = RegionFilter::window(usize::MAX - 4, usize::MAX).apply(&regions);
    assert_eq!(spans(&out), vec![(usize::MAX - 4, 4)]);
}

#[test]
fn region_filter_output_is_sorted_by_base() {
    let regions = vec![Region::new(0x8000, 0x100), Region::new(0x1000, 0x100)];
    let out = RegionFilter::window(0, usize::MAX - 1).apply(&regions);
    assert_eq!(spans(&out), vec![(0x1000, 0x100), (0x8000, 0x100)]);
}

// ── region filter: end-to-end through the scanner ──────────────────────────

/// The `multi_region_scan_across_chunks` fixture: `7i32` at `BASE+4` and
/// `BASE+40`, in two disjoint 16-byte regions.
fn two_region_target() -> MockTarget {
    let mut buf = vec![0u8; 64];
    buf[4..8].copy_from_slice(&7i32.to_le_bytes());
    buf[40..44].copy_from_slice(&7i32.to_le_bytes());
    let regions = vec![Region::new(BASE, 16), Region::new(BASE + 32, 16)];
    MockTarget::with_regions(BASE, buf, regions)
}

fn scan_for_seven(scanner: &mut Scanner<MockTarget>) -> Vec<usize> {
    let n = needle(ScanValueType::I32, "7");
    scanner
        .first_scan(ScanCompareType::Exact, Some(n))
        .unwrap()
        .iter()
        .map(|r| r.address)
        .collect()
}

#[test]
fn first_scan_respects_region_filter_window() {
    let mut scanner = Scanner::new(two_region_target(), ScanValueType::I32)
        .with_region_filter(RegionFilter::window(BASE + 32, usize::MAX));
    assert_eq!(scan_for_seven(&mut scanner), vec![BASE + 40]);
    assert_eq!(scanner.scanned_region_count(), 1);
}

#[test]
fn first_scan_respects_include_list() {
    let mut scanner = Scanner::new(two_region_target(), ScanValueType::I32)
        .with_region_filter(
            RegionFilter::default().with_include(vec![Region::new(BASE + 32, 16)]),
        );
    assert_eq!(scan_for_seven(&mut scanner), vec![BASE + 40]);
}

#[test]
fn first_scan_window_clamp_drops_straddling_match() {
    // The value at BASE+4 occupies 4..8; a window starting at BASE+6 truncates
    // the region under it, so it is not found. This mirrors ReClass.NET and is
    // deliberate — documenting it here so nobody "fixes" it later.
    let mut scanner = Scanner::new(two_region_target(), ScanValueType::I32)
        .with_region_filter(RegionFilter::window(BASE + 6, BASE + 16));
    assert!(scan_for_seven(&mut scanner).is_empty());
}

#[test]
fn first_scan_reports_zero_scanned_regions_when_filter_excludes_everything() {
    // A window over the gap between the two regions. The UI keys its "scope
    // matched no memory" message off this count, so it must stay accurate —
    // an empty result set alone is indistinguishable from "value not found".
    let mut scanner = Scanner::new(two_region_target(), ScanValueType::I32)
        .with_region_filter(RegionFilter::window(BASE + 16, BASE + 32));
    assert!(scan_for_seven(&mut scanner).is_empty());
    assert_eq!(scanner.scanned_region_count(), 0);
}

#[test]
fn next_scan_ignores_region_filter() {
    // Scope is a first-scan concept: a next scan re-reads the previous match
    // addresses and must not re-filter them.
    let mut scanner = Scanner::new(two_region_target(), ScanValueType::I32);
    assert_eq!(scan_for_seven(&mut scanner), vec![BASE + 4, BASE + 40]);

    scanner.set_region_filter(RegionFilter::window(BASE + 32, usize::MAX));
    let after = scanner
        .next_scan(ScanCompareType::Unchanged, None)
        .unwrap()
        .iter()
        .map(|r| r.address)
        .collect::<Vec<_>>();
    assert_eq!(after, vec![BASE + 4, BASE + 40]);
}

#[test]
fn filtered_region_narrower_than_stride_yields_no_match() {
    // A 3-byte window can't hold an i32; the walk must come up empty, not panic.
    let mut scanner = Scanner::new(two_region_target(), ScanValueType::I32)
        .with_region_filter(RegionFilter::window(BASE + 4, BASE + 7));
    assert!(scan_for_seven(&mut scanner).is_empty());
    assert_eq!(scanner.scanned_region_count(), 1);
}

// ── section filter: protection and memory type ─────────────────────────────

fn section(kind: SectionType, prot: Protection) -> Section {
    Section { base: 0x1000, size: 0x1000, prot, kind, module: None }
}

#[test]
fn filter_state_tri_state_truth_table() {
    assert!(FilterState::Yes.accepts(true) && !FilterState::Yes.accepts(false));
    assert!(!FilterState::No.accepts(true) && FilterState::No.accepts(false));
    assert!(FilterState::Any.accepts(true) && FilterState::Any.accepts(false));
    // `Any` is the do-nothing default.
    assert_eq!(FilterState::default(), FilterState::Any);
}

#[test]
fn section_filter_default_matches_previous_writable_only_behaviour() {
    let filter = SectionFilter::default();
    // A writable heap mapping — what a value scan is looking for.
    assert!(filter.keep(&section(SectionType::Private, Protection::RW)));
    // A module's writable data section.
    assert!(filter.keep(&section(SectionType::Image, Protection::RW)));
    // Executable, non-writable code is skipped.
    assert!(!filter.keep(&section(SectionType::Image, Protection::RX)));
    // Shared memory is off by default (ReClass.NET's `ScanMappedMemory = false`).
    assert!(!filter.keep(&section(SectionType::Mapped, Protection::RW)));
    // Copy-on-write is excluded by default.
    assert!(!filter.keep(&section(SectionType::Image, Protection::RW | Protection::COW)));
    // An unclassifiable mapping is never scanned.
    assert!(!filter.keep(&section(SectionType::Unknown, Protection::RW)));
}

#[test]
fn section_filter_memory_type_toggles_are_independent() {
    let only_private = SectionFilter { scan_image: false, ..SectionFilter::default() };
    assert!(only_private.keep(&section(SectionType::Private, Protection::RW)));
    assert!(!only_private.keep(&section(SectionType::Image, Protection::RW)));

    let with_shared = SectionFilter { scan_mapped: true, ..SectionFilter::default() };
    assert!(with_shared.keep(&section(SectionType::Mapped, Protection::RW)));

    // No type ticked: nothing passes, whatever the protection.
    let none = SectionFilter {
        scan_private: false,
        scan_image: false,
        scan_mapped: false,
        ..SectionFilter::default()
    };
    assert!(!none.keep(&section(SectionType::Private, Protection::RW)));
}

#[test]
fn section_filter_protection_tri_states_apply_independently() {
    // Executable-only, ignoring writability: how you'd scan a module's code.
    let code = SectionFilter {
        writable: FilterState::Any,
        executable: FilterState::Yes,
        ..SectionFilter::default()
    };
    assert!(code.keep(&section(SectionType::Image, Protection::RX)));
    assert!(!code.keep(&section(SectionType::Image, Protection::RW)));

    // Explicitly asking for copy-on-write inverts the default.
    let cow = SectionFilter { copy_on_write: FilterState::Yes, ..SectionFilter::default() };
    assert!(cow.keep(&section(SectionType::Image, Protection::RW | Protection::COW)));
    assert!(!cow.keep(&section(SectionType::Image, Protection::RW)));

    // Fully permissive: everything with a known type passes.
    let any = SectionFilter {
        writable: FilterState::Any,
        executable: FilterState::Any,
        copy_on_write: FilterState::Any,
        scan_private: true,
        scan_image: true,
        scan_mapped: true,
    };
    assert!(any.keep(&section(SectionType::Mapped, Protection::empty())));
    assert!(!any.keep(&section(SectionType::Unknown, Protection::RW)));
}

// ── next scan: the compares that used to be silently wrong ─────────────────

/// Writes a little-endian `f32` at `offset` in a 32-byte buffer.
fn buf_with_f32(offset: usize, value: f32) -> Vec<u8> {
    let mut buf = vec![0u8; 32];
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    buf
}

#[test]
fn next_scan_unknown_is_rejected_and_keeps_results() {
    let mut scanner = Scanner::new(
        MockTarget::new(BASE, buf_with_i32(4, 7)),
        ScanValueType::I32,
    );
    let found = scanner.first_scan(ScanCompareType::Unknown, None).unwrap().len();
    assert!(found > 0);

    // `Unknown` is a first-scan baseline. On a next scan it used to fall through
    // to a catch-all `false` and silently drop every result.
    let err = scanner.next_scan(ScanCompareType::Unknown, None).unwrap_err();
    assert!(matches!(err, crate::ScanError::CompareIsFirstScanOnly(_)));
    assert_eq!(
        scanner.results().len(),
        found,
        "a rejected next scan must not touch the result set"
    );
    assert!(!scanner.can_undo(), "no generation should have been pushed");
}

#[test]
fn next_scan_signed_increase_across_zero() {
    // -1 -> 1 is an increase for an i32, but 0xFFFFFFFF > 0x00000001 as an
    // unsigned magnitude, so the old byte-magnitude path dropped it.
    let target = CellTarget::new(BASE, buf_with_i32(4, -1));
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "-1")))
        .unwrap();
    assert_eq!(scanner.results().len(), 1);

    scanner.target().poke(BASE + 4, &1i32.to_le_bytes());
    let r = scanner.next_scan(ScanCompareType::Increased, None).unwrap();
    assert_eq!(r.len(), 1, "-1 -> 1 must count as Increased for a signed type");
}

#[test]
fn next_scan_signed_decrease_across_zero() {
    let target = CellTarget::new(BASE, buf_with_i32(4, 1));
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "1")))
        .unwrap();

    scanner.target().poke(BASE + 4, &(-1i32).to_le_bytes());
    let r = scanner.next_scan(ScanCompareType::Decreased, None).unwrap();
    assert_eq!(r.len(), 1, "1 -> -1 must count as Decreased for a signed type");
}

#[test]
fn next_scan_unsigned_still_uses_unsigned_order() {
    // The same bytes under U32: 0xFFFFFFFF -> 1 is a *decrease*.
    let target = CellTarget::new(BASE, buf_with_i32(4, -1));
    let mut scanner = Scanner::new(target, ScanValueType::U32);
    scanner
        .first_scan(
            ScanCompareType::Exact,
            Some(needle(ScanValueType::U32, "4294967295")),
        )
        .unwrap();
    assert_eq!(scanner.results().len(), 1);

    scanner.target().poke(BASE + 4, &1u32.to_le_bytes());
    assert_eq!(
        scanner
            .clone_for_test()
            .next_scan(ScanCompareType::Increased, None)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        scanner.next_scan(ScanCompareType::Decreased, None).unwrap().len(),
        1
    );
}

#[test]
fn next_scan_float_order_is_not_bitwise() {
    // -1.5 -> -0.5 is an increase, but 0xBFC00000 -> 0xBF000000 is a decrease
    // as a raw magnitude.
    let target = CellTarget::new(BASE, buf_with_f32(8, -1.5));
    let mut scanner = Scanner::new(target, ScanValueType::F32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::F32, "-1.5")))
        .unwrap();
    assert_eq!(scanner.results().len(), 1);

    scanner.target().poke(BASE + 8, &(-0.5f32).to_le_bytes());
    let r = scanner.next_scan(ScanCompareType::Increased, None).unwrap();
    assert_eq!(r.len(), 1, "-1.5 -> -0.5 must count as Increased for a float");
}

#[test]
fn next_scan_float_unchanged_tolerates_ulp() {
    // A 1-ULP wobble is not a change: the needle-less path now uses the same
    // tolerance the needle-ful one always did, instead of byte equality.
    let start = 3.25f32;
    let target = CellTarget::new(BASE, buf_with_f32(0, start));
    let mut scanner = Scanner::new(target, ScanValueType::F32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::F32, "3.25")))
        .unwrap();

    let nudged = f32::from_bits(start.to_bits() + 1);
    assert_ne!(nudged.to_le_bytes(), start.to_le_bytes());
    scanner.target().poke(BASE, &nudged.to_le_bytes());

    assert_eq!(
        scanner
            .clone_for_test()
            .next_scan(ScanCompareType::Changed, None)
            .unwrap()
            .len(),
        0,
        "a 1-ULP wobble is not a Changed match"
    );
    assert_eq!(
        scanner.next_scan(ScanCompareType::Unchanged, None).unwrap().len(),
        1
    );
}

// ── next scan: unreadable addresses ────────────────────────────────────────

/// A target whose `read` fails for a chosen set of addresses, modelling memory
/// freed between two scans. `MockTarget` cannot express this — it returns
/// `Ok(0)` out of range rather than an error.
#[derive(Clone)]
struct FailingTarget {
    base: usize,
    buf: Vec<u8>,
    poisoned: Vec<usize>,
}

impl crate::ScanTarget for FailingTarget {
    fn regions(&self) -> nemclass_core::Result<Vec<Region>> {
        Ok(vec![Region::new(self.base, self.buf.len())])
    }

    fn read(&self, addr: usize, buf: &mut [u8]) -> nemclass_core::Result<usize> {
        if self.poisoned.contains(&addr) {
            return Err(nemclass_core::Error::ProcessNotFound);
        }
        let off = addr - self.base;
        let n = buf.len().min(self.buf.len().saturating_sub(off));
        buf[..n].copy_from_slice(&self.buf[off..off + n]);
        Ok(n)
    }
}

#[test]
fn next_scan_skips_unreadable_addresses() {
    // Two matches; the first address is unmapped by the time the next scan runs.
    let mut buf = buf_with_i32(4, 55);
    buf[12..16].copy_from_slice(&55i32.to_le_bytes());
    let target = FailingTarget {
        base: BASE,
        buf,
        poisoned: vec![],
    };

    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "55")))
        .unwrap();
    assert_eq!(scanner.results().len(), 2);

    scanner.target_mut().poisoned = vec![BASE + 4];
    let r = scanner
        .next_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "55")))
        .unwrap();

    assert_eq!(r.len(), 1, "one dead address must not take the survivor with it");
    assert_eq!(r.iter().next().unwrap().address, BASE + 12);
    assert_eq!(scanner.last_scan_stats().unreadable, 1);
    assert_eq!(scanner.last_scan_stats().scanned, 2);
}

#[test]
fn next_scan_all_unreadable_is_an_error_not_an_empty_result() {
    let target = FailingTarget {
        base: BASE,
        buf: buf_with_i32(4, 55),
        poisoned: vec![],
    };
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "55")))
        .unwrap();
    let before = scanner.results().len();

    scanner.target_mut().poisoned = vec![BASE + 4];
    let err = scanner
        .next_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "55")))
        .unwrap_err();

    assert!(matches!(err, crate::ScanError::TargetUnreadable(_)));
    assert_eq!(
        scanner.results().len(),
        before,
        "a dead target must not look like a narrowing to zero"
    );
}

// ── value type changes mid-session ─────────────────────────────────────────

#[test]
fn set_value_type_rejects_a_width_change() {
    let mut scanner = Scanner::new(MockTarget::new(BASE, vec![0u8; 16]), ScanValueType::I32);
    assert!(!scanner.set_value_type(ScanValueType::I64));
    assert!(!scanner.set_value_type(ScanValueType::Bytes));
    assert_eq!(scanner.value_type(), ScanValueType::I32);
}

#[test]
fn set_value_type_accepts_same_width_reinterpretation() {
    let mut scanner = Scanner::new(MockTarget::new(BASE, vec![0u8; 16]), ScanValueType::I32);
    assert!(scanner.set_value_type(ScanValueType::F32));
    assert_eq!(scanner.value_type(), ScanValueType::F32);
    assert!(scanner.set_value_type(ScanValueType::U32));
    assert_eq!(scanner.value_type(), ScanValueType::U32);
}

// ── first-scan alignment and the result cap ────────────────────────────────

#[test]
fn alignment_defaults_to_the_type_width() {
    // 1337 written at offset 6, which is not 4-aligned: Fast Scan skips it.
    let mut buf = vec![0u8; 32];
    buf[6..10].copy_from_slice(&1337i32.to_le_bytes());
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::I32);

    let r = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "1337")))
        .unwrap();
    assert!(r.is_empty(), "a misaligned i32 is not a Fast Scan candidate");
}

#[test]
fn alignment_1_still_finds_unaligned_values() {
    let mut buf = vec![0u8; 32];
    buf[6..10].copy_from_slice(&1337i32.to_le_bytes());
    let mut scanner =
        Scanner::new(MockTarget::new(BASE, buf), ScanValueType::I32).with_alignment(1);

    let addrs: Vec<usize> = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "1337")))
        .unwrap()
        .iter()
        .map(|r| r.address)
        .collect();
    assert_eq!(addrs, vec![BASE + 6]);
}

#[test]
fn variable_width_types_stay_byte_granular() {
    // An AOB or an embedded string has no natural alignment, so the default
    // must not step by the needle's length.
    let mut buf = vec![0u8; 32];
    buf[7..10].copy_from_slice(&[0xDE, 0xAD, 0xBE]);
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::Bytes);

    let addrs: Vec<usize> = scanner
        .first_scan(
            ScanCompareType::Exact,
            Some(needle(ScanValueType::Bytes, "DE AD BE")),
        )
        .unwrap()
        .iter()
        .map(|r| r.address)
        .collect();
    assert_eq!(addrs, vec![BASE + 7]);
}

#[test]
fn unknown_baseline_lands_on_the_alignment_lattice() {
    let scanner_results = |align: usize| {
        let mut s =
            Scanner::new(MockTarget::new(BASE, vec![0u8; 64]), ScanValueType::I32)
                .with_alignment(align);
        s.first_scan(ScanCompareType::Unknown, None)
            .unwrap()
            .iter()
            .map(|r| r.address)
            .collect::<Vec<_>>()
    };

    // 64 bytes, stride 4: aligned candidates are 0,4,…,60.
    assert_eq!(scanner_results(4).len(), 16);
    assert!(scanner_results(4).iter().all(|a| (a - BASE).is_multiple_of(4)));
    // Byte-granular: 0..=60 inclusive.
    assert_eq!(scanner_results(1).len(), 61);
}

#[test]
fn result_limit_truncates_and_reports() {
    let mut scanner = Scanner::new(MockTarget::new(BASE, vec![0u8; 256]), ScanValueType::I32)
        .with_result_limit(10);

    let r = scanner.first_scan(ScanCompareType::Unknown, None).unwrap();
    assert_eq!(r.len(), 10);
    assert!(scanner.results_truncated());
}

#[test]
fn an_uncapped_scan_is_not_reported_as_truncated() {
    let mut scanner = Scanner::new(MockTarget::new(BASE, vec![0u8; 64]), ScanValueType::I32);
    scanner.first_scan(ScanCompareType::Unknown, None).unwrap();
    assert!(!scanner.results_truncated());
}

// ── the Current / Previous pair ────────────────────────────────────────────

#[test]
fn first_scan_previous_equals_current() {
    let mut scanner = Scanner::new(
        MockTarget::new(BASE, buf_with_i32(4, 42)),
        ScanValueType::I32,
    );
    let r = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "42")))
        .unwrap();
    let row = r.get(0).unwrap();
    assert_eq!(row.current, 42i32.to_le_bytes());
    assert_eq!(
        row.previous, 42i32.to_le_bytes(),
        "nothing preceded a first scan, so Previous shows the same value"
    );
}

#[test]
fn next_scan_previous_is_the_prior_generations_current() {
    // 500 -> 400 -> 300: after the second next scan, Previous must be 400, not
    // 500 and not 300.
    let target = CellTarget::new(BASE, buf_with_i32(4, 500));
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "500")))
        .unwrap();

    scanner.target().poke(BASE + 4, &400i32.to_le_bytes());
    scanner.next_scan(ScanCompareType::Decreased, None).unwrap();
    let row = scanner.results().get(0).unwrap();
    assert_eq!(row.current, 400i32.to_le_bytes());
    assert_eq!(row.previous, 500i32.to_le_bytes());

    scanner.target().poke(BASE + 4, &300i32.to_le_bytes());
    scanner.next_scan(ScanCompareType::Decreased, None).unwrap();
    let row = scanner.results().get(0).unwrap();
    assert_eq!(row.current, 300i32.to_le_bytes());
    assert_eq!(
        row.previous, 400i32.to_le_bytes(),
        "Previous is the generation before this one, not the original"
    );
}

#[test]
fn undo_restores_both_columns() {
    let target = CellTarget::new(BASE, buf_with_i32(4, 500));
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "500")))
        .unwrap();

    scanner.target().poke(BASE + 4, &400i32.to_le_bytes());
    scanner.next_scan(ScanCompareType::Decreased, None).unwrap();
    assert!(scanner.undo());

    let row = scanner.results().get(0).unwrap();
    assert_eq!(row.current, 500i32.to_le_bytes());
    assert_eq!(row.previous, 500i32.to_le_bytes());
}

#[test]
fn results_stride_round_trips_for_a_bytes_scan() {
    // A variable-width type carries the needle's length as the generation
    // stride, so the column store still slices correctly.
    let mut buf = vec![0u8; 32];
    buf[5..10].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
    let mut scanner = Scanner::new(MockTarget::new(BASE, buf), ScanValueType::Bytes);

    let r = scanner
        .first_scan(
            ScanCompareType::Exact,
            Some(needle(ScanValueType::Bytes, "11 22 33 44 55")),
        )
        .unwrap();
    assert_eq!(r.stride(), 5);
    let row = r.get(0).unwrap();
    assert_eq!(row.address, BASE + 5);
    assert_eq!(row.current, [0x11, 0x22, 0x33, 0x44, 0x55]);
}

// ── progress reporting and cancellation ────────────────────────────────────

#[test]
fn first_scan_reports_monotonic_progress() {
    // Big enough to cross the progress interval several times.
    let mut scanner = Scanner::new(
        MockTarget::new(BASE, vec![0u8; 200_000]),
        ScanValueType::I32,
    );

    let mut ticks: Vec<crate::ScanProgress> = Vec::new();
    scanner
        .first_scan_with(ScanCompareType::Unknown, None, &mut |p| {
            ticks.push(p);
            true
        })
        .unwrap();

    assert!(!ticks.is_empty(), "a 200 KiB scan must report progress");
    assert!(
        ticks.windows(2).all(|w| w[1].done >= w[0].done),
        "progress must never go backwards"
    );
    assert!(
        ticks.iter().all(|p| p.done <= p.total),
        "done must stay within total"
    );
    assert!(ticks.iter().all(|p| p.total > 0));
}

#[test]
fn a_cancelled_first_scan_leaves_the_results_untouched() {
    let mut scanner = Scanner::new(
        MockTarget::new(BASE, vec![0u8; 200_000]),
        ScanValueType::I32,
    );
    // Seed a session worth protecting.
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "0")))
        .unwrap();
    let before = scanner.results().len();
    assert!(before > 0);

    let err = scanner
        .first_scan_with(ScanCompareType::Unknown, None, &mut |_| false)
        .unwrap_err();

    assert!(matches!(err, crate::ScanError::Cancelled));
    assert_eq!(
        scanner.results().len(),
        before,
        "stopping a scan must not push a partial generation"
    );
}

#[test]
fn a_cancelled_next_scan_leaves_the_results_untouched() {
    let mut scanner = Scanner::new(
        MockTarget::new(BASE, vec![0u8; 200_000]),
        ScanValueType::I32,
    );
    scanner.first_scan(ScanCompareType::Unknown, None).unwrap();
    let before = scanner.results().len();

    let err = scanner
        .next_scan_with(ScanCompareType::Unchanged, None, &mut |_| false)
        .unwrap_err();

    assert!(matches!(err, crate::ScanError::Cancelled));
    assert_eq!(scanner.results().len(), before);
    assert!(!scanner.can_undo(), "no generation should have been pushed");
}

#[test]
fn next_scan_progress_totals_the_previous_generation() {
    let mut scanner = Scanner::new(
        MockTarget::new(BASE, vec![0u8; 200_000]),
        ScanValueType::I32,
    );
    let candidates = scanner
        .first_scan(ScanCompareType::Unknown, None)
        .unwrap()
        .len();

    let mut totals = Vec::new();
    scanner
        .next_scan_with(ScanCompareType::Unchanged, None, &mut |p: crate::ScanProgress| {
            totals.push(p.total);
            true
        })
        .unwrap();

    assert!(!totals.is_empty());
    assert!(
        totals.iter().all(|&t| t == candidates),
        "a next scan's total is exactly the previous generation's size"
    );
}

// ── fault tolerance ────────────────────────────────────────────────────────

#[test]
fn a_hole_inside_a_region_does_not_abort_the_scan() {
    // Three pages. The middle one is unreadable — the target unmapped it after
    // the maps snapshot was taken. The value in page 1 and the value in page 3
    // must both still be found, and the skipped span reported.
    const PAGE: usize = 4096;
    let mut buf = vec![0u8; 3 * PAGE];
    buf[0..4].copy_from_slice(&1337i32.to_le_bytes());
    buf[2 * PAGE + 16..2 * PAGE + 20].copy_from_slice(&1337i32.to_le_bytes());

    let target = MockTarget::new(BASE, buf).with_hole(BASE + PAGE, BASE + 2 * PAGE);

    let mut scanner = Scanner::new(target, ScanValueType::I32);
    let results = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "1337")))
        .expect("a hole must not abort the pass");

    let addrs: Vec<usize> = results.iter().map(|r| r.address).collect();
    assert!(
        addrs.contains(&BASE) && addrs.contains(&(BASE + 2 * PAGE + 16)),
        "both readable pages must be scanned, got {addrs:x?}"
    );
    assert_eq!(
        scanner.last_scan_stats().skipped_bytes,
        PAGE,
        "exactly the unreadable page is reported skipped — no double counting"
    );
}

#[test]
fn a_fully_unmapped_region_is_skipped_without_erroring() {
    const PAGE: usize = 4096;
    let mut buf = vec![0u8; 2 * PAGE];
    buf[PAGE..PAGE + 4].copy_from_slice(&42i32.to_le_bytes());

    // The first region is entirely gone; the second still holds the value.
    let regions = vec![Region::new(BASE, PAGE), Region::new(BASE + PAGE, PAGE)];
    let target =
        MockTarget::with_regions(BASE, buf, regions).with_hole(BASE, BASE + PAGE);

    let mut scanner = Scanner::new(target, ScanValueType::I32);
    let results = scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "42")))
        .expect("a dead region must not abort the pass");

    assert_eq!(results.iter().map(|r| r.address).collect::<Vec<_>>(), vec![BASE + PAGE]);
    assert!(scanner.last_scan_stats().skipped_bytes > 0);
}

#[test]
fn a_clean_scan_reports_nothing_skipped() {
    let target = MockTarget::new(BASE, buf_with_i32(8, 1337));
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner
        .first_scan(ScanCompareType::Exact, Some(needle(ScanValueType::I32, "1337")))
        .unwrap();
    assert_eq!(scanner.last_scan_stats().skipped_bytes, 0);
}

#[test]
fn mock_target_write_actually_stores_bytes() {
    // A test double that accepted writes and discarded them let freeze/write
    // code pass its tests having written nothing.
    let target = MockTarget::new(BASE, vec![0u8; 16]);
    let n = target.write(BASE + 4, &7i32.to_le_bytes()).unwrap();
    assert_eq!(n, 4);
    assert_eq!(target.peek(BASE + 4, 4).unwrap(), 7i32.to_le_bytes());
}

#[test]
fn freeze_reports_why_an_entry_did_not_stick() {
    // One entry lands on a live page, one on an unmapped one. The old `apply`
    // returned only a success count, so the UI could not tell the user which
    // value was not actually pinned, or why.
    let target = MockTarget::new(BASE, vec![0u8; 32]).with_hole(BASE + 16, BASE + 32);
    let mut freeze = FreezeSet::new();
    freeze.set(BASE + 4, 99i32.to_le_bytes().to_vec());
    freeze.set(BASE + 20, 7i32.to_le_bytes().to_vec());

    let report = freeze.apply(&target);
    assert_eq!(report.written, 1);
    assert_eq!(report.failed, 1);
    assert!(!report.all_written());
    assert!(
        report.problem().is_some_and(|m| m.contains("1 of 2")),
        "the report must name how many values did not stick, and why"
    );
    // The reachable entry was still pinned: one bad address does not abort.
    assert_eq!(target.peek(BASE + 4, 4).unwrap(), 99i32.to_le_bytes());
}

// ── Cheat Engine parity: needles, comparisons and the parallel walk ─────────

#[test]
fn a_hex_needle_that_fills_a_signed_width_is_read_as_a_bit_pattern() {
    // Cheat Engine reads `0xFFFFFFFF` for a 4-byte signed value as -1. Parsing
    // it as a magnitude and range-checking rejected it outright, so a hex
    // constant for any negative value could not be typed at all.
    let needle = ScanValueType::I32.parse_needle("0xFFFFFFFF").unwrap();
    assert!(needle.compare_first(&(-1i32).to_le_bytes(), 0, ScanCompareType::Exact));

    assert!(
        ScanValueType::I8
            .parse_needle("0x80")
            .unwrap()
            .compare_first(&(-128i8).to_le_bytes(), 0, ScanCompareType::Exact)
    );
    // Decimal is still range-checked: 4294967295 typed as a signed 32-bit
    // value is a mistake, not a bit pattern.
    assert!(ScanValueType::I32.parse_needle("4294967295").is_err());
    // And a hex value that does not fit the width is still an error.
    assert!(ScanValueType::I32.parse_needle("0x1FFFFFFFF").is_err());
}

#[test]
fn a_between_without_an_upper_bound_is_refused_not_silently_widened() {
    let target = MockTarget::new(BASE, buf_with_i32(8, 42));
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    let needle = ScanValueType::I32.parse_needle("10").unwrap();
    // It used to degrade to `value > 10`, which is a different search with far
    // more results and nothing to tell the user it happened.
    let err = scanner.first_scan(ScanCompareType::Between, Some(needle)).unwrap_err();
    assert!(matches!(err, crate::ScanError::BetweenNeedsUpperBound), "{err}");

    let bounded = ScanValueType::I32
        .parse_needle("10")
        .unwrap()
        .with_upper_bound("100")
        .unwrap();
    let results = scanner.first_scan(ScanCompareType::Between, Some(bounded)).unwrap();
    assert_eq!(results.len(), 1);
}

#[test]
fn truncate_rounding_finds_a_float_by_the_integer_the_game_displays() {
    // A health bar showing "100" is really 100.63 in memory; with the default
    // tolerance a needle of 100 misses it entirely.
    let mut buf = vec![0u8; 32];
    buf[8..12].copy_from_slice(&100.63f32.to_le_bytes());
    let target = MockTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::F32);

    let plain = ScanValueType::F32.parse_needle("100").unwrap();
    assert_eq!(
        scanner.first_scan(ScanCompareType::Exact, Some(plain)).unwrap().len(),
        0,
        "the default tolerance is too tight for this"
    );

    let truncating = ScanValueType::F32
        .parse_needle("100")
        .unwrap()
        .with_round_mode(crate::FloatRound::Truncate);
    let hits = scanner.first_scan(ScanCompareType::Exact, Some(truncating)).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits.get(0).unwrap().address, BASE + 8);
}

#[test]
fn strict_rounding_matches_only_the_exact_float() {
    let mut buf = vec![0u8; 32];
    buf[0..4].copy_from_slice(&1.0f32.to_le_bytes());
    buf[8..12].copy_from_slice(&1.005f32.to_le_bytes());
    let target = MockTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::F32);

    let strict = ScanValueType::F32
        .parse_needle("1.0")
        .unwrap()
        .with_round_mode(crate::FloatRound::Strict);
    let hits = scanner.first_scan(ScanCompareType::Exact, Some(strict)).unwrap();
    assert_eq!(hits.len(), 1, "1.005 is within the default tolerance but not equal");
    assert_eq!(hits.get(0).unwrap().address, BASE);
}

#[test]
fn a_case_insensitive_string_scan_finds_either_casing() {
    let mut buf = vec![0u8; 64];
    buf[8..16].copy_from_slice(b"PlayerHP");
    let target = MockTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::StringUtf8).with_alignment(1);

    let exact = ScanValueType::StringUtf8.parse_needle("playerhp").unwrap();
    assert_eq!(
        scanner.first_scan(ScanCompareType::Exact, Some(exact)).unwrap().len(),
        0
    );

    let folded = ScanValueType::StringUtf8
        .parse_needle("playerhp")
        .unwrap()
        .with_case_insensitive(true);
    let hits = scanner.first_scan(ScanCompareType::Exact, Some(folded)).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits.get(0).unwrap().address, BASE + 8);
}

#[test]
fn a_utf32_string_scan_matches_four_byte_code_units() {
    let mut buf = vec![0u8; 64];
    for (i, ch) in "Hi!".chars().enumerate() {
        buf[8 + i * 4..12 + i * 4].copy_from_slice(&(ch as u32).to_le_bytes());
    }
    let target = MockTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::StringUtf32).with_alignment(1);
    let needle = ScanValueType::StringUtf32.parse_needle("Hi!").unwrap();
    assert_eq!(needle.stride(), 12);
    let hits = scanner.first_scan(ScanCompareType::Exact, Some(needle)).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits.get(0).unwrap().address, BASE + 8);
}

#[test]
fn same_as_first_scan_compares_against_the_original_not_the_previous_value() {
    let target = CellTarget::new(BASE, buf_with_i32(8, 100));
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    let needle = ScanValueType::I32.parse_needle("100").unwrap();
    scanner.first_scan(ScanCompareType::Exact, Some(needle)).unwrap();

    // Move away, then back. `Unchanged` compares to the step before and fails;
    // `UnchangedFromFirst` compares to the first scan and holds.
    scanner.target().poke(BASE + 8, &50i32.to_le_bytes());
    assert_eq!(scanner.next_scan(ScanCompareType::Changed, None).unwrap().len(), 1);
    scanner.target().poke(BASE + 8, &100i32.to_le_bytes());

    let mut branch = scanner.clone_for_test();
    assert_eq!(
        branch.next_scan(ScanCompareType::Unchanged, None).unwrap().len(),
        0,
        "the value did change since the previous scan"
    );
    assert_eq!(
        scanner
            .next_scan(ScanCompareType::UnchangedFromFirst, None)
            .unwrap()
            .len(),
        1,
        "but it is back to what the first scan saw"
    );
}

#[test]
fn a_percentage_decrease_finds_a_drop_a_fixed_delta_could_not() {
    let mut buf = vec![0u8; 32];
    buf[0..4].copy_from_slice(&1000i32.to_le_bytes());
    buf[8..12].copy_from_slice(&50i32.to_le_bytes());
    let target = CellTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::I32);
    scanner.first_scan(ScanCompareType::Unknown, None).unwrap();

    // Both fall by 20%, but by 200 and by 10 — no single delta finds both.
    scanner.target().poke(BASE, &800i32.to_le_bytes());
    scanner.target().poke(BASE + 8, &40i32.to_le_bytes());

    let needle = ScanValueType::I32.parse_needle("20").unwrap();
    let hits = scanner
        .next_scan(ScanCompareType::DecreasedByPercent, Some(needle))
        .unwrap();
    let addresses: Vec<usize> = hits.iter().map(|r| r.address).collect();
    assert!(addresses.contains(&BASE), "the 1000 → 800 drop: {addresses:?}");
    assert!(addresses.contains(&(BASE + 8)), "the 50 → 40 drop: {addresses:?}");
}

#[test]
fn a_parallel_first_scan_finds_exactly_what_the_serial_one_does() {
    // Large enough to cross the parallel threshold and to be sharded, with the
    // needle planted either side of a shard cut so a boundary bug shows up.
    const SPAN: usize = 24 * 1024 * 1024;
    let mut buf = vec![0u8; SPAN];
    let planted: Vec<usize> = vec![
        0,
        4096,
        8 * 1024 * 1024 - 4,   // ends exactly on a shard boundary
        8 * 1024 * 1024,       // starts one
        8 * 1024 * 1024 + 4,
        16 * 1024 * 1024 - 8,
        SPAN - 4,
    ];
    for &off in &planted {
        buf[off..off + 4].copy_from_slice(&0x1234_5678i32.to_le_bytes());
    }

    let expected: Vec<usize> = planted.iter().map(|o| BASE + o).collect();

    for threads in [1usize, 4] {
        let target = MockTarget::new(BASE, buf.clone());
        let mut scanner = Scanner::new(target, ScanValueType::I32).with_threads(threads);
        let needle = ScanValueType::I32.parse_needle("0x12345678").unwrap();
        let results = scanner.first_scan(ScanCompareType::Exact, Some(needle)).unwrap();
        let found: Vec<usize> = results.iter().map(|r| r.address).collect();
        assert_eq!(found, expected, "threads = {threads}");
    }
}

#[test]
fn a_cancelled_parallel_scan_leaves_the_previous_results_alone() {
    const SPAN: usize = 24 * 1024 * 1024;
    let target = MockTarget::new(BASE, vec![7u8; SPAN]);
    let mut scanner = Scanner::new(target, ScanValueType::U8).with_threads(4);

    let needle = ScanValueType::U8.parse_needle("7").unwrap();
    let baseline = scanner
        .first_scan(ScanCompareType::Exact, Some(needle.clone()))
        .unwrap()
        .len();
    assert!(baseline > 0);

    let mut ticks = 0usize;
    let err = scanner
        .first_scan_with(ScanCompareType::Exact, Some(needle), &mut |_p| {
            ticks += 1;
            ticks < 4
        })
        .unwrap_err();
    assert!(matches!(err, crate::ScanError::Cancelled), "{err}");
    assert_eq!(scanner.results().len(), baseline, "the old generation survived");
}

#[test]
fn abutting_regions_are_merged_so_a_straddling_value_is_found() {
    // Two adjacent `rw-p` mappings — exactly how the heap appears in
    // /proc/<pid>/maps once part of one `mmap` gets different flags.
    let merged = crate::coalesce_regions(vec![
        Region::new(0x1000, 0x1000),
        Region::new(0x2000, 0x1000),
        Region::new(0x5000, 0x1000),
    ]);
    assert_eq!(merged, vec![Region::new(0x1000, 0x2000), Region::new(0x5000, 0x1000)]);

    // And overlapping ones do not double-count the overlap.
    let overlapping = crate::coalesce_regions(vec![
        Region::new(0x1000, 0x2000),
        Region::new(0x2000, 0x2000),
    ]);
    assert_eq!(overlapping, vec![Region::new(0x1000, 0x3000)]);
}

#[test]
fn a_value_straddling_two_adjacent_regions_is_found_once_they_are_merged() {
    let mut buf = vec![0u8; 0x2000];
    // Two bytes either side of the 0x1000 boundary.
    buf[0xFFE..0x1002].copy_from_slice(&0x1234_5678i32.to_le_bytes());

    let split = MockTarget::with_regions(
        BASE,
        buf.clone(),
        vec![Region::new(BASE, 0x1000), Region::new(BASE + 0x1000, 0x1000)],
    );
    let mut scanner = Scanner::new(split, ScanValueType::I32).with_alignment(1);
    let needle = ScanValueType::I32.parse_needle("0x12345678").unwrap();
    assert_eq!(
        scanner.first_scan(ScanCompareType::Exact, Some(needle.clone())).unwrap().len(),
        0,
        "each region's walk stops at its own end"
    );

    let merged = MockTarget::with_regions(
        BASE,
        buf,
        crate::coalesce_regions(vec![
            Region::new(BASE, 0x1000),
            Region::new(BASE + 0x1000, 0x1000),
        ]),
    );
    let mut scanner = Scanner::new(merged, ScanValueType::I32).with_alignment(1);
    let hits = scanner.first_scan(ScanCompareType::Exact, Some(needle)).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits.get(0).unwrap().address, BASE + 0xFFE);
}

#[test]
fn the_byte_prefilter_does_not_change_which_positions_match() {
    let mut buf = vec![0u8; 4096];
    for (i, off) in [100usize, 1000, 2500].iter().enumerate() {
        buf[*off..*off + 4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF - i as u8]);
    }
    let target = MockTarget::new(BASE, buf);
    let mut scanner = Scanner::new(target, ScanValueType::Bytes).with_alignment(1);

    // A leading literal byte: the prefilter is active.
    let literal = ScanValueType::Bytes.parse_needle("DE AD BE ??").unwrap();
    let hits = scanner.first_scan(ScanCompareType::Exact, Some(literal)).unwrap();
    assert_eq!(hits.iter().map(|r| r.address).collect::<Vec<_>>(), [
        BASE + 100,
        BASE + 1000,
        BASE + 2500
    ]);

    // A leading wildcard: any byte is a legal start, so the prefilter must not
    // engage — and the same positions must still be found.
    let wildcarded = ScanValueType::Bytes.parse_needle("?? AD BE ??").unwrap();
    let hits = scanner.first_scan(ScanCompareType::Exact, Some(wildcarded)).unwrap();
    assert_eq!(hits.iter().map(|r| r.address).collect::<Vec<_>>(), [
        BASE + 100,
        BASE + 1000,
        BASE + 2500
    ]);
}

// ── freeze modes ───────────────────────────────────────────────────────────

#[test]
fn an_allow_increase_freeze_lets_the_value_rise_and_holds_the_new_high() {
    use crate::{FreezeMode, FreezeSet};

    let target = CellTarget::new(BASE, buf_with_i32(0, 100));
    let mut set = FreezeSet::new();
    set.set_with(BASE, 100i32.to_le_bytes().to_vec(), FreezeMode::AllowIncrease, Some(ScanValueType::I32));

    // It went up on its own: leave it, and hold the new value from now on.
    target.poke(BASE, &150i32.to_le_bytes());
    set.apply_ratcheting(&target);
    assert_eq!(target.peek(BASE, 4), 150i32.to_le_bytes());

    // It went down: put it back to the *new* high, not the original.
    target.poke(BASE, &20i32.to_le_bytes());
    set.apply_ratcheting(&target);
    assert_eq!(
        target.peek(BASE, 4),
        150i32.to_le_bytes(),
        "the ratchet moved; restoring 100 would be an exact freeze wearing a different label"
    );
}

#[test]
fn an_allow_decrease_freeze_is_the_mirror_image() {
    use crate::{FreezeMode, FreezeSet};

    let target = CellTarget::new(BASE, buf_with_i32(0, 100));
    let mut set = FreezeSet::new();
    set.set_with(BASE, 100i32.to_le_bytes().to_vec(), FreezeMode::AllowDecrease, Some(ScanValueType::I32));

    target.poke(BASE, &40i32.to_le_bytes());
    set.apply_ratcheting(&target);
    assert_eq!(target.peek(BASE, 4), 40i32.to_le_bytes(), "falling is allowed");

    target.poke(BASE, &900i32.to_le_bytes());
    set.apply_ratcheting(&target);
    assert_eq!(target.peek(BASE, 4), 40i32.to_le_bytes(), "rising is not");
}

#[test]
fn an_exact_freeze_pins_the_value_in_both_directions() {
    use crate::{FreezeMode, FreezeSet};

    let target = CellTarget::new(BASE, buf_with_i32(0, 100));
    let mut set = FreezeSet::new();
    set.set_with(BASE, 100i32.to_le_bytes().to_vec(), FreezeMode::Exact, Some(ScanValueType::I32));

    for other in [5i32, 5000] {
        target.poke(BASE, &other.to_le_bytes());
        set.apply_ratcheting(&target);
        assert_eq!(target.peek(BASE, 4), 100i32.to_le_bytes());
    }
}

#[test]
fn a_ratchet_compares_as_the_value_type_not_as_bytes() {
    use crate::{FreezeMode, FreezeSet};

    // -1 has a larger *unsigned* byte pattern than 1, so a bytewise comparison
    // gets the direction exactly backwards for a signed value.
    let target = CellTarget::new(BASE, buf_with_i32(0, 1));
    let mut set = FreezeSet::new();
    set.set_with(BASE, 1i32.to_le_bytes().to_vec(), FreezeMode::AllowIncrease, Some(ScanValueType::I32));

    target.poke(BASE, &(-1i32).to_le_bytes());
    set.apply_ratcheting(&target);
    assert_eq!(
        target.peek(BASE, 4),
        1i32.to_le_bytes(),
        "-1 is a decrease, so it is written back"
    );
}

#[test]
fn a_ratchet_with_no_value_type_falls_back_to_an_exact_freeze() {
    use crate::{FreezeMode, FreezeSet};

    // Without a type there is no way to compare correctly, and guessing
    // bytewise would be wrong for most types.
    let target = CellTarget::new(BASE, buf_with_i32(0, 100));
    let mut set = FreezeSet::new();
    set.set_with(BASE, 100i32.to_le_bytes().to_vec(), FreezeMode::AllowIncrease, None);

    target.poke(BASE, &900i32.to_le_bytes());
    set.apply_ratcheting(&target);
    assert_eq!(target.peek(BASE, 4), 100i32.to_le_bytes());
}
