//! Scanner proof via a mock target — no live process.
//!
//! Every test drives the engine through [`MockTarget`] (an in-memory buffer plus
//! fabricated regions), so the whole scan pipeline (first scan, next scan,
//! change-relative filtering, AOB wildcards, region-boundary safety, freeze)
//! runs deterministically on any platform.

use crate::{
    BytePattern, FreezeSet, MockTarget, Region, ScanCompareType, ScanValueType, Scanner,
    WriteTarget,
};

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
    assert_eq!(results.iter().next().unwrap().previous_value_bytes, 1337i32.to_le_bytes());
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
    // 16 bytes, stride 4, positions 0..=12 -> 13 candidates.
    assert_eq!(first.len(), 13);

    // Decrease only the value at offset 0 (500 -> 400); everything else stays.
    scanner_target_mut(&mut scanner).buf_mut()[0..4].copy_from_slice(&400i32.to_le_bytes());
    let r = scanner.next_scan(ScanCompareType::Decreased, None).unwrap();
    // Only overlapping windows touching offset 0 that decreased. Offset 0 is the
    // clean match; verify it is present.
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
    let mut scanner = Scanner::new(target, ScanValueType::I32);

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

    let ok = freeze.apply(&target).unwrap();
    assert_eq!(ok, 1);
    assert_eq!(target.peek(BASE + 4, 4), 99i32.to_le_bytes());

    // Simulate the target changing the value, then re-apply pins it back.
    target.poke(BASE + 4, &0i32.to_le_bytes());
    assert_eq!(target.peek(BASE + 4, 4), 0i32.to_le_bytes());
    freeze.apply(&target).unwrap();
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

/// An interior-mutable write target for the freeze test.
struct CellTarget {
    base: usize,
    buf: std::cell::RefCell<Vec<u8>>,
}

impl CellTarget {
    fn new(base: usize, buf: Vec<u8>) -> Self {
        Self {
            base,
            buf: std::cell::RefCell::new(buf),
        }
    }

    fn peek(&self, addr: usize, len: usize) -> Vec<u8> {
        let off = addr - self.base;
        self.buf.borrow()[off..off + len].to_vec()
    }

    fn poke(&self, addr: usize, bytes: &[u8]) {
        let off = addr - self.base;
        self.buf.borrow_mut()[off..off + bytes.len()].copy_from_slice(bytes);
    }
}

impl WriteTarget for CellTarget {
    fn write(&self, addr: usize, buf: &[u8]) -> crate::Result<usize> {
        let off = addr - self.base;
        let mut b = self.buf.borrow_mut();
        let n = buf.len().min(b.len().saturating_sub(off));
        b[off..off + n].copy_from_slice(&buf[..n]);
        Ok(n)
    }
}
