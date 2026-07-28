//! Reverse pointer-chain scan — the "Pointer scan" feature from Cheat Engine /
//! PINCE, ported onto the crate's [`ScanTarget`] seam so it is platform-neutral
//! and mock-testable.
//!
//! # What it does
//! Given a *goal* address (the address whose value you want to watch) and a set
//! of *static* address ranges (module images, whose base is stable across runs),
//! it finds pointer paths `base → [+off₀] → [+off₁] → … → goal` such that
//! dereferencing `base` and applying each offset in turn lands on `goal`. These
//! paths survive ASLR because `base` is expressed relative to a module.
//!
//! # How it works
//! 1. [`PointerMap::build`] walks every readable [`Region`], reads each aligned
//!    machine word, and — when that word points into mapped memory — records
//!    `value → address_holding_it`. The result is sorted by value for fast range
//!    queries.
//! 2. [`PointerMap::find_paths`] runs a bounded reverse DFS from `goal`: it looks
//!    for addresses `A` whose stored value `V` satisfies `goal - max_offset ≤ V ≤
//!    goal` (so `*A + (goal - V) == goal`). Each such `A` becomes the new goal one
//!    level up; recursion stops when `A` falls inside a static range (a complete
//!    path) or the depth budget is exhausted.
//!
//! Pointer scans can combinatorially explode, so every knob is bounded and the
//! result count is capped ([`PointerScanConfig::max_results`]); truncation is
//! reported via [`PointerScanResult::truncated`] rather than silently dropped.

use std::collections::HashSet;

use nemclass_core::Result;

use crate::target::{Region, ScanTarget};

/// Tunables for a pointer scan. Defaults mirror Cheat Engine's common settings.
#[derive(Debug, Clone)]
pub struct PointerScanConfig {
    /// Maximum number of offsets in a chain (chain length / pointer depth).
    pub max_depth: usize,
    /// Maximum positive struct offset applied at each hop.
    pub max_offset: usize,
    /// Pointer alignment when harvesting candidate pointers (4 or 8).
    pub alignment: usize,
    /// Pointer width in bytes (8 for 64-bit targets).
    pub pointer_size: usize,
    /// Static anchor ranges (module images). A chain must start inside one.
    pub static_ranges: Vec<Region>,
    /// Hard cap on returned paths; the scan stops early once reached.
    pub max_results: usize,
    /// Hard cap on harvested pointer-map entries, to bound memory on huge targets.
    pub max_map_entries: usize,
}

impl Default for PointerScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_offset: 0x1000,
            alignment: 4,
            pointer_size: 8,
            static_ranges: Vec::new(),
            max_results: 5000,
            max_map_entries: 8_000_000,
        }
    }
}

/// One discovered pointer path: `base` is a (static) anchor address; `offsets`
/// are applied base→goal (deref `base`, add `offsets[0]`, deref, add
/// `offsets[1]`, … the final add lands on the goal address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerPath {
    /// Absolute static anchor address (map to `module+off` for display).
    pub base: usize,
    /// Offsets applied in order from `base` to the goal.
    pub offsets: Vec<usize>,
}

impl PointerPath {
    /// Render this path as a nemclass **address formula** anchored at a module,
    /// e.g. `[[<game.exe> + 0x1000] + 0x40] + 0x14`. The module name is emitted in
    /// the `<...>` form the address tokenizer expects. The result parses with
    /// `nemclass_model::parse_address` and can be assigned directly to a
    /// `ClassNode.address_formula`, turning a pointer-scan hit into a live,
    /// ASLR-stable class base.
    ///
    /// Re-resolve this chain against live memory, returning the final address it
    /// currently points at (or `None` if any hop reads unmapped memory).
    ///
    /// `read_ptr(addr)` must read a pointer-sized word at `addr`. Semantics match
    /// [`Self::to_formula`]: dereference `base`, then for each offset add it and
    /// dereference — except the last offset, which is added without a final
    /// dereference (it names the target *address*). Use this to filter a
    /// pointer-scan result set after the target process relocates (Cheat Engine's
    /// "rescan").
    pub fn resolve(&self, read_ptr: impl Fn(usize) -> Option<usize>) -> Option<usize> {
        let mut addr = read_ptr(self.base)?;
        let n = self.offsets.len();
        for (i, &off) in self.offsets.iter().enumerate() {
            let stepped = addr.checked_add(off)?;
            addr = if i + 1 < n { read_ptr(stepped)? } else { stepped };
        }
        Some(addr)
    }

    /// `module_base` is the runtime base the path was discovered against; the
    /// static offset `base - module_base` is emitted relative to `module_name`.
    pub fn to_formula(&self, module_name: &str, module_base: usize) -> String {
        let base_off = self.base.wrapping_sub(module_base);
        let mut expr = if base_off == 0 {
            format!("<{module_name}>")
        } else {
            format!("<{module_name}> + {base_off:#x}")
        };
        for off in &self.offsets {
            expr = format!("[{expr}] + {off:#x}");
        }
        expr
    }
}

/// The outcome of [`PointerMap::find_paths`] / [`pointer_scan`].
#[derive(Debug, Clone)]
pub struct PointerScanResult {
    /// Discovered paths (bounded by `max_results`).
    pub paths: Vec<PointerPath>,
    /// True if the search hit `max_results` and stopped early.
    pub truncated: bool,
}

/// A harvested `value → holder-address` index, reusable across many goals so a
/// UI can build it once and scan several targets.
#[derive(Debug, Clone)]
pub struct PointerMap {
    /// `(value, address_holding_value)` sorted ascending by value.
    entries: Vec<(usize, usize)>,
    /// True if harvesting stopped at `max_map_entries`.
    truncated: bool,
}

impl PointerMap {
    /// Harvest all aligned pointers from `target`'s readable regions.
    pub fn build<T: ScanTarget>(target: &T, cfg: &PointerScanConfig) -> Result<Self> {
        let regions = target.regions()?;
        let mut ranges: Vec<(usize, usize)> =
            regions.iter().map(|r| (r.base, r.end())).collect();
        ranges.sort_unstable();

        let psize = cfg.pointer_size.max(1);
        let align = cfg.alignment.max(1);
        // Read in bounded chunks with a `psize` overlap so a pointer that
        // straddles a chunk edge is still parsed exactly once (keyed by address).
        const CHUNK: usize = 1 << 20; // 1 MiB

        let mut entries: Vec<(usize, usize)> = Vec::new();
        let mut truncated = false;

        'regions: for region in &regions {
            let mut pos = region.base;
            let end = region.end();
            let mut buf = vec![0u8; CHUNK + psize];
            while pos < end {
                let want = (end - pos).min(CHUNK + psize);
                let n = target.read(pos, &mut buf[..want])?;
                if n < psize {
                    break;
                }
                // Iterate aligned offsets whose full word lies within [pos, pos+n).
                let first_align = pos.next_multiple_of(align) - pos;
                let mut i = first_align;
                while i + psize <= n {
                    let addr = pos + i;
                    // Only emit words fully inside this chunk's non-overlap span,
                    // except for the final chunk of the region.
                    let val = read_word(&buf[i..i + psize]);
                    if is_mapped(&ranges, val) {
                        entries.push((val, addr));
                        if entries.len() >= cfg.max_map_entries {
                            truncated = true;
                            break 'regions;
                        }
                    }
                    i += align;
                }
                // Advance by the non-overlap span so the trailing `psize` window
                // is re-read at the next chunk (addresses stay unique because the
                // loop condition `i + psize <= n` excludes partial tails).
                if want <= psize {
                    break;
                }
                pos += want - psize;
            }
        }

        entries.sort_unstable_by_key(|&(v, _)| v);
        // Deduplicate identical (value,address) pairs that the chunk overlap can
        // produce at region-internal boundaries.
        entries.dedup();

        Ok(Self { entries, truncated })
    }

    /// True if pointer-map harvesting was capped at `max_map_entries`.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Number of harvested pointer entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Reverse-scan for pointer paths that resolve to `goal`.
    pub fn find_paths(&self, goal: usize, cfg: &PointerScanConfig) -> PointerScanResult {
        let mut out: Vec<PointerPath> = Vec::new();
        let mut truncated = false;
        let mut visited: HashSet<usize> = HashSet::new();
        // Sorted once here, not per DFS frame: `solve` recurses thousands of
        // times and used to re-allocate and re-sort this on every one of them.
        let statics = cfg.static_ranges_sorted();
        self.solve(
            goal,
            cfg.max_depth,
            &mut Vec::new(),
            cfg,
            &statics,
            &mut visited,
            &mut out,
            &mut truncated,
        );
        PointerScanResult { paths: out, truncated }
    }

    /// Recursive worker. `suffix` holds the offsets already fixed for the portion
    /// of the chain *below* `goal` (closer to the target); a newly found hop is
    /// prepended so the emitted `offsets` read base→target.
    #[allow(clippy::too_many_arguments)]
    fn solve(
        &self,
        goal: usize,
        depth: usize,
        suffix: &mut Vec<usize>,
        cfg: &PointerScanConfig,
        statics: &[(usize, usize)],
        visited: &mut HashSet<usize>,
        out: &mut Vec<PointerPath>,
        truncated: &mut bool,
    ) {
        if depth == 0 || out.len() >= cfg.max_results {
            if out.len() >= cfg.max_results {
                *truncated = true;
            }
            return;
        }
        // Cycle guard: never revisit a goal already on the current DFS path.
        if !visited.insert(goal) {
            return;
        }

        let lo = goal.saturating_sub(cfg.max_offset);
        for (value, addr) in self.range(lo, goal) {
            if out.len() >= cfg.max_results {
                *truncated = true;
                break;
            }
            let off = goal - value;
            // Build the offsets for a chain anchored at `addr`: this hop, then
            // everything already fixed below.
            let mut chain = Vec::with_capacity(suffix.len() + 1);
            chain.push(off);
            chain.extend_from_slice(suffix);

            if is_mapped(statics, addr) {
                out.push(PointerPath { base: addr, offsets: chain });
                // A static anchor completes the path; don't extend past it.
                continue;
            }

            // Recurse: `addr` becomes the next goal one level up.
            suffix.insert(0, off);
            self.solve(addr, depth - 1, suffix, cfg, statics, visited, out, truncated);
            suffix.remove(0);
        }

        visited.remove(&goal);
    }

    /// All `(value, holder_addr)` with `lo ≤ value ≤ hi`.
    fn range(&self, lo: usize, hi: usize) -> impl Iterator<Item = (usize, usize)> + '_ {
        let start = self.entries.partition_point(|&(v, _)| v < lo);
        self.entries[start..]
            .iter()
            .take_while(move |&&(v, _)| v <= hi)
            .copied()
    }
}

impl PointerScanConfig {
    /// The static ranges as sorted `(base, end)` pairs for containment checks.
    fn static_ranges_sorted(&self) -> Vec<(usize, usize)> {
        let mut v: Vec<(usize, usize)> = self.static_ranges.iter().map(|r| (r.base, r.end())).collect();
        v.sort_unstable();
        v
    }
}

/// Convenience: build a [`PointerMap`] and immediately scan it for `goal`.
pub fn pointer_scan<T: ScanTarget>(
    target: &T,
    goal: usize,
    cfg: &PointerScanConfig,
) -> Result<PointerScanResult> {
    let map = PointerMap::build(target, cfg)?;
    let mut result = map.find_paths(goal, cfg);
    result.truncated |= map.truncated();
    Ok(result)
}

/// Read a little-endian pointer-sized word (1..=8 bytes) into a `usize`.
///
/// Shared with [`crate::spider`], which harvests candidate pointers the same way.
pub(crate) fn read_word(bytes: &[u8]) -> usize {
    let mut v = 0usize;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        v |= (b as usize) << (i * 8);
    }
    v
}

/// True if `addr` falls inside any `(base, end)` range (sorted ascending).
///
/// Shared with [`crate::spider`], which uses it to decide whether a candidate
/// pointer is worth following. Both callers sort their ranges once up front —
/// this is a per-slot hot path, so a linear scan over unsorted regions is not an
/// acceptable substitute.
pub(crate) fn is_mapped(ranges: &[(usize, usize)], addr: usize) -> bool {
    // Find the last range whose base ≤ addr, then check its end.
    let idx = ranges.partition_point(|&(base, _)| base <= addr);
    idx > 0 && addr < ranges[idx - 1].1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::MockTarget;

    /// Store a little-endian usize into `buf` at absolute `addr` (base 0x10000).
    fn put(buf: &mut [u8], base: usize, addr: usize, val: usize) {
        let off = addr - base;
        buf[off..off + 8].copy_from_slice(&(val as u64).to_le_bytes());
    }

    /// Build a target with a static module region and a heap region holding a
    /// two-hop pointer chain to a goal address.
    fn two_level_target() -> (MockTarget, usize) {
        let base = 0x10000usize;
        // Buffer spans [0x10000, 0x20100); regions are the module + the heap.
        let mut buf = vec![0u8; 0x10100];
        // Static base 0x10000 -> 0x20000
        put(&mut buf, base, 0x10000, 0x20000);
        // Heap 0x20040 -> 0x20030   (so *(0x20040) + 0x14 == 0x20044 == goal)
        put(&mut buf, base, 0x20040, 0x20030);
        let regions = vec![Region::new(0x10000, 0x100), Region::new(0x20000, 0x100)];
        (MockTarget::with_regions(base, buf, regions), 0x20044)
    }

    #[test]
    fn finds_two_level_chain() {
        let (target, goal) = two_level_target();
        let cfg = PointerScanConfig {
            max_depth: 4,
            max_offset: 0x1000,
            alignment: 4,
            pointer_size: 8,
            static_ranges: vec![Region::new(0x10000, 0x100)],
            ..Default::default()
        };
        let result = pointer_scan(&target, goal, &cfg).unwrap();
        assert!(
            result.paths.iter().any(|p| p.base == 0x10000 && p.offsets == vec![0x40, 0x14]),
            "expected base=0x10000 offsets=[0x40,0x14], got {:?}",
            result.paths
        );
    }

    #[test]
    fn finds_three_level_chain() {
        // S(0x10000)->0x20000; 0x20030->0x21000; 0x21008->0x22000; goal 0x22014.
        // => offsets [0x30, 0x8, 0x14].
        let base = 0x10000usize;
        let mut buf = vec![0u8; 0x12100];
        put(&mut buf, base, 0x10000, 0x20000);
        put(&mut buf, base, 0x20030, 0x21000);
        put(&mut buf, base, 0x21008, 0x22000);
        let regions = vec![Region::new(0x10000, 0x100), Region::new(0x20000, 0x2100)];
        let target = MockTarget::with_regions(base, buf, regions);
        let goal = 0x22014;

        let cfg = PointerScanConfig {
            max_depth: 4,
            max_offset: 0x1000,
            static_ranges: vec![Region::new(0x10000, 0x100)],
            ..Default::default()
        };
        let result = pointer_scan(&target, goal, &cfg).unwrap();
        assert!(
            result.paths.iter().any(|p| p.base == 0x10000 && p.offsets == vec![0x30, 0x8, 0x14]),
            "expected [0x30,0x8,0x14], got {:?}",
            result.paths
        );
    }

    #[test]
    fn respects_max_depth() {
        // With depth 1, the two-level chain (needs depth 2) must NOT be found;
        // only a direct static→goal (none here) would qualify.
        let (target, goal) = two_level_target();
        let cfg = PointerScanConfig {
            max_depth: 1,
            static_ranges: vec![Region::new(0x10000, 0x100)],
            ..Default::default()
        };
        let result = pointer_scan(&target, goal, &cfg).unwrap();
        assert!(
            !result.paths.iter().any(|p| p.offsets.len() > 1),
            "depth 1 must not yield multi-hop chains: {:?}",
            result.paths
        );
    }

    #[test]
    fn direct_static_pointer() {
        // Static 0x10000 holds 0x10040; goal 0x10050 => offset 0x10.
        let base = 0x10000usize;
        let mut buf = vec![0u8; 0x100];
        put(&mut buf, base, 0x10000, 0x10040);
        let target = MockTarget::with_regions(base, buf, vec![Region::new(0x10000, 0x100)]);
        let cfg = PointerScanConfig {
            max_depth: 3,
            static_ranges: vec![Region::new(0x10000, 0x100)],
            ..Default::default()
        };
        let result = pointer_scan(&target, 0x10050, &cfg).unwrap();
        assert!(
            result.paths.iter().any(|p| p.base == 0x10000 && p.offsets == vec![0x10]),
            "expected [0x10] path, got {:?}",
            result.paths
        );
    }

    #[test]
    fn path_to_formula() {
        let p = PointerPath { base: 0x140001000, offsets: vec![0x40, 0x14] };
        assert_eq!(
            p.to_formula("game.exe", 0x140000000),
            "[[<game.exe> + 0x1000] + 0x40] + 0x14"
        );
        // Zero base offset omits the "+ 0x0".
        let p0 = PointerPath { base: 0x140000000, offsets: vec![0x8] };
        assert_eq!(p0.to_formula("game.exe", 0x140000000), "[<game.exe>] + 0x8");
        // No offsets → just the anchor.
        let p_empty = PointerPath { base: 0x140000010, offsets: vec![] };
        assert_eq!(p_empty.to_formula("mod", 0x140000000), "<mod> + 0x10");
    }

    #[test]
    fn resolve_recovers_the_goal() {
        let (target, goal) = two_level_target();
        let read_ptr = |addr: usize| -> Option<usize> {
            let mut b = [0u8; 8];
            let n = target.read(addr, &mut b).ok()?;
            (n >= 8).then(|| u64::from_le_bytes(b) as usize)
        };
        let path = PointerPath { base: 0x10000, offsets: vec![0x40, 0x14] };
        assert_eq!(path.resolve(read_ptr), Some(goal));

        // A wrong offset must resolve elsewhere (not the goal).
        let bad = PointerPath { base: 0x10000, offsets: vec![0x40, 0x99] };
        assert_ne!(bad.resolve(read_ptr), Some(goal));
    }

    #[test]
    fn is_mapped_boundaries() {
        let ranges = vec![(0x1000usize, 0x2000usize), (0x3000, 0x4000)];
        assert!(is_mapped(&ranges, 0x1000));
        assert!(is_mapped(&ranges, 0x1fff));
        assert!(!is_mapped(&ranges, 0x2000)); // exclusive end
        assert!(!is_mapped(&ranges, 0x2500)); // gap
        assert!(is_mapped(&ranges, 0x3000));
        assert!(!is_mapped(&ranges, 0x0fff));
    }
}
