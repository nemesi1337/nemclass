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
    /// Maximum *negative* struct offset. Zero — the default, and Cheat Engine's
    /// — means forwards only. Non-zero finds a field addressed backwards from a
    /// pointer stored in the middle of a structure, which happens with intrusive
    /// lists and with `container_of`-style layouts.
    pub max_negative_offset: usize,
    /// Only accept offsets that are a multiple of this. `1` accepts any. Set it
    /// to the pointer size when the target's fields are aligned: it cuts the
    /// branching factor by that factor with no real loss.
    pub offset_alignment: usize,
    /// Pointer alignment when harvesting candidate pointers (4 or 8).
    pub alignment: usize,
    /// Pointer width in bytes (8 for 64-bit targets).
    pub pointer_size: usize,
    /// Static anchor ranges (module images). A chain must start inside one.
    pub static_ranges: Vec<Region>,
    /// Whether a path is only reported when it starts inside a static range.
    ///
    /// `true` is what makes a chain survive a restart, and is the default. `false`
    /// also reports chains that ran out of depth on the heap, which are useful
    /// for understanding a structure but will not reproduce.
    pub must_end_in_static: bool,
    /// Hard cap on returned paths; the scan stops early once reached.
    pub max_results: usize,
    /// Hard cap on harvested pointer-map entries, to bound memory on huge targets.
    pub max_map_entries: usize,
    /// Hard cap on how many distinct addresses one BFS level may hold.
    ///
    /// The frontier is what actually explodes: an offset window of 0x1000 over a
    /// dense heap can turn a hundred nodes into a hundred thousand in one step.
    pub max_frontier: usize,
}

impl Default for PointerScanConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_offset: 0x1000,
            max_negative_offset: 0,
            offset_alignment: 1,
            alignment: 4,
            pointer_size: 8,
            static_ranges: Vec::new(),
            must_end_in_static: true,
            max_results: 10000,
            max_map_entries: 8_000_000,
            max_frontier: 200_000,
        }
    }
}

/// Progress of an in-flight pointer scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerScanProgress {
    /// Which phase is running.
    pub phase: PointerScanPhase,
    /// Work done in this phase.
    pub done: usize,
    /// Total work in this phase, when it is known.
    pub total: usize,
    /// Complete paths found so far.
    pub found: usize,
}

/// The two phases of a pointer scan, which have very different costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointerScanPhase {
    /// Harvesting `value → holder` pairs from the target's memory.
    BuildingMap,
    /// Walking outwards from the goal, one pointer level at a time.
    Searching,
}

/// Called periodically during a pointer scan. Returning `false` aborts it.
///
/// This is the longest operation in the application — minutes over a large
/// target — and it previously showed a spinner and nothing else, with no way to
/// stop it short of killing the process.
pub trait PointerScanObserver {
    /// Reports progress. Return `false` to abort.
    fn tick(&mut self, progress: PointerScanProgress) -> bool;
}

impl<F: FnMut(PointerScanProgress) -> bool> PointerScanObserver for F {
    fn tick(&mut self, progress: PointerScanProgress) -> bool {
        self(progress)
    }
}

/// A [`PointerScanObserver`] that ignores progress and never aborts.
pub struct NoPointerObserver;

impl PointerScanObserver for NoPointerObserver {
    fn tick(&mut self, _progress: PointerScanProgress) -> bool {
        true
    }
}

/// One discovered pointer path: `base` is a (static) anchor address; `offsets`
/// are applied base→goal (deref `base`, add `offsets[0]`, deref, add
/// `offsets[1]`, … the final add lands on the goal address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PointerPath {
    /// Absolute static anchor address (map to `module+off` for display).
    pub base: usize,
    /// Offsets applied in order from `base` to the goal. Signed, because a
    /// pointer stored in the middle of a structure is reached with a negative
    /// offset from a field after it.
    pub offsets: Vec<isize>,
}

impl PointerPath {
    /// How good a chain this is, lower being better.
    ///
    /// Shorter chains first, then smaller offsets. A three-hop chain through
    /// `+0x8` fields is far more likely to be a real structure relationship —
    /// and to survive a patch — than a five-hop one through `+0xFA0`, and a
    /// result list of ten thousand is useless without an order.
    pub fn score(&self) -> u64 {
        let magnitude: u64 = self
            .offsets
            .iter()
            .map(|o| o.unsigned_abs() as u64)
            .sum();
        (self.offsets.len() as u64) << 40 | magnitude.min((1 << 40) - 1)
    }

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
            let stepped = addr.checked_add_signed(off)?;
            addr = if i + 1 < n { read_ptr(stepped)? } else { stepped };
        }
        Some(addr)
    }

    /// Render this path as a nemclass **address formula** anchored at a module,
    /// e.g. `[[<game.exe> + 0x1000] + 0x40] + 0x14`. The module name is emitted in
    /// the `<...>` form the address tokenizer expects. The result parses with
    /// `nemclass_model::parse_address` and can be assigned directly to a
    /// `ClassNode.address_formula`, turning a pointer-scan hit into a live,
    /// ASLR-stable class base.
    ///
    /// `module_base` is the runtime base the path was discovered against; the
    /// static offset `base - module_base` is emitted relative to `module_name`.
    pub fn to_formula(&self, module_name: &str, module_base: usize) -> String {
        let base_off = self.base.wrapping_sub(module_base);
        let base = if base_off == 0 {
            format!("<{module_name}>")
        } else {
            format!("<{module_name}> + {base_off:#x}")
        };
        self.to_formula_expr(&base)
    }

    /// [`Self::to_formula`] on top of an arbitrary base expression.
    ///
    /// Note the shape differs from [`SpiderPath::to_formula`](crate::SpiderPath::to_formula):
    /// here each offset is added *after* a dereference (`[expr] + off`), because
    /// a `PointerPath` dereferences its base. See [`Self::resolve`].
    pub fn to_formula_expr(&self, base_expr: &str) -> String {
        let mut expr = base_expr.to_string();
        for &off in &self.offsets {
            expr = if off < 0 {
                format!("[{expr}] - {:#x}", off.unsigned_abs())
            } else {
                format!("[{expr}] + {off:#x}")
            };
        }
        expr
    }

    /// [`Self::to_formula`] with the anchor as a bare hex literal, for a chain
    /// that never reached a module image. Only valid until the target restarts.
    pub fn to_formula_raw(&self) -> String {
        self.to_formula_expr(&format!("{:#x}", self.base))
    }
}

/// The outcome of [`PointerMap::find_paths`] / [`pointer_scan`].
#[derive(Debug, Clone)]
pub struct PointerScanResult {
    /// Discovered paths, best first (see [`PointerPath::score`]).
    pub paths: Vec<PointerPath>,
    /// True if the search hit `max_results` or `max_frontier` and stopped early.
    pub truncated: bool,
    /// How many alternative routes through an already-seen address were
    /// collapsed. Non-zero means other chains to the same goal exist; they go
    /// through the same intermediate pointers with different offsets.
    pub collapsed: usize,
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

/// Magic + version for a saved pointer map.
const MAP_MAGIC: &[u8; 8] = b"NEMPMAP\x01";

impl PointerMap {
    /// Harvest all aligned pointers from `target`'s readable regions.
    pub fn build<T: ScanTarget>(target: &T, cfg: &PointerScanConfig) -> Result<Self> {
        Self::build_with(target, cfg, &mut NoPointerObserver)
    }

    /// [`Self::build`] with progress reporting and cooperative cancellation.
    ///
    /// A cancelled build returns the entries harvested so far, marked truncated,
    /// rather than an error: a partial map is still usable, and the caller
    /// already knows it asked to stop.
    pub fn build_with<T: ScanTarget>(
        target: &T,
        cfg: &PointerScanConfig,
        observer: &mut dyn PointerScanObserver,
    ) -> Result<Self> {
        let regions = coalesce_ranges(target.regions()?);
        let ranges: Vec<(usize, usize)> = regions.iter().map(|r| (r.base, r.end())).collect();

        let psize = cfg.pointer_size.max(1);
        let align = cfg.alignment.max(1);
        // Read in bounded chunks with a `psize` overlap so a pointer that
        // straddles a chunk edge is still parsed exactly once (keyed by address).
        const CHUNK: usize = 1 << 20; // 1 MiB

        let mut entries: Vec<(usize, usize)> = Vec::new();
        let mut truncated = false;
        let total: usize = regions.iter().map(|r| r.size).sum();
        let mut walked = 0usize;
        // Hoisted out of the region loop: this is a megabyte, and allocating and
        // zeroing it once per region cost more than the reads for a target with
        // a few hundred small mappings.
        let mut buf = vec![0u8; CHUNK + psize];

        'regions: for region in &regions {
            let mut pos = region.base;
            let end = region.end();
            while pos < end {
                if !observer.tick(PointerScanProgress {
                    phase: PointerScanPhase::BuildingMap,
                    done: walked,
                    total,
                    found: entries.len(),
                }) {
                    truncated = true;
                    break 'regions;
                }
                let want = (end - pos).min(CHUNK + psize);
                // A region that faults part-way is stepped over, not fatal: the
                // maps snapshot is taken once and the target keeps running.
                let n = match target.read(pos, &mut buf[..want]) {
                    Ok(n) => n,
                    Err(_) => break,
                };
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
                walked += want - psize;
            }
        }

        // Sort by the whole `(value, address)` tuple, not just the value. The
        // chunk overlap above deliberately re-emits the last `psize` bytes of
        // each window, so every internal chunk boundary produces a genuine
        // duplicate pair — and `dedup` only removes *consecutive* equals. Keying
        // the sort on `value` alone leaves equal-valued entries in arbitrary
        // order, so those duplicates survive and `find_paths` then yields the
        // same `PointerPath` more than once (2^depth times through a chain).
        entries.sort_unstable();
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

    /// Serialize the map so a later session can scan a new goal without walking
    /// the target's memory again.
    ///
    /// Building the map is most of the cost of a pointer scan, and it was
    /// rebuilt from scratch for every goal — including for a second goal
    /// seconds later against the same unchanged process.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.entries.len() * 16);
        out.extend_from_slice(MAP_MAGIC);
        out.push(u8::from(self.truncated));
        out.extend_from_slice(&[0u8; 7]);
        out.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for &(value, addr) in &self.entries {
            out.extend_from_slice(&(value as u64).to_le_bytes());
            out.extend_from_slice(&(addr as u64).to_le_bytes());
        }
        out
    }

    /// Read a map written by [`Self::to_bytes`].
    pub fn from_bytes(data: &[u8]) -> core::result::Result<Self, PointerMapIoError> {
        if data.len() < 24 || &data[..8] != MAP_MAGIC {
            return Err(PointerMapIoError::BadFormat);
        }
        let truncated = data[8] != 0;
        let count =
            u64::from_le_bytes(data[16..24].try_into().unwrap()) as usize;
        // Checked before allocating: a corrupt header must not be able to ask
        // for a terabyte.
        let needed = count.checked_mul(16).ok_or(PointerMapIoError::Truncated)?;
        if data.len() - 24 != needed {
            return Err(PointerMapIoError::Truncated);
        }
        let mut entries = Vec::with_capacity(count);
        for chunk in data[24..].as_chunks::<16>().0 {
            let value = u64::from_le_bytes(chunk[..8].try_into().unwrap()) as usize;
            let addr = u64::from_le_bytes(chunk[8..].try_into().unwrap()) as usize;
            entries.push((value, addr));
        }
        // The search relies on this ordering for its range queries, and the file
        // is not trusted to have preserved it.
        entries.sort_unstable();
        entries.dedup();
        Ok(Self { entries, truncated })
    }

    /// Reverse-scan for pointer paths that resolve to `goal`.
    pub fn find_paths(&self, goal: usize, cfg: &PointerScanConfig) -> PointerScanResult {
        self.find_paths_with(goal, cfg, &mut NoPointerObserver)
    }

    /// Level-by-level reverse breadth-first search from `goal`.
    ///
    /// The previous implementation was an unmemoized depth-first search: the same
    /// intermediate address was re-expanded once per route that reached it, so
    /// the cost was exponential in the depth and a depth-6 scan over a real
    /// process did not finish. This visits each address once per level instead,
    /// which is what makes a deep scan tractable — the same trade Cheat Engine
    /// makes.
    ///
    /// The cost is fidelity: when two routes reach the same address at the same
    /// level, only the first is kept and the second is counted in
    /// [`PointerScanResult::collapsed`] rather than silently dropped. Those
    /// alternatives pass through the same pointers with different offsets.
    pub fn find_paths_with(
        &self,
        goal: usize,
        cfg: &PointerScanConfig,
        observer: &mut dyn PointerScanObserver,
    ) -> PointerScanResult {
        let statics = cfg.static_ranges_sorted();
        let offset_align = cfg.offset_alignment.max(1);
        let mut nodes: Vec<Node> = Vec::new();
        let mut paths: Vec<PointerPath> = Vec::new();
        let mut truncated = false;
        let mut collapsed = 0usize;

        // Addresses already expanded, at any level. Revisiting one can only
        // produce a longer route to the same place.
        let mut seen: HashSet<usize> = HashSet::new();
        seen.insert(goal);

        // The frontier holds `(target address, node index that produced it)`.
        // Level 0 is the goal itself, which has no node behind it.
        let mut frontier: Vec<(usize, Option<usize>)> = vec![(goal, None)];

        for _level in 0..cfg.max_depth {
            if frontier.is_empty() {
                break;
            }
            let mut next: Vec<(usize, Option<usize>)> = Vec::new();

            for (done, &(target, parent)) in frontier.iter().enumerate() {
                if paths.len() >= cfg.max_results {
                    truncated = true;
                    break;
                }
                if done % 256 == 0
                    && !observer.tick(PointerScanProgress {
                        phase: PointerScanPhase::Searching,
                        done,
                        total: frontier.len(),
                        found: paths.len(),
                    })
                {
                    truncated = true;
                    return finish(paths, truncated, collapsed);
                }

                let lo = target.saturating_sub(cfg.max_offset);
                let hi = target.saturating_add(cfg.max_negative_offset);
                let mut extended = false;
                for (value, addr) in self.range(lo, hi) {
                    // `offset` is what gets added *after* dereferencing `addr`,
                    // so it is the distance from the stored value to the target.
                    let offset = target as isize - value as isize;
                    if !offset.unsigned_abs().is_multiple_of(offset_align) {
                        continue;
                    }

                    let node_index = nodes.len();
                    nodes.push(Node { offset, parent });

                    if is_mapped(&statics, addr) {
                        paths.push(PointerPath {
                            base: addr,
                            offsets: chain_from(&nodes, node_index),
                        });
                        if paths.len() >= cfg.max_results {
                            truncated = true;
                            break;
                        }
                        // A static anchor completes the path; a chain does not
                        // continue past its own base.
                        continue;
                    }

                    if !seen.insert(addr) {
                        // Reached before, at this level or a shallower one.
                        collapsed += 1;
                        continue;
                    }
                    if next.len() >= cfg.max_frontier {
                        truncated = true;
                        continue;
                    }
                    extended = true;
                    next.push((addr, Some(node_index)));
                }

                // Nothing points at this address, so the chain ends here. It is
                // not anchored and will not survive a restart, which is exactly
                // what `must_end_in_static` decides about.
                if !extended
                    && !cfg.must_end_in_static
                    && let Some(parent) = parent
                {
                    paths.push(PointerPath {
                        base: target,
                        offsets: chain_from(&nodes, parent),
                    });
                }
            }

            if paths.len() >= cfg.max_results {
                truncated = true;
                break;
            }
            frontier = next;
        }

        // Chains still in flight when the depth budget ran out. Same caveat as
        // the dead ends above.
        if !cfg.must_end_in_static {
            for &(addr, parent) in &frontier {
                if let Some(parent) = parent {
                    paths.push(PointerPath { base: addr, offsets: chain_from(&nodes, parent) });
                }
            }
        }

        finish(paths, truncated, collapsed)
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

/// One node in a reverse search: an address holding a pointer, the offset
/// applied after dereferencing it, and the node one level closer to the goal.
struct Node {
    offset: isize,
    parent: Option<usize>,
}

/// Walk a node back to the root, producing the offsets in base→goal order.
fn chain_from(nodes: &[Node], index: usize) -> Vec<isize> {
    // `index` is the node nearest the base and its parent chain runs toward the
    // goal, so walking it yields the offsets already in application order.
    let mut offsets = Vec::new();
    let mut cursor = Some(index);
    while let Some(i) = cursor {
        offsets.push(nodes[i].offset);
        cursor = nodes[i].parent;
    }
    offsets
}

/// Order the results and hand them back.
fn finish(
    mut paths: Vec<PointerPath>,
    truncated: bool,
    collapsed: usize,
) -> PointerScanResult {
    // Identical chains can be produced by two static anchors that alias, and a
    // result list is much easier to read best-first.
    paths.sort_by_key(|p| (p.score(), p.base));
    paths.dedup();
    PointerScanResult { paths, truncated, collapsed }
}

/// A failure reading a saved pointer map.
#[derive(Debug)]
pub enum PointerMapIoError {
    /// Not a nemclass pointer map, or from a newer format.
    BadFormat,
    /// Truncated or corrupt.
    Truncated,
}

impl core::fmt::Display for PointerMapIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadFormat => write!(f, "not a nemclass pointer-map file"),
            Self::Truncated => write!(f, "the pointer-map file is truncated or corrupt"),
        }
    }
}

impl std::error::Error for PointerMapIoError {}

impl PointerScanConfig {
    /// The static ranges as sorted, coalesced `(base, end)` pairs.
    ///
    /// Coalesced because two selected modules with abutting or overlapping spans
    /// would otherwise each contain the same address, and `is_mapped`'s
    /// "last range whose base ≤ addr" lookup only ever consults one of them —
    /// so an anchor inside the overlap could be missed depending on which range
    /// sorted first.
    fn static_ranges_sorted(&self) -> Vec<(usize, usize)> {
        coalesce_ranges(self.static_ranges.clone())
            .into_iter()
            .map(|r| (r.base, r.end()))
            .collect()
    }
}

/// Sort and merge touching or overlapping regions.
fn coalesce_ranges(regions: Vec<Region>) -> Vec<Region> {
    crate::target::coalesce_regions(regions)
}

/// Read a little-endian pointer-sized word (1..=8 bytes) into a `usize`.
///
/// Shared with [`crate::spider`], which harvests candidate pointers the same way.
pub(crate) fn read_word(bytes: &[u8]) -> usize {
    // Accumulate in `u64`, not `usize`: the default `pointer_size` is 8, so on a
    // 32-bit host `(b as usize) << (i * 8)` would shift a 32-bit value by up to
    // 56 — a panic in debug and a silently masked result in release.
    let mut v = 0u64;
    for (i, &b) in bytes.iter().take(8).enumerate() {
        v |= u64::from(b) << (i * 8);
    }
    v as usize
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

/// Convenience: build a [`PointerMap`] and immediately scan it for `goal`.
pub fn pointer_scan<T: ScanTarget>(
    target: &T,
    goal: usize,
    cfg: &PointerScanConfig,
) -> Result<PointerScanResult> {
    pointer_scan_with(target, goal, cfg, &mut NoPointerObserver)
}

/// [`pointer_scan`] with progress reporting and cooperative cancellation.
pub fn pointer_scan_with<T: ScanTarget>(
    target: &T,
    goal: usize,
    cfg: &PointerScanConfig,
    observer: &mut dyn PointerScanObserver,
) -> Result<PointerScanResult> {
    let map = PointerMap::build_with(target, cfg, observer)?;
    let mut result = map.find_paths_with(goal, cfg, observer);
    result.truncated |= map.truncated();
    Ok(result)
}

/// Re-check a set of paths against the live target after it has restarted.
///
/// Cheat Engine's "rescan": module bases move, the heap is laid out differently,
/// and most of a previous scan's chains no longer lead anywhere. `module_base`
/// pairs let a path's static anchor be re-based; a path whose anchor is not
/// inside any known module is kept as an absolute address.
///
/// Returns the paths that still resolve to `goal`.
pub fn rescan_paths(
    paths: &[PointerPath],
    goal: usize,
    rebase: impl Fn(usize) -> Option<usize>,
    read_ptr: impl Fn(usize) -> Option<usize>,
) -> Vec<PointerPath> {
    paths
        .iter()
        .filter_map(|path| {
            let base = rebase(path.base).unwrap_or(path.base);
            let candidate = PointerPath { base, offsets: path.offsets.clone() };
            (candidate.resolve(&read_ptr) == Some(goal)).then_some(candidate)
        })
        .collect()
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

    #[test]
    fn chunk_overlap_does_not_duplicate_map_entries() {
        // `build` walks a region in 1 MiB windows that deliberately overlap by
        // one pointer width, so the word at each internal boundary is harvested
        // twice. Sorting on the value alone left those pairs in arbitrary order
        // and `dedup` (consecutive-only) missed them, so every boundary leaked a
        // duplicate entry — and `find_paths` then emitted the same path twice.
        const CHUNK: usize = 1 << 20;
        let base = 0x10000usize;
        let mut buf = vec![0u8; CHUNK + 0x100];

        // The duplicated slot is the one at the window boundary.
        let dup_addr = base + CHUNK;
        put(&mut buf, base, dup_addr, 0x20000);

        let target =
            MockTarget::with_regions(base, buf, vec![Region::new(base, CHUNK + 0x100)]);
        let cfg = PointerScanConfig { alignment: 8, pointer_size: 8, ..Default::default() };
        let map = PointerMap::build(&target, &cfg).unwrap();

        let hits = map.entries.iter().filter(|&&(v, a)| v == 0x20000 && a == dup_addr).count();
        assert_eq!(hits, 1, "the boundary word must be harvested exactly once");

        let mut sorted = map.entries.clone();
        sorted.sort_unstable();
        let before = sorted.len();
        sorted.dedup();
        assert_eq!(before, sorted.len(), "the map must contain no duplicate pairs at all");
    }

    // ── the parity work: BFS, negative offsets, filters, persistence ────────

    #[test]
    fn a_deep_scan_over_a_dense_chain_finishes() {
        // A pointer that every slot in a block points at, repeated down a chain.
        // Under the previous unmemoized depth-first search this re-expanded the
        // same address once per route reaching it, so the work was exponential
        // in the depth and a depth-6 scan did not return. The level-by-level
        // walk visits each address once, so this completes.
        let base = 0x10000usize;
        let mut buf = vec![0u8; 0x8000];
        // Static anchor.
        put(&mut buf, base, 0x10000, 0x11000);
        // 256 slots in the first block all point into the second, and so on.
        for level in 0..4 {
            let block = 0x11000 + level * 0x1000;
            let next = block + 0x1000;
            for slot in 0..256 {
                put(&mut buf, base, block + slot * 8, next);
            }
        }
        let target = MockTarget::with_regions(
            base,
            buf,
            vec![Region::new(0x10000, 0x100), Region::new(0x11000, 0x5000)],
        );
        let cfg = PointerScanConfig {
            max_depth: 6,
            max_offset: 0x800,
            alignment: 8,
            static_ranges: vec![Region::new(0x10000, 0x100)],
            max_results: 200,
            ..Default::default()
        };
        let result = pointer_scan(&target, 0x15000, &cfg).unwrap();
        assert!(!result.paths.is_empty(), "a chain to the goal exists");
        // Collapsed routes are reported rather than silently dropped.
        assert!(result.collapsed > 0, "the dense block has alternative routes");
    }

    #[test]
    fn a_negative_offset_chain_is_found_only_when_asked_for() {
        // The pointer sits *after* the field it names: 0x20040 holds 0x20050,
        // and the goal is 0x20040 — reached with -0x10.
        let base = 0x10000usize;
        let mut buf = vec![0u8; 0x10100];
        put(&mut buf, base, 0x10000, 0x20050);
        let target = MockTarget::with_regions(
            base,
            buf,
            vec![Region::new(0x10000, 0x100), Region::new(0x20000, 0x100)],
        );
        let statics = vec![Region::new(0x10000, 0x100)];

        let forwards = PointerScanConfig {
            max_depth: 3,
            static_ranges: statics.clone(),
            ..Default::default()
        };
        assert!(
            pointer_scan(&target, 0x20040, &forwards).unwrap().paths.is_empty(),
            "a backwards hop is not reachable with forward offsets only"
        );

        let backwards = PointerScanConfig {
            max_depth: 3,
            max_negative_offset: 0x100,
            static_ranges: statics,
            ..Default::default()
        };
        let result = pointer_scan(&target, 0x20040, &backwards).unwrap();
        assert!(
            result.paths.iter().any(|p| p.base == 0x10000 && p.offsets == vec![-0x10]),
            "expected [-0x10], got {:?}",
            result.paths
        );
    }

    #[test]
    fn the_offset_alignment_filter_drops_unaligned_hops() {
        // *0x10000 == 0x20000, and the goal is 4 bytes in — an offset of 4.
        let base = 0x10000usize;
        let mut buf = vec![0u8; 0x10100];
        put(&mut buf, base, 0x10000, 0x20000);
        let target = MockTarget::with_regions(
            base,
            buf,
            vec![Region::new(0x10000, 0x100), Region::new(0x20000, 0x100)],
        );
        let statics = vec![Region::new(0x10000, 0x100)];

        let any = PointerScanConfig {
            max_depth: 2,
            static_ranges: statics.clone(),
            ..Default::default()
        };
        assert_eq!(pointer_scan(&target, 0x20004, &any).unwrap().paths.len(), 1);

        let eight_aligned = PointerScanConfig {
            max_depth: 2,
            offset_alignment: 8,
            static_ranges: statics,
            ..Default::default()
        };
        assert!(
            pointer_scan(&target, 0x20004, &eight_aligned).unwrap().paths.is_empty(),
            "an offset of 4 is not 8-aligned"
        );
    }

    #[test]
    fn without_must_end_in_static_the_heap_chains_are_reported_too() {
        // No static range at all: every chain runs out of depth on the heap.
        let (target, goal) = two_level_target();
        let strict = PointerScanConfig {
            max_depth: 3,
            static_ranges: Vec::new(),
            ..Default::default()
        };
        assert!(
            pointer_scan(&target, goal, &strict).unwrap().paths.is_empty(),
            "nothing anchors, so nothing survives a restart"
        );

        let loose = PointerScanConfig {
            max_depth: 3,
            static_ranges: Vec::new(),
            must_end_in_static: false,
            ..Default::default()
        };
        assert!(
            !pointer_scan(&target, goal, &loose).unwrap().paths.is_empty(),
            "the same chains are useful for understanding the structure"
        );
    }

    #[test]
    fn results_come_back_best_first() {
        let paths = vec![
            PointerPath { base: 0x1000, offsets: vec![0x8, 0x10, 0x18] },
            PointerPath { base: 0x1000, offsets: vec![0xFA0] },
            PointerPath { base: 0x1000, offsets: vec![0x8] },
        ];
        let mut sorted = paths.clone();
        sorted.sort_by_key(|p| (p.score(), p.base));
        assert_eq!(sorted[0].offsets, vec![0x8], "shortest and smallest first");
        assert_eq!(sorted[1].offsets, vec![0xFA0], "still shorter than three hops");
        assert_eq!(sorted[2].offsets.len(), 3);
    }

    #[test]
    fn a_saved_pointer_map_reloads_and_finds_the_same_paths() {
        let (target, goal) = two_level_target();
        let cfg = PointerScanConfig {
            max_depth: 4,
            static_ranges: vec![Region::new(0x10000, 0x100)],
            ..Default::default()
        };
        let map = PointerMap::build(&target, &cfg).unwrap();
        let expected = map.find_paths(goal, &cfg);

        // Building the map is most of the cost of a scan, and it was rebuilt
        // from scratch for every goal.
        let bytes = map.to_bytes();
        let reloaded = PointerMap::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded.len(), map.len());
        assert_eq!(reloaded.find_paths(goal, &cfg).paths, expected.paths);

        assert!(matches!(
            PointerMap::from_bytes(b"junk"),
            Err(PointerMapIoError::BadFormat)
        ));
        let mut corrupt = bytes.clone();
        corrupt[16..24].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        assert!(matches!(
            PointerMap::from_bytes(&corrupt),
            Err(PointerMapIoError::Truncated)
        ));
    }

    #[test]
    fn a_rescan_keeps_only_the_chains_that_still_reach_the_goal() {
        let (target, goal) = two_level_target();
        let read_ptr = |addr: usize| -> Option<usize> {
            let mut b = [0u8; 8];
            let n = target.read(addr, &mut b).ok()?;
            (n >= 8).then(|| u64::from_le_bytes(b) as usize)
        };
        let paths = vec![
            PointerPath { base: 0x10000, offsets: vec![0x40, 0x14] },
            PointerPath { base: 0x10000, offsets: vec![0x40, 0x99] },
        ];
        let kept = rescan_paths(&paths, goal, |_| None, read_ptr);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].offsets, vec![0x40, 0x14]);
    }

    #[test]
    fn a_rescan_rebases_a_moved_module() {
        // The chain was found against a module at 0x10000; after a restart the
        // same module is at 0x30000, so the anchor has to move with it.
        let base = 0x10000usize;
        let mut buf = vec![0u8; 0x21000];
        put(&mut buf, base, 0x30000, 0x20000);
        let target = MockTarget::with_regions(
            base,
            buf,
            vec![Region::new(0x30000, 0x100), Region::new(0x20000, 0x100)],
        );
        let read_ptr = |addr: usize| -> Option<usize> {
            let mut b = [0u8; 8];
            let n = target.read(addr, &mut b).ok()?;
            (n >= 8).then(|| u64::from_le_bytes(b) as usize)
        };
        let stale = vec![PointerPath { base: 0x10000, offsets: vec![0x10] }];
        assert!(rescan_paths(&stale, 0x20010, |_| None, read_ptr).is_empty());

        let kept = rescan_paths(&stale, 0x20010, |a| Some(a + 0x20000), read_ptr);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].base, 0x30000, "the anchor followed the module");
    }

    #[test]
    fn a_cancelled_scan_returns_what_it_had_rather_than_hanging() {
        let (target, goal) = two_level_target();
        let cfg = PointerScanConfig {
            max_depth: 4,
            static_ranges: vec![Region::new(0x10000, 0x100)],
            ..Default::default()
        };
        let mut ticks = 0usize;
        let result = pointer_scan_with(&target, goal, &cfg, &mut |_p: PointerScanProgress| {
            ticks += 1;
            false
        })
        .unwrap();
        assert!(ticks > 0, "the observer was consulted");
        assert!(result.truncated, "a stopped scan says its results are partial");
    }

    #[test]
    fn overlapping_static_ranges_do_not_hide_an_anchor() {
        // Two selected modules whose spans overlap. `is_mapped` consults only the
        // last range whose base is below the address, so an un-merged pair could
        // report an anchor inside the overlap as not static.
        let cfg = PointerScanConfig {
            static_ranges: vec![Region::new(0x1000, 0x3000), Region::new(0x2000, 0x1000)],
            ..Default::default()
        };
        let merged = cfg.static_ranges_sorted();
        assert_eq!(merged, vec![(0x1000, 0x4000)]);
        assert!(is_mapped(&merged, 0x3500));
    }
}
