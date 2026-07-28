//! Structure spider — a forward, depth-bounded search for a value *inside* a
//! known object, following nested pointers as it goes.
//!
//! # What it is (and what it is not)
//! The [`Scanner`](crate::Scanner) answers "which addresses hold 100?" and knows
//! nothing about structure. The [pointer scan](crate::pointerscan) answers "what
//! static chain reaches this address?" and works *backwards* from a known
//! address. The spider answers the question you actually have while reversing a
//! struct:
//!
//! > I have a pointer to the player object. Where inside it — through however
//! > many nested pointers — does health live?
//!
//! So it is a combination of both: at every aligned slot of a hypothetical
//! struct it *simultaneously* (a) compares the slot against a needle, exactly as
//! the value scanner does, and (b) follows the slot as a pointer into a child
//! struct one level down, exactly as a pointer chain does. Hits come out as
//! offset paths — `[[0x7f2a10 + 0x18] + 0x40] + 0x14` — that drop straight into
//! the address list or become a `ClassNode.address_formula`.
//!
//! # How it works
//! A breadth-first frontier of [`Frame`]s, drained one depth level at a time:
//!
//! 1. Snapshot the target's readable regions once, sorted, as the mapped-memory
//!    oracle for candidate pointers.
//! 2. Seed the frontier with the root address at depth 0.
//! 3. For each frame, read its whole struct window in **one** call, then walk the
//!    window on the alignment lattice. Each slot is value-compared, and each
//!    pointer-aligned slot whose word points into mapped memory becomes a child
//!    frame one level deeper.
//! 4. Stop at [`SpiderConfig::max_depth`] hops, [`SpiderConfig::max_results`]
//!    hits, or [`SpiderConfig::max_nodes`] visited structs — reporting the cap
//!    via [`SpiderScanResult::truncated`] rather than silently dropping work.
//!
//! # Deviations from the yclass original this was ported from
//! - **BFS + a visited set** instead of an unbounded recursive spawn. yclass is
//!   exponential (branching `struct_size / pointer_size` to the power of depth);
//!   bounding by *unique struct* makes the cost linear in reachable memory and
//!   guarantees the **shortest** path to each struct is the one reported. Two
//!   paths to the same struct therefore collapse to one — set
//!   [`SpiderConfig::dedupe_nodes`] to `false` to get yclass's behaviour back.
//! - **One read per node**, not one per slot. Syscalls dominate this workload;
//!   at `struct_size = 0x1000, alignment = 8` that is ~512× fewer of them.
//! - **Typed comparison** via [`Needle`], so a `u64` above 2⁵³ matches exactly
//!   (yclass widens every value to `f64`) and `GreaterThan`/`Between` work.
//! - **Width-aware pointer reads** via [`SpiderConfig::pointer_size`], so 32-bit
//!   targets resolve correctly.
//! - **Offsets anchored to the raw node address**, never to the alignment-rounded
//!   start of the window — see [`SpiderPath`].

use std::collections::HashSet;
use std::sync::Arc;

use crate::compare::ScanCompareType;
use crate::pointerscan::{is_mapped, read_word};
use crate::scanner::{ScanError, ScanObserver, ScanProgress};
use crate::target::ScanTarget;
use crate::value_type::{Needle, ScanValueType};

/// The result type of a spider pass. Shares [`ScanError`] with the value scanner
/// so a UI has one error vocabulary and one status line to format.
pub type Result<T> = core::result::Result<T, ScanError>;

/// Upper bound on [`SpiderConfig::struct_size`]. Matches yclass's cap: past this
/// a "struct" is really just a region scan, which the value scanner does better.
pub const MAX_STRUCT_SIZE: usize = 0x4000;

/// Upper bound on [`SpiderConfig::max_depth`], also from yclass.
pub const MAX_DEPTH: usize = 8;

/// Page granularity for the fallback read path (see [`read_window`]).
const PAGE: usize = 4096;

/// How many struct nodes to visit between [`ScanObserver`] ticks. A node is a
/// syscall plus a window walk, so this is far coarser than the value scanner's
/// per-candidate interval while still keeping Stop responsive.
const PROGRESS_INTERVAL: usize = 64;

/// Tunables for a spider search.
#[derive(Debug, Clone)]
pub struct SpiderConfig {
    /// How many bytes of each candidate struct to examine, starting at its base.
    /// Clamped to `1..=`[`MAX_STRUCT_SIZE`].
    pub struct_size: usize,
    /// Step between candidate value slots. `0` means "use the value type's
    /// width" — Cheat Engine's Fast Scan.
    pub alignment: usize,
    /// Maximum number of dereference hops, i.e. the largest
    /// [`SpiderPath::parent_offsets`] length a hit may have. `0` searches only
    /// the root struct. Clamped to `0..=`[`MAX_DEPTH`].
    pub max_depth: usize,
    /// Pointer width in bytes (8 for 64-bit targets, 4 for 32-bit).
    pub pointer_size: usize,
    /// Hard cap on returned hits; the search stops early once reached.
    pub max_results: usize,
    /// Hard cap on visited struct nodes, bounding a search over a densely
    /// self-referential heap.
    pub max_nodes: usize,
    /// Collapse multiple paths reaching the same struct into the shortest one.
    /// See the module docs; `false` reproduces yclass, at exponential cost.
    pub dedupe_nodes: bool,
}

impl Default for SpiderConfig {
    fn default() -> Self {
        Self {
            struct_size: 0x1000,
            alignment: 4,
            max_depth: 3,
            pointer_size: 8,
            max_results: 100_000,
            max_nodes: 1_000_000,
            dedupe_nodes: true,
        }
    }
}

impl SpiderConfig {
    /// This config with every knob forced into its supported range. Applied
    /// internally by [`spider_scan_with`], so a caller can pass raw user input.
    pub fn clamped(&self) -> Self {
        Self {
            struct_size: self.struct_size.clamp(1, MAX_STRUCT_SIZE),
            alignment: self.alignment,
            max_depth: self.max_depth.min(MAX_DEPTH),
            pointer_size: self.pointer_size.clamp(1, 8),
            max_results: self.max_results.max(1),
            max_nodes: self.max_nodes.max(1),
            dedupe_nodes: self.dedupe_nodes,
        }
    }
}

/// One discovered path from the search root to a matching value.
///
/// Read it as: dereference `root + parent_offsets[0]`, then `+ parent_offsets[1]`
/// and dereference again, and so on; the value sits at `+ offset` from the last
/// dereferenced address, with **no** final dereference. An empty
/// `parent_offsets` means the value lives directly inside the root struct.
///
/// # Offsets anchor to the raw root
/// Every offset is relative to the *unrounded* address of its struct, never to
/// the alignment-rounded first slot. This is the bug the yclass egui build still
/// has: with `root = 0x1003` and `alignment = 4` the first slot is `0x1004`, and
/// recording offsets against `0x1004` makes the chain resolve to the wrong place.
/// [`spider_scan`] and [`SpiderPath::resolve`] agree on the raw-root convention,
/// and a test pins it.
///
/// Note this differs from [`PointerPath`](crate::PointerPath), whose *last*
/// offset is the one that is not dereferenced; a `SpiderPath` keeps that offset
/// in a separate field precisely so the two conventions cannot be confused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiderPath {
    /// The address the search started from.
    pub root: usize,
    /// Offsets that are dereferenced, in order from the root.
    ///
    /// Shared behind an `Arc` because every hit found in one struct carries the
    /// same prefix — on a wide search that is the difference between one
    /// allocation per struct and one per hit.
    pub parent_offsets: Arc<[usize]>,
    /// The final offset, at which the value sits. Not dereferenced.
    pub offset: usize,
}

impl SpiderPath {
    /// Number of dereference hops from the root (0 for a value in the root
    /// struct itself).
    pub fn depth(&self) -> usize {
        self.parent_offsets.len()
    }

    /// Walk this path against live memory, returning the address the value
    /// currently sits at, or `None` if any hop reads unmapped memory or a null
    /// pointer.
    ///
    /// `read_ptr(addr)` must read a pointer-sized word at `addr`. A null hop is
    /// treated as a failure rather than dereferenced, so a stale path can never
    /// resolve to a small bogus address.
    pub fn resolve(&self, mut read_ptr: impl FnMut(usize) -> Option<usize>) -> Option<usize> {
        let mut addr = self.root;
        for &off in self.parent_offsets.iter() {
            addr = read_ptr(addr.checked_add(off)?)?;
            if addr == 0 {
                return None;
            }
        }
        addr.checked_add(self.offset)
    }

    /// Render this path as a nemclass **address formula** on top of an arbitrary
    /// base expression, e.g. `[[<game.exe> + 0x18] + 0x40] + 0x14`.
    ///
    /// The caller supplies the base so the engine stays free of module-lookup
    /// concerns: pass [`Self::to_formula_raw`]'s literal for a bare address, or
    /// [`Self::to_formula_at_module`] to anchor the chain in a module image so it
    /// survives ASLR. The result parses with `nemclass_model::parse_address` and
    /// can be assigned directly to a `ClassNode.address_formula` or used as a
    /// cheat-table entry's address.
    pub fn to_formula(&self, base_expr: &str) -> String {
        let mut expr = base_expr.to_string();
        for off in self.parent_offsets.iter() {
            expr = format!("[{expr} + {off:#x}]");
        }
        format!("{expr} + {:#x}", self.offset)
    }

    /// [`Self::to_formula`] with the root as a bare hex literal. Simple, but the
    /// formula is only valid until the target restarts.
    pub fn to_formula_raw(&self) -> String {
        self.to_formula(&format!("{:#x}", self.root))
    }

    /// [`Self::to_formula`] with the root expressed relative to a module image,
    /// so the whole chain survives ASLR. `module_base` is the runtime base the
    /// search ran against.
    pub fn to_formula_at_module(&self, module_name: &str, module_base: usize) -> String {
        let base_off = self.root.wrapping_sub(module_base);
        let base = if base_off == 0 {
            format!("<{module_name}>")
        } else {
            format!("<{module_name}> + {base_off:#x}")
        };
        self.to_formula(&base)
    }
}

/// One spider hit: where the value is, and what it read.
///
/// `current`/`previous` mirror [`ScanResults`](crate::ScanResults): on the
/// initial search they are equal, and each [`spider_refine_with`] pass rotates
/// the reading that survived into `previous`. That is what makes
/// `Changed`/`Unchanged` refinement work.
#[derive(Debug, Clone)]
pub struct SpiderHit {
    /// The offset path from the search root to this value.
    pub path: SpiderPath,
    /// The value's bytes as of the most recent pass.
    pub current: Vec<u8>,
    /// The value's bytes as of the pass before that.
    pub previous: Vec<u8>,
}

/// The outcome of a spider search.
#[derive(Debug, Clone)]
pub struct SpiderScanResult {
    /// Discovered hits, shallowest first (a consequence of the breadth-first
    /// walk — no explicit sort needed).
    pub hits: Vec<SpiderHit>,
    /// True if the search stopped at `max_results` or `max_nodes`.
    pub truncated: bool,
    /// How many distinct struct nodes were examined. Surfaced in the UI because
    /// it is the honest measure of how much of the object graph was covered.
    pub nodes_visited: usize,
}

/// A struct node still to be examined.
struct Frame {
    /// Base address of the candidate struct.
    addr: usize,
    /// Dereference hops taken to get here.
    depth: usize,
    /// The offsets dereferenced to get here, shared by every hit found inside.
    path: Arc<[usize]>,
}

/// Which parts of a read window actually came back.
///
/// The common case is one contiguous read, kept separate so the per-slot bounds
/// check stays a single comparison.
enum Cover {
    /// Bytes `0..n` are valid.
    Full(usize),
    /// Only these (sorted, disjoint) offset spans are valid.
    Sparse(Vec<(usize, usize)>),
}

impl Cover {
    /// Whether `[off, off + need)` was read successfully.
    fn has(&self, off: usize, need: usize) -> bool {
        let Some(end) = off.checked_add(need) else {
            return false;
        };
        match self {
            Self::Full(n) => end <= *n,
            Self::Sparse(spans) => spans.iter().any(|&(s, e)| off >= s && end <= e),
        }
    }

    /// The highest valid offset, for bounding the slot walk.
    fn limit(&self) -> usize {
        match self {
            Self::Full(n) => *n,
            Self::Sparse(spans) => spans.last().map_or(0, |&(_, e)| e),
        }
    }
}

/// Read `[addr, addr + buf.len())`, tolerating unmapped pages inside the span.
///
/// A struct window is one `read` in the common case. But a real target's read is
/// a single `process_vm_readv`, which fails *wholesale* if any page in the span
/// is unmapped — whereas yclass's per-slot reads only ever lost the one slot. So
/// on a failed or short read this retries page by page and reports exactly which
/// spans came back, restoring that granularity for the price of one extra
/// syscall per page, and only on windows that straddle a hole.
fn read_window<T: ScanTarget>(target: &T, addr: usize, buf: &mut [u8]) -> Cover {
    if let Ok(n) = target.read(addr, buf) {
        if n == buf.len() {
            return Cover::Full(n);
        }
        // A short read is still contiguous from the start; only fall through to
        // the page walk if nothing came back at all, since a short read at a
        // region edge is normal and the tail genuinely is not there.
        if n > 0 {
            return Cover::Full(n);
        }
    }

    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut off = 0usize;
    while off < buf.len() {
        // Split on absolute page boundaries so each retry maps to one real page.
        let next_boundary = (addr + off).next_multiple_of(PAGE) - addr;
        let end = next_boundary.clamp(off + 1, buf.len());
        if let Ok(n) = target.read(addr + off, &mut buf[off..end])
            && n > 0
        {
            match spans.last_mut() {
                // Coalesce with the previous span when the pages abut.
                Some(last) if last.1 == off => last.1 = off + n,
                _ => spans.push((off, off + n)),
            }
        }
        off = end;
    }
    Cover::Sparse(spans)
}

/// Search `target` for `needle` inside the object graph reachable from `root`.
///
/// Convenience wrapper over [`spider_scan_with`] with no progress reporting.
pub fn spider_scan<T: ScanTarget>(
    target: &T,
    root: usize,
    cfg: &SpiderConfig,
    value_type: ScanValueType,
    compare: ScanCompareType,
    needle: Option<Needle>,
) -> Result<SpiderScanResult> {
    spider_scan_with(
        target,
        root,
        cfg,
        value_type,
        compare,
        needle,
        &mut crate::scanner::NoObserver,
    )
}

/// [`spider_scan`] with progress reporting and cooperative cancellation.
///
/// `observer` is ticked every [`PROGRESS_INTERVAL`] struct nodes; returning
/// `false` aborts with [`ScanError::Cancelled`]. Because the total work is not
/// knowable up front (it is discovered as pointers are followed),
/// [`ScanProgress::total`] is reported as "nodes done plus nodes queued" — an
/// estimate that grows as the frontier expands and converges as it drains.
pub fn spider_scan_with<T: ScanTarget>(
    target: &T,
    root: usize,
    cfg: &SpiderConfig,
    value_type: ScanValueType,
    compare: ScanCompareType,
    needle: Option<Needle>,
    observer: &mut dyn ScanObserver,
) -> Result<SpiderScanResult> {
    let cfg = cfg.clamped();

    // A spider pass is always a "first scan": there is no previous generation to
    // compare against, so the change-relative compares and the Unknown baseline
    // are both meaningless here. Unknown would additionally match every slot and
    // return the entire reachable object graph.
    if compare.is_baseline() {
        return Err(ScanError::CompareIsFirstScanOnly(compare));
    }
    if compare.needs_previous() {
        return Err(ScanError::CompareNeedsPrevious(compare));
    }
    let Some(needle) = needle else {
        return Err(ScanError::MissingNeedle(compare));
    };
    if needle.value_type() != value_type {
        return Err(ScanError::NeedleTypeMismatch {
            needle: needle.value_type(),
            scanner: value_type,
        });
    }
    let stride = needle.stride();
    if stride == 0 {
        return Err(ScanError::NoStride(value_type));
    }

    // Alignment 0 means "the value type's own width" (Fast Scan).
    let align = if cfg.alignment == 0 { stride } else { cfg.alignment }.max(1);
    let psize = cfg.pointer_size;

    let ranges = {
        let regions = target.regions().map_err(ScanError::Target)?;
        let mut v: Vec<(usize, usize)> = regions.iter().map(|r| (r.base, r.end())).collect();
        v.sort_unstable();
        v
    };

    let mut hits: Vec<SpiderHit> = Vec::new();
    let mut truncated = false;
    let mut nodes_visited = 0usize;

    let mut visited: HashSet<usize> = HashSet::new();
    visited.insert(root);

    // Breadth-first: drain one depth level completely before starting the next,
    // so the first path found to any struct is also the shortest.
    let mut frontier: Vec<Frame> = vec![Frame {
        addr: root,
        depth: 0,
        path: Arc::from(Vec::new()),
    }];
    let mut next: Vec<Frame> = Vec::new();

    // Room for the struct itself, one extra pointer so the last slot's full word
    // is available, and one alignment step of slack for an unaligned root.
    let mut win = vec![0u8; cfg.struct_size + psize + align];

    'search: while !frontier.is_empty() {
        let level = std::mem::take(&mut frontier);
        let mut queued = level.len();
        for frame in level {
            queued -= 1;
            if nodes_visited >= cfg.max_nodes {
                truncated = true;
                break 'search;
            }
            nodes_visited += 1;

            if nodes_visited.is_multiple_of(PROGRESS_INTERVAL)
                && !observer.tick(ScanProgress {
                    done: nodes_visited,
                    total: nodes_visited + queued + next.len(),
                    matches: hits.len(),
                })
            {
                return Err(ScanError::Cancelled);
            }

            let cover = read_window(target, frame.addr, &mut win);
            let limit = cover.limit();
            if limit == 0 {
                continue;
            }

            // First slot at or after the struct base that is absolutely aligned;
            // offsets stay relative to the raw base (see `SpiderPath`).
            let start = frame.addr.next_multiple_of(align) - frame.addr;
            let window_end = start + cfg.struct_size;

            let mut off = start;
            while off < window_end && off < limit {
                // Value branch: does this slot hold what we are looking for?
                if cover.has(off, stride) && needle.compare_first(&win, off, compare) {
                    let bytes = win[off..off + stride].to_vec();
                    hits.push(SpiderHit {
                        path: SpiderPath {
                            root,
                            parent_offsets: Arc::clone(&frame.path),
                            offset: off,
                        },
                        previous: bytes.clone(),
                        current: bytes,
                    });
                    if hits.len() >= cfg.max_results {
                        truncated = true;
                        break 'search;
                    }
                }

                // Pointer branch: does this slot point at another struct? Real
                // pointers are aligned in absolute terms, so test the absolute
                // address rather than the offset.
                if frame.depth < cfg.max_depth
                    && (frame.addr + off) % psize == 0
                    && cover.has(off, psize)
                {
                    let word = read_word(&win[off..off + psize]);
                    if word != 0 && word != frame.addr && is_mapped(&ranges, word) {
                        // The visited set collapses two routes to one struct into
                        // the shorter; with it off, `max_nodes` is the only bound
                        // and a cycle costs one pass per depth level.
                        let fresh = if cfg.dedupe_nodes {
                            visited.insert(word)
                        } else {
                            true
                        };
                        if fresh {
                            let mut path = Vec::with_capacity(frame.path.len() + 1);
                            path.extend_from_slice(&frame.path);
                            path.push(off);
                            next.push(Frame {
                                addr: word,
                                depth: frame.depth + 1,
                                path: Arc::from(path),
                            });
                        }
                    }
                }

                off += align;
            }
        }
        frontier = std::mem::take(&mut next);
    }

    Ok(SpiderScanResult {
        hits,
        truncated,
        nodes_visited,
    })
}

/// Narrow an existing hit list the way Cheat Engine's Next Scan does.
///
/// Every path is re-walked against live memory and re-read; hits whose chain no
/// longer resolves are dropped, and the rest are kept only if the fresh reading
/// satisfies `compare`. Surviving hits rotate their reading into
/// [`SpiderHit::previous`], which is what lets `Changed`/`Unchanged` work on the
/// pass after this one.
///
/// Unlike the initial search this accepts the change-relative compares, and
/// (like [`crate::Scanner::next_scan`]) rejects the `Unknown` baseline.
pub fn spider_refine_with<T: ScanTarget>(
    target: &T,
    hits: &mut Vec<SpiderHit>,
    cfg: &SpiderConfig,
    value_type: ScanValueType,
    compare: ScanCompareType,
    needle: Option<Needle>,
    observer: &mut dyn ScanObserver,
) -> Result<()> {
    if compare.is_baseline() {
        return Err(ScanError::CompareIsFirstScanOnly(compare));
    }
    if compare.needs_needle() && needle.is_none() {
        return Err(ScanError::MissingNeedle(compare));
    }
    if let Some(n) = &needle
        && n.value_type() != value_type
    {
        return Err(ScanError::NeedleTypeMismatch {
            needle: n.value_type(),
            scanner: value_type,
        });
    }
    let stride = match &needle {
        Some(n) => n.stride(),
        None => value_type.fixed_width().unwrap_or(0),
    };
    if stride == 0 {
        return Err(ScanError::NoStride(value_type));
    }

    let psize = cfg.clamped().pointer_size;
    let total = hits.len();
    let mut buf = vec![0u8; stride];
    let mut ptr = vec![0u8; psize];
    let mut kept = 0usize;
    let mut done = 0usize;
    // Collected up front so cancelling mid-pass leaves `hits` untouched.
    let mut verdicts: Vec<Option<Vec<u8>>> = Vec::with_capacity(total);

    for hit in hits.iter() {
        done += 1;
        if done.is_multiple_of(PROGRESS_INTERVAL)
            && !observer.tick(ScanProgress {
                done,
                total,
                matches: kept,
            })
        {
            return Err(ScanError::Cancelled);
        }

        let resolved = hit.path.resolve(|addr| {
            let n = target.read(addr, &mut ptr).ok()?;
            (n == psize).then(|| read_word(&ptr[..psize]))
        });
        let Some(addr) = resolved else {
            verdicts.push(None);
            continue;
        };
        let Ok(n) = target.read(addr, &mut buf) else {
            verdicts.push(None);
            continue;
        };
        if n < stride {
            verdicts.push(None);
            continue;
        }

        let keep = match &needle {
            Some(n) => n.compare_next(&buf, 0, compare, &hit.current),
            None => value_type.compare_change(compare, &buf, &hit.current),
        };
        if keep {
            kept += 1;
            verdicts.push(Some(buf.clone()));
        } else {
            verdicts.push(None);
        }
    }

    let mut it = verdicts.into_iter();
    hits.retain_mut(|hit| match it.next().flatten() {
        Some(fresh) => {
            hit.previous = std::mem::replace(&mut hit.current, fresh);
            true
        }
        None => false,
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{MockTarget, Region};

    const BASE: usize = 0x10000;
    const LEN: usize = 0x1000;

    /// A zeroed buffer mapped at [`BASE`], with absolute-address writers so the
    /// tests read like a memory map rather than like slice arithmetic.
    struct Mem(Vec<u8>);

    impl Mem {
        fn new() -> Self {
            Self(vec![0u8; LEN])
        }

        fn with_len(len: usize) -> Self {
            Self(vec![0u8; len])
        }

        fn ptr(&mut self, at: usize, value: usize) -> &mut Self {
            let off = at - BASE;
            self.0[off..off + 8].copy_from_slice(&(value as u64).to_le_bytes());
            self
        }

        fn ptr32(&mut self, at: usize, value: usize) -> &mut Self {
            let off = at - BASE;
            self.0[off..off + 4].copy_from_slice(&(value as u32).to_le_bytes());
            self
        }

        fn i32(&mut self, at: usize, value: i32) -> &mut Self {
            let off = at - BASE;
            self.0[off..off + 4].copy_from_slice(&value.to_le_bytes());
            self
        }

        fn u64(&mut self, at: usize, value: u64) -> &mut Self {
            let off = at - BASE;
            self.0[off..off + 8].copy_from_slice(&value.to_le_bytes());
            self
        }

        fn target(self) -> MockTarget {
            MockTarget::new(BASE, self.0)
        }
    }

    fn cfg(struct_size: usize, max_depth: usize) -> SpiderConfig {
        SpiderConfig {
            struct_size,
            alignment: 4,
            max_depth,
            ..SpiderConfig::default()
        }
    }

    fn needle_i32(v: &str) -> Needle {
        ScanValueType::I32.parse_needle(v).unwrap()
    }

    fn scan(
        target: &MockTarget,
        root: usize,
        cfg: &SpiderConfig,
        value: &str,
    ) -> SpiderScanResult {
        spider_scan(
            target,
            root,
            cfg,
            ScanValueType::I32,
            ScanCompareType::Exact,
            Some(needle_i32(value)),
        )
        .unwrap()
    }

    /// The headline case: a value two dereferences deep is found, and the path
    /// records the offsets that actually lead to it.
    #[test]
    fn finds_a_value_two_pointers_deep() {
        let mut mem = Mem::new();
        mem.ptr(BASE + 0x10, BASE + 0x200)
            .ptr(BASE + 0x220, BASE + 0x400)
            .i32(BASE + 0x408, 1337);

        let out = scan(&mem.target(), BASE, &cfg(0x100, 2), "1337");

        assert_eq!(out.hits.len(), 1);
        let hit = &out.hits[0];
        assert_eq!(&*hit.path.parent_offsets, &[0x10, 0x20]);
        assert_eq!(hit.path.offset, 0x8);
        assert_eq!(hit.path.depth(), 2);
        assert_eq!(hit.current, 1337i32.to_le_bytes());
        assert_eq!(hit.current, hit.previous, "a first pass seeds previous == current");
        assert!(!out.truncated);
    }

    /// Offsets anchor to the *raw* struct base, not to the alignment-rounded
    /// first slot. This is the exact case the yclass egui build gets wrong: with
    /// `root = 0x10003` and alignment 4 the first slot is `0x10004`, and offsets
    /// recorded against that resolve one struct short.
    #[test]
    fn unaligned_base_offsets_anchor_to_the_raw_root() {
        let root = BASE + 3;
        let child = BASE + 0x207;
        let mut mem = Mem::new();
        mem.ptr(BASE + 0x8, child).i32(BASE + 0x210, 1337);

        let out = scan(&mem.target(), root, &cfg(0x100, 1), "1337");

        assert_eq!(out.hits.len(), 1);
        let path = &out.hits[0].path;
        // 0x10008 - 0x10003 = 0x5, and 0x10210 - 0x10207 = 0x9.
        assert_eq!(&*path.parent_offsets, &[0x5]);
        assert_eq!(path.offset, 0x9);
        assert_eq!(path.to_formula_raw(), "[0x10003 + 0x5] + 0x9");

        // And the recorded offsets round-trip: walking them lands on the value.
        let mut chain = Mem::new();
        chain.ptr(BASE + 0x8, child);
        let target = chain.target();
        let mut buf = [0u8; 8];
        let resolved = path.resolve(|addr| {
            target.read(addr, &mut buf).ok()?;
            Some(read_word(&buf))
        });
        assert_eq!(resolved, Some(BASE + 0x210));
    }

    #[test]
    fn depth_bound_excludes_deeper_hits() {
        let mut mem = Mem::new();
        mem.ptr(BASE + 0x10, BASE + 0x200)
            .ptr(BASE + 0x220, BASE + 0x400)
            .i32(BASE + 0x408, 1337);
        let target = mem.target();

        assert_eq!(scan(&target, BASE, &cfg(0x100, 1), "1337").hits.len(), 0);
        assert_eq!(scan(&target, BASE, &cfg(0x100, 2), "1337").hits.len(), 1);
    }

    /// A pointer cycle must terminate rather than run to the depth bound.
    #[test]
    fn cycles_terminate() {
        let mut mem = Mem::new();
        mem.ptr(BASE + 0x10, BASE + 0x200)
            .ptr(BASE + 0x210, BASE) // back-edge to the root
            .i32(BASE + 0x208, 1337);

        let out = scan(&mem.target(), BASE, &cfg(0x100, 8), "1337");

        assert_eq!(out.hits.len(), 1);
        assert_eq!(out.nodes_visited, 2, "the root and one child, not one per depth level");
    }

    /// Two routes reach the same struct; breadth-first order plus the visited set
    /// means the *shorter* one is the one reported.
    #[test]
    fn dedupe_keeps_the_shortest_path() {
        let mut mem = Mem::new();
        mem.ptr(BASE + 0x10, BASE + 0x400) // root -> C, one hop
            .ptr(BASE + 0x18, BASE + 0x200) // root -> B
            .ptr(BASE + 0x208, BASE + 0x400) // B    -> C, two hops
            .i32(BASE + 0x430, 1337);

        let out = scan(&mem.target(), BASE, &cfg(0x100, 3), "1337");

        assert_eq!(out.hits.len(), 1);
        assert_eq!(&*out.hits[0].path.parent_offsets, &[0x10]);
    }

    /// With dedupe off, both routes to the same struct are reported — yclass's
    /// behaviour, and the reason it explodes exponentially.
    #[test]
    fn dedupe_off_reports_every_route() {
        let mut mem = Mem::new();
        mem.ptr(BASE + 0x10, BASE + 0x400)
            .ptr(BASE + 0x18, BASE + 0x200)
            .ptr(BASE + 0x208, BASE + 0x400)
            .i32(BASE + 0x430, 1337);

        let c = SpiderConfig { dedupe_nodes: false, ..cfg(0x100, 3) };
        let out = scan(&mem.target(), BASE, &c, "1337");

        let mut paths: Vec<Vec<usize>> =
            out.hits.iter().map(|h| h.path.parent_offsets.to_vec()).collect();
        paths.sort();
        assert_eq!(paths, vec![vec![0x10], vec![0x18, 0x8]]);
    }

    /// A wide root so the search runs past a progress interval, letting the
    /// observer abort it.
    fn wide_target() -> MockTarget {
        let mut mem = Mem::with_len(0x40000);
        for i in 0..100usize {
            mem.ptr(BASE + i * 8, BASE + 0x10000 + i * 0x100);
        }
        mem.target()
    }

    #[test]
    fn observer_can_cancel() {
        let mut ticks = 0usize;
        let err = spider_scan_with(
            &wide_target(),
            BASE,
            &cfg(0x400, 2),
            ScanValueType::I32,
            ScanCompareType::Exact,
            Some(needle_i32("1337")),
            &mut |_p: ScanProgress| {
                ticks += 1;
                false
            },
        )
        .unwrap_err();

        assert!(matches!(err, ScanError::Cancelled));
        assert_eq!(ticks, 1, "aborts on the first refusal");
    }

    #[test]
    fn observer_sees_progress() {
        let mut last = ScanProgress { done: 0, total: 0, matches: 0 };
        let out = spider_scan_with(
            &wide_target(),
            BASE,
            &cfg(0x400, 2),
            ScanValueType::I32,
            ScanCompareType::Exact,
            Some(needle_i32("1337")),
            &mut |p: ScanProgress| {
                last = p;
                true
            },
        )
        .unwrap();

        assert!(last.done > 0);
        assert!(last.total >= last.done);
        assert_eq!(out.nodes_visited, 101, "the root plus its 100 children");
    }

    #[test]
    fn max_results_truncates() {
        let mut mem = Mem::new();
        for i in 0..8usize {
            mem.i32(BASE + 0x10 + i * 4, 1337);
        }
        let c = SpiderConfig { max_results: 3, ..cfg(0x100, 0) };

        let out = scan(&mem.target(), BASE, &c, "1337");

        assert_eq!(out.hits.len(), 3);
        assert!(out.truncated);
    }

    /// A target with one unreadable page in the middle of the struct window.
    /// A real `read` fails wholesale when its span touches a hole, so the engine
    /// must fall back to per-page reads rather than losing the whole node.
    struct HoleTarget {
        buf: Vec<u8>,
        hole: (usize, usize),
    }

    impl ScanTarget for HoleTarget {
        fn regions(&self) -> nemclass_core::Result<Vec<Region>> {
            Ok(vec![Region::new(BASE, self.buf.len())])
        }

        fn read(&self, addr: usize, buf: &mut [u8]) -> nemclass_core::Result<usize> {
            let end = addr + buf.len();
            if addr < self.hole.1 && end > self.hole.0 {
                return Ok(0); // the whole transfer fails, as `process_vm_readv` would
            }
            let Some(off) = addr.checked_sub(BASE) else {
                return Ok(0);
            };
            let n = self.buf.len().saturating_sub(off).min(buf.len());
            buf[..n].copy_from_slice(&self.buf[off..off + n]);
            Ok(n)
        }
    }

    #[test]
    fn an_unmapped_page_costs_only_that_page() {
        let mut mem = Mem::with_len(0x3000);
        mem.i32(BASE + 0x800, 1337) // readable page
            .i32(BASE + 0x1800, 1337); // inside the hole
        let target = HoleTarget {
            buf: mem.0,
            hole: (BASE + 0x1000, BASE + 0x2000),
        };

        let out = spider_scan(
            &target,
            BASE,
            &cfg(0x2000, 0),
            ScanValueType::I32,
            ScanCompareType::Exact,
            Some(needle_i32("1337")),
        )
        .unwrap();

        assert_eq!(out.hits.len(), 1, "the readable hit survives the hole");
        assert_eq!(out.hits[0].path.offset, 0x800);
    }

    #[test]
    fn thirty_two_bit_pointer_chains_resolve() {
        let mut mem = Mem::new();
        mem.ptr32(BASE + 0x10, BASE + 0x200).i32(BASE + 0x208, 1337);
        let c = SpiderConfig { pointer_size: 4, ..cfg(0x100, 1) };

        let out = scan(&mem.target(), BASE, &c, "1337");

        assert_eq!(out.hits.len(), 1);
        assert_eq!(&*out.hits[0].path.parent_offsets, &[0x10]);
        assert_eq!(out.hits[0].path.offset, 0x8);
    }

    /// yclass widens every value to `f64` before comparing, so `2^53` and
    /// `2^53 + 1` collide. Typed comparison keeps them distinct.
    #[test]
    fn u64_above_two_to_the_fifty_three_compares_exactly() {
        let mut mem = Mem::new();
        mem.u64(BASE + 0x10, (1u64 << 53) + 1).u64(BASE + 0x20, 1u64 << 53);

        let c = SpiderConfig { alignment: 8, ..cfg(0x100, 0) };
        let out = spider_scan(
            &mem.target(),
            BASE,
            &c,
            ScanValueType::U64,
            ScanCompareType::Exact,
            Some(ScanValueType::U64.parse_needle("9007199254740993").unwrap()),
        )
        .unwrap();

        assert_eq!(out.hits.len(), 1);
        assert_eq!(out.hits[0].path.offset, 0x10);
    }

    #[test]
    fn refine_keeps_only_changed_values_and_rotates_previous() {
        let mut mem = Mem::new();
        mem.i32(BASE + 0x10, 100).i32(BASE + 0x20, 100);
        let mut target = mem.target();

        let mut hits = scan(&target, BASE, &cfg(0x100, 0), "100").hits;
        assert_eq!(hits.len(), 2);

        // Only the first value moves.
        target.buf_mut()[0x10..0x14].copy_from_slice(&150i32.to_le_bytes());

        spider_refine_with(
            &target,
            &mut hits,
            &SpiderConfig::default(),
            ScanValueType::I32,
            ScanCompareType::Changed,
            None,
            &mut crate::scanner::NoObserver,
        )
        .unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path.offset, 0x10);
        assert_eq!(hits[0].previous, 100i32.to_le_bytes());
        assert_eq!(hits[0].current, 150i32.to_le_bytes());
    }

    #[test]
    fn refine_drops_paths_whose_chain_no_longer_resolves() {
        let mut mem = Mem::new();
        mem.ptr(BASE + 0x10, BASE + 0x200).i32(BASE + 0x208, 100);
        let mut target = mem.target();

        let mut hits = scan(&target, BASE, &cfg(0x100, 1), "100").hits;
        assert_eq!(hits.len(), 1);

        // The intermediate pointer is nulled — the chain is now dangling.
        target.buf_mut()[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());

        spider_refine_with(
            &target,
            &mut hits,
            &SpiderConfig::default(),
            ScanValueType::I32,
            ScanCompareType::Exact,
            Some(needle_i32("100")),
            &mut crate::scanner::NoObserver,
        )
        .unwrap();

        assert!(hits.is_empty());
    }

    #[test]
    fn misuse_is_rejected_with_an_actionable_error() {
        let target = Mem::new().target();
        let c = cfg(0x100, 1);
        let run = |compare, needle| {
            spider_scan(&target, BASE, &c, ScanValueType::I32, compare, needle).unwrap_err()
        };

        // Unknown would match every slot in the reachable object graph.
        assert!(matches!(
            run(ScanCompareType::Unknown, None),
            ScanError::CompareIsFirstScanOnly(_)
        ));
        // There is no previous generation on an initial spider pass.
        assert!(matches!(
            run(ScanCompareType::Changed, None),
            ScanError::CompareNeedsPrevious(_)
        ));
        assert!(matches!(run(ScanCompareType::Exact, None), ScanError::MissingNeedle(_)));
        assert!(matches!(
            run(ScanCompareType::Exact, Some(ScanValueType::F32.parse_needle("1.0").unwrap())),
            ScanError::NeedleTypeMismatch { .. }
        ));
    }

    #[test]
    fn config_is_clamped_to_supported_ranges() {
        let c = SpiderConfig {
            struct_size: usize::MAX,
            max_depth: 999,
            pointer_size: 64,
            ..SpiderConfig::default()
        }
        .clamped();

        assert_eq!(c.struct_size, MAX_STRUCT_SIZE);
        assert_eq!(c.max_depth, MAX_DEPTH);
        assert_eq!(c.pointer_size, 8);
    }
}
