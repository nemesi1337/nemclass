//! `.ptrmap` — a saved set of pointer-scan or spider paths.
//!
//! A pointer scan returns thousands of paths and the UI renders a few hundred of
//! them. Everything past the cap was unreachable: you could not read it, filter
//! it, or carry it into the next session. Worse, [`PointerPath`] and
//! [`SpiderPath`] had no serialization at all, so restarting the target threw a
//! half-hour scan away.
//!
//! This is the file that fixes both, and it enables the workflow that actually
//! makes a pointer scan useful: scan, save, restart the target, scan again, and
//! keep only the paths present in *both* runs ([`PtrMapFile::intersect`]). The
//! survivors are the real structure relationships; everything else was a
//! coincidence of one heap layout. That intersection routinely turns twelve
//! thousand paths into a couple of hundred — which fit under the display cap
//! comfortably.
//!
//! # Anchors are module-relative
//! A path is only worth saving if it survives ASLR, so an [`Anchor`] names a
//! module and an offset into it rather than an absolute address. On load,
//! [`PtrMapFile::rebase`] re-resolves each module against the process attached
//! *now*. A chain that never reached a module image (or a spider root, which is
//! usually a heap address) is stored as [`Anchor::Absolute`] and can be shifted
//! by a caller-supplied delta instead.
//!
//! # The two path conventions
//! [`PointerPath`] dereferences its base; [`SpiderPath`] does not, and keeps its
//! final undereferenced offset in a separate field precisely so the two cannot
//! be confused (see the note on [`SpiderPath`]). Both flatten into the same
//! `offsets` vector here — the last element is always the one that is not
//! dereferenced — and every record carries a [`PathKind`] so a load can refuse
//! to reinterpret one as the other. [`ResolvedPath::to_spider_path`] also
//! rejects the negative offsets a `PointerPath` may legitimately carry.

use std::collections::HashSet;
use std::sync::Arc;

use crate::pointerscan::PointerPath;
use crate::spider::SpiderPath;

/// Magic + version for a saved path set.
///
/// A flat binary rather than TOML, matching [`PointerMap`](crate::PointerMap)
/// and [`ScanResults`](crate::ScanResults): the payload is a few fixed-width
/// integers per path repeated tens of thousands of times, and `nemclass-scan`
/// carries no serde dependency.
const PTRMAP_MAGIC: &[u8; 8] = b"NEMPTRS\x01";

/// Which dereference convention a record's offsets use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// A [`PointerPath`]: the anchor is dereferenced, then every offset except
    /// the last is added-and-dereferenced.
    Pointer,
    /// A [`SpiderPath`]: the anchor is *not* dereferenced, and the last offset
    /// locates the value without a final dereference.
    Spider,
}

impl PathKind {
    fn tag(self) -> u8 {
        match self {
            Self::Pointer => 0,
            Self::Spider => 1,
        }
    }

    fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Pointer),
            1 => Some(Self::Spider),
            _ => None,
        }
    }

    /// Lower-case name, for status lines and the text export header.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pointer => "pointer",
            Self::Spider => "spider",
        }
    }
}

/// Where a path starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Anchor {
    /// `offset` bytes into `PtrMapFile::modules[module]`. Survives ASLR.
    Module { module: u16, offset: usize },
    /// A raw address: an unanchored chain, or a spider root on the heap. Only
    /// meaningful for the process it was captured from.
    Absolute(usize),
}

/// A module image the file's anchors refer to, and the base it was captured at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRef {
    /// File name as reported by the module list, e.g. `game.exe`.
    pub name: String,
    /// The runtime base the paths were discovered against.
    pub base: usize,
}

/// One saved path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrMapEntry {
    /// Which convention [`Self::offsets`] follows.
    pub kind: PathKind,
    /// Where the chain starts.
    pub anchor: Anchor,
    /// The chain's offsets. For [`PathKind::Spider`] this is
    /// `parent_offsets ++ [offset]`; for either kind the final element is the
    /// one that is not dereferenced. Signed because a `PointerPath` can reach a
    /// pointer stored earlier in a structure with a negative offset.
    pub offsets: Vec<i64>,
}

/// A whole `.ptrmap` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtrMapFile {
    /// The address the scan was searching for. Informational — kept so a later
    /// session can see what the file was for.
    pub goal: usize,
    /// Modules referenced by [`Anchor::Module`], with the bases captured at
    /// export time.
    pub modules: Vec<ModuleRef>,
    /// The saved paths.
    pub entries: Vec<PtrMapEntry>,
    /// True if the scan that produced these hit a result cap, so the set is
    /// known to be incomplete.
    pub truncated: bool,
}

/// A failure reading a `.ptrmap`, or converting a record back into a path.
#[derive(Debug, PartialEq, Eq)]
pub enum PtrMapError {
    /// Not a nemclass path file, or from a newer format.
    BadFormat,
    /// Internally inconsistent — a truncated or corrupt write.
    Truncated,
    /// A record was loaded into the wrong panel.
    KindMismatch {
        /// What the caller asked for.
        want: PathKind,
        /// What the record actually is.
        got: PathKind,
    },
    /// A spider path cannot carry a negative offset; a pointer path can, so this
    /// is the signature of a record loaded as the wrong kind.
    NegativeSpiderOffset(i64),
    /// A spider path needs at least the final, undereferenced offset.
    EmptySpiderPath,
    /// An offset does not fit this platform's pointer width.
    OffsetOutOfRange(i64),
}

impl core::fmt::Display for PtrMapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadFormat => write!(f, "not a nemclass path-map file"),
            Self::Truncated => write!(f, "the path-map file is truncated or corrupt"),
            Self::KindMismatch { want, got } => write!(
                f,
                "this is a {} path map, not a {} one",
                got.label(),
                want.label()
            ),
            Self::NegativeSpiderOffset(off) => {
                write!(f, "a spider path cannot have the negative offset {off:#x}")
            }
            Self::EmptySpiderPath => write!(f, "a spider path needs at least one offset"),
            Self::OffsetOutOfRange(off) => {
                write!(f, "the offset {off:#x} does not fit a pointer on this platform")
            }
        }
    }
}

impl std::error::Error for PtrMapError {}

/// A path from a `.ptrmap` re-resolved against the process attached now.
///
/// Produced by [`PtrMapFile::rebase`]. The anchor is absolute again, so this
/// converts straight back into a [`PointerPath`] or [`SpiderPath`], and knows
/// its module so [`Self::to_formula`] can emit an ASLR-stable formula.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    /// Which convention [`Self::offsets`] follows.
    pub kind: PathKind,
    /// The anchor address after rebasing.
    pub anchor: usize,
    /// The module the anchor sits in, carrying its *new* base, when the file
    /// recorded one.
    pub module: Option<ModuleRef>,
    /// The chain's offsets, unchanged by rebasing.
    pub offsets: Vec<i64>,
}

impl ResolvedPath {
    /// Convert back into a pointer-scan path.
    pub fn to_pointer_path(&self) -> Result<PointerPath, PtrMapError> {
        self.require(PathKind::Pointer)?;
        let offsets = self
            .offsets
            .iter()
            .map(|&o| isize::try_from(o).map_err(|_| PtrMapError::OffsetOutOfRange(o)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PointerPath { base: self.anchor, offsets })
    }

    /// Convert back into a spider path.
    ///
    /// Fails on a negative offset rather than casting one: that would silently
    /// turn a pointer-scan record into a spider path pointing somewhere else
    /// entirely.
    pub fn to_spider_path(&self) -> Result<SpiderPath, PtrMapError> {
        self.require(PathKind::Spider)?;
        let (&last, parents) =
            self.offsets.split_last().ok_or(PtrMapError::EmptySpiderPath)?;
        let widen = |off: i64| match usize::try_from(off) {
            Ok(o) => Ok(o),
            Err(_) if off < 0 => Err(PtrMapError::NegativeSpiderOffset(off)),
            Err(_) => Err(PtrMapError::OffsetOutOfRange(off)),
        };
        let parent_offsets = parents
            .iter()
            .map(|&o| widen(o))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(SpiderPath {
            root: self.anchor,
            parent_offsets: Arc::from(parent_offsets.as_slice()),
            offset: widen(last)?,
        })
    }

    /// Render as a nemclass address formula, anchored at the module when the
    /// file recorded one and as a bare hex literal otherwise.
    pub fn to_formula(&self) -> String {
        match self.kind {
            PathKind::Pointer => {
                let Ok(path) = self.to_pointer_path() else {
                    return format!("{:#x}", self.anchor);
                };
                match &self.module {
                    Some(m) => path.to_formula(&m.name, m.base),
                    None => path.to_formula_raw(),
                }
            }
            PathKind::Spider => {
                let Ok(path) = self.to_spider_path() else {
                    return format!("{:#x}", self.anchor);
                };
                match &self.module {
                    Some(m) => path.to_formula_at_module(&m.name, m.base),
                    None => path.to_formula_raw(),
                }
            }
        }
    }

    /// Number of dereference hops, matching what the panels show as "Depth".
    pub fn depth(&self) -> usize {
        match self.kind {
            PathKind::Pointer => self.offsets.len(),
            // The trailing offset is the value's position, not a hop.
            PathKind::Spider => self.offsets.len().saturating_sub(1),
        }
    }

    fn require(&self, want: PathKind) -> Result<(), PtrMapError> {
        (self.kind == want)
            .then_some(())
            .ok_or(PtrMapError::KindMismatch { want, got: self.kind })
    }
}

impl PtrMapEntry {
    /// Record a pointer-scan path under an already-computed anchor.
    pub fn from_pointer_path(path: &PointerPath, anchor: Anchor) -> Self {
        Self {
            kind: PathKind::Pointer,
            anchor,
            offsets: path.offsets.iter().map(|&o| o as i64).collect(),
        }
    }

    /// Record a spider path under an already-computed anchor.
    pub fn from_spider_path(path: &SpiderPath, anchor: Anchor) -> Self {
        let mut offsets: Vec<i64> =
            path.parent_offsets.iter().map(|&o| o as i64).collect();
        offsets.push(path.offset as i64);
        Self { kind: PathKind::Spider, anchor, offsets }
    }
}

/// The identity of a path for comparison purposes.
///
/// Deliberately *excludes* the absolute base of a module-anchored path: the base
/// is exactly what moves between two runs of the target, so keying on it would
/// make every comparison empty. A `bool` distinguishes an absolute anchor from a
/// module one so the two cannot collide on the same number.
type PathKey<'a> = (PathKind, bool, Option<&'a str>, usize, &'a [i64]);

impl PtrMapFile {
    /// Look up (or add) a module by name, returning the index an [`Anchor`] uses.
    pub fn module_index(&mut self, name: &str, base: usize) -> u16 {
        if let Some(i) = self.modules.iter().position(|m| m.name == name) {
            return i as u16;
        }
        self.modules.push(ModuleRef { name: name.to_string(), base });
        (self.modules.len() - 1) as u16
    }

    /// Every distinct [`PathKind`] present, in a stable order.
    pub fn kinds(&self) -> Vec<PathKind> {
        let mut out = Vec::new();
        for kind in [PathKind::Pointer, PathKind::Spider] {
            if self.entries.iter().any(|e| e.kind == kind) {
                out.push(kind);
            }
        }
        out
    }

    /// Re-resolve every anchor against the process attached now.
    ///
    /// `live` maps a module name to its current base; a module missing from it
    /// keeps the base recorded in the file, which is what lets the UI offer a
    /// hand-typed override for a module it could not match. `absolute_delta` is
    /// added to every [`Anchor::Absolute`] — the knob that matters for spider
    /// paths, whose root is a heap address in no module at all.
    pub fn rebase(
        &self,
        live: &dyn Fn(&str) -> Option<usize>,
        absolute_delta: isize,
    ) -> Vec<ResolvedPath> {
        self.entries
            .iter()
            .map(|e| {
                let (anchor, module) = match e.anchor {
                    Anchor::Module { module, offset } => match self.modules.get(module as usize) {
                        Some(m) => {
                            let base = live(&m.name).unwrap_or(m.base);
                            (
                                base.wrapping_add(offset),
                                Some(ModuleRef { name: m.name.clone(), base }),
                            )
                        }
                        // A corrupt index: fall back to treating the offset as
                        // an address rather than dropping the path silently.
                        None => (offset, None),
                    },
                    Anchor::Absolute(a) => (a.wrapping_add_signed(absolute_delta), None),
                };
                ResolvedPath { kind: e.kind, anchor, module, offsets: e.offsets.clone() }
            })
            .collect()
    }

    /// The paths in `self` that also appear in `other`.
    ///
    /// Cheat Engine's "compare two pointer maps": scan, restart the target, scan
    /// again, and keep the intersection. Matching is on the module-relative
    /// anchor and the offsets, never the absolute base, so it works across the
    /// relocation that makes the comparison worth doing in the first place.
    ///
    /// Returned entries come from `self`, in `self`'s order, so they stay valid
    /// against `self.modules`.
    pub fn intersect(&self, other: &PtrMapFile) -> Vec<PtrMapEntry> {
        self.intersect_indices(other)
            .into_iter()
            .map(|i| self.entries[i].clone())
            .collect()
    }

    /// [`Self::intersect`] as indices into [`Self::entries`], ascending.
    ///
    /// The form a caller wants when its own rows are index-aligned with the
    /// entries and carry state the file does not — a spider hit's live value
    /// readings, say — so the survivors can be retained in place rather than
    /// rebuilt from the file and silently stripped.
    pub fn intersect_indices(&self, other: &PtrMapFile) -> Vec<usize> {
        let keys: HashSet<PathKey<'_>> = other.entries.iter().map(|e| other.key(e)).collect();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| keys.contains(&self.key(e)))
            .map(|(i, _)| i)
            .collect()
    }

    fn key<'a>(&'a self, e: &'a PtrMapEntry) -> PathKey<'a> {
        match e.anchor {
            Anchor::Module { module, offset } => (
                e.kind,
                false,
                self.modules.get(module as usize).map(|m| m.name.as_str()),
                offset,
                &e.offsets,
            ),
            Anchor::Absolute(a) => (e.kind, true, None, a, &e.offsets),
        }
    }

    /// Serialize for round-tripping.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.entries.len() * 24);
        out.extend_from_slice(PTRMAP_MAGIC);
        out.push(u8::from(self.truncated));
        out.extend_from_slice(&[0u8; 7]);
        out.extend_from_slice(&(self.goal as u64).to_le_bytes());

        out.extend_from_slice(&(self.modules.len() as u32).to_le_bytes());
        for m in &self.modules {
            out.extend_from_slice(&(m.name.len() as u32).to_le_bytes());
            out.extend_from_slice(m.name.as_bytes());
            out.extend_from_slice(&(m.base as u64).to_le_bytes());
        }

        out.extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for e in &self.entries {
            let (tag, module, value) = match e.anchor {
                Anchor::Module { module, offset } => (0u8, module, offset as u64),
                Anchor::Absolute(a) => (1u8, 0u16, a as u64),
            };
            out.push(e.kind.tag());
            out.push(tag);
            out.extend_from_slice(&module.to_le_bytes());
            out.extend_from_slice(&value.to_le_bytes());
            out.extend_from_slice(&(e.offsets.len() as u32).to_le_bytes());
            for &off in &e.offsets {
                out.extend_from_slice(&off.to_le_bytes());
            }
        }
        out
    }

    /// Read a file written by [`Self::to_bytes`].
    pub fn from_bytes(data: &[u8]) -> Result<Self, PtrMapError> {
        // A plain function taking the cursor by `&mut` rather than a closure, so
        // the borrow ends at each call and the size checks can still read it.
        fn take<'a>(
            data: &'a [u8],
            cursor: &mut usize,
            n: usize,
        ) -> Result<&'a [u8], PtrMapError> {
            let end = cursor.checked_add(n).ok_or(PtrMapError::Truncated)?;
            let slice = data.get(*cursor..end).ok_or(PtrMapError::Truncated)?;
            *cursor = end;
            Ok(slice)
        }
        let mut cursor = 0usize;
        macro_rules! take {
            ($n:expr) => {
                take(data, &mut cursor, $n)?
            };
        }
        macro_rules! u32le {
            () => {
                u32::from_le_bytes(take!(4).try_into().unwrap()) as usize
            };
        }
        macro_rules! u64le {
            () => {
                u64::from_le_bytes(take!(8).try_into().unwrap()) as usize
            };
        }

        if take!(8) != PTRMAP_MAGIC {
            return Err(PtrMapError::BadFormat);
        }
        let truncated = take!(1)[0] != 0;
        let _pad = take!(7);
        let goal = u64le!();

        let module_count = u32le!();
        // Checked before allocating: the counts come straight from the file, and
        // a corrupt header must not be able to ask for a terabyte. Each module is
        // at least 12 bytes on the wire.
        if module_count
            .checked_mul(12)
            .is_none_or(|n| n > data.len() - cursor)
        {
            return Err(PtrMapError::Truncated);
        }
        let mut modules = Vec::with_capacity(module_count);
        for _ in 0..module_count {
            let name_len = u32le!();
            let name = String::from_utf8(take!(name_len).to_vec())
                .map_err(|_| PtrMapError::BadFormat)?;
            let base = u64le!();
            modules.push(ModuleRef { name, base });
        }

        let entry_count = u64le!();
        // Each entry is at least 16 bytes on the wire.
        if entry_count
            .checked_mul(16)
            .is_none_or(|n| n > data.len() - cursor)
        {
            return Err(PtrMapError::Truncated);
        }
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let kind = PathKind::from_tag(take!(1)[0]).ok_or(PtrMapError::BadFormat)?;
            let anchor_tag = take!(1)[0];
            let module = u16::from_le_bytes(take!(2).try_into().unwrap());
            let value = u64le!();
            let anchor = match anchor_tag {
                0 => Anchor::Module { module, offset: value },
                1 => Anchor::Absolute(value),
                _ => return Err(PtrMapError::BadFormat),
            };
            let n = u32le!();
            if n.checked_mul(8).is_none_or(|b| b > data.len() - cursor) {
                return Err(PtrMapError::Truncated);
            }
            let mut offsets = Vec::with_capacity(n);
            for chunk in take!(n * 8).chunks_exact(8) {
                offsets.push(i64::from_le_bytes(chunk.try_into().unwrap()));
            }
            entries.push(PtrMapEntry { kind, anchor, offsets });
        }

        if cursor != data.len() {
            return Err(PtrMapError::Truncated);
        }
        Ok(Self { goal, modules, entries, truncated })
    }

    /// Render as a plain-text listing: a comment header, then one address
    /// formula per line.
    ///
    /// Export only — this is the format you grep, sort, and diff outside the
    /// tool, which is the whole point of being able to get past the display cap.
    /// Formulas are emitted against the bases recorded in the file.
    ///
    /// ```
    /// use nemclass_scan::{Anchor, ModuleRef, PathKind, PtrMapEntry, PtrMapFile};
    ///
    /// let file = PtrMapFile {
    ///     goal: 0x7f2c4a18,
    ///     modules: vec![ModuleRef { name: "game.exe".into(), base: 0x400000 }],
    ///     entries: vec![
    ///         PtrMapEntry {
    ///             kind: PathKind::Pointer,
    ///             anchor: Anchor::Module { module: 0, offset: 0x4a1230 },
    ///             offsets: vec![0x18, 0x8],
    ///         },
    ///         PtrMapEntry {
    ///             kind: PathKind::Pointer,
    ///             anchor: Anchor::Absolute(0x55550000),
    ///             offsets: vec![0x10],
    ///         },
    ///     ],
    ///     truncated: false,
    /// };
    ///
    /// // Written on one line each because rustdoc eats a line starting with "# ".
    /// assert_eq!(file.to_text(), concat!(
    ///     "# nemclass ptrmap v1\n",
    ///     "# kind = pointer\n",
    ///     "# goal = 0x7f2c4a18\n",
    ///     "# paths = 2\n",
    ///     "# truncated = false\n",
    ///     "# module game.exe = 0x400000\n",
    ///     "[[<game.exe> + 0x4a1230] + 0x18] + 0x8\n",
    ///     "[0x55550000] + 0x10\n",
    /// ));
    /// ```
    pub fn to_text(&self) -> String {
        let kinds = self.kinds();
        let kind = match kinds.as_slice() {
            [k] => k.label(),
            [] => "empty",
            _ => "mixed",
        };
        let mut out = String::new();
        out.push_str("# nemclass ptrmap v1\n");
        out.push_str(&format!("# kind = {kind}\n"));
        out.push_str(&format!("# goal = {:#x}\n", self.goal));
        out.push_str(&format!("# paths = {}\n", self.entries.len()));
        out.push_str(&format!("# truncated = {}\n", self.truncated));
        for m in &self.modules {
            out.push_str(&format!("# module {} = {:#x}\n", m.name, m.base));
        }
        for path in self.rebase(&|_| None, 0) {
            out.push_str(&path.to_formula());
            out.push('\n');
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PtrMapFile {
        PtrMapFile {
            goal: 0x7F2C_4A18,
            modules: vec![
                ModuleRef { name: "game.exe".into(), base: 0x40_0000 },
                ModuleRef { name: "libfoo.so".into(), base: 0x7F00_0000 },
            ],
            entries: vec![
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Module { module: 0, offset: 0x4A1230 },
                    offsets: vec![0x18, 0x40, 0x8],
                },
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Module { module: 1, offset: 0x2210 },
                    offsets: vec![-0x20, 0x8],
                },
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Absolute(0x5555_0000),
                    offsets: vec![0x10],
                },
            ],
            truncated: true,
        }
    }

    #[test]
    fn a_saved_path_set_round_trips_byte_for_byte() {
        let file = sample();
        let back = PtrMapFile::from_bytes(&file.to_bytes()).unwrap();
        assert_eq!(back, file);
    }

    #[test]
    fn an_empty_set_round_trips() {
        let file = PtrMapFile { goal: 0, modules: vec![], entries: vec![], truncated: false };
        assert_eq!(PtrMapFile::from_bytes(&file.to_bytes()).unwrap(), file);
    }

    #[test]
    fn a_foreign_file_is_rejected() {
        assert_eq!(
            PtrMapFile::from_bytes(b"NEMPMAP\x01and then some"),
            Err(PtrMapError::BadFormat)
        );
        assert_eq!(PtrMapFile::from_bytes(b"tiny"), Err(PtrMapError::Truncated));
    }

    #[test]
    fn a_cut_short_file_is_rejected_rather_than_half_read() {
        let bytes = sample().to_bytes();
        for cut in [24, 40, bytes.len() - 1] {
            assert_eq!(
                PtrMapFile::from_bytes(&bytes[..cut]),
                Err(PtrMapError::Truncated),
                "cut at {cut} should not parse",
            );
        }
    }

    #[test]
    fn a_header_claiming_a_terabyte_does_not_allocate_one() {
        // No modules, so the counts sit at known offsets: magic(8) + flags(8) +
        // goal(8) = 24 for the module count, and 28 for the entry count.
        let file = PtrMapFile {
            goal: 0,
            modules: vec![],
            entries: vec![PtrMapEntry {
                kind: PathKind::Pointer,
                anchor: Anchor::Absolute(0x1000),
                offsets: vec![0x8],
            }],
            truncated: false,
        };

        let mut bytes = file.to_bytes();
        bytes[28..36].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(PtrMapFile::from_bytes(&bytes), Err(PtrMapError::Truncated));

        let mut bytes = file.to_bytes();
        bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(PtrMapFile::from_bytes(&bytes), Err(PtrMapError::Truncated));

        // And a per-entry offset count, which is checked separately.
        let mut bytes = file.to_bytes();
        let n_at = bytes.len() - 12;
        bytes[n_at..n_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(PtrMapFile::from_bytes(&bytes), Err(PtrMapError::Truncated));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = sample().to_bytes();
        bytes.push(0);
        assert_eq!(PtrMapFile::from_bytes(&bytes), Err(PtrMapError::Truncated));
    }

    #[test]
    fn rebasing_follows_a_moved_module_and_leaves_the_rest_alone() {
        let file = sample();
        let paths = file.rebase(
            &|name| (name == "game.exe").then_some(0x7FFF_0000),
            0,
        );
        // The moved module follows its new base.
        assert_eq!(paths[0].anchor, 0x7FFF_0000 + 0x4A1230);
        assert_eq!(paths[0].module.as_ref().unwrap().base, 0x7FFF_0000);
        // The unmatched one keeps the base recorded in the file.
        assert_eq!(paths[1].anchor, 0x7F00_0000 + 0x2210);
        // An absolute anchor is untouched at delta 0.
        assert_eq!(paths[2].anchor, 0x5555_0000);
        assert!(paths[2].module.is_none());
    }

    #[test]
    fn the_absolute_delta_shifts_only_unanchored_paths() {
        let file = sample();
        let paths = file.rebase(&|_| None, 0x1000);
        assert_eq!(paths[0].anchor, 0x40_0000 + 0x4A1230, "module anchors ignore the delta");
        assert_eq!(paths[2].anchor, 0x5555_1000);

        let back = file.rebase(&|_| None, -0x1000);
        assert_eq!(back[2].anchor, 0x5554_F000, "a negative delta walks backwards");
    }

    #[test]
    fn intersect_matches_across_a_relocation() {
        let a = sample();
        // Same paths, discovered against a completely different set of bases.
        let b = PtrMapFile {
            goal: 0x1234,
            modules: vec![ModuleRef { name: "game.exe".into(), base: 0x7FFF_0000 }],
            entries: vec![PtrMapEntry {
                kind: PathKind::Pointer,
                anchor: Anchor::Module { module: 0, offset: 0x4A1230 },
                offsets: vec![0x18, 0x40, 0x8],
            }],
            truncated: false,
        };
        let kept = a.intersect(&b);
        assert_eq!(kept, vec![a.entries[0].clone()]);
    }

    #[test]
    fn intersect_separates_paths_that_differ_only_in_module_or_offsets() {
        let a = sample();
        let b = PtrMapFile {
            goal: 0,
            // Same offset into a *different* module, and the same module with
            // different offsets. Neither is the same path.
            modules: vec![ModuleRef { name: "other.so".into(), base: 0x40_0000 }],
            entries: vec![
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Module { module: 0, offset: 0x4A1230 },
                    offsets: vec![0x18, 0x40, 0x8],
                },
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Absolute(0x5555_0000),
                    offsets: vec![0x11],
                },
            ],
            truncated: false,
        };
        assert!(a.intersect(&b).is_empty());
    }

    #[test]
    fn intersect_indices_line_up_with_the_entries_they_came_from() {
        let a = sample();
        // Matches the first and third entries, in the opposite order, and adds
        // one of its own — the indices must still come back ascending and
        // pointing at `a`.
        let b = PtrMapFile {
            goal: 0,
            modules: vec![ModuleRef { name: "game.exe".into(), base: 0x9000_0000 }],
            entries: vec![
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Absolute(0x5555_0000),
                    offsets: vec![0x10],
                },
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Module { module: 0, offset: 0x4A1230 },
                    offsets: vec![0x18, 0x40, 0x8],
                },
                PtrMapEntry {
                    kind: PathKind::Pointer,
                    anchor: Anchor::Absolute(0x9999),
                    offsets: vec![0x1],
                },
            ],
            truncated: false,
        };

        let idx = a.intersect_indices(&b);
        assert_eq!(idx, vec![0, 2]);
        // And the two views agree.
        let by_index: Vec<PtrMapEntry> =
            idx.iter().map(|&i| a.entries[i].clone()).collect();
        assert_eq!(a.intersect(&b), by_index);
    }

    #[test]
    fn intersect_does_not_match_a_spider_path_to_a_pointer_one() {
        let mut a = sample();
        a.entries.truncate(1);
        let mut b = a.clone();
        b.entries[0].kind = PathKind::Spider;
        assert!(a.intersect(&b).is_empty());
    }

    #[test]
    fn a_pointer_path_survives_the_whole_round_trip() {
        let path = PointerPath { base: 0x40_1000, offsets: vec![0x18, -0x40, 0x8] };
        let entry = PtrMapEntry::from_pointer_path(
            &path,
            Anchor::Module { module: 0, offset: 0x1000 },
        );
        let file = PtrMapFile {
            goal: 0,
            modules: vec![ModuleRef { name: "game.exe".into(), base: 0x40_0000 }],
            entries: vec![entry],
            truncated: false,
        };
        let back = PtrMapFile::from_bytes(&file.to_bytes()).unwrap();
        let resolved = &back.rebase(&|_| None, 0)[0];
        assert_eq!(resolved.to_pointer_path().unwrap(), path);
        assert_eq!(resolved.depth(), 3);
    }

    #[test]
    fn a_spider_path_survives_the_whole_round_trip() {
        let path = SpiderPath {
            root: 0x5555_0000,
            parent_offsets: Arc::from([0x18usize, 0x40].as_slice()),
            offset: 0x14,
        };
        let entry = PtrMapEntry::from_spider_path(&path, Anchor::Absolute(0x5555_0000));
        let file = PtrMapFile {
            goal: 0,
            modules: vec![],
            entries: vec![entry],
            truncated: false,
        };
        let back = PtrMapFile::from_bytes(&file.to_bytes()).unwrap();
        let resolved = &back.rebase(&|_| None, 0)[0];
        assert_eq!(resolved.to_spider_path().unwrap(), path);
        // The trailing offset locates the value; it is not a hop.
        assert_eq!(resolved.depth(), 2);
    }

    #[test]
    fn loading_a_path_as_the_wrong_kind_is_refused() {
        let resolved = ResolvedPath {
            kind: PathKind::Pointer,
            anchor: 0x1000,
            module: None,
            offsets: vec![0x8],
        };
        assert_eq!(
            resolved.to_spider_path(),
            Err(PtrMapError::KindMismatch {
                want: PathKind::Spider,
                got: PathKind::Pointer
            })
        );
        let spider = ResolvedPath { kind: PathKind::Spider, ..resolved };
        assert_eq!(
            spider.to_pointer_path(),
            Err(PtrMapError::KindMismatch {
                want: PathKind::Pointer,
                got: PathKind::Spider
            })
        );
    }

    #[test]
    fn a_negative_offset_is_refused_rather_than_cast_into_a_spider_path() {
        let resolved = ResolvedPath {
            kind: PathKind::Spider,
            anchor: 0x1000,
            module: None,
            offsets: vec![0x18, -0x40],
        };
        assert_eq!(
            resolved.to_spider_path(),
            Err(PtrMapError::NegativeSpiderOffset(-0x40))
        );
    }

    #[test]
    fn a_spider_path_needs_a_final_offset() {
        let resolved = ResolvedPath {
            kind: PathKind::Spider,
            anchor: 0x1000,
            module: None,
            offsets: vec![],
        };
        assert_eq!(resolved.to_spider_path(), Err(PtrMapError::EmptySpiderPath));
    }

    #[test]
    fn formulas_use_the_module_when_there_is_one_and_hex_otherwise() {
        let file = sample();
        let paths = file.rebase(&|_| None, 0);
        assert_eq!(paths[0].to_formula(), "[[[<game.exe> + 0x4a1230] + 0x18] + 0x40] + 0x8");
        assert_eq!(paths[1].to_formula(), "[[<libfoo.so> + 0x2210] - 0x20] + 0x8");
        assert_eq!(paths[2].to_formula(), "[0x55550000] + 0x10");
    }

    #[test]
    fn a_spider_formula_keeps_its_own_bracket_shape() {
        let path = SpiderPath {
            root: 0x1400,
            parent_offsets: Arc::from([0x18usize, 0x40].as_slice()),
            offset: 0x14,
        };
        let resolved = ResolvedPath {
            kind: PathKind::Spider,
            anchor: 0x1400,
            module: None,
            offsets: vec![0x18, 0x40, 0x14],
        };
        // Spider brackets enclose the offset; pointer brackets close before it.
        assert_eq!(resolved.to_formula(), path.to_formula_raw());
        assert_eq!(resolved.to_formula(), "[[0x1400 + 0x18] + 0x40] + 0x14");
    }

    #[test]
    fn the_text_export_lists_every_path_with_a_readable_header() {
        let text = sample().to_text();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.contains(&"# nemclass ptrmap v1"));
        assert!(lines.contains(&"# kind = pointer"));
        assert!(lines.contains(&"# goal = 0x7f2c4a18"));
        assert!(lines.contains(&"# paths = 3"));
        assert!(lines.contains(&"# truncated = true"));
        assert!(lines.contains(&"# module game.exe = 0x400000"));
        // Every path is present, past any display cap.
        assert_eq!(lines.iter().filter(|l| !l.starts_with('#')).count(), 3);
    }

    #[test]
    fn a_mixed_file_says_so_in_the_text_header() {
        let mut file = sample();
        file.entries[2].kind = PathKind::Spider;
        assert!(file.to_text().contains("# kind = mixed"));
        assert_eq!(file.kinds(), vec![PathKind::Pointer, PathKind::Spider]);
    }

    #[test]
    fn module_index_interns_by_name() {
        let mut file = PtrMapFile {
            goal: 0,
            modules: vec![],
            entries: vec![],
            truncated: false,
        };
        assert_eq!(file.module_index("game.exe", 0x1000), 0);
        assert_eq!(file.module_index("libfoo.so", 0x2000), 1);
        assert_eq!(file.module_index("game.exe", 0x9999), 0, "same name, same slot");
        assert_eq!(file.modules.len(), 2);
        assert_eq!(file.modules[0].base, 0x1000, "the first base wins");
    }
}
