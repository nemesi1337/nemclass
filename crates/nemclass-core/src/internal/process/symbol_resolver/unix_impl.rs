//! Unix (DWARF + ELF) implementation of [`super::SymbolResolver`].
//!
//! Opens the module's on-disk ELF once, derives the load bias from its `PT_LOAD`
//! segments, and answers lookups against three tiers (DWARF → symbol table → ELF
//! symbol map). See the parent module docs for the tier order and the load-bias
//! reasoning.

use std::path::Path;

use object::{Object, ObjectSegment, ObjectSymbol};

use crate::Error;

use super::{load_bias, probe_address};

/// How far past a zero-sized symbol an address may still be attributed to it.
///
/// The tier-3 floor falls back to "the nearest symbol at or before the probe".
/// Unbounded, that confidently names an address megabytes past the last symbol
/// in the object after the symbol it actually belongs to. Symbols that carry a
/// size are bounded by that size instead; this only applies to the zero-sized
/// ones (assembly labels, some hand-written stubs).
const MAX_ZERO_SIZE_SLACK: u64 = 0x1000;

/// One on-disk symbol, owned. Sorted ascending by `address`.
struct OwnedSymbol {
    address: u64,
    /// `0` when the object does not record a size.
    size: u64,
    name: String,
}

/// Owns the parsed object for the on-disk module and the runtime load bias.
///
/// `addr2line::Loader` memory-maps the file and builds a DWARF `Context` + the
/// object's symbol table lazily/internally; we keep it for tiers 1 and 2. For
/// the tier-3 floor we keep our own **owned** symbol table (`Loader` exposes
/// only a per-address `find_symbol`, not the full map).
///
/// The owned table matters: `object`'s `SymbolMap` borrows the file bytes, and
/// the previous implementation satisfied that by `Box::leak`ing the whole file.
/// One resolver exists per module and the cache is dropped with the `Process`,
/// so every attach leaked the full on-disk image of every module it
/// symbolicated — hundreds of megabytes across a handful of re-attaches, on top
/// of the copy `addr2line::Loader` already mmaps.
pub(super) struct UnixResolver {
    loader: addr2line::Loader,
    symbols: Vec<OwnedSymbol>,
    // Runtime-absolute -> object-space translation constant (see parent docs).
    load_bias: usize,
}

impl UnixResolver {
    /// Opens and indexes the ELF at `path`, computing the load bias against
    /// `module_base`.
    pub(super) fn open(path: &Path, module_base: usize) -> crate::Result<Self> {
        // Tier 1/2: addr2line memory-maps the file and parses DWARF + symtab.
        let loader = addr2line::Loader::new(path)
            .map_err(|e| Error::SymbolInfo(format!("addr2line: open {}: {e}", path.display())))?;

        // Read the file once more for the load-bias computation (min loadable
        // segment vaddr) and to build the tier-3 symbol table. The bytes are
        // dropped at the end of this function — every name is copied out first.
        let data = std::fs::read(path)?;
        let file = object::File::parse(&*data)
            .map_err(|e| Error::SymbolInfo(format!("object: parse {}: {e}", path.display())))?;

        let min_vaddr = min_load_vaddr(&file);
        let bias = load_bias(module_base, min_vaddr);

        // Tier 3 floor: the object's symbols (ELF `.symtab`/`.dynsym`, including
        // dynamic exports), keyed by object-space address.
        let mut symbols: Vec<OwnedSymbol> = file
            .symbols()
            .filter(|s| s.address() != 0)
            .filter_map(|s| {
                let name = s.name().ok()?;
                (!name.is_empty()).then(|| OwnedSymbol {
                    address: s.address(),
                    size: s.size(),
                    name: name.to_owned(),
                })
            })
            .collect();
        symbols.sort_unstable_by_key(|s| s.address);

        Ok(UnixResolver {
            loader,
            symbols,
            load_bias: bias,
        })
    }

    /// The tier-3 lookup: the symbol whose `[address, address + size)` range
    /// contains `probe`, else the nearest symbol at or before it within
    /// [`MAX_ZERO_SIZE_SLACK`].
    fn symbol_for(&self, probe: u64) -> Option<&OwnedSymbol> {
        // The last symbol whose address is <= probe.
        let idx = self.symbols.partition_point(|s| s.address <= probe);
        let candidate = self.symbols.get(idx.checked_sub(1)?)?;
        let covers = if candidate.size > 0 {
            probe < candidate.address.saturating_add(candidate.size)
        } else {
            probe < candidate.address.saturating_add(MAX_ZERO_SIZE_SLACK)
        };
        covers.then_some(candidate)
    }

    /// Resolve a runtime absolute address, best-name-wins across the tiers.
    pub(super) fn resolve(&self, addr_abs: usize) -> Option<String> {
        let probe = probe_address(addr_abs, self.load_bias)?;

        // Tier 1 — DWARF: the innermost function frame at this address. `demangle`
        // yields a human-readable Rust/C++ name; fall back to the raw name.
        if let Ok(mut frames) = self.loader.find_frames(probe) {
            // The first frame is the innermost (possibly inlined) function.
            if let Ok(Some(frame)) = frames.next()
                && let Some(func) = frame.function
            {
                if let Ok(name) = func.demangle() {
                    return Some(name.into_owned());
                }
                if let Ok(name) = func.raw_name() {
                    return Some(name.into_owned());
                }
            }
        }

        // Tier 2 — object symbol table (via addr2line's `find_symbol`), for
        // stripped-of-DWARF-but-not-symtab binaries.
        if let Some(name) = self.loader.find_symbol(probe) {
            return Some(name.to_owned());
        }

        // Tier 3 — export/symbol-map floor. Prefer the symbol whose [addr, addr+
        // size) range *contains* the probe; fall back to the nearest symbol at or
        // before it, bounded so an address far past the last symbol is reported
        // as unknown rather than confidently mis-named.
        if let Some(sym) = self.symbol_for(probe) {
            return Some(sym.name.clone());
        }

        None
    }
}

/// The lowest virtual address among the object's loadable segments — the
/// object-space address the image "starts" at.
///
/// For `ET_DYN`/PIE this is typically `0` (bias == base); for `ET_EXEC` it is the
/// absolute link base such as `0x400000` (bias == 0). An object with no loadable
/// segment (e.g. a `.o` relocatable) yields `0`, so the bias degrades to the raw
/// base — acceptable, since such objects are not something we symbolicate live.
///
/// Deliberately **not** filtered on `SegmentFlags::Elf`. `object` only yields
/// loadable segments, so the filter was a no-op for ELF — but it silently
/// excluded everything for a Wine-mapped PE, whose segments report
/// `SegmentFlags::Coff`. That made `min` yield `None`, the bias collapse to the
/// raw module base instead of `base - ImageBase`, and every probe into a PE land
/// `0x140000000` off.
fn min_load_vaddr(file: &object::File) -> u64 {
    file.segments().map(|seg| seg.address()).min().unwrap_or(0)
}
