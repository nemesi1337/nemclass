//! Unix (DWARF + ELF) implementation of [`super::SymbolResolver`].
//!
//! Opens the module's on-disk ELF once, derives the load bias from its `PT_LOAD`
//! segments, and answers lookups against three tiers (DWARF → symbol table → ELF
//! symbol map). See the parent module docs for the tier order and the load-bias
//! reasoning.

use std::path::Path;

use object::{Object, ObjectSegment, SegmentFlags};

use crate::Error;

use super::{load_bias, probe_address};

/// Owns the parsed object for the on-disk module and the runtime load bias.
///
/// `addr2line::Loader` memory-maps the file and builds a DWARF `Context` + the
/// object's symbol table lazily/internally; we keep it for tiers 1 and 2. We
/// additionally keep an owned copy of the file bytes to build `object`'s
/// [`object::read::SymbolMap`] for the tier-3 floor (`Loader` does not expose the
/// full symbol map, only a per-address `find_symbol`).
pub(super) struct UnixResolver {
    loader: addr2line::Loader,
    // Owned file bytes backing `symbol_map`'s borrowed names, kept alive for the
    // resolver's lifetime. `object::File`/`SymbolMap` borrow from these bytes, so
    // we store the parsed names instead of a self-referential borrow.
    symbol_map: object::read::SymbolMap<object::read::SymbolMapName<'static>>,
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

        // Read the file once more for the load-bias computation (min PT_LOAD
        // vaddr) and to build the tier-3 symbol map. `object` parses lazily, but
        // `SymbolMap` borrows the file bytes, so we leak an owned `Vec<u8>` into a
        // `'static` slice tied to this resolver's lifetime (freed on drop is not
        // needed — resolvers are long-lived per module and few in number).
        let data = std::fs::read(path)?;
        let data: &'static [u8] = Box::leak(data.into_boxed_slice());
        let file = object::File::parse(data)
            .map_err(|e| Error::SymbolInfo(format!("object: parse {}: {e}", path.display())))?;

        let min_vaddr = min_pt_load_vaddr(&file);
        let bias = load_bias(module_base, min_vaddr);

        // Tier 3 floor: the object's symbol map (ELF `.symtab`/`.dynsym` names,
        // including dynamic exports), keyed by object-space address.
        let symbol_map = file.symbol_map();

        Ok(UnixResolver {
            loader,
            symbol_map,
            load_bias: bias,
        })
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
        // before it (covers zero-size symbols and address-in-body probes). Mirrors
        // the live-image export floor but reads the richer on-disk symbol map.
        if let Some(sym) = self
            .symbol_map
            .containing(probe)
            .or_else(|| self.symbol_map.before(probe))
        {
            return Some(sym.name().to_owned());
        }

        None
    }
}

/// The lowest `p_vaddr` among the object's loadable (`PT_LOAD`) segments — the
/// object-space address the image "starts" at.
///
/// For `ET_DYN`/PIE this is typically `0` (bias == base); for `ET_EXEC` it is the
/// absolute link base such as `0x400000` (bias == 0). An object with no loadable
/// segment (e.g. a `.o` relocatable) yields `0`, so the bias degrades to the raw
/// base — acceptable, since such objects are not something we symbolicate live.
fn min_pt_load_vaddr(file: &object::File) -> u64 {
    file.segments()
        .filter(|seg| {
            // `object` exposes ELF `p_flags` via `SegmentFlags::Elf`; every
            // `segments()` entry is already a PT_LOAD (object only yields loadable
            // segments), so we accept them all and just read the vaddr. The flag
            // match is a defensive no-op that keeps us on the ELF path.
            matches!(seg.flags(), SegmentFlags::Elf { .. })
        })
        .map(|seg| seg.address())
        .min()
        .unwrap_or(0)
}
