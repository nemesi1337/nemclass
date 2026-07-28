//! Windows (PDB + PE) implementation of [`super::SymbolResolver`].
//!
//! **Compile-gated only.** This path is `#[cfg(windows)]` and is not exercised on
//! the Linux CI host — it exists so the same [`super::SymbolResolver`] API is
//! available on Windows and so the workspace `cargo check --target
//! x86_64-pc-windows-gnu` gate keeps it honest. The runtime behaviour (matching a
//! module to its PDB, resolving an RVA) has not been validated here; treat it as a
//! best-effort port to finish when a Windows target is available.
//!
//! ## Tiers
//!
//! 1. **PDB** — `pdb-addr2line` resolves an RVA to the innermost function frame.
//!    The PDB is located next to the on-disk image (`foo.exe` -> `foo.pdb`); a
//!    full implementation would instead read the RSDS entry from the PE debug
//!    directory and consult a symbol server. That refinement is left as a TODO.
//! 2. **PE exports floor** — the existing live-image
//!    [`crate::symbols::pe_exports`] analogue is not reusable from disk here, so
//!    the floor is simply "PDB missing -> `None`"; wiring an on-disk PE export
//!    reader is a follow-up.
//!
//! ## Address translation
//!
//! A PDB addresses code by **RVA** (offset from the PE image base). The runtime
//! absolute address maps as `rva = addr_abs - module_base`, i.e. the load bias is
//! exactly `module_base` and the object-space probe is the RVA. This reuses the
//! same [`super::load_bias`]/[`super::probe_address`] helpers with
//! `min_pt_load_vaddr == 0` (RVAs are already image-base-relative).

use std::path::{Path, PathBuf};

use crate::Error;

use super::{load_bias, probe_address};

/// Owns the PDB context (self-referential over leaked PDB bytes) and the load
/// bias (== `module_base`, since PDBs are RVA-addressed).
pub(super) struct WindowsResolver {
    // `pdb_addr2line::Context` borrows from `ContextPdbData`, which borrows the
    // PDB bytes. We leak both into `'static` so the borrow chain is satisfied for
    // the resolver's lifetime; resolvers are few and long-lived per module.
    context: pdb_addr2line::Context<'static, 'static>,
    load_bias: usize,
}

impl WindowsResolver {
    /// Opens the PDB sitting next to `image_path` and indexes it. `module_base`
    /// is the PE image base at runtime; the load bias equals it (RVA addressing).
    pub(super) fn open(image_path: &Path, module_base: usize) -> crate::Result<Self> {
        let pdb_path = sibling_pdb_path(image_path);
        let file = std::fs::File::open(&pdb_path).map_err(|e| {
            Error::SymbolInfo(format!("pdb: open {}: {e}", pdb_path.display()))
        })?;

        // Open via `pdb_addr2line`'s own re-exported `pdb` crate. `pdb-addr2line`
        // vendors a specific `pdb` (exposed as `pdb_addr2line::pdb`); its
        // `try_from_pdb` requires *that* crate's `PDB` type, not an independently
        // versioned `pdb` — hence the re-export rather than the standalone dep.
        let pdb = pdb_addr2line::pdb::PDB::open(file)
            .map_err(|e| Error::SymbolInfo(format!("pdb: parse {}: {e}", pdb_path.display())))?;

        // Leak the parsed PDB owner so the borrowed `Context` can be `'static`.
        // `ContextPdbData<'p, 's, S>`: `'p` is the (owned) borrow lifetime, `'s`
        // the source lifetime, `S` the `pdb::Source` (here `std::fs::File`).
        let pdb_data = pdb_addr2line::ContextPdbData::try_from_pdb(pdb)
            .map_err(|e| Error::SymbolInfo(format!("pdb-addr2line: {e}")))?;
        let pdb_data: &'static pdb_addr2line::ContextPdbData<'static, 'static, std::fs::File> =
            Box::leak(Box::new(pdb_data));

        let context = pdb_data
            .make_context()
            .map_err(|e| Error::SymbolInfo(format!("pdb-addr2line: make_context: {e}")))?;

        // PDBs address code by RVA (image-base-relative), so min vaddr is 0 and
        // the bias is the module base: probe == addr_abs - module_base == rva.
        let bias = load_bias(module_base, 0);

        Ok(WindowsResolver {
            context,
            load_bias: bias,
        })
    }

    /// Resolve a runtime absolute address to a function name via the PDB.
    pub(super) fn resolve(&self, addr_abs: usize) -> Option<String> {
        let rva = probe_address(addr_abs, self.load_bias)?;
        // pdb-addr2line takes a u32 RVA; a >4GiB RVA cannot exist in a PE image.
        let rva = u32::try_from(rva).ok()?;

        let frames = self.context.find_frames(rva).ok()??;
        // The first frame is the innermost (possibly inlined) function.
        frames.frames.into_iter().find_map(|f| f.function)
    }
}

/// `foo.exe`/`foo.dll` -> `foo.pdb` alongside it. A production implementation
/// would read the PDB path/GUID from the PE debug directory and honour a symbol
/// server; this sibling-name heuristic is a documented placeholder.
fn sibling_pdb_path(image_path: &Path) -> PathBuf {
    image_path.with_extension("pdb")
}
