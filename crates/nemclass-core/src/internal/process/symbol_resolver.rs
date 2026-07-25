//! Richer, on-disk **symbolication** (phase M5.2).
//!
//! [`crate::symbols`] resolves only a module's *exported* symbols, and it does so
//! from the **live, mapped image**. That is the right tool when all you have is a
//! running process and an image base, but it is a floor: stripped-of-exports
//! internals, DWARF line/function info, and a full `.symtab` never appear in the
//! mapped image. This module fills that gap by reading the **on-disk object
//! file** (with its debug sections intact) and mapping a *runtime* code address
//! back to a function name.
//!
//! ## Resolution tiers (best-name-wins, in order)
//!
//! For a given absolute runtime address we try, and return the first hit:
//!
//! 1. **DWARF** — `addr2line`'s [`Loader::find_frames`] walks `.debug_info` for
//!    the innermost (inlined) function frame. Richest source; present only in a
//!    `-g` / not-fully-stripped object. Demangled (Rust/C++) when possible.
//! 2. **Symbol table** — `addr2line`'s [`Loader::find_symbol`] consults the
//!    object's `.symtab`/`.dynsym`. Covers "stripped of debug info but keeps the
//!    symbol table" binaries.
//! 3. **Exports floor** — the object's [`object::Object::symbol_map`], which on
//!    ELF includes the dynamic-export names. This is the on-disk analogue of the
//!    live-image [`crate::symbols::elf_exports`]/[`crate::symbols::pe_exports`]
//!    floor and always succeeds in *parsing* even when no name covers the probe.
//!
//! On Windows the tiers are: PDB (via `pdb-addr2line`) → PE exports. The PDB path
//! is `#[cfg(windows)]` and compile-gated only; it cannot be exercised here.
//!
//! ## Address translation (the load bias) — get this RIGHT
//!
//! `addr2line`/`object` speak the object file's **link-time virtual addresses**
//! (the `p_vaddr` of its `PT_LOAD` segments / the vaddrs baked into DWARF and the
//! symbol table). A live [`crate::Process`] hands us a **runtime absolute**
//! address, i.e. where the loader actually mapped the code. The two differ by a
//! constant **load bias**:
//!
//! ```text
//!   load_bias = module_base - min(p_vaddr of PT_LOAD segments)
//!   probe     = addr_abs - load_bias                // object-space address
//! ```
//!
//! - **PIE executable / shared object (`ET_DYN`)**: the object's lowest
//!   `PT_LOAD` `p_vaddr` starts at (or near) `0`, so `load_bias ≈ module_base`
//!   and `probe ≈ addr_abs - module_base`. This is the common case for `.so`s and
//!   modern PIE binaries.
//! - **Non-PIE executable (`ET_EXEC`)**: the `PT_LOAD` vaddrs are already
//!   *absolute* (e.g. `0x400000`), and the loader maps the image there, so
//!   `module_base == min p_vaddr`, `load_bias == 0`, and `probe == addr_abs`.
//!
//! Deriving the bias from the ELF headers (rather than hard-coding "subtract the
//! base") is what makes both cases correct. A wrong bias does not error — it
//! silently probes the wrong place and returns a wrong name or `None`, so the
//! bias math is unit-tested in isolation (see [`load_bias`] and the tests).

use std::path::Path;

// The Unix (DWARF/ELF) resolver and the Windows (PDB/PE) resolver are two
// disjoint implementations of the same `SymbolResolver` surface, each behind its
// own `cfg`. Only one is ever compiled for a given target.
#[cfg(unix)]
mod unix_impl;
#[cfg(windows)]
mod windows_impl;

/// Computes the ELF **load bias** for the object whose lowest `PT_LOAD` segment
/// has virtual address `min_pt_load_vaddr`, mapped at runtime base `module_base`.
///
/// The bias is `module_base - min_pt_load_vaddr` (see the module docs). It is the
/// value you subtract from a runtime absolute address to get the corresponding
/// object-space (link-time) address that `addr2line`/`object` expect.
///
/// Wrapping-subtracts so a degenerate object whose vaddrs exceed `module_base`
/// (should not happen for a real mapping) yields a defined, if useless, bias
/// rather than panicking in debug builds.
#[inline]
pub(crate) fn load_bias(module_base: usize, min_pt_load_vaddr: u64) -> usize {
    module_base.wrapping_sub(min_pt_load_vaddr as usize)
}

/// Translates a runtime absolute address to the object-space probe address the
/// symbolication backends expect: `probe = addr_abs - load_bias`.
///
/// Returns `None` when `addr_abs` sits below the bias (i.e. the address is not
/// inside this module's mapped range), so callers surface a miss rather than a
/// wrapped, in-bounds-looking probe.
#[inline]
pub(crate) fn probe_address(addr_abs: usize, load_bias: usize) -> Option<u64> {
    addr_abs.checked_sub(load_bias).map(|p| p as u64)
}

/// Maps a runtime code address in one module to a function name using on-disk
/// debug info, richer than the export-only [`crate::symbols`] path.
///
/// Built once per module from the module's **on-disk object file** and its
/// **runtime base**; construction is pure with respect to any process (it only
/// needs the file + base), so it is trivially testable against a compiled fixture
/// (see the tests). Internally it caches the parsed object / DWARF context, so
/// repeated [`SymbolResolver::resolve`] calls are cheap.
pub struct SymbolResolver {
    // The per-target implementation (DWARF+ELF on unix, PDB+PE on windows). Boxed
    // behind a thin platform enum so the public type is identical everywhere.
    #[cfg(unix)]
    inner: unix_impl::UnixResolver,
    #[cfg(windows)]
    inner: windows_impl::WindowsResolver,
}

impl SymbolResolver {
    /// Builds a resolver for the module whose on-disk image is `on_disk_path`,
    /// mapped at runtime base `module_base`.
    ///
    /// This opens and indexes the file eagerly enough to answer lookups; it does
    /// **not** touch any process. Fails with [`Error::SymbolInfo`] if the file
    /// cannot be opened or parsed as a recognised object.
    ///
    /// The `module_base` is used purely to compute the load bias (see the module
    /// docs); pass `0` when the object's vaddrs are already the addresses you will
    /// probe with (e.g. a non-PIE `ET_EXEC`, or a pure unit test).
    pub fn for_module(on_disk_path: &Path, module_base: usize) -> crate::Result<Self> {
        #[cfg(unix)]
        {
            Ok(SymbolResolver {
                inner: unix_impl::UnixResolver::open(on_disk_path, module_base)?,
            })
        }
        #[cfg(windows)]
        {
            Ok(SymbolResolver {
                inner: windows_impl::WindowsResolver::open(on_disk_path, module_base)?,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (on_disk_path, module_base);
            Err(crate::Error::SymbolInfo(
                "symbolication unsupported on this target".into(),
            ))
        }
    }

    /// Resolves the runtime **absolute** address `addr_abs` to a function name,
    /// or `None` if no tier can name it (unmapped-in-object address, fully
    /// stripped module, or an address between functions).
    ///
    /// The name is demangled (Rust/C++) when the underlying tier supports it.
    pub fn resolve(&self, addr_abs: usize) -> Option<String> {
        self.inner.resolve(addr_abs)
    }
}

// A Linux convenience that finds a module's on-disk path from `/proc/<pid>/maps`
// and builds a resolver for it. Kept Linux-specific (it reads `/proc`) while the
// core `for_module` stays platform-neutral.
#[cfg(target_os = "linux")]
impl SymbolResolver {
    /// Builds a resolver for the module mapped at `module_base` in process `pid`,
    /// discovering its on-disk backing-file path from `/proc/<pid>/maps`.
    ///
    /// Fails with [`Error::ModuleNotFound`] if no file-backed mapping covers
    /// `module_base`, or [`Error::SymbolInfo`] if the backing file cannot be
    /// parsed.
    pub fn for_process_module(pid: crate::Pid, module_base: usize) -> crate::Result<Self> {
        let path = module_disk_path(pid, module_base)?;
        Self::for_module(Path::new(&path), module_base)
    }
}

/// Finds the on-disk backing-file path of the module mapped at `module_base` in
/// `/proc/<pid>/maps`.
///
/// [`crate::Process::modules`] aggregates a module to a **basename** and a base;
/// symbolication needs the *full path*, which is the maps pathname column of the
/// mapping at that base. We take the pathname of the file-backed mapping whose
/// start equals `module_base` (the offset-0 header mapping is the module base per
/// [`crate::internal::process`]'s maps parser); if none starts exactly there we
/// fall back to the file-backed mapping that *covers* `module_base`.
#[cfg(target_os = "linux")]
fn module_disk_path(pid: crate::Pid, module_base: usize) -> crate::Result<String> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|_| crate::Error::ProcessDied)?;

    let mut covering: Option<String> = None;
    for line in maps.lines() {
        // File-backed mappings are the lines with a pathname, which starts at the
        // first '/' (the address/perms/offset/dev/inode columns never contain
        // one). Mirror `parse_maps_modules`' path handling, incl. `(deleted)`.
        let Some(slash) = line.find('/') else {
            continue;
        };
        let path = line[slash..].trim_end();
        let path = path
            .strip_suffix("(deleted)")
            .map(str::trim_end)
            .unwrap_or(path);
        if path.is_empty() {
            continue;
        }

        let Some((from, to)) = line[..slash].split_whitespace().next().and_then(|r| r.split_once('-'))
        else {
            continue;
        };
        let (Ok(start), Ok(end)) =
            (usize::from_str_radix(from, 16), usize::from_str_radix(to, 16))
        else {
            continue;
        };

        // Exact base match wins immediately — that is the image-base mapping.
        if start == module_base {
            return Ok(path.to_owned());
        }
        // Otherwise remember the first file-backed mapping that spans the base, in
        // case no mapping starts exactly at it.
        if covering.is_none() && (start..end).contains(&module_base) {
            covering = Some(path.to_owned());
        }
    }

    covering.ok_or(crate::Error::ModuleNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- pure load-bias / probe translation (no I/O) ---------------------------

    #[test]
    fn load_bias_pie_shared_object_subtracts_base() {
        // ET_DYN / PIE: lowest PT_LOAD vaddr is 0, image mapped at a runtime base.
        // The bias equals the base, so probe = addr_abs - module_base.
        let module_base = 0x7f00_1234_0000usize;
        let bias = load_bias(module_base, 0);
        assert_eq!(bias, module_base);

        let addr_abs = module_base + 0x1550;
        assert_eq!(probe_address(addr_abs, bias), Some(0x1550));
    }

    #[test]
    fn load_bias_pie_with_nonzero_first_vaddr() {
        // Some PIE objects place the first PT_LOAD at a small non-zero vaddr
        // (e.g. after a load-segment gap). probe = addr_abs - (base - min_vaddr).
        let module_base = 0x5555_0000_0000usize;
        let min_vaddr = 0x1000u64;
        let bias = load_bias(module_base, min_vaddr);
        assert_eq!(bias, module_base - 0x1000);

        // A runtime address 0x2abc into the mapping is object vaddr 0x1000+0x2abc.
        let addr_abs = module_base + 0x2abc;
        assert_eq!(probe_address(addr_abs, bias), Some(0x1000 + 0x2abc));
    }

    #[test]
    fn load_bias_non_pie_exec_is_zero() {
        // ET_EXEC: PT_LOAD vaddrs are absolute (0x400000) and the loader maps the
        // image there, so module_base == min_vaddr, bias == 0, probe == addr_abs.
        let base = 0x40_0000usize;
        let bias = load_bias(base, 0x40_0000);
        assert_eq!(bias, 0);

        let addr_abs = 0x40_1180usize;
        assert_eq!(probe_address(addr_abs, bias), Some(0x40_1180));
    }

    #[test]
    fn probe_below_bias_is_none() {
        // An address below the module's mapped range must not wrap into an
        // in-bounds-looking object probe.
        let bias = 0x7f00_0000_0000usize;
        assert_eq!(probe_address(0x1000, bias), None);
    }

    // --- integration: compile a real fixture with the system toolchain ---------
    //
    // These build a tiny C program with the system `cc` and resolve a known
    // function's address through a real `SymbolResolver`. They SKIP (not fail) if
    // the toolchain is unavailable, so CI on a bare host stays green.
    #[cfg(target_os = "linux")]
    mod integration {
        use super::super::SymbolResolver;
        use std::path::{Path, PathBuf};
        use std::process::Command;

        // A tiny program with a distinctively-named function so it cannot collide
        // with a libc symbol. `main` keeps the linker happy for a full executable.
        const FIXTURE_C: &str = r#"
            int the_answer(void) { return 42; }
            int main(void) { return the_answer(); }
        "#;

        /// A unique temp path root for this test process, cleaned by [`Fixtures`].
        fn tmp_root() -> PathBuf {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "nemclass_symres_{}_{}",
                std::process::id(),
                // A per-call nonce so the two variants don't clash.
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            p
        }

        /// Self-cleaning set of fixture files.
        struct Fixtures(Vec<PathBuf>);
        impl Drop for Fixtures {
            fn drop(&mut self) {
                for p in &self.0 {
                    let _ = std::fs::remove_file(p);
                }
            }
        }

        /// Returns `Some(())` if `cc` and `strip` and `nm` are all runnable, else
        /// `None` (caller should SKIP).
        fn toolchain_ok() -> bool {
            ["cc", "strip", "nm"]
                .iter()
                .all(|t| Command::new(t).arg("--version").output().is_ok())
        }

        /// Looks up `the_answer`'s **file (object-space) address** via `nm`, so the
        /// test can probe `resolve(addr)` with a `module_base` of 0 (probe == file
        /// address). Returns `None` if `nm` yields no matching line.
        fn file_addr_of(binary: &Path, symbol: &str) -> Option<usize> {
            let out = Command::new("nm").arg(binary).output().ok()?;
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                // `nm` lines are: "<hexaddr> <type> <name>". Undefined symbols have
                // no address ("         U name") and are skipped by the split.
                let mut cols = line.split_whitespace();
                let addr = cols.next()?;
                let _ty = cols.next();
                let name = cols.next();
                if name == Some(symbol)
                    && let Ok(v) = usize::from_str_radix(addr, 16)
                {
                    return Some(v);
                }
            }
            None
        }

        #[test]
        fn resolves_named_function_from_dwarf_and_symtab() {
            if !toolchain_ok() {
                eprintln!("SKIP resolves_named_function_from_dwarf_and_symtab: cc/strip/nm unavailable");
                return;
            }

            let root = tmp_root();
            let src = root.with_extension("c");
            let dbg = root.with_extension("dbg"); // -g build (DWARF + symtab)
            let stripped = root.with_extension("stripped"); // stripped build
            let fixtures = Fixtures(vec![src.clone(), dbg.clone(), stripped.clone()]);

            if std::fs::write(&src, FIXTURE_C).is_err() {
                eprintln!("SKIP: could not write fixture source");
                return;
            }

            // Variant 1: with DWARF debug info. A default PIE build is ET_DYN with
            // its lowest PT_LOAD at vaddr 0, so with module_base 0 the load bias is
            // 0 and the probe equals the file address `nm` prints (probe == file
            // addr). This mirrors the common shared-object / PIE mapping case.
            let g = Command::new("cc")
                .args(["-g", "-O0"])
                .arg("-o")
                .arg(&dbg)
                .arg(&src)
                .status();
            match g {
                Ok(s) if s.success() => {}
                _ => {
                    eprintln!("SKIP: cc -g build failed");
                    return;
                }
            }

            let addr = match file_addr_of(&dbg, "the_answer") {
                Some(a) => a,
                None => {
                    eprintln!("SKIP: nm found no `the_answer` in -g build");
                    return;
                }
            };

            // module_base 0: the fixture's file/link addresses are exactly the
            // probe addresses (bias 0), so `resolve(file_addr)` must name it.
            let resolver = SymbolResolver::for_module(&dbg, 0)
                .expect("open -g fixture");
            let name = resolver.resolve(addr);
            assert_eq!(
                name.as_deref(),
                Some("the_answer"),
                "DWARF/symtab tier should name the function at its own address"
            );

            // Variant 2: stripped (no DWARF, no symtab). Must NOT panic; either
            // returns None or falls back to whatever remains (e.g. a dynamic
            // symbol) — we only require graceful, non-panicking behaviour.
            let c = Command::new("cc")
                .args(["-O0"])
                .arg("-o")
                .arg(&stripped)
                .arg(&src)
                .status();
            if matches!(c, Ok(s) if s.success())
                && matches!(Command::new("strip").arg(&stripped).status(), Ok(s) if s.success())
            {
                let stripped_resolver = SymbolResolver::for_module(&stripped, 0)
                    .expect("open stripped fixture");
                // Whatever address we probe, this must not panic. A fully stripped
                // static function is not recoverable, so None is the expected and
                // acceptable outcome; a fallback name is also acceptable.
                let _ = stripped_resolver.resolve(addr);
            } else {
                eprintln!("SKIP (stripped variant only): build/strip failed");
            }

            // Keep `fixtures` alive until here so the files exist for the whole
            // test; its `Drop` removes them on the way out.
            drop(fixtures);
        }
    }
}
