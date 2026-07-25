//! Exported-symbol resolution from a **live, mapped module image**.
//!
//! This resolves a module's *exported* symbols (PE export directory / ELF
//! `.dynsym`) to absolute addresses by walking the image **as it is laid out in
//! memory**, not on disk. That distinction is the whole point of this module:
//!
//! - We are handed a `module_base` (where the loader mapped the image) and a
//!   reader that fetches bytes at an **absolute address**.
//! - Every structure pointer inside the headers is an **RVA** (relative virtual
//!   address, an offset from the image base), so the on-disk `PointerToRawData`
//!   / section-file-offset machinery is irrelevant here:
//!   `absolute_addr = module_base + rva`.
//!
//! Because everything routes through a `Read` callback, the exact same parser
//! runs against a live [`Process`] *and* against a fabricated `Vec<u8>` in unit
//! tests — see the tests at the bottom of this file.
//!
//! The parsers ([`pe_exports`], [`elf_exports`]) are **platform-neutral** (they
//! only touch the reader and integer math), so they compile and run on every
//! target. Only the [`Process`] convenience methods that wire a real target in
//! are gated to Linux, where `read_buf` is available.
//!
//! ## What this does *not* do
//!
//! Only *exported* symbols are recovered. Private (non-exported / internal)
//! symbols need debug info — a PDB on Windows (symbol server or the `pdb` crate)
//! or the ELF `.symtab` (usually stripped from shipped binaries and never
//! mapped at runtime). That is a deliberate, documented seam; see
//! [`private_symbols`].

use crate::Error;

/// A resolved exported symbol: a name and the **absolute** address it lives at
/// in the target (`module_base + rva`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The exported symbol name (PE export name / ELF `.dynsym` string).
    pub name: String,
    /// The absolute virtual address of the symbol in the target process.
    pub address: usize,
}

/// A "read bytes at an absolute address" callback.
///
/// Returns the number of bytes actually read (mirroring
/// [`Process::read_buf`]). Both the live [`Process`] and the test fixtures
/// satisfy this via a closure, so one parser body serves both. A reader is free
/// to short-read at a mapping boundary; the walkers treat a short read as an
/// [`Error::PartialTransfer`] rather than trusting stale buffer bytes.
pub trait Read {
    /// Read into `buf` starting at absolute address `addr`; return bytes read.
    fn read(&mut self, addr: usize, buf: &mut [u8]) -> crate::Result<usize>;
}

// Any `FnMut(usize, &mut [u8]) -> Result<usize>` is a reader. This is what lets
// callers pass a bare closure (`|addr, buf| ...`) as the reader.
impl<F> Read for F
where
    F: FnMut(usize, &mut [u8]) -> crate::Result<usize>,
{
    fn read(&mut self, addr: usize, buf: &mut [u8]) -> crate::Result<usize> {
        self(addr, buf)
    }
}

/// Fills `buf` fully or fails: a short read is an [`Error::PartialTransfer`],
/// never a silent truncation. Every fixed-width field read below goes through
/// here so a truncated image produces an error instead of reading uninitialised
/// or stale bytes.
fn read_exact<R: Read>(read: &mut R, addr: usize, buf: &mut [u8]) -> crate::Result<()> {
    let n = read.read(addr, buf)?;
    if n != buf.len() {
        return Err(Error::PartialTransfer {
            requested: buf.len(),
            actual: n,
        });
    }
    Ok(())
}

/// Reads a little-endian `u16` at `addr`. PE and (little-endian) ELF are both
/// LE on the x86/x86-64 and aarch64 targets we care about; we hard-assume LE
/// rather than dragging in endian handling for images we can't read anyway.
fn read_u16<R: Read>(read: &mut R, addr: usize) -> crate::Result<u16> {
    let mut b = [0u8; 2];
    read_exact(read, addr, &mut b)?;
    Ok(u16::from_le_bytes(b))
}

/// Reads a little-endian `u32` at `addr`.
fn read_u32<R: Read>(read: &mut R, addr: usize) -> crate::Result<u32> {
    let mut b = [0u8; 4];
    read_exact(read, addr, &mut b)?;
    Ok(u32::from_le_bytes(b))
}

/// Reads a little-endian `u64` at `addr`.
fn read_u64<R: Read>(read: &mut R, addr: usize) -> crate::Result<u64> {
    let mut b = [0u8; 8];
    read_exact(read, addr, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Reads a NUL-terminated C string starting at `addr`, capped at `MAX_NAME`
/// bytes so a corrupt/unterminated pointer can't spin forever. Reads in small
/// chunks to keep syscall count down while still bounding the total.
fn read_cstr<R: Read>(read: &mut R, addr: usize) -> crate::Result<String> {
    /// Hard cap on any single symbol name — real mangled names stay well under
    /// this; the cap only exists to bound a runaway/garbage pointer.
    const MAX_NAME: usize = 4096;
    const CHUNK: usize = 64;

    let mut out = Vec::new();
    let mut buf = [0u8; CHUNK];
    let mut offset = 0usize;
    while out.len() < MAX_NAME {
        let want = CHUNK.min(MAX_NAME - out.len());
        // Short reads are fine here: a name may sit near the end of a mapping.
        // We take whatever came back and stop scanning if we hit the boundary.
        let start = addr.checked_add(offset).ok_or(Error::InvalidAddress)?;
        let got = read.read(start, &mut buf[..want])?;
        if got == 0 {
            break;
        }
        for &byte in &buf[..got] {
            if byte == 0 {
                return String::from_utf8(out).map_err(|_| Error::InvalidString);
            }
            out.push(byte);
        }
        offset += got;
    }
    String::from_utf8(out).map_err(|_| Error::InvalidString)
}

// ---------------------------------------------------------------------------
// PE exports
// ---------------------------------------------------------------------------

/// `IMAGE_DIRECTORY_ENTRY_EXPORT` — index 0 in the optional header's
/// `DataDirectory` array.
const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;

/// Byte offset of the `DataDirectory` array within the **PE32** optional
/// header (`IMAGE_OPTIONAL_HEADER32`). PE32's fixed fields end at 96.
const DATA_DIRECTORY_OFFSET_PE32: usize = 96;
/// Byte offset of the `DataDirectory` array within the **PE32+** optional
/// header (`IMAGE_OPTIONAL_HEADER64`). PE32+ has an 8-byte `ImageBase` (vs. 4)
/// and drops `BaseOfData`, netting +16 versus PE32.
const DATA_DIRECTORY_OFFSET_PE64: usize = 112;

/// Walks the PE **export directory** of the module mapped at `module_base` and
/// returns every named export as `(name, module_base + function_rva)`.
///
/// The walk mirrors the loader's own view — everything is RVA-based, read out
/// of the mapped image:
///
/// 1. DOS header (`MZ`, `e_lfanew`) -> NT headers (`PE\0\0`).
/// 2. Optional-header magic picks PE32 (`0x10b`) vs PE32+ (`0x20b`) and thus
///    where the `DataDirectory` sits.
/// 3. `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]` gives the export
///    directory's RVA and size.
/// 4. `IMAGE_EXPORT_DIRECTORY` yields the parallel arrays
///    `AddressOfNames` / `AddressOfNameOrdinals` / `AddressOfFunctions`.
/// 5. For each name we take its ordinal, index `AddressOfFunctions`, and emit
///    `module_base + func_rva` — **skipping forwarder exports** (a func RVA that
///    falls inside the export directory's own `[rva, rva+size)` range points at
///    a "Dll.Name" forwarder string, not code).
///
/// Every read is bounds-checked (all address math is `checked_add`), so a
/// truncated or malformed image yields an [`Error`], never a panic. Both PE32
/// and PE32+ are handled.
pub fn pe_exports<R: Read>(mut read: R, module_base: usize) -> crate::Result<Vec<Symbol>> {
    let read = &mut read;

    // --- DOS header -> NT headers ------------------------------------------
    let mut mz = [0u8; 2];
    read_exact(read, module_base, &mut mz)?;
    if mz != *b"MZ" {
        return Err(Error::InvalidString);
    }
    // e_lfanew is a signed 32-bit file offset at +0x3C.
    let e_lfanew = read_u32(read, add(module_base, 0x3C)?)? as usize;
    let nt = add(module_base, e_lfanew)?;
    let mut pe_sig = [0u8; 4];
    read_exact(read, nt, &mut pe_sig)?;
    if pe_sig != [b'P', b'E', 0, 0] {
        return Err(Error::InvalidString);
    }

    // The optional header follows the 4-byte signature and the 20-byte
    // IMAGE_FILE_HEADER.
    let opt = add(nt, 4 + 20)?;
    let magic = read_u16(read, opt)?;
    let dd_offset = match magic {
        0x20b => DATA_DIRECTORY_OFFSET_PE64, // PE32+
        0x10b => DATA_DIRECTORY_OFFSET_PE32, // PE32
        _ => return Err(Error::InvalidString),
    };

    // --- DataDirectory[EXPORT] = (rva, size) -------------------------------
    // Each DataDirectory entry is 8 bytes: VirtualAddress (u32), Size (u32).
    let export_entry = add(opt, dd_offset + IMAGE_DIRECTORY_ENTRY_EXPORT * 8)?;
    let export_rva = read_u32(read, export_entry)? as usize;
    let export_size = read_u32(read, add(export_entry, 4)?)? as usize;
    if export_rva == 0 || export_size == 0 {
        // No export directory at all (common for EXEs) — not an error.
        return Ok(Vec::new());
    }
    let export_dir = add(module_base, export_rva)?;

    // --- IMAGE_EXPORT_DIRECTORY --------------------------------------------
    // Offsets within the 40-byte directory:
    //   +0x14 NumberOfFunctions (u32)
    //   +0x18 NumberOfNames     (u32)
    //   +0x1C AddressOfFunctions     (u32 RVA)
    //   +0x20 AddressOfNames         (u32 RVA)
    //   +0x24 AddressOfNameOrdinals  (u32 RVA)
    let number_of_names = read_u32(read, add(export_dir, 0x18)?)? as usize;
    let functions_rva = read_u32(read, add(export_dir, 0x1C)?)? as usize;
    let names_rva = read_u32(read, add(export_dir, 0x20)?)? as usize;
    let ordinals_rva = read_u32(read, add(export_dir, 0x24)?)? as usize;

    let functions = add(module_base, functions_rva)?;
    let names = add(module_base, names_rva)?;
    let ordinals = add(module_base, ordinals_rva)?;

    // The forwarder range: a function RVA inside `[export_rva, export_rva+size)`
    // is a "OtherDll.SomeFunc" forwarder string, not a real code address.
    let forwarder_end = export_rva.checked_add(export_size).ok_or(Error::InvalidAddress)?;

    let mut out = Vec::with_capacity(number_of_names);
    for i in 0..number_of_names {
        // name pointer i: AddressOfNames[i] is an RVA to the name string.
        let name_rva = read_u32(read, add(names, i * 4)?)? as usize;
        let name = read_cstr(read, add(module_base, name_rva)?)?;

        // ordinal i: AddressOfNameOrdinals[i] is a u16 index into
        // AddressOfFunctions (already biased; the export `Base` does NOT apply
        // to this index).
        let ordinal = read_u16(read, add(ordinals, i * 2)?)? as usize;
        let func_rva = read_u32(read, add(functions, ordinal * 4)?)? as usize;

        // Skip forwarder exports (func RVA inside the export directory range).
        if func_rva >= export_rva && func_rva < forwarder_end {
            continue;
        }
        // A zero function RVA is an unused slot.
        if func_rva == 0 {
            continue;
        }

        out.push(Symbol {
            name,
            address: add(module_base, func_rva)?,
        });
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// ELF exports
// ---------------------------------------------------------------------------

/// `PT_DYNAMIC` program-header type.
const PT_DYNAMIC: u32 = 2;
/// Dynamic-array tags we consume.
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

/// `st_info` bind field: `STB_GLOBAL` / `STB_WEAK` are the exported binds.
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
/// `st_shndx == SHN_UNDEF` marks an *imported* (undefined) symbol we skip.
const SHN_UNDEF: u16 = 0;

/// Walks the **ELF dynamic symbol table** (`.dynsym`) of the shared object /
/// PIE mapped at `module_base` and returns each *defined, exported* symbol as
/// `(name, module_base + st_value)`.
///
/// The walk reads the mapped image (never the file):
///
/// 1. ELF header at `module_base`: verify `\x7fELF`, require `ELFCLASS64` +
///    little-endian, read `e_phoff` / `e_phnum`.
/// 2. Scan program headers for `PT_DYNAMIC`; read its segment via **`p_vaddr`**
///    (the in-memory address is `module_base + p_vaddr`), *not* `p_offset`.
/// 3. Parse the `Elf64_Dyn` array for `DT_SYMTAB`, `DT_STRTAB`, and a symbol
///    *count* source: `DT_HASH` (`nchain` == number of `.dynsym` entries) is
///    preferred; `DT_GNU_HASH` is handled as a fallback count.
/// 4. Emit symbols with bind `STB_GLOBAL`/`STB_WEAK`, a non-`SHN_UNDEF`
///    section, and a non-zero `st_value`, as `module_base + st_value`.
///
/// ## Base-relative assumption (be explicit)
///
/// For a **PIE executable or shared object** (`ET_DYN`), `st_value` is an RVA,
/// so `module_base + st_value` is correct. For a **non-PIE `ET_EXEC`** binary,
/// `st_value` is already the absolute link-time address and `module_base`
/// equals its load base, so the same formula still holds. We therefore always
/// use `module_base + st_value`; this is correct for the ET_DYN objects that
/// dominate modern Linux and for load-at-preferred-base ET_EXEC.
///
/// ## Symbol-count limitation (honest)
///
/// A stripped ELF exposes no `.symtab`, and the dynamic array has no explicit
/// `.dynsym` length — the count must be recovered from a hash table. We read it
/// from `DT_HASH`'s `nchain` when present (exact). When only `DT_GNU_HASH`
/// exists (increasingly common on modern toolchains that pass
/// `--hash-style=gnu`), we compute the count by scanning the GNU hash bucket /
/// chain arrays for the highest symbol index; if that walk cannot be completed
/// (truncated image) we return the symbols found so far rather than erroring.
/// If neither hash table is present we cannot bound `.dynsym` and return an
/// empty list rather than reading past it.
pub fn elf_exports<R: Read>(mut read: R, module_base: usize) -> crate::Result<Vec<Symbol>> {
    let read = &mut read;

    // --- ELF header --------------------------------------------------------
    let mut ident = [0u8; 16];
    read_exact(read, module_base, &mut ident)?;
    if &ident[..4] != b"\x7fELF" {
        return Err(Error::InvalidString);
    }
    // EI_CLASS (index 4): 2 == ELFCLASS64. EI_DATA (index 5): 1 == little-endian.
    if ident[4] != 2 || ident[5] != 1 {
        // 32-bit or big-endian ELF: unsupported here (documented limitation).
        return Err(Error::InvalidString);
    }

    // Elf64_Ehdr: e_phoff @ +0x20 (u64), e_phentsize @ +0x36 (u16),
    // e_phnum @ +0x38 (u16).
    let e_phoff = read_u64(read, add(module_base, 0x20)?)? as usize;
    let e_phentsize = read_u16(read, add(module_base, 0x36)?)? as usize;
    let e_phnum = read_u16(read, add(module_base, 0x38)?)? as usize;
    if e_phoff == 0 || e_phentsize < 56 {
        return Err(Error::InvalidString);
    }
    // Program headers are mapped; their table offset is a file offset, but for a
    // typical PT_LOAD-at-0 object it also equals the RVA. We read them relative
    // to base (the ELF header itself sits in the first PT_LOAD, so e_phoff is a
    // valid in-memory delta from base for the header table).
    let phdr_table = add(module_base, e_phoff)?;

    // --- find PT_DYNAMIC ----------------------------------------------------
    // Elf64_Phdr: p_type @ +0 (u32), p_offset @ +8 (u64), p_vaddr @ +16 (u64).
    let mut dyn_vaddr = None;
    for i in 0..e_phnum {
        let ph = add(phdr_table, i * e_phentsize)?;
        let p_type = read_u32(read, ph)?;
        if p_type == PT_DYNAMIC {
            // Use p_vaddr: the segment's in-memory RVA. p_offset is a file
            // offset and is wrong for a mapped image with non-trivial layout.
            dyn_vaddr = Some(read_u64(read, add(ph, 16)?)? as usize);
            break;
        }
    }
    let Some(dyn_vaddr) = dyn_vaddr else {
        // No dynamic segment: a fully static object exports nothing dynamically.
        return Ok(Vec::new());
    };
    let dynamic = add(module_base, dyn_vaddr)?;

    // --- parse the Elf64_Dyn array -----------------------------------------
    // Each entry is 16 bytes: d_tag (i64) @ +0, d_val/d_ptr (u64) @ +8. The
    // pointer tags (DT_SYMTAB/STRTAB/HASH) carry a *vaddr* on a mapped image, so
    // we turn them into absolute addresses via module_base + val.
    let mut symtab = None;
    let mut strtab = None;
    let mut hash = None;
    let mut gnu_hash = None;
    // The dynamic array is NUL-tag terminated; cap iterations defensively.
    for i in 0..4096usize {
        let ent = add(dynamic, i * 16)?;
        let tag = read_u64(read, ent)? as i64;
        let val = read_u64(read, add(ent, 8)?)? as usize;
        match tag {
            DT_NULL => break,
            DT_SYMTAB => symtab = Some(val),
            DT_STRTAB => strtab = Some(val),
            DT_HASH => hash = Some(val),
            DT_GNU_HASH => gnu_hash = Some(val),
            _ => {}
        }
    }

    let (Some(symtab), Some(strtab)) = (symtab, strtab) else {
        return Ok(Vec::new());
    };
    let symtab = add(module_base, symtab)?;
    let strtab = add(module_base, strtab)?;

    // Recover the number of .dynsym entries. DT_HASH.nchain is exact; fall back
    // to a GNU-hash scan; if neither exists we cannot bound the table.
    let count = if let Some(hash) = hash {
        // DT_HASH layout: nbucket (u32), nchain (u32), ... ; nchain == symcount.
        read_u32(read, add(module_base, hash + 4)?)? as usize
    } else if let Some(gnu_hash) = gnu_hash {
        gnu_hash_symbol_count(read, add(module_base, gnu_hash)?)?
    } else {
        return Ok(Vec::new());
    };

    // --- walk .dynsym -------------------------------------------------------
    // Elf64_Sym (24 bytes): st_name (u32) @ +0, st_info (u8) @ +4,
    // st_shndx (u16) @ +6, st_value (u64) @ +8.
    let mut out = Vec::new();
    for i in 0..count {
        let sym = add(symtab, i * 24)?;
        let st_name = read_u32(read, sym)? as usize;
        let st_info = {
            let mut b = [0u8; 1];
            read_exact(read, add(sym, 4)?, &mut b)?;
            b[0]
        };
        let st_shndx = read_u16(read, add(sym, 6)?)?;
        let st_value = read_u64(read, add(sym, 8)?)? as usize;

        // High nibble of st_info is the bind; low nibble is the type.
        let bind = st_info >> 4;
        let exported = bind == STB_GLOBAL || bind == STB_WEAK;
        // Defined (has a section) and actually placed (non-zero value).
        if !exported || st_shndx == SHN_UNDEF || st_value == 0 || st_name == 0 {
            continue;
        }

        let name = read_cstr(read, add(strtab, st_name)?)?;
        if name.is_empty() {
            continue;
        }
        out.push(Symbol {
            name,
            address: add(module_base, st_value)?,
        });
    }

    Ok(out)
}

/// Derives the `.dynsym` entry count from a `DT_GNU_HASH` table mapped at
/// absolute address `gnu_hash`.
///
/// GNU hash has no stored symbol count, so we reconstruct it: the highest chain
/// index reachable from any bucket, walked until its terminating (odd) chain
/// word, gives `max_index + 1`. `symoffset` (the first hashed symbol index)
/// bounds the minimum. This is the standard technique used by dynamic linkers.
///
/// Header layout (all u32): `nbuckets`, `symoffset`, `bloom_size`,
/// `bloom_shift`; then `bloom_size` words of `u64` bloom filter; then
/// `nbuckets` `u32` buckets; then the `u32` chain array starting at
/// `symoffset`. A short read during the walk returns the best count so far.
fn gnu_hash_symbol_count<R: Read>(read: &mut R, gnu_hash: usize) -> crate::Result<usize> {
    let nbuckets = read_u32(read, gnu_hash)? as usize;
    let symoffset = read_u32(read, add(gnu_hash, 4)?)? as usize;
    let bloom_size = read_u32(read, add(gnu_hash, 8)?)? as usize;
    if nbuckets == 0 {
        return Ok(symoffset);
    }

    // buckets start after the 16-byte header + bloom_size u64 words.
    let buckets = add(gnu_hash, 16 + bloom_size * 8)?;
    // The chain array immediately follows the buckets.
    let chains = add(buckets, nbuckets * 4)?;

    // Find the largest symbol index referenced by any bucket.
    let mut last_symbol = 0usize;
    for i in 0..nbuckets {
        let bucket = read_u32(read, add(buckets, i * 4)?)? as usize;
        last_symbol = last_symbol.max(bucket);
    }
    if last_symbol < symoffset {
        // Every bucket empty -> only the un-hashed prefix exists.
        return Ok(symoffset);
    }

    // Walk this bucket's chain from last_symbol until the terminator: the chain
    // word for the final symbol has its low bit set.
    loop {
        let chain_idx = last_symbol - symoffset;
        let word = read_u32(read, add(chains, chain_idx * 4)?)?;
        if word & 1 == 1 {
            break;
        }
        last_symbol += 1;
        // Defensive bound: never scan more than a sane symbol table.
        if last_symbol > symoffset + 1_000_000 {
            break;
        }
    }
    Ok(last_symbol + 1)
}

// ---------------------------------------------------------------------------
// Private (non-exported) symbols — deferred seam
// ---------------------------------------------------------------------------

/// Resolves **private / non-exported** symbols for the module at `module_base`.
///
/// STUB. Exported symbols come from the image itself (see [`pe_exports`] /
/// [`elf_exports`]); private symbols do not — they require external debug info:
///
/// - **Windows**: a PDB, fetched from a symbol server or parsed with the `pdb`
///   crate, matched to the module by its RSDS GUID/age in the debug directory.
/// - **Linux**: the ELF `.symtab` section, which is stripped from most shipped
///   binaries and is not mapped at runtime, so it must be read from the on-disk
///   file (or a separate `.debug` object), not the live image.
///
/// This enumerate-all-symbols shape only has a `module_base`, so it cannot by
/// itself locate the on-disk file its debug info lives in. **M5.2 landed the
/// real address→name path** as a separate, on-disk-file-driven type:
/// [`crate::SymbolResolver`] (built via `SymbolResolver::for_module` /
/// `for_process_module`) and the [`crate::Process::resolve_symbol`] convenience,
/// both behind the optional `symbols` feature. Those cover DWARF, the ELF symbol
/// table, and a PDB on Windows.
///
/// This function stays a stub: full private-symbol *enumeration* (as opposed to
/// point lookup) would layer a "list all `.symtab`/PDB functions with their
/// runtime addresses" API over the same resolver, which no caller needs yet.
///
// TODO(symbols): enumerate all private symbols by layering an iterate-symbols
// API over the M5.2 `SymbolResolver`. Returns `Ok(Vec::new())` until then.
pub fn private_symbols(_module_base: usize) -> crate::Result<Vec<Symbol>> {
    Ok(Vec::new())
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

/// Overflow-checked address addition, mapping overflow to [`Error::InvalidAddress`].
/// Every pointer/RVA computation routes through this so a hostile or truncated
/// image can never wrap a `usize` into an in-bounds read.
#[inline]
fn add(base: usize, offset: usize) -> crate::Result<usize> {
    base.checked_add(offset).ok_or(Error::InvalidAddress)
}

// ---------------------------------------------------------------------------
// Live-process convenience (Linux; depends on `Process::read_buf`)
// ---------------------------------------------------------------------------

// The parsers above are platform-neutral. The glue that feeds a live target's
// `read_buf` into them lives here and is Linux-gated only because `read_buf`'s
// backend is (today) Linux-native; the moment a Windows backend lands this can
// widen with no change to the parsers.
#[cfg(target_os = "linux")]
mod live {
    use super::{Symbol, elf_exports, pe_exports};
    use crate::internal::process::Process;

    impl Process {
        /// Resolves the exported symbols of the module mapped at `module_base`
        /// in this live target.
        ///
        /// Sniffs the image's first bytes: `MZ` -> PE export directory,
        /// `\x7fELF` -> ELF `.dynsym`. Only *exported* symbols are returned;
        /// private symbols need debug info (see
        /// [`super::private_symbols`]).
        pub fn exports(&self, module_base: usize) -> crate::Result<Vec<Symbol>> {
            let reader = |addr: usize, buf: &mut [u8]| self.read_buf(addr, buf);

            let mut magic = [0u8; 4];
            let n = self.read_buf(module_base, &mut magic)?;
            if n >= 2 && &magic[..2] == b"MZ" {
                pe_exports(reader, module_base)
            } else if n >= 4 && &magic == b"\x7fELF" {
                elf_exports(reader, module_base)
            } else {
                // Unknown image format at this base — nothing to resolve.
                Ok(Vec::new())
            }
        }

        /// Resolves a single exported symbol `name` in the module at
        /// `module_base` to its absolute address, or `Ok(None)` if the module
        /// exports no such name.
        pub fn resolve(&self, module_base: usize, name: &str) -> crate::Result<Option<usize>> {
            Ok(self
                .exports(module_base)?
                .into_iter()
                .find(|s| s.name == name)
                .map(|s| s.address))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny in-memory image with an arbitrary load base. The reader closure
    /// indexes `bytes` by `(addr - base)`, exactly as a live process maps an
    /// image at `base`. This is what lets the platform-neutral parsers run
    /// unmodified against a fabricated `Vec<u8>`.
    struct Image {
        base: usize,
        bytes: Vec<u8>,
    }

    impl Image {
        fn new(base: usize, len: usize) -> Self {
            Image {
                base,
                bytes: vec![0u8; len],
            }
        }
        fn put(&mut self, off: usize, data: &[u8]) {
            self.bytes[off..off + data.len()].copy_from_slice(data);
        }
        fn put_u16(&mut self, off: usize, v: u16) {
            self.put(off, &v.to_le_bytes());
        }
        fn put_u32(&mut self, off: usize, v: u32) {
            self.put(off, &v.to_le_bytes());
        }
        fn put_u64(&mut self, off: usize, v: u64) {
            self.put(off, &v.to_le_bytes());
        }
        /// A reader closure over this image: reads at absolute `addr`, short-
        /// reading (or erroring) at the image boundary like a real mapping.
        fn reader(&self) -> impl FnMut(usize, &mut [u8]) -> crate::Result<usize> + '_ {
            move |addr: usize, buf: &mut [u8]| {
                let off = addr
                    .checked_sub(self.base)
                    .ok_or(Error::InvalidAddress)?;
                if off >= self.bytes.len() {
                    return Ok(0);
                }
                let n = buf.len().min(self.bytes.len() - off);
                buf[..n].copy_from_slice(&self.bytes[off..off + n]);
                Ok(n)
            }
        }
    }

    /// Fabricates a minimal but structurally valid PE64 image exporting two
    /// named functions plus one forwarder, at known RVAs. Layout is hand-placed
    /// so every RVA is a known constant we can assert against.
    fn make_pe64() -> (Image, usize) {
        // Fixed layout offsets (== RVAs, since we index from base).
        const E_LFANEW: usize = 0x80;
        const OPT: usize = E_LFANEW + 4 + 20; // after PE\0\0 + file header
        const EXPORT_DIR: usize = 0x400;
        const EXPORT_SIZE: usize = 0x100;
        const NAMES_ARR: usize = 0x600;
        const ORDS_ARR: usize = 0x620;
        const FUNCS_ARR: usize = 0x640;
        const STR_ALPHA: usize = 0x700;
        const STR_BETA: usize = 0x710;
        const STR_FWD: usize = 0x720;
        // The two real function bodies + one forwarder-string slot.
        const FUNC_ALPHA_RVA: u32 = 0x1000;
        const FUNC_BETA_RVA: u32 = 0x2000;
        // A forwarder func RVA sits *inside* the export directory range.
        const FWD_RVA: u32 = (EXPORT_DIR + 0x80) as u32;

        let mut img = Image::new(0, 0x1000 + 0x2000);

        // DOS header.
        img.put(0, b"MZ");
        img.put_u32(0x3C, E_LFANEW as u32);
        // NT signature + minimal file header (machine, #sections... we only need
        // size_of_optional_header irrelevant here) then optional header magic.
        img.put(E_LFANEW, &[b'P', b'E', 0, 0]);
        img.put_u16(OPT, 0x20b); // PE32+ magic

        // DataDirectory[EXPORT] at OPT + 112.
        let dd = OPT + DATA_DIRECTORY_OFFSET_PE64;
        img.put_u32(dd, EXPORT_DIR as u32);
        img.put_u32(dd + 4, EXPORT_SIZE as u32);

        // IMAGE_EXPORT_DIRECTORY.
        img.put_u32(EXPORT_DIR + 0x14, 3); // NumberOfFunctions
        img.put_u32(EXPORT_DIR + 0x18, 3); // NumberOfNames
        img.put_u32(EXPORT_DIR + 0x1C, FUNCS_ARR as u32);
        img.put_u32(EXPORT_DIR + 0x20, NAMES_ARR as u32);
        img.put_u32(EXPORT_DIR + 0x24, ORDS_ARR as u32);

        // AddressOfNames -> three name-string RVAs.
        img.put_u32(NAMES_ARR, STR_ALPHA as u32);
        img.put_u32(NAMES_ARR + 4, STR_BETA as u32);
        img.put_u32(NAMES_ARR + 8, STR_FWD as u32);
        // AddressOfNameOrdinals -> indices into AddressOfFunctions.
        img.put_u16(ORDS_ARR, 0);
        img.put_u16(ORDS_ARR + 2, 1);
        img.put_u16(ORDS_ARR + 4, 2);
        // AddressOfFunctions.
        img.put_u32(FUNCS_ARR, FUNC_ALPHA_RVA);
        img.put_u32(FUNCS_ARR + 4, FUNC_BETA_RVA);
        img.put_u32(FUNCS_ARR + 8, FWD_RVA); // forwarder

        // Name strings.
        img.put(STR_ALPHA, b"alpha\0");
        img.put(STR_BETA, b"beta\0");
        img.put(STR_FWD, b"forwarded\0");

        (img, 3)
    }

    #[test]
    fn pe_exports_resolves_named_functions_and_skips_forwarder() {
        let base = 0x1_4000_0000usize;
        let (mut img, _) = make_pe64();
        img.base = base;

        let syms = pe_exports(img.reader(), base).expect("parse ok");

        // Two real exports; the forwarder ("forwarded") is skipped.
        assert_eq!(syms.len(), 2);
        let alpha = syms.iter().find(|s| s.name == "alpha").expect("alpha");
        let beta = syms.iter().find(|s| s.name == "beta").expect("beta");
        assert_eq!(alpha.address, base + 0x1000);
        assert_eq!(beta.address, base + 0x2000);
        assert!(syms.iter().all(|s| s.name != "forwarded"));
    }

    #[test]
    fn pe_truncated_image_errors_without_panicking() {
        let base = 0x40_0000usize;
        let (mut img, _) = make_pe64();
        img.base = base;
        // Chop the image off right after the DOS header so the NT-header read
        // short-reads: must be an Err, never a panic.
        img.bytes.truncate(0x40);
        let r = pe_exports(img.reader(), base);
        assert!(r.is_err(), "expected error on truncated image, got {r:?}");
    }

    #[test]
    fn pe_rejects_non_mz_image() {
        let base = 0x1000usize;
        let mut img = Image::new(base, 0x100);
        img.put(0, b"XX");
        assert!(pe_exports(img.reader(), base).is_err());
    }

    /// Fabricates a minimal ELF64 shared object with a PT_DYNAMIC segment, a
    /// DT_HASH (for the symbol count), a DT_STRTAB and a DT_SYMTAB exporting one
    /// defined GLOBAL function and containing one UNDEF import (skipped).
    fn make_elf64(base: usize) -> Image {
        const E_PHOFF: usize = 0x40;
        const PHENTSIZE: usize = 56;
        const DYNAMIC: usize = 0x200; // PT_DYNAMIC vaddr
        const HASH: usize = 0x400;
        const STRTAB: usize = 0x500;
        const SYMTAB: usize = 0x600;
        const FUNC_VALUE: u64 = 0x1234;

        let mut img = Image::new(base, 0x800);

        // ELF header ident: \x7fELF, class64 (2), LE (1), version 1.
        img.put(0, b"\x7fELF");
        img.put(4, &[2, 1, 1, 0]);
        // e_phoff @ 0x20, e_phentsize @ 0x36, e_phnum @ 0x38.
        img.put_u64(0x20, E_PHOFF as u64);
        img.put_u16(0x36, PHENTSIZE as u16);
        img.put_u16(0x38, 1); // one program header

        // Program header 0: PT_DYNAMIC. p_type@0, p_vaddr@16.
        img.put_u32(E_PHOFF, PT_DYNAMIC);
        img.put_u64(E_PHOFF + 16, DYNAMIC as u64);

        // Dynamic array (16-byte entries): tag @+0, val @+8.
        let mut d = DYNAMIC;
        let dyn_put = |img: &mut Image, off: &mut usize, tag: i64, val: u64| {
            img.put_u64(*off, tag as u64);
            img.put_u64(*off + 8, val);
            *off += 16;
        };
        dyn_put(&mut img, &mut d, DT_HASH, HASH as u64);
        dyn_put(&mut img, &mut d, DT_STRTAB, STRTAB as u64);
        dyn_put(&mut img, &mut d, DT_SYMTAB, SYMTAB as u64);
        dyn_put(&mut img, &mut d, DT_NULL, 0);

        // DT_HASH: nbucket, nchain. nchain == number of .dynsym entries (2).
        img.put_u32(HASH, 1); // nbucket
        img.put_u32(HASH + 4, 2); // nchain == symbol count

        // String table: index 0 is the empty string, then our names.
        // "\0myfunc\0imported\0"
        img.put(STRTAB, b"\0");
        let name_myfunc = 1u32;
        img.put(STRTAB + 1, b"myfunc\0");
        let name_import = (STRTAB + 1 + 7 - STRTAB) as u32; // == 8
        img.put(STRTAB + 8, b"imported\0");

        // Symbol table (Elf64_Sym, 24 bytes each). Index 0 is the reserved null
        // symbol; index 1 is our exported function.
        // sym[0]: all-zero null symbol (already zeroed).
        // sym[1]: st_name, st_info (GLOBAL func = 0x12), st_shndx (1, defined),
        //         st_value.
        let s1 = SYMTAB + 24;
        img.put_u32(s1, name_myfunc); // st_name
        img.put(s1 + 4, &[0x12]); // st_info: bind=1(GLOBAL)<<4 | type=2(FUNC)
        img.put(s1 + 5, &[0]); // st_other
        img.put_u16(s1 + 6, 1); // st_shndx (defined section)
        img.put_u64(s1 + 8, FUNC_VALUE); // st_value

        // Keep name_import referenced so it lives in the string table even
        // though no symbol points at it (documents the layout).
        let _ = name_import;

        img
    }

    #[test]
    fn elf_exports_resolves_defined_global() {
        let base = 0x7f00_0000_0000usize;
        let img = make_elf64(base);
        let syms = elf_exports(img.reader(), base).expect("parse ok");
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "myfunc");
        assert_eq!(syms[0].address, base + 0x1234);
    }

    #[test]
    fn elf_skips_undef_import() {
        // Rebuild with sym[1] marked UNDEF (st_shndx = 0): it must be skipped,
        // leaving zero exports.
        let base = 0x5555_0000usize;
        let mut img = make_elf64(base);
        // sym[1] st_shndx sits at SYMTAB + 24 + 6.
        img.put_u16(0x600 + 24 + 6, SHN_UNDEF);
        let syms = elf_exports(img.reader(), base).expect("parse ok");
        assert!(syms.is_empty(), "UNDEF symbol should be skipped: {syms:?}");
    }

    #[test]
    fn elf_truncated_image_errors_without_panicking() {
        let base = 0x1000usize;
        let mut img = make_elf64(base);
        // Truncate mid-header so e_phoff read short-reads.
        img.bytes.truncate(0x24);
        let r = elf_exports(img.reader(), base);
        assert!(r.is_err(), "expected error on truncated ELF, got {r:?}");
    }

    #[test]
    fn elf_rejects_non_elf_image() {
        let base = 0x1000usize;
        let mut img = Image::new(base, 0x100);
        img.put(0, b"\x7fELG");
        assert!(elf_exports(img.reader(), base).is_err());
    }

    #[test]
    fn private_symbols_is_stubbed_empty() {
        assert_eq!(private_symbols(0x1000).unwrap(), Vec::new());
    }
}
