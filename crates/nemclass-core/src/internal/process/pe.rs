//! Portable Executable (PE) header parsing over a live target.
//!
//! Shared between two callers that both need to read PE headers out of a
//! target's memory: today's **Wine detection** on Linux (a Wine process maps
//! Windows `.exe`/`.dll` images whose true `SizeOfImage` and pointer width can
//! only be recovered from the mapped headers) and a **future native Windows
//! backend** (same on-disk layout, same reads). Keeping this in one platform
//! neutral module means the Windows impl reuses it verbatim.
//!
//! All reads go through [`Process::read`], so this module works against any
//! `MemoryBackend` the process was opened with.

use crate::internal::process::Process;

/// `"MZ"` — the DOS header magic at the start of every PE image.
pub const IMAGE_DOS_SIGNATURE: [u8; 2] = *b"MZ";
/// `"PE\0\0"` — the NT header signature `e_lfanew` bytes into the image.
pub const IMAGE_NT_SIGNATURE: [u8; 4] = [b'P', b'E', 0, 0];

/// PE32 optional-header magic (32-bit / WoW64).
pub const PE32_MAGIC: u16 = 0x10b;
/// PE32+ optional-header magic (64-bit).
pub const PE32PLUS_MAGIC: u16 = 0x20b;

/// `SizeOfImage` sits at this byte offset within the optional header in *both*
/// PE32 and PE32+, so a 32-bit module can be read without modelling a second
/// optional-header layout.
pub const SIZE_OF_IMAGE_OFFSET: usize = 56;

/// The `IMAGE_DOS_HEADER` — only the two fields we actually consume are named;
/// the rest of the 64-byte header is reserved padding.
#[repr(C, packed)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ImageDosHeader {
    /// Magic number, must equal [`IMAGE_DOS_SIGNATURE`] (`"MZ"`).
    pub e_magic: [u8; 2],
    /// Reserved header bytes between the magic and `e_lfanew`.
    pub reserved: [u8; 58],
    /// File offset of the NT headers ([`IMAGE_NT_SIGNATURE`]).
    pub e_lfanew: i32,
}

/// The `IMAGE_FILE_HEADER` (COFF header) that follows the NT signature. Modelled
/// so callers can size and skip past it to reach the optional header.
#[repr(C, packed)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ImageFileHeader {
    /// Target machine architecture.
    pub machine: u16,
    /// Number of section headers.
    pub number_of_sections: u16,
    /// Low 32 bits of the image creation timestamp.
    pub time_date_stamp: u32,
    /// File offset of the COFF symbol table (deprecated; usually 0).
    pub pointer_to_symbol_table: u32,
    /// Number of entries in the symbol table.
    pub number_of_symbols: u32,
    /// Size of the optional header that follows.
    pub size_of_optional_header: u16,
    /// Image characteristics flags.
    pub characteristics: u16,
}

/// The PE32+ (`0x20b`, 64-bit) `IMAGE_OPTIONAL_HEADER64`, truncated at the
/// `SizeOfImage` field we need. PE32 (32-bit) shares field offsets up to and
/// including `SizeOfImage`, so this models the only variant we read wholesale.
#[repr(C, packed)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ImageOptionalHeader64 {
    /// [`PE32_MAGIC`] or [`PE32PLUS_MAGIC`].
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    /// Total size of the image in memory — the authoritative module size.
    pub size_of_image: u32,
}

/// Returns the file offset of the optional header for a PE mapped at `base`, and
/// the magic word identifying its variant, or `None` when there is no readable
/// PE header at `base` (e.g. a native ELF object). The returned offset points at
/// the optional header's `magic` field.
fn optional_header(proc: &Process, base: usize) -> Option<(usize, u16)> {
    let dos: ImageDosHeader = proc.read(base).ok()?;
    // Copy packed fields out to locals before use (no references into packed).
    let magic = dos.e_magic;
    let e_lfanew = dos.e_lfanew;
    if magic != IMAGE_DOS_SIGNATURE || e_lfanew < 0 {
        return None;
    }

    let nt = base.checked_add(e_lfanew as usize)?;
    let sig: [u8; 4] = proc.read(nt).ok()?;
    if sig != IMAGE_NT_SIGNATURE {
        return None;
    }

    // The optional header follows the 4-byte "PE\0\0" signature and the file
    // header.
    let opt = nt + IMAGE_NT_SIGNATURE.len() + core::mem::size_of::<ImageFileHeader>();
    let variant = proc.read::<u16>(opt).ok()?;
    Some((opt, variant))
}

/// Returns the target's pointer width in bytes by reading the PE optional
/// header magic of the module mapped at `base`: `4` for PE32 (`0x10b`, 32-bit /
/// WoW64) and `8` for PE32+ (`0x20b`, 64-bit). Returns `None` when there is no
/// readable PE header at `base` (e.g. a native ELF object).
pub fn pointer_size(proc: &Process, base: usize) -> Option<usize> {
    match optional_header(proc, base)?.1 {
        PE32PLUS_MAGIC => Some(8),
        PE32_MAGIC => Some(4),
        _ => None,
    }
}

/// Reads a mapped PE module's true `SizeOfImage` out of the headers Wine maps
/// at `base` (the image base). Returns `None` when there is no readable PE
/// header there — e.g. a native `.so`, or a page that can't be read.
///
/// Wine splits one PE across several `/proc/<pid>/maps` entries, so the span of
/// those mappings undercounts the image; `SizeOfImage` is the authoritative
/// size. The field sits at offset 56 of the optional header in both PE32 and
/// PE32+, so 32-bit (WoW64) modules are handled too.
pub fn size_of_image(proc: &Process, base: usize) -> Option<u32> {
    let (opt, variant) = optional_header(proc, base)?;
    match variant {
        // PE32+ (64-bit): read the whole optional header we model.
        PE32PLUS_MAGIC => {
            let oh: ImageOptionalHeader64 = proc.read(opt).ok()?;
            let size = oh.size_of_image;
            Some(size)
        }
        // PE32 (32-bit / WoW64): SizeOfImage is at the same offset (56) as in
        // PE32+, so read it directly rather than modelling a second header.
        PE32_MAGIC => proc.read::<u32>(opt + SIZE_OF_IMAGE_OFFSET).ok(),
        _ => None,
    }
}
