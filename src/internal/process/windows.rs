use std::fs;
use std::path::Path;
use crate::internal::process::Process;

pub const IMAGE_DOS_SIGNATURE: [u8; 2] = *b"MZ";
pub const IMAGE_NT_SIGNATURE: [u8; 4] = [b'P', b'E', 0, 0];

#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct ImageDosHeader {
    pub e_magic: [u8; 2],
    pub _reserved: [u8; 58],
    pub e_lfanew: i32,
}
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct ImageFileHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}
#[repr(C, packed)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub struct ImageOptionalHeader64 {
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
    pub size_of_image: u32,
}

/// Returns the Windows executable name (e.g. `Terraria.exe`) that a Wine
/// process is running, or `None` when `pid` is not a Wine process or no program
/// `.exe` has been mapped yet.
///
/// The presence of mapped PE images (or a Wine install path) in
/// `/proc/<pid>/maps` is what identifies the process as Wine; the program's own
/// `.exe` is the mapped executable that lives under a Wine drive rather than in
/// Wine's install tree.
pub(crate) fn windows_exe_name(pid: u32) -> Option<String> {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).ok()?;

    let mut is_wine = false;
    let mut exe: Option<String> = None;
    let mut exe_builtin = true;

    for line in maps.lines() {
        // maps fields: address perms offset dev inode pathname. Only file-backed
        // mappings carry a pathname (the 6th field, an absolute unix path).
        let path = match line.split_whitespace().nth(5) {
            Some(p) if p.starts_with('/') => p,
            _ => continue,
        };
        let lower = path.to_ascii_lowercase();

        // A mapped PE image or a Wine install path marks this as a Wine process.
        if lower.ends_with(".dll") || lower.ends_with(".exe") || lower.contains("/wine/") {
            is_wine = true;
        }

        if lower.ends_with(".exe") {
            let name = match Path::new(path).file_name() {
                Some(n) => n.to_string_lossy().into_owned(),
                None => continue,
            };
            // The program's own .exe lives under a Wine drive (drive_c, the
            // dosdevices tree, ...); Wine's builtin tool .exes live in the
            // install tree. Prefer the former so a builtin never shadows the
            // real program.
            let builtin = lower.contains("/lib/wine/")
                || lower.contains("/lib64/wine/")
                || lower.contains("/share/wine/");
            if exe.is_none() || (exe_builtin && !builtin) {
                exe = Some(name);
                exe_builtin = builtin;
            }
        }
    }

    if is_wine { exe } else { None }
}

/// Returns the target's pointer width in bytes by reading the PE optional
/// header magic of the module mapped at `base`: `4` for PE32 (`0x10b`, 32-bit /
/// WoW64) and `8` for PE32+ (`0x20b`, 64-bit). Returns `None` when there is no
/// readable PE header at `base` (e.g. a native ELF object).
pub(crate) fn pointer_size(proc: &Process, base: usize) -> Option<usize> {
    let dos: ImageDosHeader = proc.read(base).ok()?;
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

    let opt = nt + IMAGE_NT_SIGNATURE.len() + core::mem::size_of::<ImageFileHeader>();
    match proc.read::<u16>(opt).ok()? {
        0x20b => Some(8),
        0x10b => Some(4),
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
pub(crate) fn size_of_image(proc: &Process, base: usize) -> Option<u32> {
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

    // Optional header follows the 4-byte "PE\0\0" signature and the file header.
    let opt = nt + IMAGE_NT_SIGNATURE.len() + core::mem::size_of::<ImageFileHeader>();
    match proc.read::<u16>(opt).ok()? {
        // PE32+ (64-bit): read the whole optional header we model.
        0x20b => {
            let oh: ImageOptionalHeader64 = proc.read(opt).ok()?;
            let size = oh.size_of_image;
            Some(size)
        }
        // PE32 (32-bit / WoW64): SizeOfImage is at the same offset (56) as in
        // PE32+, so read it directly rather than modelling a second header.
        0x10b => proc.read::<u32>(opt + 56).ok(),
        _ => None,
    }
}
