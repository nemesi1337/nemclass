//! Wine detection on Linux.
//!
//! A Wine process's ELF image is just the loader, so identifying the actual
//! Windows program it runs means inspecting the PE images it has mapped. This is
//! Linux-specific (`/proc/<pid>/maps`) Wine glue; the platform-neutral PE header
//! parsing it conceptually relates to lives in [`crate::pe`].

use std::fs;
use std::path::Path;

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
