//! Wine detection on Linux.
//!
//! A Wine/Proton process's ELF image is just the loader (`wine-preloader`,
//! `wine64-preloader`, `wine`, `wine64`), so a whole Wine prefix — the game plus
//! Wine's own service processes (`services.exe`, `explorer.exe`, `plugplay.exe`,
//! `winedevice.exe`, …) — all list under that one useless loader name. To make
//! the process picker usable we surface the actual Windows program each one runs.
//!
//! This is Linux-specific (`/proc/<pid>`) Wine glue; the platform-neutral PE
//! header parsing it conceptually relates to lives in [`crate::pe`].

use std::fs;
use std::path::Path;

/// Returns the Windows program name (e.g. `Terraria.exe`) that a Wine process is
/// running, or `None` when it cannot be determined yet (e.g. `wineserver`, or a
/// loader caught before it has exec'd its program).
///
/// The caller has already identified `pid` as a Wine loader (its ELF `exe` is
/// `wine`/`wine64`/`*-preloader`), so this only has to pick the program out of
/// the loader's environment. It tries the cheap, precise `/proc/<pid>/cmdline`
/// first — Wine's argv carries the program it launched — and falls back to
/// scanning the process's mapped PE images only when argv yields nothing (the
/// maps of a running game are multi-megabyte, so we avoid reading them when we
/// can).
pub(crate) fn wine_program_name(pid: u32) -> Option<String> {
    exe_from_cmdline(pid).or_else(|| exe_from_maps(pid))
}

/// Extracts the program `.exe` from `/proc/<pid>/cmdline` (NUL-separated argv).
fn exe_from_cmdline(pid: u32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    program_from_cmdline_bytes(&raw)
}

/// Pure core of [`exe_from_cmdline`]: the first argv entry that names a Windows
/// `.exe` wins, taking its basename. Split out so it is unit-testable without a
/// live `/proc`.
fn program_from_cmdline_bytes(raw: &[u8]) -> Option<String> {
    raw.split(|&b| b == 0)
        .filter(|arg| !arg.is_empty())
        .filter_map(|arg| std::str::from_utf8(arg).ok())
        .find_map(program_exe_basename)
}

/// If `arg` names a Windows program `.exe`, returns its basename. The Wine loader
/// binaries themselves (`wine`, `wine64`, `*-preloader`) don't end in `.exe`, so
/// any `.exe` argument is the program (or a Wine builtin like `services.exe`,
/// which is exactly the useful name for that process).
fn program_exe_basename(arg: &str) -> Option<String> {
    if !arg.to_ascii_lowercase().ends_with(".exe") {
        return None;
    }
    Some(win_basename(arg).to_owned())
}

/// Basename of a path that may use either `/` (unix / a Wine drive) or `\`
/// (a Windows path like `C:\windows\system32\services.exe`) separators.
fn win_basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// Fallback: find the program `.exe` among the process's mapped PE images in
/// `/proc/<pid>/maps`. Prefers a program mapped under a Wine *drive* over one in
/// Wine's *install tree*, so a builtin tool never shadows the real program.
fn exe_from_maps(pid: u32) -> Option<String> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;

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
        if !lower.ends_with(".exe") {
            continue;
        }

        let name = match Path::new(path).file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => continue,
        };
        // The program's own .exe lives under a Wine drive (drive_c, the
        // dosdevices tree, …); Wine's builtin tool .exes live in the install
        // tree. Prefer the former so a builtin never shadows the real program.
        let builtin = lower.contains("/lib/wine/")
            || lower.contains("/lib64/wine/")
            || lower.contains("/share/wine/");
        if exe.is_none() || (exe_builtin && !builtin) {
            exe = Some(name);
            exe_builtin = builtin;
        }
    }

    exe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win_basename_handles_both_separators() {
        assert_eq!(win_basename("C:\\windows\\system32\\services.exe"), "services.exe");
        assert_eq!(win_basename("/home/u/.wine/drive_c/Game.exe"), "Game.exe");
        assert_eq!(win_basename("Z:\\mixed/path\\Terraria.exe"), "Terraria.exe");
        assert_eq!(win_basename("noseparators.exe"), "noseparators.exe");
    }

    #[test]
    fn cmdline_prefers_first_exe_argument() {
        // Typical Wine argv: the preloader + wine binary, then the program. The
        // loader binaries don't end in `.exe`, so the program is picked.
        let raw = b"/usr/lib/wine/wine64-preloader\0/usr/lib/wine/wine64\0Z:\\game\\Terraria.exe\0";
        assert_eq!(program_from_cmdline_bytes(raw).as_deref(), Some("Terraria.exe"));
    }

    #[test]
    fn cmdline_windows_path_and_trailing_args() {
        let raw = b"C:\\windows\\system32\\services.exe\0-k\0netsvcs\0";
        assert_eq!(program_from_cmdline_bytes(raw).as_deref(), Some("services.exe"));
    }

    #[test]
    fn cmdline_unix_drive_path() {
        let raw = b"/home/u/.wine/drive_c/Program Files/App/App.EXE\0--flag\0";
        assert_eq!(program_from_cmdline_bytes(raw).as_deref(), Some("App.EXE"));
    }

    #[test]
    fn cmdline_without_exe_is_none() {
        // e.g. `wineserver` — a Wine process that runs no Windows program.
        assert_eq!(program_from_cmdline_bytes(b"wineserver\0-p\0"), None);
        assert_eq!(program_from_cmdline_bytes(b""), None);
    }
}
