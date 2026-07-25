//! Auto-loading of the `nemclass_mod` kernel auth-key from a well-known file.
//!
//! The key file path is resolved as follows:
//! 1. If `NEMCLASS_KEY_FILE` is set and non-empty, use that path.
//! 2. Otherwise use `$HOME/.local/data/nemclass_kernel_key`.
//! 3. If `HOME` is unset (unusual), return `None` — no file, no error.
//!
//! The file is expected to contain the key as raw hex text, optionally
//! surrounded by whitespace or a trailing newline.  An absent, unreadable, or
//! empty file is silently ignored; the caller receives `None`.
//!
//! This module uses only `std` — no extra dependencies, no `#[cfg]` guards
//! (it compiles cleanly on every target, returning `None` wherever the
//! environment variable / home dir is unavailable).

use std::path::PathBuf;

/// Returns the path to the key file, honouring the `NEMCLASS_KEY_FILE`
/// environment variable override.  Returns `None` only when neither the
/// override nor `HOME` is set.
pub fn kernel_key_path() -> Option<PathBuf> {
    // Honour the explicit override first.
    if let Ok(v) = std::env::var("NEMCLASS_KEY_FILE") {
        let v = v.trim().to_owned();
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }

    // Fall back to $HOME/.local/data/nemclass_kernel_key.
    let home = std::env::var("HOME").ok()?;
    let home = home.trim();
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home).join(".local/data/nemclass_kernel_key"))
}

/// Attempts to read the kernel auth-key hex string from the key file.
///
/// Returns `Some(hex_string)` (trimmed, non-empty) on success, `None` on any
/// error (file absent, unreadable, or empty after trimming).  Never panics.
pub fn read_kernel_key() -> Option<String> {
    let path = kernel_key_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let trimmed = raw.trim().to_owned();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
