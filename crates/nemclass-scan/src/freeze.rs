//! Frozen values — addresses whose bytes are periodically re-written so the
//! target can't change them (Cheat Engine's "freeze" checkbox).

use crate::target::WriteTarget;

/// A set of frozen `(address, bytes)` entries. The UI calls [`FreezeSet::apply`]
/// on a cadence (e.g. once per frame) to re-pin each value in the target.
#[derive(Debug, Clone, Default)]
pub struct FreezeSet {
    /// The frozen entries: an absolute address and the exact bytes to hold there.
    pub entries: Vec<(usize, Vec<u8>)>,
}

impl FreezeSet {
    /// An empty freeze set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) a frozen value at `address`.
    pub fn set(&mut self, address: usize, bytes: Vec<u8>) {
        if let Some(entry) = self.entries.iter_mut().find(|(a, _)| *a == address) {
            entry.1 = bytes;
        } else {
            self.entries.push((address, bytes));
        }
    }

    /// Removes the frozen value at `address`, if present.
    pub fn remove(&mut self, address: usize) {
        self.entries.retain(|(a, _)| *a != address);
    }

    /// Number of frozen entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no frozen entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Writes every entry into `target`. Called periodically by the UI so frozen
    /// values stay pinned.
    ///
    /// A short or failed write on one entry does not abort the rest — freezing
    /// is best-effort and a transiently-unmapped page should not stop the other
    /// entries from being re-pinned. The per-entry outcome is reported rather
    /// than discarded: a caller that only saw a success count could not tell
    /// "not frozen because the process died" from "not frozen because the page
    /// is read-only" from "frozen fine".
    pub fn apply<T: WriteTarget>(&self, target: &T) -> FreezeReport {
        let mut report = FreezeReport::default();
        for (addr, bytes) in &self.entries {
            match target.write(*addr, bytes) {
                Ok(written) if written == bytes.len() => report.written += 1,
                Ok(_) => report.short += 1,
                Err(e) => {
                    report.failed += 1;
                    report.last_error = Some(e);
                }
            }
        }
        report
    }
}

/// The per-pass outcome of [`FreezeSet::apply`].
///
/// `written + short + failed` always equals the entry count, so a caller can
/// tell the user exactly how many values are actually pinned and why the rest
/// are not.
#[derive(Debug, Default)]
pub struct FreezeReport {
    /// Entries whose full byte span was written.
    pub written: usize,
    /// Entries the target accepted only partially (a page boundary, a shrinking
    /// mapping).
    pub short: usize,
    /// Entries whose write returned an error.
    pub failed: usize,
    /// The last error seen, for a status message.
    pub last_error: Option<nemclass_core::Error>,
}

impl FreezeReport {
    /// Whether every entry was fully written.
    pub fn all_written(&self) -> bool {
        self.short == 0 && self.failed == 0
    }

    /// A short human-readable reason when some entry did not stick, else `None`.
    pub fn problem(&self) -> Option<String> {
        if self.all_written() {
            return None;
        }
        Some(match &self.last_error {
            Some(e) => format!(
                "{} of {} frozen values not written: {e}",
                self.short + self.failed,
                self.written + self.short + self.failed
            ),
            None => format!(
                "{} of {} frozen values only partially written",
                self.short,
                self.written + self.short + self.failed
            ),
        })
    }
}
