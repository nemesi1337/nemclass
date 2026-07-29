//! Frozen values — addresses whose bytes are periodically re-written so the
//! target can't change them (Cheat Engine's "freeze" checkbox).

use crate::target::{ScanTarget, WriteTarget};
use crate::value_type::ScanValueType;

/// How strictly a value is held.
///
/// Cheat Engine's freeze dropdown. "Allow increase" is not a weaker freeze — it
/// is a *ratchet*: the value may rise on its own and the new high becomes the
/// floor, which is how a score or a level is held without pinning it to one
/// number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FreezeMode {
    /// Hold exactly this value.
    #[default]
    Exact,
    /// Let the value rise; write it back if it falls.
    AllowIncrease,
    /// Let the value fall; write it back if it rises.
    AllowDecrease,
}

impl FreezeMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Exact => "Exact",
            Self::AllowIncrease => "Allow increase",
            Self::AllowDecrease => "Allow decrease",
        }
    }

    /// Whether the mode needs to read before it writes.
    pub fn reads_first(self) -> bool {
        !matches!(self, Self::Exact)
    }
}

/// One frozen value.
#[derive(Debug, Clone, PartialEq)]
pub struct FreezeEntry {
    /// Absolute address.
    pub address: usize,
    /// The exact bytes to hold there.
    pub bytes: Vec<u8>,
    /// How strictly.
    pub mode: FreezeMode,
    /// How to compare, for the ratchet modes. `None` compares bytewise, which is
    /// wrong for a signed or floating-point value — so a ratchet without a type
    /// falls back to an exact freeze rather than comparing nonsense.
    pub value_type: Option<ScanValueType>,
}

/// A set of frozen entries. The UI calls [`FreezeSet::apply`] on a cadence
/// (e.g. once per frame) to re-pin each value in the target.
#[derive(Debug, Clone, Default)]
pub struct FreezeSet {
    /// The frozen entries.
    pub entries: Vec<FreezeEntry>,
}

impl FreezeSet {
    /// An empty freeze set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds (or replaces) an exact frozen value at `address`.
    pub fn set(&mut self, address: usize, bytes: Vec<u8>) {
        self.set_with(address, bytes, FreezeMode::Exact, None);
    }

    /// Adds (or replaces) a frozen value with an explicit mode.
    pub fn set_with(
        &mut self,
        address: usize,
        bytes: Vec<u8>,
        mode: FreezeMode,
        value_type: Option<ScanValueType>,
    ) {
        let entry = FreezeEntry { address, bytes, mode, value_type };
        match self.entries.iter_mut().find(|e| e.address == address) {
            Some(existing) => *existing = entry,
            None => self.entries.push(entry),
        }
    }

    /// Removes the frozen value at `address`, if present.
    pub fn remove(&mut self, address: usize) {
        self.entries.retain(|e| e.address != address);
    }

    /// Consumes the set, returning its entries.
    ///
    /// For handing a snapshot to a writer thread: the set is rebuilt from the
    /// table on every UI tick, so there is nothing to keep.
    pub fn into_entries(self) -> Vec<FreezeEntry> {
        self.entries
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
        for entry in &self.entries {
            match target.write(entry.address, &entry.bytes) {
                Ok(written) if written == entry.bytes.len() => report.written += 1,
                Ok(_) => report.short += 1,
                Err(e) => {
                    report.failed += 1;
                    report.last_error = Some(e);
                }
            }
        }
        report
    }

    /// [`Self::apply`], honouring the ratchet modes.
    ///
    /// Takes `&mut self` because a ratchet *moves*: when the value rises past an
    /// `AllowIncrease` floor, the new high becomes the floor. Storing that back
    /// is the whole behaviour — without it the next pass would drag the value
    /// back down to the original, which is an exact freeze wearing a different
    /// label.
    pub fn apply_ratcheting<T: ScanTarget + WriteTarget>(
        &mut self,
        target: &T,
    ) -> FreezeReport {
        let mut report = FreezeReport::default();
        for entry in &mut self.entries {
            // A ratchet needs a numeric comparison, and a bytewise one is wrong
            // for anything signed or floating-point.
            let ratchet = match (entry.mode, entry.value_type) {
                (FreezeMode::Exact, _) | (_, None) => None,
                (mode, Some(vt)) => Some((mode, vt)),
            };

            if let Some((mode, value_type)) = ratchet {
                let mut current = vec![0u8; entry.bytes.len()];
                match target.read(entry.address, &mut current) {
                    Ok(n) if n == current.len() => {
                        let moved_the_right_way = match mode {
                            FreezeMode::AllowIncrease => value_type.compare_change(
                                crate::compare::ScanCompareType::Increased,
                                &current,
                                &entry.bytes,
                            ),
                            FreezeMode::AllowDecrease => value_type.compare_change(
                                crate::compare::ScanCompareType::Decreased,
                                &current,
                                &entry.bytes,
                            ),
                            FreezeMode::Exact => false,
                        };
                        if moved_the_right_way {
                            // Let it stand, and hold the new value from now on.
                            entry.bytes = current;
                            report.written += 1;
                            continue;
                        }
                    }
                    // Unreadable: fall through and write, which is the safer of
                    // the two — a ratchet that stops writing because one read
                    // failed silently stops freezing.
                    _ => {}
                }
            }

            match target.write(entry.address, &entry.bytes) {
                Ok(written) if written == entry.bytes.len() => report.written += 1,
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
