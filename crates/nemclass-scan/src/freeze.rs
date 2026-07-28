//! Frozen values — addresses whose bytes are periodically re-written so the
//! target can't change them (Cheat Engine's "freeze" checkbox).

use nemclass_core::Result;

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
    /// entries from being re-pinned. Returns the number of entries whose full
    /// byte span was written.
    pub fn apply<T: WriteTarget>(&self, target: &T) -> Result<usize> {
        let mut ok = 0;
        for (addr, bytes) in &self.entries {
            if let Ok(written) = target.write(*addr, bytes)
                && written == bytes.len()
            {
                ok += 1;
            }
        }
        Ok(ok)
    }
}
