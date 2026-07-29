//! Byte patches: what was changed in the target, what it used to be, and how to
//! put it back.
//!
//! NOP-ing an instruction was the only patch the application could make, it was
//! irreversible, and nothing recorded it — so a session's changes were
//! untrackable and a mistake was unrecoverable short of restarting the target.
//!
//! A [`PatchSet`] keeps the original bytes alongside the new ones, so any patch
//! can be reverted, and persists to TOML alongside the project so a set of edits
//! survives a restart.
//!
//! Addresses are absolute. A patch is only meaningful for the process it was
//! made against — module bases move — so a persisted set records the module and
//! offset it was taken at where one is known, and
//! [`Patch::rebased`] moves it to a new run.

use serde::{Deserialize, Serialize};

use crate::error::{ModelError, Result};

/// One recorded byte patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// Absolute address the patch was applied at.
    pub address: usize,
    /// The bytes that were there before, as hex (`48 89 E5`).
    pub original: String,
    /// The bytes written, as hex.
    pub patched: String,
    /// What the patch is for.
    #[serde(default)]
    pub description: String,
    /// The module the address fell inside when the patch was made, if known.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub module: String,
    /// The offset within that module.
    #[serde(default)]
    pub module_offset: usize,
    /// Whether the patched bytes are currently in the target.
    #[serde(default)]
    pub applied: bool,
}

impl Patch {
    /// Record a patch from the bytes on either side.
    pub fn new(address: usize, original: &[u8], patched: &[u8]) -> Self {
        Self {
            address,
            original: to_hex(original),
            patched: to_hex(patched),
            description: String::new(),
            module: String::new(),
            module_offset: 0,
            applied: false,
        }
    }

    /// Anchor the patch to a module, so it can be re-applied after a restart.
    pub fn anchored(mut self, module: impl Into<String>, module_base: usize) -> Self {
        self.module = module.into();
        self.module_offset = self.address.wrapping_sub(module_base);
        self
    }

    /// The original bytes.
    pub fn original_bytes(&self) -> Result<Vec<u8>> {
        from_hex(&self.original)
    }

    /// The patched bytes.
    pub fn patched_bytes(&self) -> Result<Vec<u8>> {
        from_hex(&self.patched)
    }

    /// How many bytes the patch covers.
    ///
    /// Taken from the patched side: that is what is written, and a set where the
    /// two sides disagree is rejected by [`PatchSet::validate`] before it can be
    /// applied.
    pub fn len(&self) -> usize {
        self.patched_bytes().map(|b| b.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// This patch relocated to a new base for its module.
    ///
    /// Returns `None` when the patch was never anchored — an absolute address
    /// from a previous run means nothing after ASLR, and moving it by a guess
    /// would write over whatever now lives there.
    pub fn rebased(&self, module_base: usize) -> Option<Self> {
        if self.module.is_empty() {
            return None;
        }
        let mut out = self.clone();
        out.address = module_base.wrapping_add(self.module_offset);
        out.applied = false;
        Some(out)
    }
}

/// The patches made in a session.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchSet {
    #[serde(default)]
    pub patches: Vec<Patch>,
}

impl PatchSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    pub fn len(&self) -> usize {
        self.patches.len()
    }

    /// Record a patch. An existing patch at the same address is replaced, but
    /// **keeps the older patch's original bytes**: those are the real
    /// pre-patch contents, and taking them from the second patch would record
    /// the first patch's output as the thing to revert to.
    pub fn record(&mut self, patch: Patch) {
        match self.patches.iter_mut().find(|p| p.address == patch.address) {
            Some(existing) => {
                let original = existing.original.clone();
                *existing = patch;
                existing.original = original;
            }
            None => self.patches.push(patch),
        }
    }

    pub fn remove(&mut self, index: usize) -> Option<Patch> {
        (index < self.patches.len()).then(|| self.patches.remove(index))
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut Patch> {
        self.patches.get_mut(index)
    }

    /// Reject a set whose two byte strings disagree in length.
    ///
    /// A patch that writes fewer bytes than it recorded cannot be reverted
    /// cleanly, and one that writes more has clobbered bytes it never saved.
    /// Both are corruption, and finding out at revert time is far too late.
    pub fn validate(&self) -> Result<()> {
        for (i, patch) in self.patches.iter().enumerate() {
            let original = patch.original_bytes()?;
            let patched = patch.patched_bytes()?;
            if original.len() != patched.len() {
                return Err(ModelError::DeserializeError(format!(
                    "patch {i} at {:#x} records {} original byte(s) but {} patched — \
                     it could not be reverted",
                    patch.address,
                    original.len(),
                    patched.len()
                )));
            }
        }
        Ok(())
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| ModelError::SerializeError(e.to_string()))
    }

    pub fn from_toml(s: &str) -> Result<Self> {
        let set: Self =
            toml::from_str(s).map_err(|e| ModelError::DeserializeError(e.to_string()))?;
        set.validate()?;
        Ok(set)
    }
}

/// Space-separated uppercase hex — the same spelling the AOB scanner and the
/// memory viewer use, so a patch can be pasted between them.
fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

fn from_hex(text: &str) -> Result<Vec<u8>> {
    text.split_whitespace()
        .map(|token| {
            u8::from_str_radix(token, 16)
                .map_err(|_| ModelError::DeserializeError(format!("'{token}' is not a hex byte")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_patch_round_trips_through_toml_with_both_sides() {
        let mut set = PatchSet::new();
        let mut patch = Patch::new(0x140001000, &[0x48, 0x89, 0xE5], &[0x90, 0x90, 0x90])
            .anchored("game.exe", 0x140000000);
        patch.description = "skip the check".into();
        patch.applied = true;
        set.record(patch);

        let back = PatchSet::from_toml(&set.to_toml().unwrap()).unwrap();
        assert_eq!(back, set);
        assert_eq!(back.patches[0].original_bytes().unwrap(), [0x48, 0x89, 0xE5]);
        assert_eq!(back.patches[0].patched_bytes().unwrap(), [0x90, 0x90, 0x90]);
        assert_eq!(back.patches[0].module_offset, 0x1000);
    }

    #[test]
    fn re_patching_an_address_keeps_the_original_pre_patch_bytes() {
        let mut set = PatchSet::new();
        set.record(Patch::new(0x1000, &[0x48, 0x89], &[0x90, 0x90]));
        // The second patch reads the *already patched* bytes as its "original".
        // Storing those would make a revert restore the first patch's output.
        set.record(Patch::new(0x1000, &[0x90, 0x90], &[0xCC, 0xCC]));

        assert_eq!(set.len(), 1);
        assert_eq!(set.patches[0].original_bytes().unwrap(), [0x48, 0x89]);
        assert_eq!(set.patches[0].patched_bytes().unwrap(), [0xCC, 0xCC]);
    }

    #[test]
    fn a_patch_whose_sides_disagree_in_length_is_refused() {
        let mut set = PatchSet::new();
        set.record(Patch::new(0x1000, &[0x48, 0x89, 0xE5], &[0x90]));
        let Err(e) = set.validate() else {
            panic!("a patch that cannot be reverted must not validate");
        };
        assert!(e.to_string().contains("reverted"), "{e}");
        // And it cannot be loaded from a file either.
        assert!(PatchSet::from_toml(&set.to_toml().unwrap()).is_err());
    }

    #[test]
    fn an_anchored_patch_rebases_and_an_unanchored_one_refuses() {
        let anchored =
            Patch::new(0x140001000, &[0x90], &[0xCC]).anchored("game.exe", 0x140000000);
        let moved = anchored.rebased(0x7F0000000000).expect("anchored patches rebase");
        assert_eq!(moved.address, 0x7F0000001000);
        assert!(!moved.applied, "a rebased patch is not in the target yet");

        // Without a module the address is from a previous run's layout, and
        // moving it by a guess would write over whatever is there now.
        let loose = Patch::new(0x140001000, &[0x90], &[0xCC]);
        assert_eq!(loose.rebased(0x7F0000000000), None);
    }

    #[test]
    fn malformed_hex_is_an_error_rather_than_a_silently_short_patch() {
        let toml = r#"
[[patches]]
address = 4096
original = "48 ZZ"
patched = "90 90"
"#;
        assert!(PatchSet::from_toml(toml).is_err());
    }
}
