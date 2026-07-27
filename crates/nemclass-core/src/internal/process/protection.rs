bitflags::bitflags! {
    /// Protection of a memory region.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct Protection : u8 {
        /// Read
        const R = 0b001;
        /// Write
        const W = 0b010;
        /// Execute
        const X = 0b100;
        /// Read | Write
        const RW = 0b011;
        /// Read | Execute
        const RX = 0b101;
        /// Read | Write | Execute
        const RWX = 0b111;
        /// Copy-on-write: a writable, process-private view of a file-backed
        /// mapping — Windows' `PAGE_WRITECOPY`, and on Linux a writable `p`
        /// (private) mapping with a backing path. Orthogonal to `R`/`W`/`X`,
        /// and deliberately outside [`Protection::RWX`] so it never leaks into
        /// the POSIX `PROT_*` conversions.
        const COW = 0b1000;
    }
}

impl Protection {
    /// Can read?
    #[inline]
    pub const fn read(&self) -> bool {
        self.contains(Self::R)
    }

    /// Can write?
    #[inline]
    pub const fn write(&self) -> bool {
        self.contains(Self::W)
    }

    /// Can execute?
    #[inline]
    pub const fn execute(&self) -> bool {
        self.contains(Self::X)
    }

    /// Is this a copy-on-write mapping?
    ///
    /// Never set by [`Protection::parse`] — the maps `rwx` chars don't carry it.
    /// The caller that also has the sharing flag and the backing path sets it
    /// (see `parse_maps_sections`).
    #[inline]
    pub const fn copy_on_write(&self) -> bool {
        self.contains(Self::COW)
    }

    /// Parses a permission string of kind `r-x` (as found in `/proc/<pid>/maps`).
    ///
    /// Lenient by design: this parses external kernel text, so it never panics.
    /// Each of the first three bytes sets its bit iff it is `r`/`w`/`x`
    /// respectively; anything else (`-`, a missing byte, a trailing `p`/`s`
    /// sharing flag) simply leaves that bit clear.
    pub fn parse(s: &str) -> Self {
        let b = s.as_bytes();
        let mut prot = Self::empty();
        if b.first() == Some(&b'r') {
            prot |= Self::R;
        }
        if b.get(1) == Some(&b'w') {
            prot |= Self::W;
        }
        if b.get(2) == Some(&b'x') {
            prot |= Self::X;
        }
        prot
    }

    /// Converts to os protection type.
    ///
    /// Only the `rwx` bits are meaningful as POSIX `PROT_*` flags (which happen
    /// to share this layout); [`Protection::COW`] is a classification of our own
    /// and is masked off so it can never be handed to `mprotect`.
    #[cfg(unix)]
    pub const fn to_os(&self) -> i32 {
        (self.bits() & Self::RWX.bits()) as i32
    }

    /// Converts from os protection type.
    ///
    /// `PROT_*` has no copy-on-write flag, so [`Protection::COW`] is never set
    /// here — the bit is masked off rather than truncated in, in case a caller
    /// passes a value with unrelated high bits.
    #[cfg(unix)]
    pub const fn from_os(prot: i32) -> Self {
        Self::from_bits_truncate(prot as u8 & Self::RWX.bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_maps_perm_strings() {
        assert_eq!(Protection::parse("---"), Protection::empty());
        assert_eq!(Protection::parse("r--"), Protection::R);
        assert_eq!(Protection::parse("rw-"), Protection::RW);
        assert_eq!(Protection::parse("r-x"), Protection::RX);
        assert_eq!(Protection::parse("rwx"), Protection::RWX);
    }

    #[test]
    fn parse_is_lenient_on_malformed_input() {
        // Parses external kernel text, so it must never panic on short/odd input.
        assert_eq!(Protection::parse(""), Protection::empty());
        assert_eq!(Protection::parse("r"), Protection::R);
        assert_eq!(Protection::parse("rw"), Protection::RW);
        // The maps perms field is 4 chars ("rwxp"/"r-xp"); only the first 3 count.
        assert_eq!(Protection::parse("rwxp"), Protection::RWX);
        assert_eq!(Protection::parse("r-xp"), Protection::RX);
        // Unknown characters leave their bit clear.
        assert_eq!(Protection::parse("???"), Protection::empty());
    }

    #[test]
    fn accessor_predicates_match_bits() {
        let rw = Protection::parse("rw-");
        assert!(rw.read() && rw.write() && !rw.execute());

        let rx = Protection::parse("r-x");
        assert!(rx.read() && !rx.write() && rx.execute());
    }

    #[test]
    fn parse_never_sets_copy_on_write() {
        // The rwx chars don't carry it; only a caller with the sharing flag and
        // the backing path can classify a mapping as copy-on-write.
        assert!(!Protection::parse("rw-p").copy_on_write());
        assert!(!Protection::parse("rwx").copy_on_write());
    }

    #[test]
    fn copy_on_write_is_orthogonal_to_rwx() {
        let cow = Protection::RW | Protection::COW;
        assert!(cow.read() && cow.write() && !cow.execute());
        assert!(cow.copy_on_write());
        assert!(!Protection::RW.copy_on_write());
    }

    // `to_os`/`from_os` are `#[cfg(unix)]` (they map to/from POSIX `PROT_*`
    // integers), so this round-trip test is unix-only too.
    #[cfg(unix)]
    #[test]
    fn os_round_trip_preserves_rwx() {
        let p = Protection::RWX;
        assert_eq!(Protection::from_os(p.to_os()), p);
    }

    // COW has no `PROT_*` equivalent, so it must not survive a round trip —
    // and must never reach `mprotect` as a stray bit.
    #[cfg(unix)]
    #[test]
    fn os_conversion_drops_copy_on_write() {
        let p = Protection::RW | Protection::COW;
        assert_eq!(p.to_os(), Protection::RW.to_os());
        assert_eq!(Protection::from_os(p.to_os()), Protection::RW);
    }
}
