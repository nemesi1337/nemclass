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

    /// Parses string of kind `r-x`.
    /// # Panics
    /// * `s.len()` isn't 3.
    /// * s\[0\] != r | -
    /// * s\[1\] != w | -
    /// * s\[2\] != x | -
    pub fn parse(s: &str) -> Self {
        assert!(
            s.len() == 3
                && s.is_ascii()
                && s.chars()
                .all(|c| c == '-' || c == 'r' || c == 'w' || c == 'x')
        );

        let mut prot = Self::empty();
        if s.as_bytes()[0] == b'r' {
            prot |= Self::R;
        }

        if s.as_bytes()[1] == b'w' {
            prot |= Self::W;
        }

        if s.as_bytes()[2] == b'x' {
            prot |= Self::X;
        }

        prot
    }
    
    /// Converts to os protection type.
    #[cfg(all(unix, feature = "std"))]
    pub const fn to_os(&self) -> i32 {
        self.bits() as i32
    }

    /// Converts from os protection type.
    #[cfg(all(unix, feature = "std"))]
    pub const fn from_os(prot: i32) -> Self {
        Self::from_bits_truncate(prot as u8)
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
    fn accessor_predicates_match_bits() {
        let rw = Protection::parse("rw-");
        assert!(rw.read() && rw.write() && !rw.execute());

        let rx = Protection::parse("r-x");
        assert!(rx.read() && !rx.write() && rx.execute());
    }

    #[test]
    fn os_round_trip_preserves_rwx() {
        let p = Protection::RWX;
        assert_eq!(Protection::from_os(p.to_os()), p);
    }
}
