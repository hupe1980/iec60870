//! Profiles: the field widths, the maximum length and the permitted types of a link.

use crate::types::{TypeId, TypeSet};

/// The width of the cause of transmission field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CotWidth {
    /// One octet: cause, P/N, T — no originator address.
    One,
    /// Two octets: the second is the originator address.
    Two,
}

/// The width of the common address of ASDU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CaWidth {
    /// One octet (0–255).
    One,
    /// Two octets (0–65535).
    Two,
}

/// The width of the information object address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IoaWidth {
    /// One octet (0–255).
    One,
    /// Two octets (0–65535).
    Two,
    /// Three octets (0–16777215).
    Three,
}

impl CotWidth {
    /// The width in octets.
    pub const fn octets(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

impl CaWidth {
    /// The width in octets.
    pub const fn octets(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }

    /// The largest address the width carries.
    pub const fn max(self) -> u16 {
        match self {
            Self::One => 0xFF,
            Self::Two => 0xFFFF,
        }
    }
}

impl IoaWidth {
    /// The width in octets.
    pub const fn octets(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
        }
    }

    /// The largest address the width carries.
    pub const fn max(self) -> u32 {
        match self {
            Self::One => 0xFF,
            Self::Two => 0xFFFF,
            Self::Three => 0xFF_FFFF,
        }
    }
}

/// What differs between links that share the ASDU layer: the widths of the cause of
/// transmission, the common address and the information object address, the longest ASDU
/// the link carries, and the type identifications it permits.
///
/// A vendor dialect is a constant built from a standard profile:
///
/// ```
/// use iec60870::asdu::{CotWidth, Profile};
///
/// /// A 104 gateway that sends a one-octet cause of transmission.
/// const GATEWAY: Profile = Profile::IEC104.with_cot(CotWidth::One);
/// assert_eq!(GATEWAY.header_len(), 5);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Profile {
    /// The cause of transmission width.
    pub cot: CotWidth,
    /// The common address width.
    pub ca: CaWidth,
    /// The information object address width.
    pub ioa: IoaWidth,
    /// The longest ASDU, in octets, that decoding accepts and encoding produces.
    pub max_asdu_len: u8,
    /// The type identifications the link permits. Decoding a type outside the set yields
    /// [`Objects::Raw`](super::Objects::Raw); encoding a typed ASDU outside it is refused.
    pub types: TypeSet,
}

impl Profile {
    /// IEC 60870-5-104: COT 2, CA 2, IOA 3 octets; ASDU ≤ 249 octets (an APDU of 255 less
    /// the start, length and four control octets); every standard type except the
    /// CP24Time2a ones, `C_TS_NA_1` and `C_CD_NA_1` (see [`TypeSet::IEC104`]).
    pub const IEC104: Profile = Profile { cot: CotWidth::Two, ca: CaWidth::Two, ioa: IoaWidth::Three, max_asdu_len: 249, types: TypeSet::IEC104 };

    /// IEC 60870-5-101 in its common configuration: COT 1, CA 1, IOA 2 octets; ASDU ≤ 253
    /// octets (a variable frame of 255 user octets less the control field and a one-octet link
    /// address); every standard type except `C_TS_TA_1` (see [`TypeSet::IEC101`]). 101 allows
    /// COT 1/2, CA 1/2 and IOA 1/2/3 — adjust with the `with_*` builders.
    pub const IEC101: Profile = Profile { cot: CotWidth::One, ca: CaWidth::One, ioa: IoaWidth::Two, max_asdu_len: 253, types: TypeSet::IEC101 };

    /// The same profile with the cause of transmission width `cot`.
    #[must_use]
    pub const fn with_cot(self, cot: CotWidth) -> Self {
        Self { cot, ..self }
    }

    /// The same profile with the common address width `ca`.
    #[must_use]
    pub const fn with_ca(self, ca: CaWidth) -> Self {
        Self { ca, ..self }
    }

    /// The same profile with the information object address width `ioa`.
    #[must_use]
    pub const fn with_ioa(self, ioa: IoaWidth) -> Self {
        Self { ioa, ..self }
    }

    /// The same profile with the maximum ASDU length `max`.
    #[must_use]
    pub const fn with_max_asdu_len(self, max: u8) -> Self {
        Self { max_asdu_len: max, ..self }
    }

    /// The same profile with the permitted types `types`.
    #[must_use]
    pub const fn with_types(self, types: TypeSet) -> Self {
        Self { types, ..self }
    }

    /// Whether the profile permits type `id`.
    pub const fn permits(&self, id: TypeId) -> bool {
        self.types.contains(id)
    }

    /// The length of the data unit identifier: type, VSQ, COT and CA.
    pub const fn header_len(&self) -> usize {
        2 + self.cot.octets() + self.ca.octets()
    }
}

impl Default for Profile {
    fn default() -> Self {
        Self::IEC104
    }
}
