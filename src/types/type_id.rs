//! Type identifications and sets of them.

use core::fmt;

/// The type identification of an ASDU: which information elements its objects carry.
///
/// Any octet is a `TypeId`; the standard ones have constants named as in the standard
/// (`TypeId::M_ME_NC_1`), private ones (128–255) and unknown ones are just numbers.
///
/// ```
/// use iec60870::TypeId;
///
/// assert_eq!(TypeId::M_ME_TF_1, TypeId(36));
/// assert_eq!(TypeId(36).name(), Some("M_ME_TF_1"));
/// assert_eq!(TypeId(36).to_string(), "M_ME_TF_1 (36)");
/// assert_eq!(TypeId(200).to_string(), "type 200");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeId(pub u8);

macro_rules! type_ids {
    ($($name:ident = $value:literal, $description:literal;)*) => {
        #[allow(missing_docs)]
        impl TypeId {
            $(
                #[doc = $description]
                pub const $name: TypeId = TypeId($value);
            )*
        }

        const TABLE: &[(u8, &str, &str)] = &[$(($value, stringify!($name), $description)),*];
    };
}

type_ids! {
    M_SP_NA_1 = 1, "Single-point information";
    M_SP_TA_1 = 2, "Single-point information with CP24Time2a";
    M_DP_NA_1 = 3, "Double-point information";
    M_DP_TA_1 = 4, "Double-point information with CP24Time2a";
    M_ST_NA_1 = 5, "Step position information";
    M_ST_TA_1 = 6, "Step position information with CP24Time2a";
    M_BO_NA_1 = 7, "Bitstring of 32 bits";
    M_BO_TA_1 = 8, "Bitstring of 32 bits with CP24Time2a";
    M_ME_NA_1 = 9, "Measured value, normalized";
    M_ME_TA_1 = 10, "Measured value, normalized, with CP24Time2a";
    M_ME_NB_1 = 11, "Measured value, scaled";
    M_ME_TB_1 = 12, "Measured value, scaled, with CP24Time2a";
    M_ME_NC_1 = 13, "Measured value, short floating point";
    M_ME_TC_1 = 14, "Measured value, short floating point, with CP24Time2a";
    M_IT_NA_1 = 15, "Integrated totals";
    M_IT_TA_1 = 16, "Integrated totals with CP24Time2a";
    M_EP_TA_1 = 17, "Event of protection equipment with CP24Time2a";
    M_EP_TB_1 = 18, "Packed start events of protection equipment with CP24Time2a";
    M_EP_TC_1 = 19, "Packed output circuit information of protection equipment with CP24Time2a";
    M_PS_NA_1 = 20, "Packed single-point information with status change detection";
    M_ME_ND_1 = 21, "Measured value, normalized, without quality descriptor";
    M_SP_TB_1 = 30, "Single-point information with CP56Time2a";
    M_DP_TB_1 = 31, "Double-point information with CP56Time2a";
    M_ST_TB_1 = 32, "Step position information with CP56Time2a";
    M_BO_TB_1 = 33, "Bitstring of 32 bits with CP56Time2a";
    M_ME_TD_1 = 34, "Measured value, normalized, with CP56Time2a";
    M_ME_TE_1 = 35, "Measured value, scaled, with CP56Time2a";
    M_ME_TF_1 = 36, "Measured value, short floating point, with CP56Time2a";
    M_IT_TB_1 = 37, "Integrated totals with CP56Time2a";
    M_EP_TD_1 = 38, "Event of protection equipment with CP56Time2a";
    M_EP_TE_1 = 39, "Packed start events of protection equipment with CP56Time2a";
    M_EP_TF_1 = 40, "Packed output circuit information of protection equipment with CP56Time2a";
    S_IT_TC_1 = 41, "Integrated totals containing time-tagged security statistics";
    C_SC_NA_1 = 45, "Single command";
    C_DC_NA_1 = 46, "Double command";
    C_RC_NA_1 = 47, "Regulating step command";
    C_SE_NA_1 = 48, "Set-point command, normalized value";
    C_SE_NB_1 = 49, "Set-point command, scaled value";
    C_SE_NC_1 = 50, "Set-point command, short floating point";
    C_BO_NA_1 = 51, "Bitstring of 32 bits command";
    C_SC_TA_1 = 58, "Single command with CP56Time2a";
    C_DC_TA_1 = 59, "Double command with CP56Time2a";
    C_RC_TA_1 = 60, "Regulating step command with CP56Time2a";
    C_SE_TA_1 = 61, "Set-point command, normalized value, with CP56Time2a";
    C_SE_TB_1 = 62, "Set-point command, scaled value, with CP56Time2a";
    C_SE_TC_1 = 63, "Set-point command, short floating point, with CP56Time2a";
    C_BO_TA_1 = 64, "Bitstring of 32 bits command with CP56Time2a";
    M_EI_NA_1 = 70, "End of initialization";
    S_CH_NA_1 = 81, "Authentication challenge";
    S_RP_NA_1 = 82, "Authentication reply";
    S_AR_NA_1 = 83, "Aggressive mode authentication request";
    S_KR_NA_1 = 84, "Session key status request";
    S_KS_NA_1 = 85, "Session key status";
    S_KC_NA_1 = 86, "Session key change";
    S_ER_NA_1 = 87, "Authentication error";
    S_US_NA_1 = 90, "User status change";
    S_UQ_NA_1 = 91, "Update key change request";
    S_UR_NA_1 = 92, "Update key change reply";
    S_UK_NA_1 = 93, "Update key change, symmetric";
    S_UA_NA_1 = 94, "Update key change, asymmetric";
    S_UC_NA_1 = 95, "Update key change confirmation";
    C_IC_NA_1 = 100, "Interrogation command";
    C_CI_NA_1 = 101, "Counter interrogation command";
    C_RD_NA_1 = 102, "Read command";
    C_CS_NA_1 = 103, "Clock synchronization command";
    C_TS_NA_1 = 104, "Test command";
    C_RP_NA_1 = 105, "Reset process command";
    C_CD_NA_1 = 106, "Delay acquisition command";
    C_TS_TA_1 = 107, "Test command with CP56Time2a";
    P_ME_NA_1 = 110, "Parameter of measured value, normalized";
    P_ME_NB_1 = 111, "Parameter of measured value, scaled";
    P_ME_NC_1 = 112, "Parameter of measured value, short floating point";
    P_AC_NA_1 = 113, "Parameter activation";
    F_FR_NA_1 = 120, "File ready";
    F_SR_NA_1 = 121, "Section ready";
    F_SC_NA_1 = 122, "Call directory, select file, call file, call section";
    F_LS_NA_1 = 123, "Last section, last segment";
    F_AF_NA_1 = 124, "Acknowledge file, acknowledge section";
    F_SG_NA_1 = 125, "Segment";
    F_DR_TA_1 = 126, "Directory";
    F_SC_NB_1 = 127, "Query log, request archive file";
}

impl TypeId {
    fn entry(self) -> Option<&'static (u8, &'static str, &'static str)> {
        TABLE.iter().find(|(v, ..)| *v == self.0)
    }

    /// The standard's mnemonic (`"M_SP_NA_1"`), or `None` for a non-standard id.
    pub fn name(self) -> Option<&'static str> {
        self.entry().map(|(_, n, _)| *n)
    }

    /// A short English description, or `None` for a non-standard id.
    pub fn description(self) -> Option<&'static str> {
        self.entry().map(|(_, _, d)| *d)
    }

    /// Whether the standard defines this id (including the security ids 41, 81–87, 90–95).
    pub const fn is_standard(self) -> bool {
        TypeSet::STANDARD.contains(self)
    }

    /// Whether `profile` permits this id.
    pub const fn is_permitted_in(self, profile: &crate::asdu::Profile) -> bool {
        profile.permits(self)
    }
}

impl From<u8> for TypeId {
    fn from(v: u8) -> Self {
        Self(v)
    }
}

impl fmt::Display for TypeId {
    /// `M_SP_NA_1 (1)` for a standard id, `type 200` otherwise.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{name} ({})", self.0),
            None => write!(f, "type {}", self.0),
        }
    }
}

impl fmt::Debug for TypeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "TypeId::{name}"),
            None => write!(f, "TypeId({})", self.0),
        }
    }
}

/// A set of type identifications: what a [`Profile`](crate::asdu::Profile) permits.
///
/// ```
/// use iec60870::types::{TypeId, TypeSet};
///
/// let set = TypeSet::IEC104.with(TypeId::M_SP_TA_1);
/// assert!(set.contains(TypeId::M_SP_TA_1));
/// assert!(!TypeSet::IEC104.contains(TypeId::M_SP_TA_1));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeSet([u64; 4]);

const STANDARD_IDS: &[u8] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, // monitor, CP24
    30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, // monitor, CP56; security statistics
    45, 46, 47, 48, 49, 50, 51, 58, 59, 60, 61, 62, 63, 64, // control
    70, // end of initialization
    81, 82, 83, 84, 85, 86, 87, 90, 91, 92, 93, 94, 95, // security
    100, 101, 102, 103, 104, 105, 106, 107, // system
    110, 111, 112, 113, // parameter
    120, 121, 122, 123, 124, 125, 126, 127, // file transfer
];

/// The ids 104 leaves out: the CP24Time2a variants, the test command without time tag and the
/// delay acquisition command.
const NOT_IN_104: &[u8] = &[2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19, 104, 106];

/// The ids 101 leaves out: the test command with CP56Time2a, which 104 introduced.
const NOT_IN_101: &[u8] = &[107];

impl TypeSet {
    /// No type.
    pub const EMPTY: TypeSet = TypeSet([0; 4]);
    /// Every octet value 0–255.
    pub const ALL: TypeSet = TypeSet([u64::MAX; 4]);
    /// Every type identification the standard defines.
    pub const STANDARD: TypeSet = Self::EMPTY.with_all(STANDARD_IDS);
    /// The standard set without the CP24Time2a types (2, 4, 6, 8, 10, 12, 14, 16, 17–19),
    /// `C_TS_NA_1` (104) and `C_CD_NA_1` (106).
    pub const IEC104: TypeSet = Self::STANDARD.without_all(NOT_IN_104);
    /// The standard set without `C_TS_TA_1` (107).
    pub const IEC101: TypeSet = Self::STANDARD.without_all(NOT_IN_101);

    const fn word(self, id: TypeId) -> (u64, u64) {
        let [w0, w1, w2, w3] = self.0;
        let word = match id.0 >> 6 {
            0 => w0,
            1 => w1,
            2 => w2,
            _ => w3,
        };
        (word, 1u64 << (id.0 & 63))
    }

    const fn set_word(self, id: TypeId, on: bool) -> Self {
        let mut words = self.0;
        let bit = 1u64 << (id.0 & 63);
        let word = match id.0 >> 6 {
            0 => &mut words[0],
            1 => &mut words[1],
            2 => &mut words[2],
            _ => &mut words[3],
        };
        *word = if on { *word | bit } else { *word & !bit };
        Self(words)
    }

    /// Whether `id` is in the set.
    pub const fn contains(self, id: TypeId) -> bool {
        let (w, bit) = self.word(id);
        w & bit != 0
    }

    /// The set with `id` added.
    #[must_use]
    pub const fn with(self, id: TypeId) -> Self {
        self.set_word(id, true)
    }

    /// The set with `id` removed.
    #[must_use]
    pub const fn without(self, id: TypeId) -> Self {
        self.set_word(id, false)
    }

    /// The ids in either set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        let [x0, x1, x2, x3] = self.0;
        let [y0, y1, y2, y3] = other.0;
        Self([x0 | y0, x1 | y1, x2 | y2, x3 | y3])
    }

    const fn with_all(self, ids: &[u8]) -> Self {
        let mut s = self;
        let mut rest = ids;
        while let [first, tail @ ..] = rest {
            s = s.with(TypeId(*first));
            rest = tail;
        }
        s
    }

    const fn without_all(self, ids: &[u8]) -> Self {
        let mut s = self;
        let mut rest = ids;
        while let [first, tail @ ..] = rest {
            s = s.without(TypeId(*first));
            rest = tail;
        }
        s
    }

    /// The ids in the set, ascending.
    pub fn iter(self) -> impl Iterator<Item = TypeId> {
        (0..=u8::MAX).map(TypeId).filter(move |id| self.contains(*id))
    }

    /// The number of ids in the set.
    pub fn len(self) -> usize {
        self.0.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Whether the set is empty.
    pub fn is_empty(self) -> bool {
        self == Self::EMPTY
    }
}

impl Default for TypeSet {
    fn default() -> Self {
        Self::STANDARD
    }
}

impl FromIterator<TypeId> for TypeSet {
    fn from_iter<I: IntoIterator<Item = TypeId>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl fmt::Debug for TypeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter().map(|t| t.0)).finish()
    }
}
