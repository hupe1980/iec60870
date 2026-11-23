//! The application service data unit: profiles, the header, typed information objects, and the
//! codec.
//!
//! An [`Asdu`] is a cause of transmission, a common address, the SQ flag and its
//! [`Objects`] — a vector of typed [`InformationObject`]s, one variant per standard type
//! identification, or [`Raw`] for a type the profile does not permit or the crate has no typed
//! form for (private types 128–255, the security types). The type identification is not
//! stored: it follows from the Rust type of the objects, so it cannot disagree with them.
//!
//! ```
//! use iec60870::prelude::*;
//!
//! let time = Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
//! let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, [
//!     InformationObject::new(Ioa(4001), MeasuredFloat::new(21.5)).at(time),
//!     InformationObject::new(Ioa(4002), MeasuredFloat::new(-3.0).with_quality(Quality::INVALID)).at(time),
//! ]);
//! assert_eq!(asdu.type_id(), TypeId::M_ME_TF_1);
//!
//! let mut buf = [0u8; 249];
//! let n = asdu.encode(&Profile::IEC104, &mut buf)?;
//! let decoded = Asdu::decode(&buf[..n], &Profile::IEC104)?;
//! assert_eq!(decoded, asdu);
//!
//! match &decoded.objects {
//!     Objects::MeasuredFloatCp56(objects) => {
//!         for o in objects {
//!             println!("{} = {} {:?} at {}", o.ioa, o.element.value, o.element.quality, o.time);
//!         }
//!     }
//!     other => println!("{} objects of {}", other.len(), other.type_id()),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod codec;
mod error;
mod profile;

use alloc::vec::Vec;
use core::fmt;

pub use error::{DecodeError, DecodeErrorKind, EncodeError, Field};
pub use profile::{CaWidth, CotWidth, IoaWidth, Profile};

use crate::time::{Cp24Time2a, Cp56Time2a};
#[allow(clippy::wildcard_imports)] // every element type names an `Objects` variant
use crate::types::*;

mod sealed {
    pub trait Sealed {}
    impl Sealed for () {}
    impl Sealed for crate::time::Cp24Time2a {}
    impl Sealed for crate::time::Cp56Time2a {}
}

/// The time tag of an information object: `()` (none), [`Cp24Time2a`] or [`Cp56Time2a`].
pub trait TimeTag: sealed::Sealed + Copy + fmt::Debug + PartialEq {
    /// Whether the object carries a time tag on the wire.
    const PRESENT: bool;
}

impl TimeTag for () {
    const PRESENT: bool = false;
}

impl TimeTag for Cp24Time2a {
    const PRESENT: bool = true;
}

impl TimeTag for Cp56Time2a {
    const PRESENT: bool = true;
}

/// An information object: its address, its information element(s) and, for the time-tagged
/// types, its time tag.
///
/// ```
/// use iec60870::prelude::*;
///
/// let o = InformationObject::new(Ioa(7), SinglePoint::new(true));
/// let t = o.clone().at(Cp56Time2a::default());
/// assert_eq!(Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, o).type_id(), TypeId::M_SP_NA_1);
/// assert_eq!(Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, t).type_id(), TypeId::M_SP_TB_1);
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct InformationObject<E, T = ()> {
    /// The information object address.
    pub ioa: Ioa,
    /// The information element(s).
    pub element: E,
    /// The time tag, `()` when the type has none.
    pub time: T,
}

impl<E> InformationObject<E> {
    /// An object without a time tag.
    pub const fn new(ioa: Ioa, element: E) -> Self {
        Self { ioa, element, time: () }
    }

    /// The same object with time tag `time` — the type identification changes accordingly
    /// (e.g. `MeasuredFloat` is type 13 untagged, 14 with CP24Time2a, 36 with CP56Time2a).
    pub fn at<T: TimeTag>(self, time: T) -> InformationObject<E, T> {
        InformationObject { ioa: self.ioa, element: self.element, time }
    }
}

impl<E: fmt::Debug, T: TimeTag> fmt::Debug for InformationObject<E, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = f.debug_struct("InformationObject");
        s.field("ioa", &self.ioa.0).field("element", &self.element);
        if T::PRESENT {
            s.field("time", &self.time);
        }
        s.finish()
    }
}

/// The body of an ASDU the crate does not decode: a type the profile does not permit, a
/// private type (128–255), a security type, or a reserved one. Kept byte for byte so a gateway
/// can forward it and a sniffer can show it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Raw {
    /// The type identification.
    pub type_id: TypeId,
    /// The number of objects the VSQ announced (0–127).
    pub count: u8,
    /// Every octet after the common address, as received.
    pub body: Vec<u8>,
}

impl fmt::Debug for Raw {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Raw {{ type_id: {:?}, count: {}, body: [", self.type_id, self.count)?;
        for (i, b) in self.body.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{b:02x}")?;
        }
        f.write_str("] }")
    }
}

macro_rules! objects {
    ($($(#[$doc:meta])* $variant:ident($element:ty, $time:ty) = $type_id:ident;)*) => {
        /// The information objects of an ASDU: one variant per standard type identification
        /// (named after its element and time tag), or [`Raw`](Objects::Raw).
        ///
        /// Each variant converts from a `Vec`, an array or a single [`InformationObject`] of
        /// its element and time type, which is how [`Asdu::new`] infers the type.
        #[derive(Clone, Debug, PartialEq)]
        #[non_exhaustive]
        pub enum Objects {
            $(
                $(#[$doc])*
                $variant(Vec<InformationObject<$element, $time>>),
            )*
            /// Any type without a typed form, or not permitted by the profile.
            Raw(Raw),
        }

        impl Objects {
            /// The type identification.
            pub fn type_id(&self) -> TypeId {
                match self {
                    $(Self::$variant(_) => TypeId::$type_id,)*
                    Self::Raw(raw) => raw.type_id,
                }
            }

            /// The number of information objects (for `Raw`, the VSQ count).
            pub fn len(&self) -> usize {
                match self {
                    $(Self::$variant(v) => v.len(),)*
                    Self::Raw(raw) => usize::from(raw.count),
                }
            }

            /// The address of object `index`, or `None` (always `None` for `Raw`).
            pub fn ioa(&self, index: usize) -> Option<Ioa> {
                match self {
                    $(Self::$variant(v) => v.get(index).map(|o| o.ioa),)*
                    Self::Raw(_) => None,
                }
            }

            /// Element and time-tag lengths in octets for a decoded object.
            /// Excludes its explicit or implied information object address.
            /// Unknown raw payloads have no inferred object boundaries.
            pub fn field_lengths(&self, index: usize) -> Option<(usize, usize)> {
                match self {
                    $(Self::$variant(v) => v.get(index).map(|o| (codec::Wire::len(&o.element), codec::Wire::len(&o.time))),)*
                    Self::Raw(_) => None,
                }
            }

            fn decode_typed(type_id: TypeId, r: &mut codec::Reader<'_>, profile: &Profile, sequence: bool, count: u8) -> Option<Result<Self, DecodeError>> {
                match type_id {
                    $(TypeId::$type_id => Some(codec::read_objects(r, profile, sequence, count).map(Self::$variant)),)*
                    _ => None,
                }
            }

            fn check_body(&self, profile: &Profile, sequence: bool) -> Result<usize, EncodeError> {
                match self {
                    $(Self::$variant(v) => codec::check_objects(v, profile, sequence),)*
                    Self::Raw(raw) => Ok(raw.body.len()),
                }
            }

            fn body_len(&self, profile: &Profile, sequence: bool) -> usize {
                match self {
                    $(Self::$variant(v) => codec::objects_len(v, profile, sequence),)*
                    Self::Raw(raw) => raw.body.len(),
                }
            }

            fn write_body(&self, w: &mut codec::Writer<'_>, profile: &Profile, sequence: bool) {
                match self {
                    $(Self::$variant(v) => codec::write_objects(v, w, profile, sequence),)*
                    Self::Raw(raw) => w.put(&raw.body),
                }
            }
        }

        $(
            impl From<Vec<InformationObject<$element, $time>>> for Objects {
                fn from(v: Vec<InformationObject<$element, $time>>) -> Self {
                    Self::$variant(v)
                }
            }

            impl<const N: usize> From<[InformationObject<$element, $time>; N]> for Objects {
                fn from(a: [InformationObject<$element, $time>; N]) -> Self {
                    Self::$variant(Vec::from(a))
                }
            }

            impl From<InformationObject<$element, $time>> for Objects {
                fn from(o: InformationObject<$element, $time>) -> Self {
                    Self::$variant(alloc::vec![o])
                }
            }
        )*
    };
}

objects! {
    /// 1 `M_SP_NA_1`.
    SinglePoint(SinglePoint, ()) = M_SP_NA_1;
    /// 2 `M_SP_TA_1`.
    SinglePointCp24(SinglePoint, Cp24Time2a) = M_SP_TA_1;
    /// 30 `M_SP_TB_1`.
    SinglePointCp56(SinglePoint, Cp56Time2a) = M_SP_TB_1;
    /// 3 `M_DP_NA_1`.
    DoublePoint(DoublePoint, ()) = M_DP_NA_1;
    /// 4 `M_DP_TA_1`.
    DoublePointCp24(DoublePoint, Cp24Time2a) = M_DP_TA_1;
    /// 31 `M_DP_TB_1`.
    DoublePointCp56(DoublePoint, Cp56Time2a) = M_DP_TB_1;
    /// 5 `M_ST_NA_1`.
    StepPosition(StepPosition, ()) = M_ST_NA_1;
    /// 6 `M_ST_TA_1`.
    StepPositionCp24(StepPosition, Cp24Time2a) = M_ST_TA_1;
    /// 32 `M_ST_TB_1`.
    StepPositionCp56(StepPosition, Cp56Time2a) = M_ST_TB_1;
    /// 7 `M_BO_NA_1`.
    Bitstring(Bitstring32, ()) = M_BO_NA_1;
    /// 8 `M_BO_TA_1`.
    BitstringCp24(Bitstring32, Cp24Time2a) = M_BO_TA_1;
    /// 33 `M_BO_TB_1`.
    BitstringCp56(Bitstring32, Cp56Time2a) = M_BO_TB_1;
    /// 9 `M_ME_NA_1`.
    MeasuredNormalized(MeasuredNormalized, ()) = M_ME_NA_1;
    /// 10 `M_ME_TA_1`.
    MeasuredNormalizedCp24(MeasuredNormalized, Cp24Time2a) = M_ME_TA_1;
    /// 34 `M_ME_TD_1`.
    MeasuredNormalizedCp56(MeasuredNormalized, Cp56Time2a) = M_ME_TD_1;
    /// 11 `M_ME_NB_1`.
    MeasuredScaled(MeasuredScaled, ()) = M_ME_NB_1;
    /// 12 `M_ME_TB_1`.
    MeasuredScaledCp24(MeasuredScaled, Cp24Time2a) = M_ME_TB_1;
    /// 35 `M_ME_TE_1`.
    MeasuredScaledCp56(MeasuredScaled, Cp56Time2a) = M_ME_TE_1;
    /// 13 `M_ME_NC_1`.
    MeasuredFloat(MeasuredFloat, ()) = M_ME_NC_1;
    /// 14 `M_ME_TC_1`.
    MeasuredFloatCp24(MeasuredFloat, Cp24Time2a) = M_ME_TC_1;
    /// 36 `M_ME_TF_1`.
    MeasuredFloatCp56(MeasuredFloat, Cp56Time2a) = M_ME_TF_1;
    /// 15 `M_IT_NA_1`.
    IntegratedTotals(BinaryCounterReading, ()) = M_IT_NA_1;
    /// 16 `M_IT_TA_1`.
    IntegratedTotalsCp24(BinaryCounterReading, Cp24Time2a) = M_IT_TA_1;
    /// 37 `M_IT_TB_1`.
    IntegratedTotalsCp56(BinaryCounterReading, Cp56Time2a) = M_IT_TB_1;
    /// 17 `M_EP_TA_1`.
    ProtectionEventCp24(ProtectionEvent, Cp24Time2a) = M_EP_TA_1;
    /// 38 `M_EP_TD_1`.
    ProtectionEventCp56(ProtectionEvent, Cp56Time2a) = M_EP_TD_1;
    /// 18 `M_EP_TB_1`.
    PackedStartEventsCp24(PackedStartEvents, Cp24Time2a) = M_EP_TB_1;
    /// 39 `M_EP_TE_1`.
    PackedStartEventsCp56(PackedStartEvents, Cp56Time2a) = M_EP_TE_1;
    /// 19 `M_EP_TC_1`.
    PackedOutputCircuitsCp24(PackedOutputCircuits, Cp24Time2a) = M_EP_TC_1;
    /// 40 `M_EP_TF_1`.
    PackedOutputCircuitsCp56(PackedOutputCircuits, Cp56Time2a) = M_EP_TF_1;
    /// 20 `M_PS_NA_1`.
    PackedSinglePoints(PackedSinglePoints, ()) = M_PS_NA_1;
    /// 21 `M_ME_ND_1`.
    NormalizedWithoutQuality(Normalized, ()) = M_ME_ND_1;
    /// 45 `C_SC_NA_1`.
    SingleCommand(SingleCommand, ()) = C_SC_NA_1;
    /// 58 `C_SC_TA_1`.
    SingleCommandCp56(SingleCommand, Cp56Time2a) = C_SC_TA_1;
    /// 46 `C_DC_NA_1`.
    DoubleCommand(DoubleCommand, ()) = C_DC_NA_1;
    /// 59 `C_DC_TA_1`.
    DoubleCommandCp56(DoubleCommand, Cp56Time2a) = C_DC_TA_1;
    /// 47 `C_RC_NA_1`.
    StepCommand(StepCommand, ()) = C_RC_NA_1;
    /// 60 `C_RC_TA_1`.
    StepCommandCp56(StepCommand, Cp56Time2a) = C_RC_TA_1;
    /// 48 `C_SE_NA_1`.
    SetpointNormalized(SetpointNormalized, ()) = C_SE_NA_1;
    /// 61 `C_SE_TA_1`.
    SetpointNormalizedCp56(SetpointNormalized, Cp56Time2a) = C_SE_TA_1;
    /// 49 `C_SE_NB_1`.
    SetpointScaled(SetpointScaled, ()) = C_SE_NB_1;
    /// 62 `C_SE_TB_1`.
    SetpointScaledCp56(SetpointScaled, Cp56Time2a) = C_SE_TB_1;
    /// 50 `C_SE_NC_1`.
    SetpointFloat(SetpointFloat, ()) = C_SE_NC_1;
    /// 63 `C_SE_TC_1`.
    SetpointFloatCp56(SetpointFloat, Cp56Time2a) = C_SE_TC_1;
    /// 51 `C_BO_NA_1`.
    BitstringCommand(BitstringCommand, ()) = C_BO_NA_1;
    /// 64 `C_BO_TA_1`.
    BitstringCommandCp56(BitstringCommand, Cp56Time2a) = C_BO_TA_1;
    /// 70 `M_EI_NA_1`.
    EndOfInitialization(EndOfInitialization, ()) = M_EI_NA_1;
    /// 100 `C_IC_NA_1`.
    Interrogation(Interrogation, ()) = C_IC_NA_1;
    /// 101 `C_CI_NA_1`.
    CounterInterrogation(CounterInterrogation, ()) = C_CI_NA_1;
    /// 102 `C_RD_NA_1`.
    Read(Read, ()) = C_RD_NA_1;
    /// 103 `C_CS_NA_1`.
    ClockSync(ClockSync, Cp56Time2a) = C_CS_NA_1;
    /// 104 `C_TS_NA_1`.
    TestCommand(TestCommand, ()) = C_TS_NA_1;
    /// 105 `C_RP_NA_1`.
    ResetProcess(ResetProcess, ()) = C_RP_NA_1;
    /// 106 `C_CD_NA_1`.
    DelayAcquisition(DelayAcquisition, ()) = C_CD_NA_1;
    /// 107 `C_TS_TA_1`.
    TestCommandCp56(TestCounter, Cp56Time2a) = C_TS_TA_1;
    /// 110 `P_ME_NA_1`.
    ParameterNormalized(ParameterNormalized, ()) = P_ME_NA_1;
    /// 111 `P_ME_NB_1`.
    ParameterScaled(ParameterScaled, ()) = P_ME_NB_1;
    /// 112 `P_ME_NC_1`.
    ParameterFloat(ParameterFloat, ()) = P_ME_NC_1;
    /// 113 `P_AC_NA_1`.
    ParameterActivation(ParameterActivation, ()) = P_AC_NA_1;
    /// 120 `F_FR_NA_1`.
    FileReady(FileReady, ()) = F_FR_NA_1;
    /// 121 `F_SR_NA_1`.
    SectionReady(SectionReady, ()) = F_SR_NA_1;
    /// 122 `F_SC_NA_1`.
    CallSelect(CallSelect, ()) = F_SC_NA_1;
    /// 123 `F_LS_NA_1`.
    LastSection(LastSection, ()) = F_LS_NA_1;
    /// 124 `F_AF_NA_1`.
    FileAck(FileAck, ()) = F_AF_NA_1;
    /// 125 `F_SG_NA_1`.
    Segment(Segment, ()) = F_SG_NA_1;
    /// 126 `F_DR_TA_1`.
    Directory(DirectoryEntry, Cp56Time2a) = F_DR_TA_1;
    /// 127 `F_SC_NB_1`.
    QueryLog(QueryLog, ()) = F_SC_NB_1;
}

impl Objects {
    /// Whether there are no information objects.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The addresses of the objects, in order (empty for `Raw`).
    pub fn ioas(&self) -> impl Iterator<Item = Ioa> + '_ {
        (0..self.len()).map_while(|i| self.ioa(i))
    }
}

impl From<Raw> for Objects {
    fn from(raw: Raw) -> Self {
        Self::Raw(raw)
    }
}

/// The data unit identifier: what precedes the information objects.
///
/// [`AsduHeader::decode`] reads it alone, for a gateway that routes by common address without
/// decoding the objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AsduHeader {
    /// The type identification.
    pub type_id: TypeId,
    /// SQ: the objects are a sequence of consecutive addresses sharing one IOA on the wire.
    pub sequence: bool,
    /// The number of objects (0–127).
    pub count: u8,
    /// The cause of transmission.
    pub cot: Cot,
    /// The common address of ASDU.
    pub common_address: CommonAddress,
}

impl AsduHeader {
    /// The header at the start of `octets` under `profile`.
    pub fn decode(octets: &[u8], profile: &Profile) -> Result<Self, DecodeError> {
        codec::read_header(&mut codec::Reader::new(octets), profile)
    }
}

/// An application service data unit.
///
/// Built in one expression with [`Asdu::new`]; decoded with [`Asdu::decode`]; encoded into a
/// caller's buffer with [`Asdu::encode`] (or [`Asdu::to_vec`]).
#[derive(Clone, Debug, PartialEq)]
pub struct Asdu {
    /// The cause of transmission.
    pub cot: Cot,
    /// The common address of ASDU.
    pub common_address: CommonAddress,
    /// SQ = 1: the objects have consecutive addresses and only the first is on the wire.
    pub sequence: bool,
    /// The information objects.
    pub objects: Objects,
}

impl Asdu {
    /// An ASDU with SQ = 0. The type identification follows from `objects`.
    ///
    /// ```
    /// use iec60870::prelude::*;
    ///
    /// let gi = Asdu::new(CommonAddress(1), Cot::ACTIVATION, InformationObject::new(Ioa(0), Interrogation::STATION));
    /// assert_eq!(gi.to_vec(&Profile::IEC104)?, [100, 1, 6, 0, 1, 0, 0, 0, 0, 20]);
    /// # Ok::<(), iec60870::EncodeError>(())
    /// ```
    pub fn new(common_address: CommonAddress, cot: impl Into<Cot>, objects: impl Into<Objects>) -> Self {
        Self { cot: cot.into(), common_address, sequence: false, objects: objects.into() }
    }

    /// The same ASDU with SQ = 1 (the objects' addresses must then be consecutive).
    #[must_use]
    pub fn in_sequence(self) -> Self {
        Self { sequence: true, ..self }
    }

    /// The type identification.
    pub fn type_id(&self) -> TypeId {
        self.objects.type_id()
    }

    /// The number of information objects.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Whether there are no information objects.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }

    /// The header this ASDU encodes (the count saturates at 255 for an over-full ASDU, which
    /// encoding refuses).
    pub fn header(&self) -> AsduHeader {
        AsduHeader {
            type_id: self.type_id(),
            sequence: self.sequence,
            count: u8::try_from(self.len()).unwrap_or(u8::MAX),
            cot: self.cot,
            common_address: self.common_address,
        }
    }

    /// Decodes one ASDU that fills `octets` exactly.
    ///
    /// A type outside `profile.types`, or without a typed form, decodes to
    /// [`Objects::Raw`]. Values are kept as received; only structure is checked — the
    /// length against the profile, every field against the octets left, and that no octet is
    /// left over. The only allocation is bounded by the octets present, never by the VSQ's
    /// claim alone.
    pub fn decode(octets: &[u8], profile: &Profile) -> Result<Self, DecodeError> {
        codec::decode(octets, profile)
    }

    /// The encoded length under `profile` (whether or not encoding would succeed).
    pub fn encoded_len(&self, profile: &Profile) -> usize {
        profile.header_len() + self.objects.body_len(profile, self.sequence)
    }

    /// Encodes into the start of `out`, returning the number of octets written.
    ///
    /// Every check runs before the first octet is written; on error `out` is unchanged.
    /// A buffer that is too small yields [`EncodeError::BufferTooSmall`] with the size needed.
    pub fn encode(&self, profile: &Profile, out: &mut [u8]) -> Result<usize, EncodeError> {
        codec::encode(self, profile, out)
    }

    /// Encodes into a new vector.
    pub fn to_vec(&self, profile: &Profile) -> Result<Vec<u8>, EncodeError> {
        let mut v = alloc::vec![0; self.encoded_len(profile)];
        let n = self.encode(profile, &mut v)?;
        v.truncate(n);
        Ok(v)
    }
}

impl fmt::Display for Asdu {
    /// One line: `M_ME_TF_1 (36) spontaneous (3), CA 1, 2 objects, IOA 4001…`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}, CA {}", self.type_id(), self.cot, self.common_address)?;
        let n = self.len();
        write!(f, ", {n} object{}", if n == 1 { "" } else { "s" })?;
        if self.sequence {
            f.write_str(" (SQ)")?;
        }
        if let Some(first) = self.objects.ioa(0) {
            write!(f, ", IOA {first}")?;
            if let Some(last) = n.checked_sub(1).filter(|l| *l > 0).and_then(|l| self.objects.ioa(l)) {
                write!(f, "{}{last}", if self.sequence { "–" } else { "…" })?;
            }
        }
        Ok(())
    }
}
