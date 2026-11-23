//! Decode and encode errors that say which field, where, and why.

use core::fmt;

use crate::types::{Ioa, TypeId};

/// A field of the ASDU, named as the standard abbreviates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Field {
    /// The ASDU as a whole (its length).
    Asdu,
    /// Type identification.
    TypeId,
    /// Variable structure qualifier (SQ and number of objects).
    Vsq,
    /// Cause of transmission.
    Cot,
    /// Originator address (second COT octet).
    Originator,
    /// Common address of ASDU.
    CommonAddress,
    /// Information object address.
    Ioa,
    /// Single-point information with quality.
    Siq,
    /// Double-point information with quality.
    Diq,
    /// Quality descriptor.
    Qds,
    /// Value with transient state indication (step position).
    Vti,
    /// Binary state information (bitstring of 32 bits).
    Bsi,
    /// Normalized value.
    Nva,
    /// Scaled value.
    Sva,
    /// Short floating-point number.
    Float,
    /// Binary counter reading.
    Bcr,
    /// Single event of protection equipment.
    Sep,
    /// Start events of protection equipment.
    Spe,
    /// Output circuit information of protection equipment.
    Oci,
    /// Quality descriptor for events of protection equipment.
    Qdp,
    /// Status and status change detection.
    Scd,
    /// Single command.
    Sco,
    /// Double command.
    Dco,
    /// Regulating step command.
    Rco,
    /// Qualifier of set-point command.
    Qos,
    /// Qualifier of parameter of measured values.
    Qpm,
    /// Qualifier of parameter activation.
    Qpa,
    /// Qualifier of interrogation.
    Qoi,
    /// Qualifier of counter interrogation.
    Qcc,
    /// Cause of initialization.
    Coi,
    /// Qualifier of reset process.
    Qrp,
    /// Fixed test bit pattern.
    Fbp,
    /// Test sequence counter.
    Tsc,
    /// A CP16Time2a.
    Cp16Time2a,
    /// A CP24Time2a.
    Cp24Time2a,
    /// A CP56Time2a.
    Cp56Time2a,
    /// Name of file.
    Nof,
    /// Name of section.
    Nos,
    /// Length of file or section.
    Lof,
    /// Length of segment.
    Los,
    /// Segment data.
    Segment,
    /// File ready qualifier.
    Frq,
    /// Section ready qualifier.
    Srq,
    /// Select and call qualifier.
    Scq,
    /// Last section or segment qualifier.
    Lsq,
    /// Checksum.
    Chs,
    /// Acknowledge file or section qualifier.
    Afq,
    /// Status of file.
    Sof,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Asdu => "ASDU",
            Self::TypeId => "type identification",
            Self::Vsq => "variable structure qualifier (VSQ)",
            Self::Cot => "cause of transmission (COT)",
            Self::Originator => "originator address",
            Self::CommonAddress => "common address of ASDU (CA)",
            Self::Ioa => "information object address (IOA)",
            Self::Siq => "single-point information (SIQ)",
            Self::Diq => "double-point information (DIQ)",
            Self::Qds => "quality descriptor (QDS)",
            Self::Vti => "step position (VTI)",
            Self::Bsi => "bitstring (BSI)",
            Self::Nva => "normalized value (NVA)",
            Self::Sva => "scaled value (SVA)",
            Self::Float => "short floating-point value",
            Self::Bcr => "binary counter reading (BCR)",
            Self::Sep => "protection event (SEP)",
            Self::Spe => "protection start events (SPE)",
            Self::Oci => "protection output circuits (OCI)",
            Self::Qdp => "protection quality descriptor (QDP)",
            Self::Scd => "status and change detection (SCD)",
            Self::Sco => "single command (SCO)",
            Self::Dco => "double command (DCO)",
            Self::Rco => "regulating step command (RCO)",
            Self::Qos => "set-point qualifier (QOS)",
            Self::Qpm => "parameter qualifier (QPM)",
            Self::Qpa => "parameter activation qualifier (QPA)",
            Self::Qoi => "interrogation qualifier (QOI)",
            Self::Qcc => "counter interrogation qualifier (QCC)",
            Self::Coi => "cause of initialization (COI)",
            Self::Qrp => "reset process qualifier (QRP)",
            Self::Fbp => "fixed test bit pattern (FBP)",
            Self::Tsc => "test sequence counter (TSC)",
            Self::Cp16Time2a => "CP16Time2a",
            Self::Cp24Time2a => "CP24Time2a",
            Self::Cp56Time2a => "CP56Time2a",
            Self::Nof => "name of file (NOF)",
            Self::Nos => "name of section (NOS)",
            Self::Lof => "length of file or section (LOF)",
            Self::Los => "length of segment (LOS)",
            Self::Segment => "segment data",
            Self::Frq => "file ready qualifier (FRQ)",
            Self::Srq => "section ready qualifier (SRQ)",
            Self::Scq => "select and call qualifier (SCQ)",
            Self::Lsq => "last section qualifier (LSQ)",
            Self::Chs => "checksum (CHS)",
            Self::Afq => "acknowledge qualifier (AFQ)",
            Self::Sof => "status of file (SOF)",
        })
    }
}

/// What went wrong while decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The field needs `needed` octets but only `available` remain.
    Truncated {
        /// Octets the field needs.
        needed: usize,
        /// Octets left in the input.
        available: usize,
    },
    /// `count` octets follow the last information object the VSQ announced.
    TrailingOctets {
        /// The number of unaccounted octets.
        count: usize,
    },
    /// The input is longer than the profile's maximum ASDU length.
    TooLong {
        /// The input length.
        len: usize,
        /// The profile's maximum.
        max: usize,
    },
    /// With SQ = 1, the address of an object (`ioa`) exceeds what the IOA field can carry.
    AddressOverflow {
        /// The address the sequence reaches.
        ioa: u32,
        /// The largest address of the profile's IOA width.
        max: u32,
    },
}

/// A structural decoding error: which field, at which octet offset of the ASDU, in which
/// information object, and why.
///
/// ```
/// use iec60870::{asdu::Field, Asdu, Profile};
///
/// // `M_SP_NA_1`, VSQ claims 3 objects, only one is present.
/// let err = Asdu::decode(&[1, 3, 3, 0, 1, 0, 0x0A, 0, 0, 1], &Profile::IEC104).unwrap_err();
/// assert_eq!((err.field, err.offset, err.object), (Field::Ioa, 10, Some(1)));
/// assert_eq!(
///     err.to_string(),
///     "truncated ASDU: information object 2: information object address (IOA) needs 3 octets at offset 10, 0 remain"
/// );
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DecodeError {
    /// Why.
    pub kind: DecodeErrorKind,
    /// The field being read.
    pub field: Field,
    /// The octet offset within the ASDU where the field starts.
    pub offset: usize,
    /// The zero-based index of the information object being read, if any.
    pub object: Option<u8>,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let object = |f: &mut fmt::Formatter<'_>| match self.object {
            Some(i) => write!(f, "information object {}: ", u16::from(i) + 1),
            None => Ok(()),
        };
        match self.kind {
            DecodeErrorKind::Truncated { needed, available } => {
                f.write_str("truncated ASDU: ")?;
                object(f)?;
                let s = if needed == 1 { "" } else { "s" };
                write!(f, "{} needs {needed} octet{s} at offset {}, {available} remain", self.field, self.offset)
            }
            DecodeErrorKind::TrailingOctets { count } => {
                write!(f, "{count} unexpected octet(s) at offset {} after the last information object the VSQ announced", self.offset)
            }
            DecodeErrorKind::TooLong { len, max } => write!(f, "ASDU of {len} octets exceeds the profile's maximum of {max}"),
            DecodeErrorKind::AddressOverflow { ioa, max } => {
                object(f)?;
                write!(f, "the SQ = 1 address sequence reaches IOA {ioa}, beyond the profile's largest address {max}")
            }
        }
    }
}

impl core::error::Error for DecodeError {}

/// Why an ASDU could not be encoded. Nothing is written when encoding fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodeError {
    /// The output buffer holds `available` octets; the ASDU needs `needed`.
    BufferTooSmall {
        /// Octets the ASDU needs.
        needed: usize,
        /// Octets the buffer holds.
        available: usize,
    },
    /// The profile does not permit the ASDU's type identification.
    TypeNotPermitted {
        /// The type.
        type_id: TypeId,
    },
    /// The encoded ASDU would exceed the profile's maximum length.
    TooLong {
        /// The encoded length.
        len: usize,
        /// The profile's maximum.
        max: usize,
    },
    /// More objects than the VSQ's seven bits can count (127).
    TooManyObjects {
        /// The number of objects.
        count: usize,
    },
    /// A value does not fit its field under the profile.
    ValueOutOfRange {
        /// The field.
        field: Field,
        /// The zero-based index of the information object, if the field belongs to one.
        object: Option<usize>,
        /// The value (for a signed field, its two's-complement bits).
        value: u32,
        /// The largest value the field carries (for a step position, 63; −64 is the least).
        max: u32,
    },
    /// With SQ = 1, the addresses must be consecutive.
    NotInSequence {
        /// The zero-based index of the object.
        object: usize,
        /// The address SQ = 1 implies.
        expected: Ioa,
        /// The address the object has.
        found: Ioa,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BufferTooSmall { needed, available } => write!(f, "the ASDU needs {needed} octets but the buffer holds {available}"),
            Self::TypeNotPermitted { type_id } => write!(f, "the profile does not permit {type_id}"),
            Self::TooLong { len, max } => write!(f, "the ASDU would be {len} octets, more than the profile's maximum of {max}"),
            Self::TooManyObjects { count } => write!(f, "{count} information objects, more than the 127 a VSQ can count"),
            Self::ValueOutOfRange { field, object, value, max } => {
                if let Some(i) = object {
                    write!(f, "information object {}: ", i + 1)?;
                }
                if field == Field::Vti {
                    write!(f, "step position {} is outside −64…63", value as i32)
                } else if field == Field::Originator && max == 0 {
                    write!(f, "originator address {value} cannot be carried by a one-octet cause of transmission")
                } else {
                    write!(f, "{field} {value} exceeds {max}, the largest the profile can carry")
                }
            }
            Self::NotInSequence { object, expected, found } => {
                write!(f, "SQ = 1 needs consecutive addresses: information object {} has IOA {found}, expected {expected}", object + 1)
            }
        }
    }
}

impl core::error::Error for EncodeError {}
