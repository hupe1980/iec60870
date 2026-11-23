//! Every information element the standard type identifications carry.
//!
//! One type per kind of element; the time tag, where there is one, is not part of the element
//! but the `time` of its [`InformationObject`](crate::asdu::InformationObject), so the same
//! [`MeasuredFloat`] is type 13, 14 or 36 depending on whether its time is `()`,
//! [`Cp24Time2a`] or [`Cp56Time2a`].

use alloc::vec::Vec;
use core::fmt;

use super::{DoublePointValue, Normalized, OutputCircuits, ParameterQualifier, ProtectionQuality, Quality, SetpointQualifier, SingleEvent, StartEvents};
#[cfg(doc)]
use crate::time::Cp24Time2a;
use crate::time::{Cp16Time2a, Cp56Time2a};

/// SIQ — single-point information with its quality: the value (SPI, bit 0) and BL, SB, NT,
/// IV. Kept as received (bits 1–3 are reserved). Types 1, 2, 30.
///
/// ```
/// use iec60870::{types::SinglePoint, Quality};
///
/// let sp = SinglePoint::new(true).with_quality(Quality::INVALID);
/// assert_eq!(sp.bits(), 0x81);
/// assert!(sp.value() && sp.quality().is_invalid());
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SinglePoint(u8);

impl SinglePoint {
    /// The point in state `on` with good quality.
    pub const fn new(on: bool) -> Self {
        Self(on as u8)
    }

    /// The point from its octet, as received.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The octet, as received.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// SPI, the state.
    pub const fn value(self) -> bool {
        self.0 & 0x01 != 0
    }

    /// BL, SB, NT, IV (OV does not exist in a SIQ).
    pub const fn quality(self) -> Quality {
        Quality(self.0 & 0xF0)
    }

    /// The same point with BL, SB, NT, IV taken from `quality` (its OV and reserved bits are
    /// not part of a SIQ and are ignored).
    #[must_use]
    pub const fn with_quality(self, quality: Quality) -> Self {
        Self((self.0 & 0x0F) | (quality.0 & 0xF0))
    }
}

impl fmt::Debug for SinglePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SinglePoint({}, {:?}", if self.value() { "ON" } else { "OFF" }, self.quality())?;
        if self.0 & 0x0E != 0 {
            write!(f, ", reserved {:#04x}", self.0 & 0x0E)?;
        }
        f.write_str(")")
    }
}

/// DIQ — double-point information with its quality: the state (DPI, bits 0–1) and BL, SB,
/// NT, IV. Kept as received (bits 2–3 are reserved). Types 3, 4, 31.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DoublePoint(u8);

impl DoublePoint {
    /// The point in state `value` with good quality.
    pub const fn new(value: DoublePointValue) -> Self {
        Self(value as u8)
    }

    /// The point from its octet, as received.
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits)
    }

    /// The octet, as received.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// DPI, the state.
    pub const fn value(self) -> DoublePointValue {
        DoublePointValue::from_bits(self.0)
    }

    /// BL, SB, NT, IV.
    pub const fn quality(self) -> Quality {
        Quality(self.0 & 0xF0)
    }

    /// The same point with BL, SB, NT, IV taken from `quality`.
    #[must_use]
    pub const fn with_quality(self, quality: Quality) -> Self {
        Self((self.0 & 0x0F) | (quality.0 & 0xF0))
    }
}

impl fmt::Debug for DoublePoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DoublePoint({:?}, {:?}", self.value(), self.quality())?;
        if self.0 & 0x0C != 0 {
            write!(f, ", reserved {:#04x}", self.0 & 0x0C)?;
        }
        f.write_str(")")
    }
}

/// VTI + QDS — step position information: a value −64 … 63, the transient flag and the
/// quality. Types 5, 6, 32.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct StepPosition {
    /// The position, −64 … 63 (encoding refuses anything else).
    pub value: i8,
    /// T: the equipment is in transient state.
    pub transient: bool,
    /// QDS.
    pub quality: Quality,
}

impl StepPosition {
    /// The position `value`, not transient, good quality.
    pub const fn new(value: i8) -> Self {
        Self { value, transient: false, quality: Quality::GOOD }
    }
}

/// BSI + QDS — a bitstring of 32 bits with quality. Types 7, 8, 33.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Bitstring32 {
    /// The bits.
    pub value: u32,
    /// QDS.
    pub quality: Quality,
}

impl Bitstring32 {
    /// The bitstring `value` with good quality.
    pub const fn new(value: u32) -> Self {
        Self { value, quality: Quality::GOOD }
    }
}

/// NVA + QDS — a measured normalized value. Types 9, 10, 34.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct MeasuredNormalized {
    /// The value.
    pub value: Normalized,
    /// QDS.
    pub quality: Quality,
}

impl MeasuredNormalized {
    /// The value with good quality.
    pub const fn new(value: Normalized) -> Self {
        Self { value, quality: Quality::GOOD }
    }
}

/// SVA + QDS — a measured scaled value. Types 11, 12, 35.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct MeasuredScaled {
    /// The value.
    pub value: i16,
    /// QDS.
    pub quality: Quality,
}

impl MeasuredScaled {
    /// The value with good quality.
    pub const fn new(value: i16) -> Self {
        Self { value, quality: Quality::GOOD }
    }
}

/// IEEE 754 short float + QDS — a measured short floating-point value. Types 13, 14, 36.
///
/// Every bit pattern round-trips, NaN payloads included; compare with
/// [`f32::to_bits`] when NaN matters.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct MeasuredFloat {
    /// The value.
    pub value: f32,
    /// QDS.
    pub quality: Quality,
}

impl MeasuredFloat {
    /// The value with good quality.
    pub const fn new(value: f32) -> Self {
        Self { value, quality: Quality::GOOD }
    }
}

macro_rules! with_quality {
    ($($name:ident),*) => {$(
        impl $name {
            /// The same element with quality `quality`.
            #[must_use]
            pub const fn with_quality(self, quality: Quality) -> Self {
                Self { quality, ..self }
            }
        }
    )*};
}
with_quality!(StepPosition, Bitstring32, MeasuredNormalized, MeasuredScaled, MeasuredFloat, PackedSinglePoints);

/// SEP + CP16Time2a — an event of protection equipment and its elapsed time. Types 17, 38.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ProtectionEvent {
    /// SEP: the event state and its quality.
    pub event: SingleEvent,
    /// The elapsed time.
    pub elapsed: Cp16Time2a,
}

/// SPE + QDP + CP16Time2a — packed start events of protection equipment and the relay
/// duration. Types 18, 39.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct PackedStartEvents {
    /// SPE.
    pub events: StartEvents,
    /// QDP.
    pub quality: ProtectionQuality,
    /// The relay duration time.
    pub duration: Cp16Time2a,
}

/// OCI + QDP + CP16Time2a — packed output circuit information of protection equipment and the
/// relay operating time. Types 19, 40.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct PackedOutputCircuits {
    /// OCI.
    pub circuits: OutputCircuits,
    /// QDP.
    pub quality: ProtectionQuality,
    /// The relay operating time.
    pub operating_time: Cp16Time2a,
}

/// SCD + QDS — sixteen single points with their status-change detection bits. Type 20.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct PackedSinglePoints {
    /// ST: the sixteen states (bit n = point n).
    pub status: u16,
    /// CD: which states changed since the last report.
    pub change: u16,
    /// QDS.
    pub quality: Quality,
}

impl PackedSinglePoints {
    /// The states `status` with change bits `change` and good quality.
    pub const fn new(status: u16, change: u16) -> Self {
        Self { status, change, quality: Quality::GOOD }
    }
}

/// NVA + QOS — a set-point command with a normalized value. Types 48, 61.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SetpointNormalized {
    /// The set point.
    pub value: Normalized,
    /// QOS.
    pub qualifier: SetpointQualifier,
}

/// SVA + QOS — a set-point command with a scaled value. Types 49, 62.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SetpointScaled {
    /// The set point.
    pub value: i16,
    /// QOS.
    pub qualifier: SetpointQualifier,
}

/// IEEE 754 short float + QOS — a set-point command with a short floating-point value.
/// Types 50, 63.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct SetpointFloat {
    /// The set point.
    pub value: f32,
    /// QOS.
    pub qualifier: SetpointQualifier,
}

macro_rules! setpoint {
    ($($name:ident($ty:ty)),*) => {$(
        impl $name {
            /// An execute set point with the default qualifier.
            pub const fn new(value: $ty) -> Self {
                Self { value, qualifier: SetpointQualifier::DEFAULT }
            }

            /// The same set point as the select of select-before-operate.
            #[must_use]
            pub const fn select(self) -> Self {
                Self { qualifier: self.qualifier.select(), ..self }
            }
        }
    )*};
}
setpoint!(SetpointNormalized(Normalized), SetpointScaled(i16), SetpointFloat(f32));

/// BSI — a bitstring of 32 bits command. Types 51, 64.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct BitstringCommand(pub u32);

/// COI — the cause of initialization of an end-of-initialization ASDU. Type 70.
///
/// Bits 0–6 are the cause (0 local power switch on, 1 local manual reset, 2 remote reset),
/// bit 7 is set when the initialization followed a change of local parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct EndOfInitialization(pub u8);

impl EndOfInitialization {
    /// Cause 0: local power switch on.
    pub const LOCAL_POWER_ON: EndOfInitialization = EndOfInitialization(0);
    /// Cause 1: local manual reset.
    pub const LOCAL_MANUAL_RESET: EndOfInitialization = EndOfInitialization(1);
    /// Cause 2: remote reset.
    pub const REMOTE_RESET: EndOfInitialization = EndOfInitialization(2);

    /// The cause, bits 0–6.
    pub const fn cause(self) -> u8 {
        self.0 & 0x7F
    }

    /// Bit 7: initialization after a change of local parameters.
    pub const fn after_parameter_change(self) -> bool {
        self.0 & 0x80 != 0
    }

    /// The same element with bit 7 set or cleared.
    #[must_use]
    pub const fn with_parameter_change(self, changed: bool) -> Self {
        Self(if changed { self.0 | 0x80 } else { self.0 & 0x7F })
    }
}

/// QOI — the qualifier of an interrogation command. Type 100.
///
/// 20 is station (general) interrogation, 21–36 interrogation of group 1–16.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Interrogation(pub u8);

impl Interrogation {
    /// QOI 20: station interrogation (general interrogation).
    pub const STATION: Interrogation = Interrogation(20);

    /// QOI 21–36: interrogation of group `group` 1–16.
    pub const fn group(group: u8) -> Option<Self> {
        if group >= 1 && group <= 16 { Some(Self(20 + group)) } else { None }
    }

    /// The group 1–16, if this interrogates a group.
    pub const fn group_number(self) -> Option<u8> {
        if self.0 >= 21 && self.0 <= 36 { Some(self.0 - 20) } else { None }
    }
}

impl Default for Interrogation {
    fn default() -> Self {
        Self::STATION
    }
}

/// QCC — the qualifier of a counter interrogation command: the request (RQT, bits 0–5;
/// 1–4 group 1–4, 5 general) and the freeze/reset action (FRZ, bits 6–7). Type 101.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CounterInterrogation(pub u8);

impl CounterInterrogation {
    /// RQT 5, FRZ 0: read all counters, no freeze or reset.
    pub const GENERAL: CounterInterrogation = CounterInterrogation(5);
    /// FRZ 0: read only.
    pub const READ: u8 = 0;
    /// FRZ 1: counter freeze without reset.
    pub const FREEZE: u8 = 1;
    /// FRZ 2: counter freeze with reset.
    pub const FREEZE_AND_RESET: u8 = 2;
    /// FRZ 3: counter reset.
    pub const RESET: u8 = 3;

    /// RQT 1–4: the counters of group `group`, read only.
    pub const fn group(group: u8) -> Option<Self> {
        if group >= 1 && group <= 4 { Some(Self(group)) } else { None }
    }

    /// The same qualifier with FRZ `freeze` (0–3; only the low two bits are used).
    #[must_use]
    pub const fn with_freeze(self, freeze: u8) -> Self {
        Self((self.0 & 0x3F) | ((freeze & 0x03) << 6))
    }

    /// RQT, the request, 0–63.
    pub const fn request(self) -> u8 {
        self.0 & 0x3F
    }

    /// FRZ, the freeze/reset action, 0–3.
    pub const fn freeze(self) -> u8 {
        self.0 >> 6
    }
}

impl Default for CounterInterrogation {
    fn default() -> Self {
        Self::GENERAL
    }
}

/// The read command: no information element, only the address to read. Type 102.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct Read;

/// The clock synchronization command: the element is the object's [`Cp56Time2a`] time.
/// Type 103.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ClockSync;

/// FBP — the fixed test bit pattern of a test command, as received. Type 104.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TestCommand(pub u16);

impl TestCommand {
    /// The pattern the standard fixes, octets `0xAA 0x55`.
    pub const PATTERN: TestCommand = TestCommand(0x55AA);
}

impl Default for TestCommand {
    fn default() -> Self {
        Self::PATTERN
    }
}

/// QRP — the qualifier of a reset process command. Type 105.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ResetProcess(pub u8);

impl ResetProcess {
    /// QRP 1: general reset of process.
    pub const GENERAL: ResetProcess = ResetProcess(1);
    /// QRP 2: reset of pending information with time tag of the event buffer.
    pub const EVENT_BUFFER: ResetProcess = ResetProcess(2);
}

/// The delay acquisition command: the delay as CP16Time2a. Type 106.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct DelayAcquisition(pub Cp16Time2a);

/// TSC — the test sequence counter of a test command with time tag. Type 107.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct TestCounter(pub u16);

/// NVA + QPM — a parameter of measured values, normalized. Type 110.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ParameterNormalized {
    /// The parameter value.
    pub value: Normalized,
    /// QPM.
    pub qualifier: ParameterQualifier,
}

/// SVA + QPM — a parameter of measured values, scaled. Type 111.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ParameterScaled {
    /// The parameter value.
    pub value: i16,
    /// QPM.
    pub qualifier: ParameterQualifier,
}

/// IEEE 754 short float + QPM — a parameter of measured values, short floating point. Type 112.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct ParameterFloat {
    /// The parameter value.
    pub value: f32,
    /// QPM.
    pub qualifier: ParameterQualifier,
}

/// QPA — the qualifier of a parameter activation. Type 113.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct ParameterActivation(pub u8);

impl ParameterActivation {
    /// QPA 1: act/deact of the previously loaded parameters (object address 0).
    pub const LOADED_PARAMETERS: ParameterActivation = ParameterActivation(1);
    /// QPA 2: act/deact of the parameter of the addressed object.
    pub const OBJECT_PARAMETER: ParameterActivation = ParameterActivation(2);
    /// QPA 3: act/deact of persistent cyclic or periodic transmission of the addressed object.
    pub const CYCLIC_TRANSMISSION: ParameterActivation = ParameterActivation(3);
}

/// NOF + LOF + FRQ — file ready. Type 120.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct FileReady {
    /// NOF, the name of the file.
    pub name: u16,
    /// LOF, the length of the file in octets (three octets on the wire, ≤ `0xFF_FFFF`).
    pub length: u32,
    /// FRQ, the file ready qualifier (bit 7 set = negative confirmation).
    pub qualifier: u8,
}

/// NOF + NOS + LOF + SRQ — section ready. Type 121.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct SectionReady {
    /// NOF.
    pub name: u16,
    /// NOS, the name of the section.
    pub section: u8,
    /// LOF, the length of the section (≤ `0xFF_FFFF`).
    pub length: u32,
    /// SRQ, the section ready qualifier (bit 7 set = not ready).
    pub qualifier: u8,
}

/// NOF + NOS + SCQ — call directory, select file, call file, call section. Type 122.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct CallSelect {
    /// NOF.
    pub name: u16,
    /// NOS.
    pub section: u8,
    /// SCQ, the select and call qualifier (bits 0–3 the action, 4–7 the error cause).
    pub qualifier: u8,
}

/// NOF + NOS + LSQ + CHS — last section, last segment. Type 123.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct LastSection {
    /// NOF.
    pub name: u16,
    /// NOS.
    pub section: u8,
    /// LSQ, the last section or segment qualifier.
    pub qualifier: u8,
    /// CHS, the checksum.
    pub checksum: u8,
}

/// NOF + NOS + AFQ — acknowledge file, acknowledge section. Type 124.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct FileAck {
    /// NOF.
    pub name: u16,
    /// NOS.
    pub section: u8,
    /// AFQ, the acknowledge qualifier (bits 0–3 the acknowledgement, 4–7 the error cause).
    pub qualifier: u8,
}

/// NOF + NOS + LOS + segment — a segment of a file section. Type 125.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Segment {
    /// NOF.
    pub name: u16,
    /// NOS.
    pub section: u8,
    /// The segment octets (LOS, their count, is one octet on the wire: ≤ 255).
    pub data: Vec<u8>,
}

/// NOF + LOF + SOF — an entry of a directory; the creation time is the object's
/// [`Cp56Time2a`]. Type 126.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct DirectoryEntry {
    /// NOF.
    pub name: u16,
    /// LOF (≤ `0xFF_FFFF`).
    pub length: u32,
    /// SOF, the status of file (bits 0–4 status, 5 last file, 6 directory, 7 transfer active).
    pub status: u8,
}

/// NOF + two CP56Time2a — query log, request archive file between two times. Type 127.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct QueryLog {
    /// NOF.
    pub name: u16,
    /// The start of the requested range.
    pub start: Cp56Time2a,
    /// The end of the requested range.
    pub stop: Cp56Time2a,
}
