//! Quality descriptors and the protection-equipment flag octets.

use super::DoublePointValue;

/// QDS, the quality descriptor of monitored values: overflow (OV `0x01`), blocked (BL `0x10`),
/// substituted (SB `0x20`), not topical (NT `0x40`) and invalid (IV `0x80`).
///
/// The octet is kept as received; bits 1–3 are reserved. In a single- or double-point octet
/// (SIQ, DIQ) only BL, SB, NT and IV exist.
///
/// ```
/// use iec60870::Quality;
///
/// let q = Quality::INVALID | Quality::NOT_TOPICAL;
/// assert!(q.is_invalid() && !q.is_good());
/// assert_eq!(format!("{q:?}"), "Quality(NT | IV)");
/// assert_eq!(format!("{:?}", Quality::GOOD), "Quality(GOOD)");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Quality(pub(crate) u8);

flag_octet!(Quality, "GOOD", [OV = 0x01, BL = 0x10, SB = 0x20, NT = 0x40, IV = 0x80]);

impl core::fmt::Display for Quality {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_flags(f, " ", "good")
    }
}

impl Quality {
    /// No flag set.
    pub const GOOD: Quality = Quality(0);
    /// OV: the value is beyond a predefined range.
    pub const OVERFLOW: Quality = Quality(0x01);
    /// BL: the value is blocked for transmission.
    pub const BLOCKED: Quality = Quality(0x10);
    /// SB: the value was entered by an operator or an automatic source.
    pub const SUBSTITUTED: Quality = Quality(0x20);
    /// NT: the most recent update was not successful.
    pub const NOT_TOPICAL: Quality = Quality(0x40);
    /// IV: the value is invalid.
    pub const INVALID: Quality = Quality(0x80);

    /// Whether none of OV, BL, SB, NT, IV is set.
    pub const fn is_good(self) -> bool {
        self.0 & 0xF1 == 0
    }
    /// OV.
    pub const fn is_overflow(self) -> bool {
        self.0 & 0x01 != 0
    }
    /// BL.
    pub const fn is_blocked(self) -> bool {
        self.0 & 0x10 != 0
    }
    /// SB.
    pub const fn is_substituted(self) -> bool {
        self.0 & 0x20 != 0
    }
    /// NT.
    pub const fn is_not_topical(self) -> bool {
        self.0 & 0x40 != 0
    }
    /// IV.
    pub const fn is_invalid(self) -> bool {
        self.0 & 0x80 != 0
    }
}

/// QDP, the quality descriptor of protection-equipment events: elapsed time invalid
/// (EI `0x08`), BL `0x10`, SB `0x20`, NT `0x40`, IV `0x80`; bits 0–2 reserved. Kept as received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ProtectionQuality(pub(crate) u8);

flag_octet!(ProtectionQuality, "GOOD", [EI = 0x08, BL = 0x10, SB = 0x20, NT = 0x40, IV = 0x80]);

impl core::fmt::Display for ProtectionQuality {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_flags(f, " ", "good")
    }
}

impl ProtectionQuality {
    /// No flag set.
    pub const GOOD: ProtectionQuality = ProtectionQuality(0);
    /// EI: the elapsed time is invalid.
    pub const ELAPSED_INVALID: ProtectionQuality = ProtectionQuality(0x08);
    /// BL.
    pub const BLOCKED: ProtectionQuality = ProtectionQuality(0x10);
    /// SB.
    pub const SUBSTITUTED: ProtectionQuality = ProtectionQuality(0x20);
    /// NT.
    pub const NOT_TOPICAL: ProtectionQuality = ProtectionQuality(0x40);
    /// IV.
    pub const INVALID: ProtectionQuality = ProtectionQuality(0x80);

    /// EI.
    pub const fn is_elapsed_invalid(self) -> bool {
        self.0 & 0x08 != 0
    }
    /// IV.
    pub const fn is_invalid(self) -> bool {
        self.0 & 0x80 != 0
    }
}

/// SEP, a single event of protection equipment: the event state (ES, bits 0–1, as a
/// [`DoublePointValue`]) with the QDP flags in the same octet. Kept as received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SingleEvent(pub(crate) u8);

flag_octet!(SingleEvent, "INDETERMINATE", [OFF = 0x01, ON = 0x02, EI = 0x08, BL = 0x10, SB = 0x20, NT = 0x40, IV = 0x80]);

impl core::fmt::Display for SingleEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.state())?;
        if self.quality() != ProtectionQuality::GOOD {
            write!(f, " [{}]", self.quality())?;
        }
        Ok(())
    }
}

impl SingleEvent {
    /// The event with state `state` and no flag set.
    pub const fn new(state: DoublePointValue) -> Self {
        Self(state as u8)
    }

    /// The same event with the flags of `quality` (EI, BL, SB, NT, IV) replacing its own.
    #[must_use]
    pub const fn with_quality(self, quality: ProtectionQuality) -> Self {
        Self((self.0 & 0x07) | (quality.0 & 0xF8))
    }

    /// ES, the event state.
    pub const fn state(self) -> DoublePointValue {
        DoublePointValue::from_bits(self.0)
    }

    /// The QDP flags of the octet (bit 2 reserved, kept).
    pub const fn quality(self) -> ProtectionQuality {
        ProtectionQuality(self.0 & 0xFC)
    }
}

/// SPE, the start events of protection equipment: general start (GS `0x01`), start of
/// L1/L2/L3 (`0x02`/`0x04`/`0x08`), earth current (SIE `0x10`) and reverse direction
/// (SRD `0x20`). Kept as received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StartEvents(pub(crate) u8);

flag_octet!(StartEvents, "NONE", [GS = 0x01, SL1 = 0x02, SL2 = 0x04, SL3 = 0x08, SIE = 0x10, SRD = 0x20]);

impl core::fmt::Display for StartEvents {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_flags(f, " ", "none")
    }
}

impl StartEvents {
    /// No start event.
    pub const NONE: StartEvents = StartEvents(0);
    /// GS: general start of operation.
    pub const GENERAL: StartEvents = StartEvents(0x01);
    /// SL1: start of operation phase L1.
    pub const L1: StartEvents = StartEvents(0x02);
    /// SL2: start of operation phase L2.
    pub const L2: StartEvents = StartEvents(0x04);
    /// SL3: start of operation phase L3.
    pub const L3: StartEvents = StartEvents(0x08);
    /// SIE: start of operation IE (earth current).
    pub const EARTH_CURRENT: StartEvents = StartEvents(0x10);
    /// SRD: start of operation in reverse direction.
    pub const REVERSE: StartEvents = StartEvents(0x20);
}

/// OCI, the output circuit information of protection equipment: general command
/// (GC `0x01`) and the commands to output circuits L1/L2/L3 (`0x02`/`0x04`/`0x08`). Kept as
/// received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct OutputCircuits(pub(crate) u8);

flag_octet!(OutputCircuits, "NONE", [GC = 0x01, CL1 = 0x02, CL2 = 0x04, CL3 = 0x08]);

impl core::fmt::Display for OutputCircuits {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.fmt_flags(f, " ", "none")
    }
}

impl OutputCircuits {
    /// No command.
    pub const NONE: OutputCircuits = OutputCircuits(0);
    /// GC: general command to output circuit.
    pub const GENERAL: OutputCircuits = OutputCircuits(0x01);
    /// CL1: command to output circuit phase L1.
    pub const L1: OutputCircuits = OutputCircuits(0x02);
    /// CL2.
    pub const L2: OutputCircuits = OutputCircuits(0x04);
    /// CL3.
    pub const L3: OutputCircuits = OutputCircuits(0x08);
}

#[cfg(test)]
mod display_tests {
    use super::*;
    use alloc::format;

    #[test]
    fn flags_and_typed_event_states_preserve_octets() {
        assert_eq!(format!("{}", Quality::GOOD), "good");
        assert_eq!(format!("{}", Quality::from_bits(0xd3)), "OV BL NT IV 0x02");
        assert_eq!(format!("{}", ProtectionQuality::GOOD), "good");
        assert_eq!(format!("{}", ProtectionQuality::from_bits(0x89)), "EI IV 0x01");
        assert_eq!(format!("{}", StartEvents::NONE), "none");
        assert_eq!(format!("{}", StartEvents::from_bits(0x83)), "GS SL1 0x80");
        assert_eq!(format!("{}", OutputCircuits::NONE), "none");
        assert_eq!(format!("{}", OutputCircuits::from_bits(0x83)), "GC CL1 0x80");
        for (bits, state) in [(0, "INTERMEDIATE"), (1, "OFF"), (2, "ON"), (3, "INDETERMINATE")] {
            for (extra, suffix) in [(0, ""), (0xc0, " [NT IV]"), (0x04, " [0x04]")] {
                let event = SingleEvent::from_bits(bits | extra);
                assert_eq!(format!("{event}"), format!("{state}{suffix}"));
                assert_eq!(event.bits(), bits | extra);
            }
        }
    }
}
