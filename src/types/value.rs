//! Values: normalized, double-point states, binary counter readings.

use core::fmt;

/// A normalized value: a 16-bit two's-complement fraction, −1 … 1 − 2⁻¹⁵ (NVA).
///
/// ```
/// use iec60870::types::Normalized;
///
/// assert_eq!(Normalized::MIN.to_f32(), -1.0);
/// assert_eq!(Normalized::from_f32(0.5), Normalized(16384));
/// assert_eq!(Normalized::from_f32(7.0), Normalized::MAX); // saturates
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Normalized(pub i16);

impl Normalized {
    /// −1.
    pub const MIN: Normalized = Normalized(i16::MIN);
    /// 1 − 2⁻¹⁵.
    pub const MAX: Normalized = Normalized(i16::MAX);
    /// 0.
    pub const ZERO: Normalized = Normalized(0);

    /// The value as a fraction, `raw / 32768`.
    pub fn to_f32(self) -> f32 {
        f32::from(self.0) / 32768.0
    }

    /// The nearest normalized value to `x`, saturating at [`MIN`](Self::MIN) and
    /// [`MAX`](Self::MAX); NaN maps to zero.
    pub fn from_f32(x: f32) -> Self {
        let y = x * 32768.0;
        let rounded = if y >= 0.0 { y + 0.5 } else { y - 0.5 };
        // `as` saturates at the i16 limits and maps NaN to 0.
        Self(rounded as i16)
    }
}

impl fmt::Display for Normalized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.to_f32(), f)
    }
}

impl fmt::Debug for Normalized {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Normalized({} = {})", self.to_f32(), self.0)
    }
}

/// The two-bit state of a double point (DPI), a double command (DCS) or a protection event (ES).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum DoublePointValue {
    /// 0: intermediate state (between OFF and ON); not permitted in a double command.
    #[default]
    Intermediate = 0,
    /// 1: determined state OFF.
    Off = 1,
    /// 2: determined state ON.
    On = 2,
    /// 3: indeterminate state; not permitted in a double command.
    Indeterminate = 3,
}

impl fmt::Display for DoublePointValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Intermediate => "INTERMEDIATE",
            Self::Off => "OFF",
            Self::On => "ON",
            Self::Indeterminate => "INDETERMINATE",
        })
    }
}

impl DoublePointValue {
    /// The state of the low two bits of `bits`.
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::Intermediate,
            1 => Self::Off,
            2 => Self::On,
            _ => Self::Indeterminate,
        }
    }
}

impl From<bool> for DoublePointValue {
    /// `true` is [`On`](Self::On), `false` [`Off`](Self::Off).
    fn from(on: bool) -> Self {
        if on { Self::On } else { Self::Off }
    }
}

/// BCR, a binary counter reading: a signed 32-bit count, a five-bit sequence number and the
/// carry (CY), counter adjusted (CA) and invalid (IV) flags. Kept as received.
///
/// ```
/// use iec60870::types::BinaryCounterReading;
///
/// let bcr = BinaryCounterReading::new(-42).with_sequence(31).with_carry(true);
/// assert_eq!((bcr.value(), bcr.sequence(), bcr.carry(), bcr.adjusted()), (-42, 31, true, false));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BinaryCounterReading {
    value: i32,
    flags: u8,
}

impl BinaryCounterReading {
    /// The reading `value` with sequence number 0 and no flag set.
    pub const fn new(value: i32) -> Self {
        Self { value, flags: 0 }
    }

    /// The reading from its count and its fifth octet, as received.
    pub const fn from_parts(value: i32, flags: u8) -> Self {
        Self { value, flags }
    }

    /// The count.
    pub const fn value(self) -> i32 {
        self.value
    }

    /// The fifth octet: sequence `0x1F`, CY `0x20`, CA `0x40`, IV `0x80`.
    pub const fn flags(self) -> u8 {
        self.flags
    }

    /// The sequence number, 0–31.
    pub const fn sequence(self) -> u8 {
        self.flags & 0x1F
    }

    /// CY: the counter overflowed in the integration period.
    pub const fn carry(self) -> bool {
        self.flags & 0x20 != 0
    }

    /// CA: the counter was adjusted since the last reading.
    pub const fn adjusted(self) -> bool {
        self.flags & 0x40 != 0
    }

    /// IV: the reading is invalid.
    pub const fn invalid(self) -> bool {
        self.flags & 0x80 != 0
    }

    /// The same reading with the sequence number `sequence` modulo 32 (it counts modulo 32).
    #[must_use]
    pub const fn with_sequence(self, sequence: u8) -> Self {
        Self { flags: (self.flags & 0xE0) | (sequence & 0x1F), ..self }
    }

    /// The same reading with CY set or cleared.
    #[must_use]
    pub const fn with_carry(self, on: bool) -> Self {
        self.with_flag(0x20, on)
    }

    /// The same reading with CA set or cleared.
    #[must_use]
    pub const fn with_adjusted(self, on: bool) -> Self {
        self.with_flag(0x40, on)
    }

    /// The same reading with IV set or cleared.
    #[must_use]
    pub const fn with_invalid(self, on: bool) -> Self {
        self.with_flag(0x80, on)
    }

    const fn with_flag(self, mask: u8, on: bool) -> Self {
        Self { flags: if on { self.flags | mask } else { self.flags & !mask }, ..self }
    }
}

impl fmt::Debug for BinaryCounterReading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BinaryCounterReading({}, sequence {}", self.value, self.sequence())?;
        for (on, name) in [(self.carry(), "CY"), (self.adjusted(), "CA"), (self.invalid(), "IV")] {
            if on {
                write!(f, ", {name}")?;
            }
        }
        f.write_str(")")
    }
}
