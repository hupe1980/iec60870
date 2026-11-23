//! Cause of transmission and the two addresses.

use core::fmt;

/// The cause of transmission proper: the low six bits of the COT octet, 0–63.
///
/// ```
/// use iec60870::Cause;
///
/// assert_eq!(Cause::SPONTANEOUS.value(), 3);
/// assert_eq!(Cause::interrogated_by_group(1), Cause::new(21));
/// assert_eq!(Cause::new(64), None);
/// assert_eq!(Cause::ACTIVATION_CON.to_string(), "activation confirmation (7)");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Cause(u8);

macro_rules! causes {
    ($($name:ident = $value:literal, $text:literal;)*) => {
        impl Cause {
            $(
                #[doc = concat!("Cause ", stringify!($value), ": ", $text, ".")]
                pub const $name: Cause = Cause($value);
            )*
        }

        impl Cot {
            $(
                #[doc = concat!("A positive, non-test COT with cause ", stringify!($value), " (", $text, ") and originator 0.")]
                pub const $name: Cot = Cot::new(Cause::$name);
            )*
        }

        const CAUSE_NAMES: &[(u8, &str)] = &[$(($value, $text)),*];
    };
}

causes! {
    PERIODIC = 1, "periodic";
    BACKGROUND_SCAN = 2, "background scan";
    SPONTANEOUS = 3, "spontaneous";
    INITIALIZED = 4, "initialized";
    REQUEST = 5, "request";
    ACTIVATION = 6, "activation";
    ACTIVATION_CON = 7, "activation confirmation";
    DEACTIVATION = 8, "deactivation";
    DEACTIVATION_CON = 9, "deactivation confirmation";
    ACTIVATION_TERMINATION = 10, "activation termination";
    RETURN_REMOTE = 11, "return after a remote command";
    RETURN_LOCAL = 12, "return after a local command";
    FILE_TRANSFER = 13, "file transfer";
    AUTHENTICATION = 14, "authentication";
    SESSION_KEY = 15, "session key maintenance";
    USER_ROLE_AND_UPDATE_KEY = 16, "user role and update key maintenance";
    INTERROGATED_BY_STATION = 20, "interrogated by station";
    REQUESTED_BY_GENERAL_COUNTER = 37, "requested by general counter interrogation";
    UNKNOWN_TYPE_ID = 44, "unknown type identification";
    UNKNOWN_CAUSE = 45, "unknown cause of transmission";
    UNKNOWN_COMMON_ADDRESS = 46, "unknown common address";
    UNKNOWN_IOA = 47, "unknown information object address";
}

impl Cause {
    /// The cause `value`, or `None` if it does not fit six bits.
    pub const fn new(value: u8) -> Option<Self> {
        if value <= 0x3F { Some(Self(value)) } else { None }
    }

    /// The cause as a number, 0–63.
    pub const fn value(self) -> u8 {
        self.0
    }

    /// Cause 21–36, "interrogated by group `group`", for `group` 1–16.
    pub const fn interrogated_by_group(group: u8) -> Option<Self> {
        if group >= 1 && group <= 16 { Some(Self(20 + group)) } else { None }
    }

    /// Cause 38–41, "requested by counter group `group`", for `group` 1–4.
    pub const fn requested_by_counter_group(group: u8) -> Option<Self> {
        if group >= 1 && group <= 4 { Some(Self(37 + group)) } else { None }
    }

    /// The interrogation group 1–16 of causes 21–36.
    pub const fn interrogation_group(self) -> Option<u8> {
        if self.0 >= 21 && self.0 <= 36 { Some(self.0 - 20) } else { None }
    }

    /// The counter group 1–4 of causes 38–41.
    pub const fn counter_group(self) -> Option<u8> {
        if self.0 >= 38 && self.0 <= 41 { Some(self.0 - 37) } else { None }
    }

    /// Whether the standard defines this cause.
    pub fn is_standard(self) -> bool {
        self.name().is_some() || self.interrogation_group().is_some() || self.counter_group().is_some()
    }

    /// The name of a cause with a fixed meaning (not the group causes), or `None`.
    pub fn name(self) -> Option<&'static str> {
        CAUSE_NAMES.iter().find(|(v, _)| *v == self.0).map(|(_, n)| *n)
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            write!(f, "{name} ({})", self.0)
        } else if let Some(g) = self.interrogation_group() {
            write!(f, "interrogated by group {g} ({})", self.0)
        } else if let Some(g) = self.counter_group() {
            write!(f, "requested by counter group {g} ({})", self.0)
        } else {
            write!(f, "cause {}", self.0)
        }
    }
}

impl fmt::Debug for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cause({self})")
    }
}

/// The cause of transmission field: the cause, the P/N (negative confirmation) and T (test)
/// bits, and the originator address that a two-octet COT carries.
///
/// ```
/// use iec60870::{Cause, Cot};
///
/// let cot = Cot::ACTIVATION_CON.negative().with_originator(3);
/// assert_eq!(cot.cause, Cause::ACTIVATION_CON);
/// assert!(cot.negative && !cot.test);
/// assert_eq!(cot.to_string(), "activation confirmation (7), negative, originator 3");
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Cot {
    /// The cause proper.
    pub cause: Cause,
    /// P/N: a negative confirmation.
    pub negative: bool,
    /// T: the ASDU was generated under test conditions.
    pub test: bool,
    /// The originator address (second COT octet); must be 0 under a one-octet COT.
    pub originator: u8,
}

impl Cot {
    /// A positive, non-test COT with originator 0.
    pub const fn new(cause: Cause) -> Self {
        Self { cause, negative: false, test: false, originator: 0 }
    }

    /// The same COT with P/N set (a negative confirmation).
    #[must_use]
    pub const fn negative(self) -> Self {
        Self { negative: true, ..self }
    }

    /// The same COT with T set (test).
    #[must_use]
    pub const fn test(self) -> Self {
        Self { test: true, ..self }
    }

    /// The same COT with the originator address `originator`.
    #[must_use]
    pub const fn with_originator(self, originator: u8) -> Self {
        Self { originator, ..self }
    }

    /// The first COT octet: cause, P/N `0x40`, T `0x80`.
    pub const fn octet(self) -> u8 {
        self.cause.0 | if self.negative { 0x40 } else { 0 } | if self.test { 0x80 } else { 0 }
    }

    /// The COT of a first octet and an originator address.
    pub const fn from_octets(octet: u8, originator: u8) -> Self {
        Self { cause: Cause(octet & 0x3F), negative: octet & 0x40 != 0, test: octet & 0x80 != 0, originator }
    }
}

impl From<Cause> for Cot {
    fn from(cause: Cause) -> Self {
        Self::new(cause)
    }
}

impl fmt::Display for Cot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.cause)?;
        if self.negative {
            f.write_str(", negative")?;
        }
        if self.test {
            f.write_str(", test")?;
        }
        if self.originator != 0 {
            write!(f, ", originator {}", self.originator)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Cot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cot({self})")
    }
}

/// The common address of ASDU (the station address), one or two octets by profile.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct CommonAddress(pub u16);

impl From<u16> for CommonAddress {
    fn from(v: u16) -> Self {
        Self(v)
    }
}

impl fmt::Display for CommonAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// An information object address, one to three octets by profile.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ioa(pub u32);

impl From<u32> for Ioa {
    fn from(v: u32) -> Self {
        Self(v)
    }
}

impl From<u16> for Ioa {
    fn from(v: u16) -> Self {
        Self(u32::from(v))
    }
}

impl fmt::Display for Ioa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl fmt::Debug for CommonAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CommonAddress({})", self.0)
    }
}

impl fmt::Debug for Ioa {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ioa({})", self.0)
    }
}

#[cfg(test)]
mod display_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use alloc::format;

    #[test]
    fn operator_cause_names_and_indicators() {
        for (cause, expected) in [
            (11, "return after a remote command"),
            (12, "return after a local command"),
            (15, "session key maintenance"),
            (16, "user role and update key maintenance"),
            (20, "interrogated by station"),
            (37, "requested by general counter interrogation"),
            (46, "unknown common address"),
        ] {
            assert_eq!(format!("{}", Cause::new(cause).unwrap()), format!("{expected} ({cause})"));
        }
        for group in 1..=16 {
            assert_eq!(format!("{}", Cause::interrogated_by_group(group).unwrap()), format!("interrogated by group {group} ({})", group + 20));
        }
        for group in 1..=4 {
            assert_eq!(format!("{}", Cause::requested_by_counter_group(group).unwrap()), format!("requested by counter group {group} ({})", group + 37));
        }
        let cot = Cot::INTERROGATED_BY_STATION.negative().test().with_originator(3);
        assert_eq!(format!("{cot}"), "interrogated by station (20), negative, test, originator 3");
        assert_eq!(Cot::from_octets(cot.octet(), cot.originator), cot);
    }
}
