//! The mode of a 101 link and its timing and queue parameters.

use core::fmt;
use core::time::Duration;

use super::frame::{AddressWidth, DEFAULT_CHAR_TIMEOUT, DEFAULT_IDLE_GAP, LinkAddress};

/// Which end of a balanced link this is; it decides the DIR bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The controlling station (master): sends DIR = 1.
    Controlling,
    /// The controlled station (outstation): sends DIR = 0.
    Controlled,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Role::Controlling => "controlling",
            Role::Controlled => "controlled",
        })
    }
}

/// The transmission procedure of a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// Balanced: point-to-point, both ends primary and secondary.
    Balanced(Role),
    /// Unbalanced primary: the controlling station, polling its secondaries.
    Primary,
    /// Unbalanced secondary: the controlled station, answering its primary.
    Secondary,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Balanced(role) => write!(f, "balanced ({role})"),
            Mode::Primary => f.write_str("unbalanced primary"),
            Mode::Secondary => f.write_str("unbalanced secondary"),
        }
    }
}

/// The class of user data: class 1 is polled first and announced by ACD.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Class 1: responses, spontaneous events — anything urgent.
    One,
    /// Class 2: cyclic and background data.
    Two,
}

impl Class {
    pub(crate) const fn index(self) -> usize {
        match self {
            Class::One => 0,
            Class::Two => 1,
        }
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Class::One => "class 1",
            Class::Two => "class 2",
        })
    }
}

/// The parameters of a 101 link.
///
/// Change a field with struct update syntax:
///
/// ```
/// use core::time::Duration;
/// use iec60870::cs101::{AddressWidth, Config};
///
/// let config = Config { address_width: AddressWidth::Two, response_timeout: Duration::from_secs(2), ..Config::default() };
/// assert!(config.validate().is_ok());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Config {
    /// The width of the link address field. Default: one octet.
    pub address_width: AddressWidth,
    /// How long a primary waits for the answer to a frame before repeating it. It must cover
    /// the transmission of the longest request and the longest answer at the line's bit rate
    /// (about 290 ms for a full frame at 9600 bit/s) plus the peer's turnaround. Default 500 ms.
    pub response_timeout: Duration,
    /// How often a frame is repeated after the first transmission before the primary gives up.
    /// Default 3.
    pub retries: u8,
    /// The least time between two class 2 polls of a secondary that had no data. Default 100 ms.
    pub poll_interval: Duration,
    /// How long a primary waits before it tries to reset a link that failed. Default 5 s.
    pub reset_interval: Duration,
    /// Balanced mode: the test function is sent after this long without an exchange. Default 5 s.
    pub test_interval: Duration,
    /// A partial frame whose next octet comes later than this is thrown away. Default 300 ms.
    pub char_timeout: Duration,
    /// After a framing error, octets are discarded until the line has been idle this long.
    /// Must be less than `char_timeout`. Default 10 ms.
    pub idle_gap: Duration,
    /// Answer with the single character `0xE5` instead of a fixed ACK or "no data" frame where
    /// no ACD or DFC needs to be signalled. Received `0xE5` is accepted either way. Default on.
    pub single_char_ack: bool,
    /// The most ASDUs queued per station and class. Default 64.
    pub queue_len: u16,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            address_width: AddressWidth::One,
            response_timeout: Duration::from_millis(500),
            retries: 3,
            poll_interval: Duration::from_millis(100),
            reset_interval: Duration::from_secs(5),
            test_interval: Duration::from_secs(5),
            char_timeout: DEFAULT_CHAR_TIMEOUT,
            idle_gap: DEFAULT_IDLE_GAP,
            single_char_ack: true,
            queue_len: 64,
        }
    }
}

impl Config {
    /// Checks every parameter: no timer zero, `queue_len` at least 1, `idle_gap` less than
    /// `char_timeout`.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (name, value) in [
            ("response_timeout", self.response_timeout),
            ("poll_interval", self.poll_interval),
            ("reset_interval", self.reset_interval),
            ("test_interval", self.test_interval),
            ("char_timeout", self.char_timeout),
            ("idle_gap", self.idle_gap),
        ] {
            if value.is_zero() {
                return Err(ConfigError::Zero(name));
            }
        }
        if self.queue_len == 0 {
            return Err(ConfigError::Zero("queue_len"));
        }
        if self.idle_gap >= self.char_timeout {
            return Err(ConfigError::IdleGapNotBelowCharTimeout);
        }
        Ok(())
    }

    /// Checks a station address against the address width.
    pub(crate) fn check_address(&self, address: LinkAddress) -> Result<(), ConfigError> {
        if address.0 > self.address_width.max() {
            return Err(ConfigError::AddressOutOfRange(address));
        }
        if self.address_width.broadcast() == Some(address) {
            return Err(ConfigError::BroadcastAddress(address));
        }
        Ok(())
    }
}

/// A [`Config`] value, or a station address, that is out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// The named parameter is zero.
    Zero(&'static str),
    /// `idle_gap` is not less than `char_timeout`.
    IdleGapNotBelowCharTimeout,
    /// An address the address field cannot hold.
    AddressOutOfRange(LinkAddress),
    /// The broadcast address used as a station address.
    BroadcastAddress(LinkAddress),
    /// A primary without secondaries.
    NoSecondaries,
    /// A secondary named twice.
    DuplicateSecondary(LinkAddress),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Zero(name) => write!(f, "{name} is zero"),
            ConfigError::IdleGapNotBelowCharTimeout => f.write_str("idle_gap must be less than char_timeout"),
            ConfigError::AddressOutOfRange(a) => write!(f, "{a} does not fit the address field"),
            ConfigError::BroadcastAddress(a) => write!(f, "{a} is the broadcast address"),
            ConfigError::NoSecondaries => f.write_str("a primary needs at least one secondary"),
            ConfigError::DuplicateSecondary(a) => write!(f, "{a} is named twice"),
        }
    }
}

impl core::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_documented_ones() {
        let c = Config::default();
        assert_eq!(c.address_width, AddressWidth::One);
        assert_eq!(
            [c.response_timeout, c.poll_interval, c.reset_interval, c.test_interval, c.char_timeout, c.idle_gap].map(|d| d.as_millis()),
            [500, 100, 5000, 5000, 300, 10]
        );
        assert_eq!((c.retries, c.single_char_ack, c.queue_len), (3, true, 64));
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn every_bound_is_enforced() {
        let d = Config::default();
        assert_eq!(Config { response_timeout: Duration::ZERO, ..d }.validate(), Err(ConfigError::Zero("response_timeout")));
        assert_eq!(Config { idle_gap: Duration::ZERO, ..d }.validate(), Err(ConfigError::Zero("idle_gap")));
        assert_eq!(Config { queue_len: 0, ..d }.validate(), Err(ConfigError::Zero("queue_len")));
        assert_eq!(Config { idle_gap: d.char_timeout, ..d }.validate(), Err(ConfigError::IdleGapNotBelowCharTimeout));
        assert_eq!(Config { retries: 0, ..d }.validate(), Ok(()));
        assert_eq!(d.check_address(LinkAddress(255)), Err(ConfigError::BroadcastAddress(LinkAddress(255))));
        assert_eq!(d.check_address(LinkAddress(256)), Err(ConfigError::AddressOutOfRange(LinkAddress(256))));
        let zero = Config { address_width: AddressWidth::Zero, ..d };
        assert_eq!(zero.check_address(LinkAddress(0)), Ok(()));
        assert_eq!(zero.check_address(LinkAddress(1)), Err(ConfigError::AddressOutOfRange(LinkAddress(1))));
    }
}
