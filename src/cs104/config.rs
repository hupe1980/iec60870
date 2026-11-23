//! The role of a link and its window and timer parameters.

use core::fmt;
use core::time::Duration;

/// Which end of the connection a link is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The controlling station (master, TCP client): starts and stops data transfer.
    Controlling,
    /// The controlled station (outstation, TCP server): answers STARTDT and STOPDT.
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

/// The window sizes and timers of a 104 connection.
///
/// The defaults are k = 12, w = 8, t0 = 30 s, t1 = 15 s, t2 = 10 s, t3 = 20 s. Change a field
/// with struct update syntax:
///
/// ```
/// use core::time::Duration;
/// use iec60870::cs104::Config;
///
/// let config = Config { k: 3, t3: Duration::from_secs(60), ..Config::default() };
/// assert!(config.validate().is_ok());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Config {
    /// The most I-frames sent and not yet acknowledged (1–32767).
    pub k: u16,
    /// Acknowledge at the latest after this many received I-frames (1–32767). Keeping it at
    /// most two thirds of the peer's `k` is the usual recommendation.
    pub w: u16,
    /// The TCP connection establishment timeout, used by the client adapters.
    pub t0: Duration,
    /// The acknowledgment timeout for a sent I-frame or STARTDT/STOPDT/TESTFR act; its
    /// expiry closes the connection.
    pub t1: Duration,
    /// The latest acknowledgment of received I-frames when there is nothing to send; less
    /// than `t1`.
    pub t2: Duration,
    /// The idle time without a received frame after which TESTFR act is sent.
    pub t3: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config { k: 12, w: 8, t0: Duration::from_secs(30), t1: Duration::from_secs(15), t2: Duration::from_secs(10), t3: Duration::from_secs(20) }
    }
}

const MAX_WINDOW: u16 = 32767;
const MAX_T012: Duration = Duration::from_secs(255);
const MAX_T3: Duration = Duration::from_secs(48 * 3600);

impl Config {
    /// Checks every parameter: k and w within 1–32767, no timer zero, t0–t2 at most 255 s,
    /// t3 at most 48 h, and t2 less than t1.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !(1..=MAX_WINDOW).contains(&self.k) {
            return Err(ConfigError::K(self.k));
        }
        if !(1..=MAX_WINDOW).contains(&self.w) {
            return Err(ConfigError::W(self.w));
        }
        for (timer, value, max) in
            [(Timer::T0, self.t0, MAX_T012), (Timer::T1, self.t1, MAX_T012), (Timer::T2, self.t2, MAX_T012), (Timer::T3, self.t3, MAX_T3)]
        {
            if value.is_zero() {
                return Err(ConfigError::ZeroTimer(timer));
            }
            if value > max {
                return Err(ConfigError::TimerTooLong(timer));
            }
        }
        if self.t2 >= self.t1 {
            return Err(ConfigError::T2NotBelowT1);
        }
        Ok(())
    }
}

/// One of the four timers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Timer {
    /// Connection establishment.
    T0,
    /// Acknowledgment of a sent frame.
    T1,
    /// Acknowledgment of received frames.
    T2,
    /// Idle test.
    T3,
}

impl fmt::Display for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Timer::T0 => "t0",
            Timer::T1 => "t1",
            Timer::T2 => "t2",
            Timer::T3 => "t3",
        })
    }
}

/// A [`Config`] value outside its range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// `k` outside 1–32767.
    K(u16),
    /// `w` outside 1–32767.
    W(u16),
    /// A timer of zero.
    ZeroTimer(Timer),
    /// t0, t1 or t2 above 255 s, or t3 above 48 h.
    TimerTooLong(Timer),
    /// t2 is not less than t1.
    T2NotBelowT1,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::K(k) => write!(f, "k = {k} outside 1..=32767"),
            ConfigError::W(w) => write!(f, "w = {w} outside 1..=32767"),
            ConfigError::ZeroTimer(t) => write!(f, "{t} is zero"),
            ConfigError::TimerTooLong(Timer::T3) => f.write_str("t3 above 48 h"),
            ConfigError::TimerTooLong(t) => write!(f, "{t} above 255 s"),
            ConfigError::T2NotBelowT1 => f.write_str("t2 must be less than t1"),
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
        assert_eq!((c.k, c.w), (12, 8));
        assert_eq!([c.t0, c.t1, c.t2, c.t3].map(|d| d.as_secs()), [30, 15, 10, 20]);
        assert_eq!(c.validate(), Ok(()));
    }

    #[test]
    fn every_bound_is_enforced() {
        let d = Config::default();
        assert_eq!(Config { k: 0, ..d }.validate(), Err(ConfigError::K(0)));
        assert_eq!(Config { k: 32768, ..d }.validate(), Err(ConfigError::K(32768)));
        assert_eq!(Config { w: 0, ..d }.validate(), Err(ConfigError::W(0)));
        assert_eq!(Config { k: 32767, w: 32767, ..d }.validate(), Ok(()));
        assert_eq!(Config { t0: Duration::ZERO, ..d }.validate(), Err(ConfigError::ZeroTimer(Timer::T0)));
        assert_eq!(Config { t3: Duration::ZERO, ..d }.validate(), Err(ConfigError::ZeroTimer(Timer::T3)));
        assert_eq!(Config { t1: Duration::from_secs(256), ..d }.validate(), Err(ConfigError::TimerTooLong(Timer::T1)));
        assert_eq!(Config { t3: Duration::from_secs(48 * 3600 + 1), ..d }.validate(), Err(ConfigError::TimerTooLong(Timer::T3)));
        assert_eq!(Config { t3: Duration::from_secs(48 * 3600), ..d }.validate(), Ok(()));
        assert_eq!(Config { t2: d.t1, ..d }.validate(), Err(ConfigError::T2NotBelowT1));
        assert_eq!(Config { t1: Duration::from_millis(30), t2: Duration::from_millis(10), ..d }.validate(), Ok(()));
    }
}
