//! Time: the three binary time formats of the wire, a civil date-time, the monotonic
//! [`Instant`] the protocol cores run their timers on, and the [`Clock`] that time tags come from.
//!
//! The wire formats keep their octets **exactly as received** — the invalid (IV) and
//! summer-time (SU) flags, the reserved bits, and field values outside the calendar (a minute
//! of 61) survive a decode and re-encode unchanged. Whether a CP56Time2a is UTC or local time
//! is an agreement between the systems, not a property of the octets, so nothing here converts
//! time zones; [`Cp56Time2a::to_date_time`] and [`Cp56Time2a::from_unix_millis`] are plain
//! calendar arithmetic.
//!
//! ```
//! use iec60870::time::{Cp56Time2a, DateTime};
//!
//! let t = Cp56Time2a::from_date_time(DateTime::new(2026, 11, 22, 14, 3, 7, 123)).unwrap();
//! assert_eq!(t.to_string(), "2026-11-22 14:03:07.123");
//! assert_eq!(t.minute(), 3);
//! assert!(!t.is_invalid());
//! ```

use core::fmt;
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::time::Duration;

const MS_PER_DAY: u64 = 86_400_000;

/// A civil date and time of day, with no time zone.
///
/// The fields are plain numbers; [`DateTime::is_valid`] says whether they name a real instant
/// of the proleptic Gregorian calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DateTime {
    /// The full year, e.g. 2026.
    pub year: u16,
    /// 1–12.
    pub month: u8,
    /// 1–31.
    pub day: u8,
    /// 0–23.
    pub hour: u8,
    /// 0–59.
    pub minute: u8,
    /// 0–59.
    pub second: u8,
    /// 0–999.
    pub millisecond: u16,
}

impl DateTime {
    /// A date and time from its fields (not checked; see [`is_valid`](Self::is_valid)).
    pub const fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8, millisecond: u16) -> Self {
        Self { year, month, day, hour, minute, second, millisecond }
    }

    /// Whether every field is within the calendar (the day within its month, leap years included).
    pub const fn is_valid(&self) -> bool {
        self.month >= 1
            && self.month <= 12
            && self.day >= 1
            && self.day <= days_in_month(self.year, self.month)
            && self.hour <= 23
            && self.minute <= 59
            && self.second <= 59
            && self.millisecond <= 999
    }

    /// The day of the week, 1 = Monday … 7 = Sunday, or `None` if the date is not valid.
    pub fn weekday(&self) -> Option<u8> {
        if !self.is_valid() {
            return None;
        }
        let days = days_from_civil(i64::from(self.year), u32::from(self.month), u32::from(self.day));
        // 1970-01-01 was a Thursday (4).
        Some(((days + 3).rem_euclid(7) + 1) as u8)
    }

    /// Milliseconds since 1970-01-01 00:00:00 of the same time scale, or `None` before 1970
    /// or if the fields are not valid.
    pub fn to_unix_millis(&self) -> Option<u64> {
        if !self.is_valid() {
            return None;
        }
        let days = days_from_civil(i64::from(self.year), u32::from(self.month), u32::from(self.day));
        let days = u64::try_from(days).ok()?;
        let in_day = ((u64::from(self.hour) * 60 + u64::from(self.minute)) * 60 + u64::from(self.second)) * 1000 + u64::from(self.millisecond);
        days.checked_mul(MS_PER_DAY)?.checked_add(in_day)
    }

    /// The date and time `millis` milliseconds after 1970-01-01 00:00:00, or `None` past year 65535.
    pub fn from_unix_millis(millis: u64) -> Option<Self> {
        let days = i64::try_from(millis / MS_PER_DAY).ok()?;
        let in_day = millis % MS_PER_DAY;
        let (year, month, day) = civil_from_days(days);
        Some(Self {
            year: u16::try_from(year).ok()?,
            month,
            day,
            hour: (in_day / 3_600_000) as u8,
            minute: (in_day / 60_000 % 60) as u8,
            second: (in_day / 1000 % 60) as u8,
            millisecond: (in_day % 1000) as u16,
        })
    }
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}", self.year, self.month, self.day, self.hour, self.minute, self.second, self.millisecond)
    }
}

const fn is_leap(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The proleptic Gregorian date `days` days after 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// CP56Time2a, the seven-octet binary time: milliseconds, minutes, hours, day of month and
/// week, month and a two-digit year, with the invalid (IV), substituted and summer-time (SU)
/// flags.
///
/// The octets are kept as received. The accessors mask each field out of its octet; whether
/// the fields form a real date is [`is_in_range`](Self::is_in_range), and the IV flag is
/// [`is_invalid`](Self::is_invalid). The two-digit year maps to 2000–2099.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Cp56Time2a([u8; 7]);

impl Cp56Time2a {
    /// Wire length in octets.
    pub const LEN: usize = 7;

    /// The time from its seven wire octets, as received.
    pub const fn from_octets(octets: [u8; 7]) -> Self {
        Self(octets)
    }

    /// The seven wire octets.
    pub const fn octets(&self) -> [u8; 7] {
        self.0
    }

    /// The time for a civil date and time of the years 2000–2099, with the day of week unset
    /// (0) and no flag set; `None` if `date` is not valid or outside those years.
    pub fn from_date_time(date: DateTime) -> Option<Self> {
        if !date.is_valid() || !(2000..=2099).contains(&date.year) {
            return None;
        }
        let ms = u16::from(date.second) * 1000 + date.millisecond;
        let [lo, hi] = ms.to_le_bytes();
        Some(Self([lo, hi, date.minute, date.hour, date.day, date.month, (date.year - 2000) as u8]))
    }

    /// The civil date and time the fields name, or `None` if they are not [in
    /// range](Self::is_in_range). The flags are not consulted.
    pub fn to_date_time(&self) -> Option<DateTime> {
        if !self.is_in_range() {
            return None;
        }
        let ms = self.milliseconds();
        Some(DateTime {
            year: 2000 + u16::from(self.year()),
            month: self.month(),
            day: self.day(),
            hour: self.hour(),
            minute: self.minute(),
            second: (ms / 1000) as u8,
            millisecond: ms % 1000,
        })
    }

    /// The time `millis` milliseconds after 1970-01-01 00:00:00 of the agreed time scale, or
    /// `None` outside 2000–2099.
    pub fn from_unix_millis(millis: u64) -> Option<Self> {
        Self::from_date_time(DateTime::from_unix_millis(millis)?)
    }

    /// Milliseconds since 1970-01-01 00:00:00 of the agreed time scale, or `None` if the fields
    /// are not in range.
    pub fn to_unix_millis(&self) -> Option<u64> {
        self.to_date_time()?.to_unix_millis()
    }

    /// A usable station clock reading in milliseconds. Unlike raw calendar conversion,
    /// clock synchronisation must also respect the invalid-time flag.
    pub(crate) fn clock_millis(self) -> Option<i64> {
        if self.is_invalid() {
            return None;
        }
        i64::try_from(self.to_unix_millis()?).ok()
    }

    /// Milliseconds within the minute, nominally 0–59999 (octets 1–2).
    pub const fn milliseconds(&self) -> u16 {
        let [lo, hi, ..] = self.0;
        u16::from_le_bytes([lo, hi])
    }

    /// Minutes, nominally 0–59.
    pub const fn minute(&self) -> u8 {
        self.0[2] & 0x3F
    }

    /// Hours, nominally 0–23.
    pub const fn hour(&self) -> u8 {
        self.0[3] & 0x1F
    }

    /// Day of the month, nominally 1–31.
    pub const fn day(&self) -> u8 {
        self.0[4] & 0x1F
    }

    /// Day of the week, 1 = Monday … 7 = Sunday; 0 when not used.
    pub const fn weekday(&self) -> u8 {
        self.0[4] >> 5
    }

    /// Month, nominally 1–12.
    pub const fn month(&self) -> u8 {
        self.0[5] & 0x0F
    }

    /// Two-digit year, nominally 0–99 (2000–2099).
    pub const fn year(&self) -> u8 {
        self.0[6] & 0x7F
    }

    /// The IV flag: the time is marked invalid by its source.
    pub const fn is_invalid(&self) -> bool {
        self.0[2] & 0x80 != 0
    }

    /// The substituted flag (bit 7 of the minute octet).
    pub const fn is_substituted(&self) -> bool {
        self.0[2] & 0x40 != 0
    }

    /// The SU flag: summer time.
    pub const fn is_summer_time(&self) -> bool {
        self.0[3] & 0x80 != 0
    }

    /// Whether every field is within the calendar: milliseconds ≤ 59999, minute ≤ 59, hour ≤ 23,
    /// year 0–99, month 1–12 and the day within its month. Flags and reserved bits are
    /// not consulted.
    pub const fn is_in_range(&self) -> bool {
        let month = self.month();
        let day = self.day();
        self.year() <= 99
            && self.milliseconds() <= 59_999
            && self.minute() <= 59
            && self.hour() <= 23
            && month >= 1
            && month <= 12
            && day >= 1
            && day <= days_in_month(2000 + self.year() as u16, month)
    }

    /// The same time with the IV flag set or cleared.
    #[must_use]
    pub const fn with_invalid(self, invalid: bool) -> Self {
        self.with_bit(2, 0x80, invalid)
    }

    /// The same time with the substituted flag set or cleared.
    #[must_use]
    pub const fn with_substituted(self, substituted: bool) -> Self {
        self.with_bit(2, 0x40, substituted)
    }

    /// The same time with the SU flag set or cleared.
    #[must_use]
    pub const fn with_summer_time(self, summer: bool) -> Self {
        self.with_bit(3, 0x80, summer)
    }

    /// The same time with the day of the week set (only the low three bits are used).
    #[must_use]
    pub const fn with_weekday(self, weekday: u8) -> Self {
        let mut o = self.0;
        o[4] = (o[4] & 0x1F) | ((weekday & 0x07) << 5);
        Self(o)
    }

    const fn with_bit(self, octet: usize, mask: u8, on: bool) -> Self {
        let mut o = self.0;
        // `octet` is a literal 2 or 3 at every call site; the arms keep the function total.
        match octet {
            2 => o[2] = if on { o[2] | mask } else { o[2] & !mask },
            _ => o[3] = if on { o[3] | mask } else { o[3] & !mask },
        }
        Self(o)
    }
}

fn write_flags(f: &mut fmt::Formatter<'_>, flags: &[(bool, &str)], in_range: bool) -> fmt::Result {
    for (on, name) in flags {
        if *on {
            write!(f, " {name}")?;
        }
    }
    if !in_range {
        f.write_str(" (out of range)")?;
    }
    Ok(())
}

impl fmt::Display for Cp56Time2a {
    /// `2026-11-22 14:03:07.123`, followed by `IV`, `SB`, `SU` when set and `(out of range)`
    /// when a field is outside the calendar (the raw field values are printed either way).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = self.milliseconds();
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
            2000 + u16::from(self.year()),
            self.month(),
            self.day(),
            self.hour(),
            self.minute(),
            ms / 1000,
            ms % 1000
        )?;
        write_flags(f, &[(self.is_invalid(), "IV"), (self.is_substituted(), "SB"), (self.is_summer_time(), "SU")], self.is_in_range())
    }
}

impl fmt::Debug for Cp56Time2a {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cp56Time2a({self})")
    }
}

/// CP24Time2a, the three-octet binary time: milliseconds and minutes within the hour, with the
/// invalid (IV) and substituted flags — the first three octets of a [`Cp56Time2a`]. Kept as
/// received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Cp24Time2a([u8; 3]);

impl Cp24Time2a {
    /// Wire length in octets.
    pub const LEN: usize = 3;

    /// The time from its three wire octets, as received.
    pub const fn from_octets(octets: [u8; 3]) -> Self {
        Self(octets)
    }

    /// The three wire octets.
    pub const fn octets(&self) -> [u8; 3] {
        self.0
    }

    /// The time `minute` minutes and `milliseconds` milliseconds into the hour; `None` if
    /// `minute > 59` or `milliseconds > 59999`.
    pub const fn new(minute: u8, milliseconds: u16) -> Option<Self> {
        if minute > 59 || milliseconds > 59_999 {
            return None;
        }
        let [lo, hi] = milliseconds.to_le_bytes();
        Some(Self([lo, hi, minute]))
    }

    /// Milliseconds within the minute, nominally 0–59999.
    pub const fn milliseconds(&self) -> u16 {
        let [lo, hi, _] = self.0;
        u16::from_le_bytes([lo, hi])
    }

    /// Minutes, nominally 0–59.
    pub const fn minute(&self) -> u8 {
        self.0[2] & 0x3F
    }

    /// The IV flag.
    pub const fn is_invalid(&self) -> bool {
        self.0[2] & 0x80 != 0
    }

    /// The substituted flag.
    pub const fn is_substituted(&self) -> bool {
        self.0[2] & 0x40 != 0
    }

    /// Whether milliseconds ≤ 59999 and minute ≤ 59.
    pub const fn is_in_range(&self) -> bool {
        self.milliseconds() <= 59_999 && self.minute() <= 59
    }

    /// The same time with the IV flag set or cleared.
    #[must_use]
    pub const fn with_invalid(self, invalid: bool) -> Self {
        let [a, b, c] = self.0;
        Self([a, b, if invalid { c | 0x80 } else { c & 0x7F }])
    }
}

impl From<Cp56Time2a> for Cp24Time2a {
    /// The minute and millisecond octets (with IV and the substituted flag) of a CP56Time2a.
    fn from(t: Cp56Time2a) -> Self {
        let [a, b, c, ..] = t.0;
        Self([a, b, c])
    }
}

impl fmt::Display for Cp24Time2a {
    /// `mm:ss.mmm` within the hour, followed by `IV`/`SB` and `(out of range)` as applicable.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ms = self.milliseconds();
        write!(f, "{:02}:{:02}.{:03}", self.minute(), ms / 1000, ms % 1000)?;
        write_flags(f, &[(self.is_invalid(), "IV"), (self.is_substituted(), "SB")], self.is_in_range())
    }
}

impl fmt::Debug for Cp24Time2a {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cp24Time2a({self})")
    }
}

/// CP16Time2a, the two-octet binary time: milliseconds, nominally 0–59999. Used for elapsed
/// times of protection equipment and for the delay acquisition command. Kept as received.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Cp16Time2a(pub u16);

impl Cp16Time2a {
    /// Wire length in octets.
    pub const LEN: usize = 2;

    /// The time of `milliseconds` milliseconds.
    pub const fn from_millis(milliseconds: u16) -> Self {
        Self(milliseconds)
    }

    /// The milliseconds, as received.
    pub const fn milliseconds(&self) -> u16 {
        self.0
    }

    /// Whether the value is ≤ 59999.
    pub const fn is_in_range(&self) -> bool {
        self.0 <= 59_999
    }

    /// The value as a [`Duration`].
    pub const fn to_duration(&self) -> Duration {
        Duration::from_millis(self.0 as u64)
    }
}

impl fmt::Display for Cp16Time2a {
    /// `12.345 s`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:03} s", self.0 / 1000, self.0 % 1000)
    }
}

impl fmt::Debug for Cp16Time2a {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cp16Time2a({self})")
    }
}

/// A point on a monotonic time line: nanoseconds since an arbitrary epoch chosen by whoever
/// feeds the protocol cores.
///
/// The cores never read a clock; the caller passes `now` in. Arithmetic saturates — an
/// `Instant` never wraps, so a timer that would expire past the end of time simply never does.
///
/// ```
/// use core::time::Duration;
/// use iec60870::time::Instant;
///
/// let t0 = Instant::from_millis(1_000);
/// let deadline = t0 + Duration::from_secs(15);
/// assert_eq!(deadline - t0, Duration::from_secs(15));
/// assert_eq!(t0 - deadline, Duration::ZERO); // saturates
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Instant(u64);

impl Instant {
    /// The epoch.
    pub const ZERO: Instant = Instant(0);
    /// The last representable instant.
    pub const MAX: Instant = Instant(u64::MAX);

    /// The instant `nanos` nanoseconds after the epoch.
    pub const fn from_nanos(nanos: u64) -> Self {
        Self(nanos)
    }

    /// The instant `millis` milliseconds after the epoch (saturating).
    pub const fn from_millis(millis: u64) -> Self {
        Self(millis.saturating_mul(1_000_000))
    }

    /// Nanoseconds since the epoch.
    pub const fn as_nanos(&self) -> u64 {
        self.0
    }

    /// The time since the epoch.
    pub const fn since_epoch(&self) -> Duration {
        Duration::from_nanos(self.0)
    }

    /// The time from `earlier` to `self`, or `None` if `earlier` is later.
    pub const fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        match self.0.checked_sub(earlier.0) {
            Some(n) => Some(Duration::from_nanos(n)),
            None => None,
        }
    }

    /// The time from `earlier` to `self`, or zero if `earlier` is later.
    pub const fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }

    /// `self + d`, or `None` past [`Instant::MAX`].
    pub fn checked_add(&self, d: Duration) -> Option<Instant> {
        let n = u64::try_from(d.as_nanos()).ok()?;
        self.0.checked_add(n).map(Instant)
    }

    /// `self - d`, or `None` before the epoch.
    pub fn checked_sub(&self, d: Duration) -> Option<Instant> {
        let n = u64::try_from(d.as_nanos()).ok()?;
        self.0.checked_sub(n).map(Instant)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;
    /// Saturates at [`Instant::MAX`].
    fn add(self, d: Duration) -> Instant {
        self.checked_add(d).unwrap_or(Instant::MAX)
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, d: Duration) {
        *self = *self + d;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;
    /// Saturates at [`Instant::ZERO`].
    fn sub(self, d: Duration) -> Instant {
        self.checked_sub(d).unwrap_or(Instant::ZERO)
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, d: Duration) {
        *self = *self - d;
    }
}

impl Sub for Instant {
    type Output = Duration;
    /// Saturates at zero when `rhs` is later.
    fn sub(self, rhs: Instant) -> Duration {
        self.saturating_duration_since(rhs)
    }
}

impl fmt::Debug for Instant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Instant({:?})", self.since_epoch())
    }
}

/// The source of every time tag the crate produces.
///
/// Time tags never come from the monotonic [`Instant`] the timers run on. Implement this for
/// the system's agreed time scale (UTC, or local time if the installation says so); a closure
/// returning a [`Cp56Time2a`] is a `Clock` too, which keeps tests deterministic.
///
/// ```
/// use iec60870::time::{Clock, Cp56Time2a};
///
/// let fixed = || Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
/// assert_eq!(fixed.now().year(), 26);
/// ```
pub trait Clock {
    /// The current time.
    fn now(&self) -> Cp56Time2a;
}

impl<F: Fn() -> Cp56Time2a> Clock for F {
    fn now(&self) -> Cp56Time2a {
        self()
    }
}

/// The operating system's clock, read as UTC.
///
/// A time the format cannot carry (before 2000 or after 2099) is returned with the IV flag set.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> Cp56Time2a {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .and_then(Cp56Time2a::from_unix_millis)
            .unwrap_or_else(|| Cp56Time2a::default().with_invalid(true))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn civil_round_trip_over_the_whole_format_range() {
        // Every day from 2000-01-01 to 2099-12-31 survives date → millis → date.
        let start = DateTime::new(2000, 1, 1, 0, 0, 0, 0).to_unix_millis().unwrap();
        let end = DateTime::new(2099, 12, 31, 23, 59, 59, 999).to_unix_millis().unwrap();
        let mut ms = start;
        while ms <= end {
            let t = Cp56Time2a::from_unix_millis(ms).unwrap();
            assert!(t.is_in_range());
            assert_eq!(t.to_unix_millis(), Some(ms));
            ms += MS_PER_DAY + 3_723_004; // walk days and times of day
        }
        assert_eq!(start, 946_684_800_000);
        assert!(Cp56Time2a::from_unix_millis(start - 1).is_none());
        assert!(Cp56Time2a::from_unix_millis(end + 1).is_none());
    }

    #[test]
    fn weekday_and_leap_years() {
        assert_eq!(DateTime::new(2026, 11, 22, 0, 0, 0, 0).weekday(), Some(7)); // a Sunday
        assert_eq!(DateTime::new(2000, 1, 1, 0, 0, 0, 0).weekday(), Some(6)); // a Saturday
        assert!(DateTime::new(2000, 2, 29, 0, 0, 0, 0).is_valid());
        assert!(!DateTime::new(2100, 2, 29, 0, 0, 0, 0).is_valid());
        assert!(!DateTime::new(2026, 2, 29, 0, 0, 0, 0).is_valid());
        assert_eq!(DateTime::from_unix_millis(0), Some(DateTime::new(1970, 1, 1, 0, 0, 0, 0)));
    }

    #[test]
    fn cp56_keeps_out_of_range_fields_and_flags() {
        // minute 61 with IV and the substituted flag; hour with SU; weekday 5.
        let o = [0x10, 0x27, 0x80 | 0x40 | 0x3D, 0x80 | 0x0C, (5 << 5) | 0x16, 0xF0 | 0x0B, 0x80 | 0x1A];
        let t = Cp56Time2a::from_octets(o);
        assert_eq!(t.octets(), o);
        assert_eq!((t.minute(), t.hour(), t.day(), t.weekday(), t.month(), t.year()), (61, 12, 22, 5, 11, 26));
        assert!(t.is_invalid() && t.is_substituted() && t.is_summer_time());
        assert!(!t.is_in_range());
        assert_eq!(t.to_date_time(), None);
        assert_eq!(t.to_string(), "2026-11-22 12:61:10.000 IV SB SU (out of range)");
        assert_eq!(alloc::format!("{t:?}"), "Cp56Time2a(2026-11-22 12:61:10.000 IV SB SU (out of range))");
    }

    #[test]
    fn cp56_builders_touch_only_their_bit() {
        let t = Cp56Time2a::from_date_time(DateTime::new(2026, 1, 2, 3, 4, 5, 6)).unwrap();
        let u = t.with_invalid(true).with_summer_time(true).with_weekday(5).with_substituted(true);
        assert_eq!(u.with_invalid(false).with_summer_time(false).with_weekday(0).with_substituted(false), t);
        assert_eq!(u.weekday(), 5);
        assert_eq!(t.octets(), [0x8E, 0x13, 4, 3, 2, 1, 26]);
    }

    #[test]
    fn cp24_and_cp16() {
        let t = Cp24Time2a::new(59, 59_999).unwrap();
        assert_eq!(t.octets(), [0x5F, 0xEA, 59]);
        assert!(Cp24Time2a::new(60, 0).is_none());
        assert_eq!(t.with_invalid(true).to_string(), "59:59.999 IV");
        assert_eq!(Cp24Time2a::from_octets([0xFF, 0xFF, 0xFF]).to_string(), "63:65.535 IV SB (out of range)");
        assert_eq!(Cp16Time2a(1234).to_string(), "1.234 s");
        assert_eq!(Cp16Time2a(1234).to_duration(), Duration::from_millis(1234));
    }

    #[test]
    fn instant_saturates() {
        let t = Instant::from_nanos(10);
        assert_eq!(t + Duration::from_nanos(5), Instant::from_nanos(15));
        assert_eq!(t - Duration::from_nanos(50), Instant::ZERO);
        assert_eq!(Instant::MAX + Duration::from_secs(1), Instant::MAX);
        assert_eq!(t + Duration::MAX, Instant::MAX);
        assert_eq!(Instant::ZERO - t, Duration::ZERO);
        assert_eq!(t.checked_duration_since(Instant::from_nanos(11)), None);
        assert_eq!(Instant::from_millis(u64::MAX), Instant::MAX);
        let mut u = t;
        u += Duration::from_nanos(1);
        u -= Duration::from_nanos(2);
        assert_eq!(u.as_nanos(), 9);
        assert_eq!(alloc::format!("{:?}", Instant::from_millis(1500)), "Instant(1.5s)");
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_clock_is_utc_now() {
        let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let t = SystemClock.now();
        let after = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let ms = t.to_unix_millis().unwrap();
        assert!(before <= ms && ms <= after);
        assert!(!t.is_invalid());
    }
}
