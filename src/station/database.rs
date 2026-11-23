//! The controlled station's point database.

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};
use core::fmt;

use super::command::{CommandKind, CommandMode, Parameter};
use super::value::{TimeFormat, Value, ValueKind};
use crate::time::Cp56Time2a;
use crate::types::{BinaryCounterReading, CommonAddress, Ioa};

/// One monitored point: its state and how it is transmitted.
#[derive(Clone, Debug, PartialEq)]
pub struct PointEntry {
    pub(crate) value: Value,
    pub(crate) time: Option<Cp56Time2a>,
    pub(crate) format: TimeFormat,
    pub(crate) spontaneous: bool,
    pub(crate) interrogation: bool,
    pub(crate) group: Option<u8>,
    pub(crate) cyclic: bool,
    pub(crate) background: bool,
    pub(crate) counter_group: Option<u8>,
    pub(crate) frozen: Option<BinaryCounterReading>,
    pub(crate) parameters: [Option<Parameter>; 4],
}

impl PointEntry {
    /// A point with the same transmission defaults as [`Database::insert`].
    pub fn new(value: impl Into<Value>) -> Self {
        let value = value.into();
        let counter = value.kind() == ValueKind::Counter;
        let protection = !super::value::has_untimed_type(value.kind());
        Self {
            value,
            time: None,
            format: TimeFormat::Cp56,
            spontaneous: !counter,
            interrogation: !counter && !protection,
            group: None,
            cyclic: false,
            background: false,
            counter_group: None,
            frozen: None,
            parameters: [None; 4],
        }
    }

    /// Configure the point before it is served.
    pub fn options(&mut self) -> PointOptions<'_> {
        PointOptions(self)
    }

    /// The current monitored value and its quality.
    pub fn value(&self) -> Value {
        self.value
    }

    /// The timestamp of its most recent update, if known.
    pub fn time(&self) -> Option<Cp56Time2a> {
        self.time
    }
}

/// Local process image used by a controlled station.
///
/// Keep addresses and value kinds stable while serving. Enumerate each common
/// address once (including command-only stations), and points in increasing IOA
/// order. Lookups and iterators refer to the same entries. Methods run on the
/// station thread: refresh slow or fallible upstream data outside these calls,
/// then submit updates through the station to retain timestamps and event delivery.
pub trait PointSource: Send {
    /// Station addresses in increasing order.
    fn addresses(&self) -> Vec<CommonAddress>;
    /// Monitored points at one station, in increasing IOA order.
    fn points(&self, ca: CommonAddress) -> Box<dyn Iterator<Item = (Ioa, &PointEntry)> + '_>;
    /// Mutable access in the same order, including counter freeze/reset state.
    fn points_mut(&mut self, ca: CommonAddress) -> Box<dyn Iterator<Item = (Ioa, &mut PointEntry)> + '_>;
    /// Look up a monitored point.
    fn point(&self, ca: CommonAddress, ioa: Ioa) -> Option<&PointEntry>;
    /// Look up a monitored point for an update.
    fn point_mut(&mut self, ca: CommonAddress, ioa: Ioa) -> Option<&mut PointEntry>;
    /// Declared command kind and mode. A monitoring-only source has none.
    fn command_at(&self, _ca: CommonAddress, _ioa: Ioa) -> Option<(CommandKind, CommandMode)> {
        None
    }
    /// Whether a station address is served.
    fn has_common_address(&self, ca: CommonAddress) -> bool {
        self.addresses().contains(&ca)
    }
    /// Current value of one point.
    fn value(&self, ca: CommonAddress, ioa: Ioa) -> Option<Value> {
        self.point(ca, ioa).map(PointEntry::value)
    }
    /// Stable address and kind catalog for validating adapter updates.
    fn kinds(&self) -> BTreeMap<(CommonAddress, Ioa), ValueKind> {
        self.addresses().into_iter().flat_map(|ca| self.points(ca).map(move |(ioa, p)| ((ca, ioa), p.value.kind()))).collect()
    }
}

/// One command point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CommandEntry {
    pub kind: CommandKind,
    pub mode: CommandMode,
}

/// The points of a controlled station, keyed by common address and information object address.
///
/// A monitored point is inserted with its initial value — its kind is the value's kind — and
/// sensible defaults: spontaneous events with a CP56Time2a time tag, answered in station
/// interrogation. Integrated totals are answered in counter interrogation instead and are not
/// spontaneous. Each default is one call away:
///
/// ```
/// use iec60870::prelude::*;
/// use iec60870::station::{CommandKind, CommandMode, Database, TimeFormat};
///
/// let ca = CommonAddress(1);
/// let mut db = Database::new();
/// db.insert(ca, Ioa(100), false);                                  // single point
/// db.insert(ca, Ioa(200), 21.5f32).group(1);                       // float, also in group 1
/// db.insert(ca, Ioa(201), 0i16).time_format(TimeFormat::None);     // scaled, events without time
/// db.insert(ca, Ioa(300), BinaryCounterReading::new(0)).counter_group(1);
/// db.command(ca, Ioa(5000), CommandKind::Single);                  // select-before-operate
/// db.command(ca, Ioa(5001), CommandKind::Float).mode(CommandMode::Direct);
/// assert_eq!(db.len(), 4);
/// assert_eq!(db.value(ca, Ioa(200)), Some(21.5f32.into()));
/// ```
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Database {
    pub(crate) points: BTreeMap<(CommonAddress, Ioa), PointEntry>,
    pub(crate) commands: BTreeMap<(CommonAddress, Ioa), CommandEntry>,
}

impl Database {
    /// An empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts (or replaces) a monitored point with its initial value and returns its options.
    pub fn insert(&mut self, common_address: CommonAddress, ioa: Ioa, value: impl Into<Value>) -> PointOptions<'_> {
        let entry = PointEntry::new(value);
        let slot = self.points.entry((common_address, ioa)).or_insert_with(|| entry.clone());
        *slot = entry;
        PointOptions(slot)
    }

    /// Declares (or replaces) a command point of `kind`, select-before-operate by default, and
    /// returns its options.
    pub fn command(&mut self, common_address: CommonAddress, ioa: Ioa, kind: CommandKind) -> CommandOptions<'_> {
        let mode = if kind == CommandKind::Bitstring { CommandMode::Direct } else { CommandMode::SelectBeforeOperate };
        let slot = self.commands.entry((common_address, ioa)).or_insert(CommandEntry { kind, mode });
        *slot = CommandEntry { kind, mode };
        CommandOptions(slot)
    }

    /// The current value of a monitored point.
    pub fn value(&self, common_address: CommonAddress, ioa: Ioa) -> Option<Value> {
        self.points.get(&(common_address, ioa)).map(|p| p.value)
    }

    /// The time of the last update of a monitored point (from the station's clock).
    pub fn time(&self, common_address: CommonAddress, ioa: Ioa) -> Option<Cp56Time2a> {
        self.points.get(&(common_address, ioa)).and_then(|p| p.time)
    }

    /// The common addresses with at least one point, in order.
    pub fn common_addresses(&self) -> impl Iterator<Item = CommonAddress> + '_ {
        self.points.keys().chain(self.commands.keys()).map(|(ca, _)| *ca).collect::<alloc::collections::BTreeSet<_>>().into_iter()
    }

    /// Whether `common_address` has any point.
    pub fn has_common_address(&self, common_address: CommonAddress) -> bool {
        let range = (common_address, Ioa(0))..=(common_address, Ioa(u32::MAX));
        self.points.range(range.clone()).next().is_some() || self.commands.range(range).next().is_some()
    }

    /// The number of monitored points.
    pub fn len(&self) -> usize {
        self.points.len()
    }

    /// Whether there is no monitored point.
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    /// The kind of every monitored point (a database's points are fixed once it is served).
    pub fn kinds(&self) -> BTreeMap<(CommonAddress, Ioa), ValueKind> {
        self.points.iter().map(|(k, p)| (*k, p.value.kind())).collect()
    }

    /// The number of command points.
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }
}

/// A map of monitored points can serve a read-only gateway directly.
impl PointSource for BTreeMap<(CommonAddress, Ioa), PointEntry> {
    fn addresses(&self) -> Vec<CommonAddress> {
        let mut addresses = Vec::new();
        for &(ca, _) in self.keys() {
            if addresses.last() != Some(&ca) {
                addresses.push(ca);
            }
        }
        addresses
    }

    fn has_common_address(&self, ca: CommonAddress) -> bool {
        self.range((ca, Ioa(0))..=(ca, Ioa(u32::MAX))).next().is_some()
    }

    fn points(&self, ca: CommonAddress) -> Box<dyn Iterator<Item = (Ioa, &PointEntry)> + '_> {
        Box::new(self.range((ca, Ioa(0))..=(ca, Ioa(u32::MAX))).map(|((_, ioa), p)| (*ioa, p)))
    }
    fn points_mut(&mut self, ca: CommonAddress) -> Box<dyn Iterator<Item = (Ioa, &mut PointEntry)> + '_> {
        Box::new(self.range_mut((ca, Ioa(0))..=(ca, Ioa(u32::MAX))).map(|((_, ioa), p)| (*ioa, p)))
    }
    fn point(&self, ca: CommonAddress, ioa: Ioa) -> Option<&PointEntry> {
        self.get(&(ca, ioa))
    }
    fn point_mut(&mut self, ca: CommonAddress, ioa: Ioa) -> Option<&mut PointEntry> {
        self.get_mut(&(ca, ioa))
    }
}

impl PointSource for Database {
    fn addresses(&self) -> Vec<CommonAddress> {
        self.common_addresses().collect()
    }
    fn points(&self, ca: CommonAddress) -> Box<dyn Iterator<Item = (Ioa, &PointEntry)> + '_> {
        self.points.points(ca)
    }
    fn points_mut(&mut self, ca: CommonAddress) -> Box<dyn Iterator<Item = (Ioa, &mut PointEntry)> + '_> {
        self.points.points_mut(ca)
    }
    fn point(&self, ca: CommonAddress, ioa: Ioa) -> Option<&PointEntry> {
        self.points.get(&(ca, ioa))
    }
    fn point_mut(&mut self, ca: CommonAddress, ioa: Ioa) -> Option<&mut PointEntry> {
        self.points.get_mut(&(ca, ioa))
    }
    fn command_at(&self, ca: CommonAddress, ioa: Ioa) -> Option<(CommandKind, CommandMode)> {
        self.commands.get(&(ca, ioa)).map(|e| (e.kind, e.mode))
    }
    fn has_common_address(&self, ca: CommonAddress) -> bool {
        Database::has_common_address(self, ca)
    }
    fn kinds(&self) -> BTreeMap<(CommonAddress, Ioa), ValueKind> {
        Database::kinds(self)
    }
}

/// The transmission options of a point just inserted into a [`Database`].
///
/// ```
/// use iec60870::prelude::*;
///
/// let mut db = Database::new();
/// db.insert(CommonAddress(1), Ioa(7), 0.0f32).group(3).cyclic(true).spontaneous(false);
/// ```
#[derive(Debug)]
pub struct PointOptions<'a>(&'a mut PointEntry);

impl PointOptions<'_> {
    /// The time tag of its spontaneous events (default CP56Time2a).
    #[must_use]
    pub fn time_format(self, format: TimeFormat) -> Self {
        self.0.format = format;
        self
    }

    /// Whether an update produces a spontaneous event (default on, off for counters).
    #[must_use]
    pub fn spontaneous(self, on: bool) -> Self {
        self.0.spontaneous = on;
        self
    }

    /// Whether station interrogation answers it (default on, off for counters and
    /// protection events).
    #[must_use]
    pub fn interrogation(self, on: bool) -> Self {
        self.0.interrogation = on;
        self
    }

    /// The interrogation group 1–16 that also answers it; other numbers clear the group.
    #[must_use]
    pub fn group(self, group: u8) -> Self {
        self.0.group = (1..=16).contains(&group).then_some(group);
        self
    }

    /// Whether it is transmitted periodically (COT 1) every `cyclic_period`.
    #[must_use]
    pub fn cyclic(self, on: bool) -> Self {
        self.0.cyclic = on;
        self
    }

    /// Whether it is transmitted in the background scan (COT 2).
    #[must_use]
    pub fn background(self, on: bool) -> Self {
        self.0.background = on;
        self
    }

    /// The counter interrogation group 1–4 of an integrated-totals point; other numbers clear it.
    #[must_use]
    pub fn counter_group(self, group: u8) -> Self {
        self.0.counter_group = (1..=4).contains(&group).then_some(group);
        self
    }
}

/// The options of a command point just declared in a [`Database`].
///
/// ```
/// use iec60870::prelude::*;
///
/// let mut db = Database::new();
/// db.command(CommonAddress(1), Ioa(5000), CommandKind::Single).mode(CommandMode::Direct);
/// ```
#[derive(Debug)]
pub struct CommandOptions<'a>(&'a mut CommandEntry);

impl CommandOptions<'_> {
    /// How commands are accepted (default select-before-operate; bitstring commands, which
    /// carry no select bit, default to direct).
    #[must_use]
    pub fn mode(self, mode: CommandMode) -> Self {
        self.0.mode = mode;
        self
    }
}

/// Why an update was refused.
///
#[cfg_attr(feature = "cs104", doc = "```")]
#[cfg_attr(not(feature = "cs104"), doc = "```ignore")]
/// use iec60870::prelude::*;
/// use iec60870::station::{ControlledStation, ServerConfig, UpdateError};
///
/// let mut db = Database::new();
/// db.insert(CommonAddress(1), Ioa(1), false);
/// let clock = || Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
/// let mut st = ControlledStation::<iec60870::cs104::Cs104Link>::new(db, ServerConfig::default(), clock);
/// assert!(matches!(st.update(CommonAddress(1), Ioa(1), 1.5f32), Err(UpdateError::KindMismatch { .. })));
/// assert!(matches!(st.update(CommonAddress(1), Ioa(2), true), Err(UpdateError::UnknownPoint { .. })));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpdateError {
    /// No monitored point at this address.
    UnknownPoint {
        /// The common address.
        common_address: CommonAddress,
        /// The information object address.
        ioa: Ioa,
    },
    /// The value is of another kind than the point.
    KindMismatch {
        /// The point's kind.
        expected: ValueKind,
        /// The update's kind.
        found: ValueKind,
    },
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::UnknownPoint { common_address, ioa } => write!(f, "no point at CA {common_address} IOA {ioa}"),
            UpdateError::KindMismatch { expected, found } => write!(f, "the point is a {expected}, the update a {found}"),
        }
    }
}

impl core::error::Error for UpdateError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::types::BinaryCounterReading;
    use alloc::string::ToString;

    #[test]
    fn defaults_and_options() {
        let ca = CommonAddress(2);
        let mut db = Database::new();
        let _ = db.insert(ca, Ioa(1), true);
        let _ = db.insert(ca, Ioa(2), BinaryCounterReading::new(5)).counter_group(9);
        let _ = db.insert(CommonAddress(3), Ioa(1), 1.0f32).group(16).cyclic(true).background(true).spontaneous(false).interrogation(false);
        let _ = db.command(CommonAddress(4), Ioa(9), CommandKind::Bitstring);
        let p = &db.points[&(ca, Ioa(1))];
        assert!(p.spontaneous && p.interrogation && p.format == TimeFormat::Cp56);
        let c = &db.points[&(ca, Ioa(2))];
        assert!(!c.spontaneous && !c.interrogation && c.counter_group.is_none());
        let f = &db.points[&(CommonAddress(3), Ioa(1))];
        assert!(f.group == Some(16) && f.cyclic && f.background && !f.spontaneous && !f.interrogation);
        assert_eq!(db.commands[&(CommonAddress(4), Ioa(9))].mode, CommandMode::Direct);
        assert_eq!(db.common_addresses().collect::<Vec<_>>(), [CommonAddress(2), CommonAddress(3), CommonAddress(4)]);
        assert!(db.has_common_address(CommonAddress(4)) && !db.has_common_address(CommonAddress(5)));
        assert_eq!(db.len(), 3);
        assert_eq!(db.command_count(), 1);
        assert_eq!(
            UpdateError::KindMismatch { expected: ValueKind::Single, found: ValueKind::Float }.to_string(),
            "the point is a single point, the update a short float"
        );
    }
}
