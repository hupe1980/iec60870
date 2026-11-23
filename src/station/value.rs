//! Point values, time tags and the points a controlling station reports.

use alloc::vec::Vec;
use core::fmt;

use crate::asdu::{Asdu, InformationObject, Objects};
use crate::time::{Cp24Time2a, Cp56Time2a};
use crate::types::{
    BinaryCounterReading, Bitstring32, CommonAddress, Cot, DoublePoint, DoublePointValue, Ioa, MeasuredFloat, MeasuredNormalized, MeasuredScaled, Normalized,
    PackedOutputCircuits, PackedSinglePoints, PackedStartEvents, ProtectionEvent, Quality, SinglePoint, StepPosition,
};

macro_rules! values {
    ($($(#[$doc:meta])* $variant:ident($element:ty) = $name:literal;)*) => {
        /// The value of a monitored point: one variant per kind of monitor information element,
        /// each carrying its quality where the element has one.
        ///
        /// Plain Rust values convert: `bool` is a single point, `f32` a short float, `i16` a
        /// scaled value, a [`DoublePointValue`] a double point.
        ///
        /// ```
        /// use iec60870::station::{Value, ValueKind};
        /// use iec60870::types::MeasuredFloat;
        /// use iec60870::Quality;
        ///
        /// assert_eq!(Value::from(true).kind(), ValueKind::Single);
        /// let v = Value::from(MeasuredFloat::new(21.5).with_quality(Quality::INVALID));
        /// assert_eq!(v.quality(), Some(Quality::INVALID));
        /// ```
        #[derive(Clone, Copy, Debug, PartialEq)]
        #[non_exhaustive]
        pub enum Value {
            $($(#[$doc])* $variant($element),)*
        }

        /// The kind of a [`Value`], without the value.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[non_exhaustive]
        pub enum ValueKind {
            $($(#[$doc])* $variant,)*
        }

        impl Value {
            /// The kind.
            pub const fn kind(&self) -> ValueKind {
                match self {
                    $(Value::$variant(_) => ValueKind::$variant,)*
                }
            }
        }

        impl fmt::Display for ValueKind {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(match self {
                    $(ValueKind::$variant => $name,)*
                })
            }
        }

        $(
            impl From<$element> for Value {
                fn from(e: $element) -> Self {
                    Value::$variant(e)
                }
            }
        )*
    };
}

values! {
    /// Single-point information (types 1, 2, 30).
    Single(SinglePoint) = "single point";
    /// Double-point information (types 3, 4, 31).
    Double(DoublePoint) = "double point";
    /// Step position (types 5, 6, 32).
    Step(StepPosition) = "step position";
    /// Bitstring of 32 bits (types 7, 8, 33).
    Bitstring(Bitstring32) = "bitstring";
    /// Measured value, normalized (types 9, 10, 34).
    Normalized(MeasuredNormalized) = "normalized value";
    /// Measured value, scaled (types 11, 12, 35).
    Scaled(MeasuredScaled) = "scaled value";
    /// Measured value, short floating point (types 13, 14, 36).
    Float(MeasuredFloat) = "short float";
    /// Integrated totals (types 15, 16, 37).
    Counter(BinaryCounterReading) = "integrated totals";
    /// Packed single points with status change detection (type 20).
    PackedSingle(PackedSinglePoints) = "packed single points";
    /// Normalized value without quality descriptor (type 21).
    NormalizedRaw(Normalized) = "normalized value without quality";
    /// Event of protection equipment (types 17, 38).
    ProtectionEvent(ProtectionEvent) = "protection event";
    /// Packed start events of protection equipment (types 18, 39).
    StartEvents(PackedStartEvents) = "packed start events";
    /// Packed output circuit information of protection equipment (types 19, 40).
    OutputCircuits(PackedOutputCircuits) = "packed output circuits";
}

impl Value {
    /// The quality descriptor, for the kinds that carry a [`Quality`].
    pub const fn quality(&self) -> Option<Quality> {
        match self {
            Value::Single(v) => Some(v.quality()),
            Value::Double(v) => Some(v.quality()),
            Value::Step(v) => Some(v.quality),
            Value::Bitstring(v) => Some(v.quality),
            Value::Normalized(v) => Some(v.quality),
            Value::Scaled(v) => Some(v.quality),
            Value::Float(v) => Some(v.quality),
            Value::PackedSingle(v) => Some(v.quality),
            Value::Counter(_) | Value::NormalizedRaw(_) | Value::ProtectionEvent(_) | Value::StartEvents(_) | Value::OutputCircuits(_) => None,
        }
    }
}

impl From<bool> for Value {
    /// A single point with good quality.
    fn from(on: bool) -> Self {
        Value::Single(SinglePoint::new(on))
    }
}

impl From<f32> for Value {
    /// A short float measured value with good quality.
    fn from(v: f32) -> Self {
        Value::Float(MeasuredFloat::new(v))
    }
}

impl From<i16> for Value {
    /// A scaled measured value with good quality.
    fn from(v: i16) -> Self {
        Value::Scaled(MeasuredScaled::new(v))
    }
}

impl From<DoublePointValue> for Value {
    /// A double point with good quality.
    fn from(v: DoublePointValue) -> Self {
        Value::Double(DoublePoint::new(v))
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Single(v) => write!(f, "{}", if v.value() { "ON" } else { "OFF" })?,
            Value::Double(v) => write!(f, "{}", v.value())?,
            Value::Step(v) => write!(f, "step {}{}", v.value, if v.transient { " (transient)" } else { "" })?,
            Value::Bitstring(v) => write!(f, "{:#010x}", v.value)?,
            Value::Normalized(v) => write!(f, "{}", v.value.to_f32())?,
            Value::Scaled(v) => write!(f, "{}", v.value)?,
            Value::Float(v) => write!(f, "{}", v.value)?,
            Value::Counter(v) => {
                write!(f, "{} (seq {})", v.value(), v.sequence())?;
                let mut separator = " [";
                for (set, label) in [(v.carry(), "CY"), (v.adjusted(), "CA"), (v.invalid(), "IV")] {
                    if set {
                        write!(f, "{separator}{label}")?;
                        separator = " ";
                    }
                }
                if v.flags() & 0xe0 != 0 {
                    f.write_str("]")?;
                }
            }
            Value::PackedSingle(v) => write!(f, "{:#06x} changed {:#06x}", v.status, v.change)?,
            Value::NormalizedRaw(v) => write!(f, "{}", v.to_f32())?,
            Value::ProtectionEvent(v) => write!(f, "{} after {}", v.event, v.elapsed)?,
            Value::StartEvents(v) => write!(f, "{} for {}", v.events, v.duration)?,
            Value::OutputCircuits(v) => write!(f, "{} in {}", v.circuits, v.operating_time)?,
        }
        let protection = match self {
            Value::StartEvents(v) => Some(v.quality),
            Value::OutputCircuits(v) => Some(v.quality),
            _ => None,
        };
        if let Some(q) = protection.filter(|q| q.bits() != 0) {
            write!(f, " [{q}]")?;
        }
        match self.quality() {
            Some(q) if q.bits() != 0 => write!(f, " [{q}]"),
            _ => Ok(()),
        }
    }
}

/// A time tag as received: three or seven octets.
///
/// ```
/// use iec60870::station::Timestamp;
/// use iec60870::time::Cp56Time2a;
///
/// let t = Timestamp::Cp56(Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap());
/// assert!(t.to_string().starts_with("2026-11-18"));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Timestamp {
    /// CP24Time2a (minutes and milliseconds; 101 only).
    Cp24(Cp24Time2a),
    /// CP56Time2a.
    Cp56(Cp56Time2a),
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Timestamp::Cp24(t) => fmt::Display::fmt(t, f),
            Timestamp::Cp56(t) => fmt::Display::fmt(t, f),
        }
    }
}

/// The time tag a controlled station puts on a point's spontaneous events.
///
/// Interrogation and read replies never carry one. Protection-equipment kinds always do: for
/// them `None` means CP56Time2a.
///
/// ```
/// use iec60870::prelude::*;
///
/// let mut db = Database::new();
/// db.insert(CommonAddress(1), Ioa(1), 0i16).time_format(TimeFormat::None); // events as M_ME_NB_1
/// assert_eq!(TimeFormat::default(), TimeFormat::Cp56);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum TimeFormat {
    /// No time tag (types 1, 3, 5, …).
    None,
    /// CP24Time2a (types 2, 4, 6, …; not permitted in 104).
    Cp24,
    /// CP56Time2a (types 30–40) — the default.
    #[default]
    Cp56,
}

/// A point as a controlling station received it: where it is, why it was sent, its value and
/// its time tag.
///
/// ```
/// use iec60870::prelude::*;
/// use iec60870::station::{Point, Value};
///
/// let asdu = Asdu::new(CommonAddress(1), Cot::INTERROGATED_BY_STATION, [
///     InformationObject::new(Ioa(100), SinglePoint::new(true)),
///     InformationObject::new(Ioa(101), SinglePoint::new(false)),
/// ]);
/// let points = Point::from_asdu(&asdu).unwrap();
/// assert_eq!(points.len(), 2);
/// assert_eq!(points[0].value, Value::from(true));
/// assert_eq!(points[0].to_string(), "CA 1 IOA 100 = ON, interrogated by station (20)");
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    /// The common address of the ASDU.
    pub common_address: CommonAddress,
    /// The information object address.
    pub ioa: Ioa,
    /// The cause of transmission.
    pub cause: Cot,
    /// The value with its quality.
    pub value: Value,
    /// The time tag, if the type has one.
    pub time: Option<Timestamp>,
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CA {} IOA {} = {}, {}", self.common_address, self.ioa, self.value, self.cause)?;
        if let Some(t) = self.time {
            write!(f, " at {t}")?;
        }
        Ok(())
    }
}

macro_rules! unpack {
    ($objects:expr, $kind:ident, |$o:ident| $time:expr) => {
        $objects.iter().map(|$o| ($o.ioa, Value::$kind($o.element), $time)).collect()
    };
}

impl Point {
    /// The points of a monitor ASDU, one per information object; `None` if the ASDU carries no
    /// monitored values (a command, a confirmation, a raw type).
    pub fn from_asdu(asdu: &Asdu) -> Option<Vec<Point>> {
        let items: Vec<(Ioa, Value, Option<Timestamp>)> = match &asdu.objects {
            Objects::SinglePoint(v) => unpack!(v, Single, |o| None),
            Objects::SinglePointCp24(v) => unpack!(v, Single, |o| Some(Timestamp::Cp24(o.time))),
            Objects::SinglePointCp56(v) => unpack!(v, Single, |o| Some(Timestamp::Cp56(o.time))),
            Objects::DoublePoint(v) => unpack!(v, Double, |o| None),
            Objects::DoublePointCp24(v) => unpack!(v, Double, |o| Some(Timestamp::Cp24(o.time))),
            Objects::DoublePointCp56(v) => unpack!(v, Double, |o| Some(Timestamp::Cp56(o.time))),
            Objects::StepPosition(v) => unpack!(v, Step, |o| None),
            Objects::StepPositionCp24(v) => unpack!(v, Step, |o| Some(Timestamp::Cp24(o.time))),
            Objects::StepPositionCp56(v) => unpack!(v, Step, |o| Some(Timestamp::Cp56(o.time))),
            Objects::Bitstring(v) => unpack!(v, Bitstring, |o| None),
            Objects::BitstringCp24(v) => unpack!(v, Bitstring, |o| Some(Timestamp::Cp24(o.time))),
            Objects::BitstringCp56(v) => unpack!(v, Bitstring, |o| Some(Timestamp::Cp56(o.time))),
            Objects::MeasuredNormalized(v) => unpack!(v, Normalized, |o| None),
            Objects::MeasuredNormalizedCp24(v) => unpack!(v, Normalized, |o| Some(Timestamp::Cp24(o.time))),
            Objects::MeasuredNormalizedCp56(v) => unpack!(v, Normalized, |o| Some(Timestamp::Cp56(o.time))),
            Objects::MeasuredScaled(v) => unpack!(v, Scaled, |o| None),
            Objects::MeasuredScaledCp24(v) => unpack!(v, Scaled, |o| Some(Timestamp::Cp24(o.time))),
            Objects::MeasuredScaledCp56(v) => unpack!(v, Scaled, |o| Some(Timestamp::Cp56(o.time))),
            Objects::MeasuredFloat(v) => unpack!(v, Float, |o| None),
            Objects::MeasuredFloatCp24(v) => unpack!(v, Float, |o| Some(Timestamp::Cp24(o.time))),
            Objects::MeasuredFloatCp56(v) => unpack!(v, Float, |o| Some(Timestamp::Cp56(o.time))),
            Objects::IntegratedTotals(v) => unpack!(v, Counter, |o| None),
            Objects::IntegratedTotalsCp24(v) => unpack!(v, Counter, |o| Some(Timestamp::Cp24(o.time))),
            Objects::IntegratedTotalsCp56(v) => unpack!(v, Counter, |o| Some(Timestamp::Cp56(o.time))),
            Objects::ProtectionEventCp24(v) => unpack!(v, ProtectionEvent, |o| Some(Timestamp::Cp24(o.time))),
            Objects::ProtectionEventCp56(v) => unpack!(v, ProtectionEvent, |o| Some(Timestamp::Cp56(o.time))),
            Objects::PackedStartEventsCp24(v) => unpack!(v, StartEvents, |o| Some(Timestamp::Cp24(o.time))),
            Objects::PackedStartEventsCp56(v) => unpack!(v, StartEvents, |o| Some(Timestamp::Cp56(o.time))),
            Objects::PackedOutputCircuitsCp24(v) => unpack!(v, OutputCircuits, |o| Some(Timestamp::Cp24(o.time))),
            Objects::PackedOutputCircuitsCp56(v) => unpack!(v, OutputCircuits, |o| Some(Timestamp::Cp56(o.time))),
            Objects::PackedSinglePoints(v) => unpack!(v, PackedSingle, |o| None),
            Objects::NormalizedWithoutQuality(v) => unpack!(v, NormalizedRaw, |o| None),
            _ => return None,
        };
        Some(items.into_iter().map(|(ioa, value, time)| Point { common_address: asdu.common_address, ioa, cause: asdu.cot, value, time }).collect())
    }
}

macro_rules! collect {
    ($items:expr, $kind:ident, $variant:ident, |$t:ident| $time:expr) => {
        Objects::$variant(
            $items
                .iter()
                .filter_map(|(ioa, value, $t)| match value {
                    Value::$kind(e) => Some(InformationObject { ioa: *ioa, element: *e, time: $time }),
                    _ => None,
                })
                .collect(),
        )
    };
}

/// Builds the objects of one ASDU from values of one `kind` in `format`; `None` if that kind
/// has no type in that format (a protection event without a time tag, a packed single point
/// with one). Items of another kind are skipped.
pub(crate) fn pack(kind: ValueKind, format: TimeFormat, items: &[(Ioa, Value, Cp56Time2a)]) -> Option<Objects> {
    use TimeFormat as F;
    use ValueKind as K;
    Some(match (kind, format) {
        (K::Single, F::None) => collect!(items, Single, SinglePoint, |_t| ()),
        (K::Single, F::Cp24) => collect!(items, Single, SinglePointCp24, |t| Cp24Time2a::from(*t)),
        (K::Single, F::Cp56) => collect!(items, Single, SinglePointCp56, |t| *t),
        (K::Double, F::None) => collect!(items, Double, DoublePoint, |_t| ()),
        (K::Double, F::Cp24) => collect!(items, Double, DoublePointCp24, |t| Cp24Time2a::from(*t)),
        (K::Double, F::Cp56) => collect!(items, Double, DoublePointCp56, |t| *t),
        (K::Step, F::None) => collect!(items, Step, StepPosition, |_t| ()),
        (K::Step, F::Cp24) => collect!(items, Step, StepPositionCp24, |t| Cp24Time2a::from(*t)),
        (K::Step, F::Cp56) => collect!(items, Step, StepPositionCp56, |t| *t),
        (K::Bitstring, F::None) => collect!(items, Bitstring, Bitstring, |_t| ()),
        (K::Bitstring, F::Cp24) => collect!(items, Bitstring, BitstringCp24, |t| Cp24Time2a::from(*t)),
        (K::Bitstring, F::Cp56) => collect!(items, Bitstring, BitstringCp56, |t| *t),
        (K::Normalized, F::None) => collect!(items, Normalized, MeasuredNormalized, |_t| ()),
        (K::Normalized, F::Cp24) => collect!(items, Normalized, MeasuredNormalizedCp24, |t| Cp24Time2a::from(*t)),
        (K::Normalized, F::Cp56) => collect!(items, Normalized, MeasuredNormalizedCp56, |t| *t),
        (K::Scaled, F::None) => collect!(items, Scaled, MeasuredScaled, |_t| ()),
        (K::Scaled, F::Cp24) => collect!(items, Scaled, MeasuredScaledCp24, |t| Cp24Time2a::from(*t)),
        (K::Scaled, F::Cp56) => collect!(items, Scaled, MeasuredScaledCp56, |t| *t),
        (K::Float, F::None) => collect!(items, Float, MeasuredFloat, |_t| ()),
        (K::Float, F::Cp24) => collect!(items, Float, MeasuredFloatCp24, |t| Cp24Time2a::from(*t)),
        (K::Float, F::Cp56) => collect!(items, Float, MeasuredFloatCp56, |t| *t),
        (K::Counter, F::None) => collect!(items, Counter, IntegratedTotals, |_t| ()),
        (K::Counter, F::Cp24) => collect!(items, Counter, IntegratedTotalsCp24, |t| Cp24Time2a::from(*t)),
        (K::Counter, F::Cp56) => collect!(items, Counter, IntegratedTotalsCp56, |t| *t),
        (K::ProtectionEvent, F::Cp24) => collect!(items, ProtectionEvent, ProtectionEventCp24, |t| Cp24Time2a::from(*t)),
        (K::ProtectionEvent, F::Cp56) => collect!(items, ProtectionEvent, ProtectionEventCp56, |t| *t),
        (K::StartEvents, F::Cp24) => collect!(items, StartEvents, PackedStartEventsCp24, |t| Cp24Time2a::from(*t)),
        (K::StartEvents, F::Cp56) => collect!(items, StartEvents, PackedStartEventsCp56, |t| *t),
        (K::OutputCircuits, F::Cp24) => collect!(items, OutputCircuits, PackedOutputCircuitsCp24, |t| Cp24Time2a::from(*t)),
        (K::OutputCircuits, F::Cp56) => collect!(items, OutputCircuits, PackedOutputCircuitsCp56, |t| *t),
        (K::PackedSingle, F::None) => collect!(items, PackedSingle, PackedSinglePoints, |_t| ()),
        (K::NormalizedRaw, F::None) => collect!(items, NormalizedRaw, NormalizedWithoutQuality, |_t| ()),
        _ => return None,
    })
}

/// Whether `kind` can be answered without a time tag (interrogation, read).
pub(crate) const fn has_untimed_type(kind: ValueKind) -> bool {
    !matches!(kind, ValueKind::ProtectionEvent | ValueKind::StartEvents | ValueKind::OutputCircuits)
}

/// The format events of `kind` actually use: protection kinds always carry a time tag, packed
/// single points and normalized-without-quality never do.
pub(crate) const fn event_format(kind: ValueKind, format: TimeFormat) -> TimeFormat {
    match (kind, format) {
        (ValueKind::ProtectionEvent | ValueKind::StartEvents | ValueKind::OutputCircuits, TimeFormat::None) => TimeFormat::Cp56,
        (ValueKind::PackedSingle | ValueKind::NormalizedRaw, _) => TimeFormat::None,
        _ => format,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::asdu::Profile;
    use crate::types::{OutputCircuits, ProtectionQuality, SingleEvent, StartEvents};

    fn samples() -> Vec<Value> {
        alloc::vec![
            Value::from(true),
            Value::from(DoublePointValue::On),
            Value::from(StepPosition::new(-5)),
            Value::from(Bitstring32::new(0xDEAD_BEEF)),
            Value::from(MeasuredNormalized::new(Normalized(1234))),
            Value::from(-7i16),
            Value::from(21.5f32),
            Value::from(BinaryCounterReading::new(99).with_sequence(3)),
            Value::from(PackedSinglePoints::new(0xF0F0, 0x0101)),
            Value::from(Normalized(-1)),
            Value::from(ProtectionEvent { event: SingleEvent::new(DoublePointValue::Off), elapsed: crate::time::Cp16Time2a(5) }),
            Value::from(PackedStartEvents { events: StartEvents::L1, quality: ProtectionQuality::GOOD, duration: crate::time::Cp16Time2a(7) }),
            Value::from(PackedOutputCircuits { circuits: OutputCircuits::L2, quality: ProtectionQuality::GOOD, operating_time: crate::time::Cp16Time2a(9) }),
        ]
    }

    #[test]
    fn every_kind_and_format_round_trips_through_the_codec() {
        let t = Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
        let mut types = 0;
        for value in samples() {
            for format in [TimeFormat::None, TimeFormat::Cp24, TimeFormat::Cp56] {
                let Some(objects) = pack(value.kind(), format, &[(Ioa(7), value, t), (Ioa(8), value, t)]) else {
                    assert!(matches!(
                        (value.kind(), format),
                        (ValueKind::ProtectionEvent | ValueKind::StartEvents | ValueKind::OutputCircuits, TimeFormat::None)
                            | (ValueKind::PackedSingle | ValueKind::NormalizedRaw, TimeFormat::Cp24 | TimeFormat::Cp56)
                    ));
                    continue;
                };
                types += 1;
                let asdu = Asdu::new(CommonAddress(3), Cot::SPONTANEOUS, objects);
                let profile = Profile::IEC104.with_types(crate::types::TypeSet::STANDARD);
                let before = asdu.to_vec(&profile).unwrap();
                let decoded = Asdu::decode(&before, &profile).unwrap();
                let points = Point::from_asdu(&decoded).unwrap();
                assert_eq!(points.len(), 2);
                assert_eq!(points[1].ioa, Ioa(8));
                assert_eq!(points[0].value, value);
                let _ = alloc::format!("{}", points[0]);
                assert_eq!(decoded.to_vec(&profile).unwrap(), before);
                let expected = match format {
                    TimeFormat::None => None,
                    TimeFormat::Cp24 => Some(Timestamp::Cp24(Cp24Time2a::from(t))),
                    TimeFormat::Cp56 => Some(Timestamp::Cp56(t)),
                };
                assert_eq!(points[0].time, expected);
            }
        }
        assert_eq!(types, 32);
    }

    #[test]
    fn non_monitor_asdus_are_not_points() {
        let asdu = Asdu::new(CommonAddress(1), Cot::ACTIVATION, InformationObject::new(Ioa(0), crate::types::Interrogation::STATION));
        assert!(Point::from_asdu(&asdu).is_none());
    }

    #[test]
    fn formats_of_the_special_kinds() {
        assert_eq!(event_format(ValueKind::ProtectionEvent, TimeFormat::None), TimeFormat::Cp56);
        assert_eq!(event_format(ValueKind::PackedSingle, TimeFormat::Cp56), TimeFormat::None);
        assert_eq!(event_format(ValueKind::Float, TimeFormat::Cp24), TimeFormat::Cp24);
        assert!(!has_untimed_type(ValueKind::StartEvents) && has_untimed_type(ValueKind::Counter));
        assert_eq!(alloc::format!("{}", Value::from(MeasuredFloat::new(1.5).with_quality(Quality::INVALID))), "1.5 [IV]");
    }
    #[test]
    fn readable_values_and_full_point() {
        for (state, expected) in [
            (DoublePointValue::Intermediate, "INTERMEDIATE"),
            (DoublePointValue::Off, "OFF"),
            (DoublePointValue::On, "ON"),
            (DoublePointValue::Indeterminate, "INDETERMINATE"),
        ] {
            assert_eq!(alloc::format!("{}", Value::from(state)), expected);
        }
        let lines: Vec<_> = samples().iter().map(|value| alloc::format!("{value}")).collect();
        assert_eq!(
            lines,
            [
                "ON",
                "ON",
                "step -5",
                "0xdeadbeef",
                "0.03765869",
                "-7",
                "21.5",
                "99 (seq 3)",
                "0xf0f0 changed 0x0101",
                "-0.000030517578",
                "OFF after 0.005 s",
                "SL1 for 0.007 s",
                "CL2 in 0.009 s",
            ]
        );
        assert_eq!(alloc::format!("{}", Value::from(BinaryCounterReading::from_parts(99, 0xe3))), "99 (seq 3) [CY CA IV]");
        let mut point = Point { common_address: CommonAddress(1), ioa: Ioa(100), cause: Cot::INTERROGATED_BY_STATION, value: Value::from(true), time: None };
        assert_eq!(alloc::format!("{point}"), "CA 1 IOA 100 = ON, interrogated by station (20)");
        point.value = Value::from(MeasuredFloat::new(21.5).with_quality(Quality::NOT_TOPICAL | Quality::INVALID));
        point.cause = point.cause.negative().test().with_originator(3);
        let time = Timestamp::Cp56(Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap());
        point.time = Some(time);
        assert_eq!(
            alloc::format!("{point}"),
            alloc::format!("CA 1 IOA 100 = 21.5 [NT IV], interrogated by station (20), negative, test, originator 3 at {time}")
        );
    }
}
