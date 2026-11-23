//! The wire format: a bounds-checked reader, a writer that cannot overrun, the layout of every
//! information element, and the ASDU decode/encode built from them.

use alloc::vec::Vec;

use super::{Asdu, AsduHeader, DecodeError, DecodeErrorKind, EncodeError, Field, InformationObject, Objects, Profile, Raw, TimeTag};
use crate::asdu::profile::{CaWidth, CotWidth};
use crate::time::{Cp16Time2a, Cp24Time2a, Cp56Time2a};
#[allow(clippy::wildcard_imports)] // every element type has a wire layout here
use crate::types::*;

/// A cursor over the input that never reads past it: every read names the field it is for.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    object: Option<u8>,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, object: None }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn error(&self, kind: DecodeErrorKind, field: Field) -> DecodeError {
        DecodeError { kind, field, offset: self.pos, object: self.object }
    }

    fn take(&mut self, n: usize, field: Field) -> Result<&'a [u8], DecodeError> {
        let rest = self.buf.get(self.pos..).unwrap_or_default();
        match rest.get(..n) {
            Some(s) => {
                self.pos += n;
                Ok(s)
            }
            None => Err(self.error(DecodeErrorKind::Truncated { needed: n, available: rest.len() }, field)),
        }
    }

    fn array<const N: usize>(&mut self, field: Field) -> Result<[u8; N], DecodeError> {
        let at = self.pos;
        let s = self.take(N, field)?;
        s.try_into().map_err(|_| DecodeError { kind: DecodeErrorKind::Truncated { needed: N, available: s.len() }, field, offset: at, object: self.object })
    }

    fn u8(&mut self, field: Field) -> Result<u8, DecodeError> {
        let [b] = self.array(field)?;
        Ok(b)
    }

    fn u16(&mut self, field: Field) -> Result<u16, DecodeError> {
        self.array(field).map(u16::from_le_bytes)
    }

    fn u24(&mut self, field: Field) -> Result<u32, DecodeError> {
        let [a, b, c] = self.array(field)?;
        Ok(u32::from_le_bytes([a, b, c, 0]))
    }

    fn u32(&mut self, field: Field) -> Result<u32, DecodeError> {
        self.array(field).map(u32::from_le_bytes)
    }

    fn uint(&mut self, octets: usize, field: Field) -> Result<u32, DecodeError> {
        match octets {
            1 => self.u8(field).map(u32::from),
            2 => self.u16(field).map(u32::from),
            _ => self.u24(field),
        }
    }
}

/// A cursor over the output. The encoder sizes the output before writing, so an overrun cannot
/// happen; if it did, the writer would record it instead of panicking.
pub(crate) struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    overrun: bool,
}

impl<'a> Writer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0, overrun: false }
    }

    pub(crate) fn put(&mut self, bytes: &[u8]) {
        let end = self.pos.saturating_add(bytes.len());
        match self.buf.get_mut(self.pos..end) {
            Some(slot) => {
                for (d, s) in slot.iter_mut().zip(bytes) {
                    *d = *s;
                }
                self.pos = end;
            }
            None => self.overrun = true,
        }
    }

    fn u8(&mut self, v: u8) {
        self.put(&[v]);
    }

    fn u16(&mut self, v: u16) {
        self.put(&v.to_le_bytes());
    }

    fn u24(&mut self, v: u32) {
        let [a, b, c, _] = v.to_le_bytes();
        self.put(&[a, b, c]);
    }

    fn u32(&mut self, v: u32) {
        self.put(&v.to_le_bytes());
    }

    fn uint(&mut self, octets: usize, v: u32) {
        let bytes = v.to_le_bytes();
        self.put(bytes.get(..octets).unwrap_or(&bytes));
    }
}

/// A value out of its field's range: field, value bits, maximum.
type RangeError = (Field, u32, u32);

/// The wire layout of an information element (or a time tag).
pub(crate) trait Wire: Sized {
    /// The fixed length, or the minimum for a variable-length element.
    const MIN_LEN: usize;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError>;
    fn write(&self, w: &mut Writer<'_>);
    fn len(&self) -> usize {
        Self::MIN_LEN
    }
    /// Whether every value fits its field (checked before anything is written).
    fn check(&self) -> Result<(), RangeError> {
        Ok(())
    }
}

/// Elements that are a single octet newtype.
macro_rules! octet_wire {
    ($($ty:ty => $field:ident),* $(,)?) => {$(
        impl Wire for $ty {
            const MIN_LEN: usize = 1;
            fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                r.u8(Field::$field).map(<$ty>::from_bits)
            }
            fn write(&self, w: &mut Writer<'_>) {
                w.u8(self.bits());
            }
        }
    )*};
}

octet_wire!(SinglePoint => Siq, DoublePoint => Diq, Quality => Qds, ProtectionQuality => Qdp, SingleEvent => Sep, StartEvents => Spe,
    OutputCircuits => Oci, SingleCommand => Sco, DoubleCommand => Dco, StepCommand => Rco, SetpointQualifier => Qos, ParameterQualifier => Qpm);

/// Elements that are a public single-octet tuple struct.
macro_rules! tuple_octet_wire {
    ($($ty:ident => $field:ident),* $(,)?) => {$(
        impl Wire for $ty {
            const MIN_LEN: usize = 1;
            fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
                r.u8(Field::$field).map($ty)
            }
            fn write(&self, w: &mut Writer<'_>) {
                w.u8(self.0);
            }
        }
    )*};
}

tuple_octet_wire!(EndOfInitialization => Coi, Interrogation => Qoi, CounterInterrogation => Qcc, ResetProcess => Qrp, ParameterActivation => Qpa);

impl Wire for () {
    const MIN_LEN: usize = 0;
    fn read(_: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(())
    }
    fn write(&self, _: &mut Writer<'_>) {}
}

impl Wire for Read {
    const MIN_LEN: usize = 0;
    fn read(_: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Read)
    }
    fn write(&self, _: &mut Writer<'_>) {}
}

impl Wire for ClockSync {
    const MIN_LEN: usize = 0;
    fn read(_: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ClockSync)
    }
    fn write(&self, _: &mut Writer<'_>) {}
}

impl Wire for Cp56Time2a {
    const MIN_LEN: usize = 7;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array(Field::Cp56Time2a).map(Cp56Time2a::from_octets)
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.put(&self.octets());
    }
}

impl Wire for Cp24Time2a {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array(Field::Cp24Time2a).map(Cp24Time2a::from_octets)
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.put(&self.octets());
    }
}

impl Wire for Cp16Time2a {
    const MIN_LEN: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.u16(Field::Cp16Time2a).map(Cp16Time2a)
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.0);
    }
}

impl Wire for Normalized {
    const MIN_LEN: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.array(Field::Nva).map(|b| Normalized(i16::from_le_bytes(b)))
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.put(&self.0.to_le_bytes());
    }
}

fn read_i16(r: &mut Reader<'_>, field: Field) -> Result<i16, DecodeError> {
    r.array(field).map(i16::from_le_bytes)
}

fn read_f32(r: &mut Reader<'_>) -> Result<f32, DecodeError> {
    r.u32(Field::Float).map(f32::from_bits)
}

impl Wire for StepPosition {
    const MIN_LEN: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let vti = r.u8(Field::Vti)?;
        // Sign-extend the seven-bit value.
        let value = ((vti << 1) as i8) >> 1;
        Ok(Self { value, transient: vti & 0x80 != 0, quality: Quality::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u8((self.value as u8 & 0x7F) | if self.transient { 0x80 } else { 0 });
        self.quality.write(w);
    }
    fn check(&self) -> Result<(), RangeError> {
        if (-64..=63).contains(&self.value) { Ok(()) } else { Err((Field::Vti, i32::from(self.value) as u32, 63)) }
    }
}

impl Wire for Bitstring32 {
    const MIN_LEN: usize = 5;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: r.u32(Field::Bsi)?, quality: Quality::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u32(self.value);
        self.quality.write(w);
    }
}

impl Wire for MeasuredNormalized {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: Normalized::read(r)?, quality: Quality::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        self.value.write(w);
        self.quality.write(w);
    }
}

impl Wire for MeasuredScaled {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: read_i16(r, Field::Sva)?, quality: Quality::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.put(&self.value.to_le_bytes());
        self.quality.write(w);
    }
}

impl Wire for MeasuredFloat {
    const MIN_LEN: usize = 5;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: read_f32(r)?, quality: Quality::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u32(self.value.to_bits());
        self.quality.write(w);
    }
}

impl Wire for BinaryCounterReading {
    const MIN_LEN: usize = 5;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let [b0, b1, b2, b3, flags] = r.array(Field::Bcr)?;
        Ok(Self::from_parts(i32::from_le_bytes([b0, b1, b2, b3]), flags))
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.put(&self.value().to_le_bytes());
        w.u8(self.flags());
    }
}

impl Wire for ProtectionEvent {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { event: SingleEvent::read(r)?, elapsed: Cp16Time2a::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        self.event.write(w);
        self.elapsed.write(w);
    }
}

impl Wire for PackedStartEvents {
    const MIN_LEN: usize = 4;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { events: StartEvents::read(r)?, quality: ProtectionQuality::read(r)?, duration: Cp16Time2a::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        self.events.write(w);
        self.quality.write(w);
        self.duration.write(w);
    }
}

impl Wire for PackedOutputCircuits {
    const MIN_LEN: usize = 4;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { circuits: OutputCircuits::read(r)?, quality: ProtectionQuality::read(r)?, operating_time: Cp16Time2a::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        self.circuits.write(w);
        self.quality.write(w);
        self.operating_time.write(w);
    }
}

impl Wire for PackedSinglePoints {
    const MIN_LEN: usize = 5;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let [s0, s1, c0, c1] = r.array(Field::Scd)?;
        Ok(Self { status: u16::from_le_bytes([s0, s1]), change: u16::from_le_bytes([c0, c1]), quality: Quality::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.status);
        w.u16(self.change);
        self.quality.write(w);
    }
}

impl Wire for SetpointNormalized {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: Normalized::read(r)?, qualifier: SetpointQualifier::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        self.value.write(w);
        self.qualifier.write(w);
    }
}

impl Wire for SetpointScaled {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: read_i16(r, Field::Sva)?, qualifier: SetpointQualifier::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.put(&self.value.to_le_bytes());
        self.qualifier.write(w);
    }
}

impl Wire for SetpointFloat {
    const MIN_LEN: usize = 5;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: read_f32(r)?, qualifier: SetpointQualifier::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u32(self.value.to_bits());
        self.qualifier.write(w);
    }
}

impl Wire for BitstringCommand {
    const MIN_LEN: usize = 4;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.u32(Field::Bsi).map(BitstringCommand)
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u32(self.0);
    }
}

impl Wire for TestCommand {
    const MIN_LEN: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.u16(Field::Fbp).map(TestCommand)
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.0);
    }
}

impl Wire for TestCounter {
    const MIN_LEN: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        r.u16(Field::Tsc).map(TestCounter)
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.0);
    }
}

impl Wire for DelayAcquisition {
    const MIN_LEN: usize = 2;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Cp16Time2a::read(r).map(DelayAcquisition)
    }
    fn write(&self, w: &mut Writer<'_>) {
        self.0.write(w);
    }
}

impl Wire for ParameterNormalized {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: Normalized::read(r)?, qualifier: ParameterQualifier::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        self.value.write(w);
        self.qualifier.write(w);
    }
}

impl Wire for ParameterScaled {
    const MIN_LEN: usize = 3;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: read_i16(r, Field::Sva)?, qualifier: ParameterQualifier::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.put(&self.value.to_le_bytes());
        self.qualifier.write(w);
    }
}

impl Wire for ParameterFloat {
    const MIN_LEN: usize = 5;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { value: read_f32(r)?, qualifier: ParameterQualifier::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u32(self.value.to_bits());
        self.qualifier.write(w);
    }
}

fn check_lof(length: u32) -> Result<(), RangeError> {
    if length <= 0xFF_FFFF { Ok(()) } else { Err((Field::Lof, length, 0xFF_FFFF)) }
}

impl Wire for FileReady {
    const MIN_LEN: usize = 6;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { name: r.u16(Field::Nof)?, length: r.u24(Field::Lof)?, qualifier: r.u8(Field::Frq)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        w.u24(self.length);
        w.u8(self.qualifier);
    }
    fn check(&self) -> Result<(), RangeError> {
        check_lof(self.length)
    }
}

impl Wire for SectionReady {
    const MIN_LEN: usize = 7;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { name: r.u16(Field::Nof)?, section: r.u8(Field::Nos)?, length: r.u24(Field::Lof)?, qualifier: r.u8(Field::Srq)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        w.u8(self.section);
        w.u24(self.length);
        w.u8(self.qualifier);
    }
    fn check(&self) -> Result<(), RangeError> {
        check_lof(self.length)
    }
}

impl Wire for CallSelect {
    const MIN_LEN: usize = 4;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { name: r.u16(Field::Nof)?, section: r.u8(Field::Nos)?, qualifier: r.u8(Field::Scq)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        w.u8(self.section);
        w.u8(self.qualifier);
    }
}

impl Wire for LastSection {
    const MIN_LEN: usize = 5;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { name: r.u16(Field::Nof)?, section: r.u8(Field::Nos)?, qualifier: r.u8(Field::Lsq)?, checksum: r.u8(Field::Chs)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        w.u8(self.section);
        w.u8(self.qualifier);
        w.u8(self.checksum);
    }
}

impl Wire for FileAck {
    const MIN_LEN: usize = 4;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { name: r.u16(Field::Nof)?, section: r.u8(Field::Nos)?, qualifier: r.u8(Field::Afq)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        w.u8(self.section);
        w.u8(self.qualifier);
    }
}

impl Wire for Segment {
    const MIN_LEN: usize = 4;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let name = r.u16(Field::Nof)?;
        let section = r.u8(Field::Nos)?;
        let los = r.u8(Field::Los)?;
        // Bounded: `take` refuses before the copy if the octets are not there.
        let data = r.take(usize::from(los), Field::Segment)?.to_vec();
        Ok(Self { name, section, data })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        w.u8(self.section);
        w.u8(self.data.len() as u8);
        w.put(&self.data);
    }
    fn len(&self) -> usize {
        Self::MIN_LEN + self.data.len()
    }
    fn check(&self) -> Result<(), RangeError> {
        let n = self.data.len();
        if n <= 255 { Ok(()) } else { Err((Field::Los, u32::try_from(n).unwrap_or(u32::MAX), 255)) }
    }
}

impl Wire for DirectoryEntry {
    const MIN_LEN: usize = 6;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { name: r.u16(Field::Nof)?, length: r.u24(Field::Lof)?, status: r.u8(Field::Sof)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        w.u24(self.length);
        w.u8(self.status);
    }
    fn check(&self) -> Result<(), RangeError> {
        check_lof(self.length)
    }
}

impl Wire for QueryLog {
    const MIN_LEN: usize = 16;
    fn read(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self { name: r.u16(Field::Nof)?, start: Cp56Time2a::read(r)?, stop: Cp56Time2a::read(r)? })
    }
    fn write(&self, w: &mut Writer<'_>) {
        w.u16(self.name);
        self.start.write(w);
        self.stop.write(w);
    }
}

pub(crate) fn read_header(r: &mut Reader<'_>, profile: &Profile) -> Result<AsduHeader, DecodeError> {
    let type_id = TypeId(r.u8(Field::TypeId)?);
    let vsq = r.u8(Field::Vsq)?;
    let cot = r.u8(Field::Cot)?;
    let originator = match profile.cot {
        CotWidth::One => 0,
        CotWidth::Two => r.u8(Field::Originator)?,
    };
    let common_address = match profile.ca {
        CaWidth::One => u16::from(r.u8(Field::CommonAddress)?),
        CaWidth::Two => r.u16(Field::CommonAddress)?,
    };
    Ok(AsduHeader {
        type_id,
        sequence: vsq & 0x80 != 0,
        count: vsq & 0x7F,
        cot: Cot::from_octets(cot, originator),
        common_address: CommonAddress(common_address),
    })
}

pub(crate) fn decode(octets: &[u8], profile: &Profile) -> Result<Asdu, DecodeError> {
    let max = usize::from(profile.max_asdu_len);
    if octets.len() > max {
        return Err(DecodeError { kind: DecodeErrorKind::TooLong { len: octets.len(), max }, field: Field::Asdu, offset: max, object: None });
    }
    let mut r = Reader::new(octets);
    let h = read_header(&mut r, profile)?;
    let body_at = r.pos;
    let typed = if profile.permits(h.type_id) { Objects::decode_typed(h.type_id, &mut r, profile, h.sequence, h.count) } else { None };
    let objects = match typed {
        Some(objects) => {
            let objects = objects?;
            r.object = None;
            if r.remaining() > 0 {
                return Err(r.error(DecodeErrorKind::TrailingOctets { count: r.remaining() }, Field::Asdu));
            }
            objects
        }
        None => Objects::Raw(Raw { type_id: h.type_id, count: h.count, body: octets.get(body_at..).unwrap_or_default().to_vec() }),
    };
    Ok(Asdu { cot: h.cot, common_address: h.common_address, sequence: h.sequence, objects })
}

pub(crate) fn read_objects<E: Wire, T: Wire + TimeTag>(
    r: &mut Reader<'_>,
    profile: &Profile,
    sequence: bool,
    count: u8,
) -> Result<Vec<InformationObject<E, T>>, DecodeError> {
    let width = profile.ioa.octets();
    let per_object = E::MIN_LEN + T::MIN_LEN + if sequence { 0 } else { width };
    // Never sized by the VSQ's claim alone: at most as many objects as the octets can hold.
    let fits = r.remaining().checked_div(per_object).unwrap_or(usize::MAX);
    let mut v = Vec::with_capacity(usize::from(count).min(fits));
    let mut base = 0;
    for i in 0..count {
        r.object = Some(i);
        let ioa = if sequence && i > 0 {
            let ioa = base + u32::from(i);
            if ioa > profile.ioa.max() {
                return Err(r.error(DecodeErrorKind::AddressOverflow { ioa, max: profile.ioa.max() }, Field::Ioa));
            }
            ioa
        } else {
            base = r.uint(width, Field::Ioa)?;
            base
        };
        let element = E::read(r)?;
        let time = T::read(r)?;
        v.push(InformationObject { ioa: Ioa(ioa), element, time });
    }
    Ok(v)
}

pub(crate) fn objects_len<E: Wire, T: Wire>(v: &[InformationObject<E, T>], profile: &Profile, sequence: bool) -> usize {
    let width = profile.ioa.octets();
    let addresses = if sequence { if v.is_empty() { 0 } else { width } } else { width * v.len() };
    addresses + v.iter().map(|o| o.element.len() + o.time.len()).sum::<usize>()
}

pub(crate) fn check_objects<E: Wire, T: Wire>(v: &[InformationObject<E, T>], profile: &Profile, sequence: bool) -> Result<usize, EncodeError> {
    let max = profile.ioa.max();
    let first = v.first().map_or(0, |o| o.ioa.0);
    for (i, o) in v.iter().enumerate() {
        if o.ioa.0 > max {
            return Err(EncodeError::ValueOutOfRange { field: Field::Ioa, object: Some(i), value: o.ioa.0, max });
        }
        if sequence {
            let expected = u32::try_from(i).ok().and_then(|i| first.checked_add(i));
            if expected != Some(o.ioa.0) {
                return Err(EncodeError::NotInSequence { object: i, expected: Ioa(expected.unwrap_or(u32::MAX)), found: o.ioa });
            }
        }
        if let Err((field, value, max)) = o.element.check().and_then(|()| o.time.check()) {
            return Err(EncodeError::ValueOutOfRange { field, object: Some(i), value, max });
        }
    }
    Ok(objects_len(v, profile, sequence))
}

pub(crate) fn write_objects<E: Wire, T: Wire>(v: &[InformationObject<E, T>], w: &mut Writer<'_>, profile: &Profile, sequence: bool) {
    let width = profile.ioa.octets();
    for (i, o) in v.iter().enumerate() {
        if !sequence || i == 0 {
            w.uint(width, o.ioa.0);
        }
        o.element.write(w);
        o.time.write(w);
    }
}

pub(crate) fn encode(asdu: &Asdu, profile: &Profile, out: &mut [u8]) -> Result<usize, EncodeError> {
    let type_id = asdu.type_id();
    if !matches!(asdu.objects, Objects::Raw(_)) && !profile.permits(type_id) {
        return Err(EncodeError::TypeNotPermitted { type_id });
    }
    let count = asdu.objects.len();
    let count = u8::try_from(count).ok().filter(|c| *c <= 127).ok_or(EncodeError::TooManyObjects { count })?;
    let cot = asdu.cot;
    if profile.cot == CotWidth::One && cot.originator != 0 {
        return Err(EncodeError::ValueOutOfRange { field: Field::Originator, object: None, value: u32::from(cot.originator), max: 0 });
    }
    let ca = asdu.common_address.0;
    if ca > profile.ca.max() {
        return Err(EncodeError::ValueOutOfRange { field: Field::CommonAddress, object: None, value: u32::from(ca), max: u32::from(profile.ca.max()) });
    }
    let len = profile.header_len() + asdu.objects.check_body(profile, asdu.sequence)?;
    let max = usize::from(profile.max_asdu_len);
    if len > max {
        return Err(EncodeError::TooLong { len, max });
    }
    let Some(out) = out.get_mut(..len) else {
        return Err(EncodeError::BufferTooSmall { needed: len, available: out.len() });
    };
    let mut w = Writer::new(out);
    w.u8(type_id.0);
    w.u8(count | if asdu.sequence { 0x80 } else { 0 });
    w.u8(cot.octet());
    if profile.cot == CotWidth::Two {
        w.u8(cot.originator);
    }
    w.uint(profile.ca.octets(), u32::from(ca));
    asdu.objects.write_body(&mut w, profile, asdu.sequence);
    if w.overrun || w.pos != len {
        // Unreachable by construction (the length was computed from the same objects); refuse
        // rather than return a short ASDU.
        return Err(EncodeError::BufferTooSmall { needed: len, available: w.pos });
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::asdu::IoaWidth;

    #[test]
    fn width_helpers_match_profiles() {
        assert_eq!(IoaWidth::Three.max(), 0xFF_FFFF);
        assert_eq!(Profile::IEC104.header_len(), 6);
        assert_eq!(Profile::IEC101.header_len(), 4);
    }

    #[test]
    fn writer_records_overrun_instead_of_panicking() {
        let mut buf = [0u8; 2];
        let mut w = Writer::new(&mut buf);
        w.u24(0x01_0203);
        assert!(w.overrun);
        assert_eq!(buf, [0, 0]);
    }

    #[test]
    fn step_position_sign_extends() {
        let mut r = Reader::new(&[0x40 | 0x80, 0x00]);
        let sp = StepPosition::read(&mut r).unwrap();
        assert_eq!((sp.value, sp.transient), (-64, true));
        let mut r = Reader::new(&[0x3F, 0x00]);
        assert_eq!(StepPosition::read(&mut r).unwrap().value, 63);
    }
}
