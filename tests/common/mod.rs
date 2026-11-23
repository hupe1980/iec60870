//! Shared test support: every field-width profile, and a proptest strategy per standard type
//! identification that walks each information element's full declared range.

#![allow(
    dead_code,
    clippy::pedantic,
    clippy::complexity,
    clippy::manual_is_multiple_of,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use iec60870::prelude::*;
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;

/// The twelve field-width combinations COT 1/2 × CA 1/2 × IOA 1/2/3, at the largest length an
/// ASDU can have (255) and with every type permitted.
pub fn all_width_profiles() -> Vec<Profile> {
    let mut out = Vec::new();
    for cot in [CotWidth::One, CotWidth::Two] {
        for ca in [CaWidth::One, CaWidth::Two] {
            for ioa in [IoaWidth::One, IoaWidth::Two, IoaWidth::Three] {
                out.push(Profile::IEC104.with_cot(cot).with_ca(ca).with_ioa(ioa).with_max_asdu_len(255).with_types(TypeSet::ALL));
            }
        }
    }
    out
}

pub fn quality() -> impl Strategy<Value = Quality> {
    any::<u8>().prop_map(Quality::from_bits)
}
pub fn pquality() -> impl Strategy<Value = ProtectionQuality> {
    any::<u8>().prop_map(ProtectionQuality::from_bits)
}
pub fn normalized() -> impl Strategy<Value = Normalized> {
    any::<i16>().prop_map(Normalized)
}
/// Every bit pattern, NaNs and infinities included.
pub fn float() -> impl Strategy<Value = f32> {
    prop_oneof![any::<u32>().prop_map(f32::from_bits), Just(f32::NAN), Just(f32::INFINITY), Just(f32::NEG_INFINITY), Just(-0.0f32)]
}
pub fn cp16() -> impl Strategy<Value = Cp16Time2a> {
    any::<u16>().prop_map(Cp16Time2a)
}
pub fn cp24() -> impl Strategy<Value = Cp24Time2a> {
    any::<[u8; 3]>().prop_map(Cp24Time2a::from_octets)
}
pub fn cp56() -> impl Strategy<Value = Cp56Time2a> {
    any::<[u8; 7]>().prop_map(Cp56Time2a::from_octets)
}
pub fn lof() -> impl Strategy<Value = u32> {
    0u32..=0xFF_FFFF
}
pub fn qos() -> impl Strategy<Value = SetpointQualifier> {
    any::<u8>().prop_map(SetpointQualifier::from_bits)
}
pub fn qpm() -> impl Strategy<Value = ParameterQualifier> {
    any::<u8>().prop_map(ParameterQualifier::from_bits)
}

/// Addresses for `n` objects: consecutive from a random base under SQ = 1, independent
/// otherwise, always within `max`.
fn place<E, T>(raw: Vec<(u32, E, T)>, base: u32, max: u32, sequence: bool) -> Vec<InformationObject<E, T>> {
    let n = raw.len() as u32;
    let base = base % (max - n.min(max) + 1);
    raw.into_iter()
        .enumerate()
        .map(|(i, (r, element, time))| {
            let ioa = if sequence { base + i as u32 } else { r % (max + 1) };
            InformationObject { ioa: Ioa(ioa), element, time }
        })
        .collect()
}

/// The maximum object count that fits a 255-octet ASDU under `profile`.
fn fit(profile: &Profile, sequence: bool, len: usize) -> usize {
    let ioa = profile.ioa.octets();
    let room = usize::from(profile.max_asdu_len) - profile.header_len() - if sequence { ioa } else { 0 };
    let per = len + if sequence { 0 } else { ioa };
    if per == 0 { 127 } else { (room / per).min(127) }
}

/// One strategy per standard type identification, named by its type, for `profile` and SQ.
pub fn arms(profile: &Profile, sequence: bool) -> Vec<(TypeId, BoxedStrategy<Objects>)> {
    let max = profile.ioa.max();
    let mut out: Vec<(TypeId, BoxedStrategy<Objects>)> = Vec::new();
    macro_rules! arm {
        ($id:ident, $len:expr, $element:expr, $time:expr) => {{
            let n = fit(profile, sequence, $len);
            let s = (vec((any::<u32>(), $element, $time), 0..=n), any::<u32>()).prop_map(move |(v, base)| Objects::from(place(v, base, max, sequence)));
            out.push((TypeId::$id, s.boxed()));
        }};
    }
    let siq = || any::<u8>().prop_map(SinglePoint::from_bits);
    let diq = || any::<u8>().prop_map(DoublePoint::from_bits);
    let step = || (-64i8..=63, any::<bool>(), quality()).prop_map(|(value, transient, quality)| StepPosition { value, transient, quality });
    let bits = || (any::<u32>(), quality()).prop_map(|(value, quality)| Bitstring32 { value, quality });
    let nva = || (normalized(), quality()).prop_map(|(value, quality)| MeasuredNormalized { value, quality });
    let sva = || (any::<i16>(), quality()).prop_map(|(value, quality)| MeasuredScaled { value, quality });
    let flt = || (float(), quality()).prop_map(|(value, quality)| MeasuredFloat { value, quality });
    let bcr = || (any::<i32>(), any::<u8>()).prop_map(|(v, f)| BinaryCounterReading::from_parts(v, f));
    let sep = || (any::<u8>(), cp16()).prop_map(|(e, elapsed)| ProtectionEvent { event: SingleEvent::from_bits(e), elapsed });
    let spe =
        || (any::<u8>(), pquality(), cp16()).prop_map(|(e, quality, duration)| PackedStartEvents { events: StartEvents::from_bits(e), quality, duration });
    let oci = || {
        (any::<u8>(), pquality(), cp16()).prop_map(|(c, quality, operating_time)| PackedOutputCircuits {
            circuits: OutputCircuits::from_bits(c),
            quality,
            operating_time,
        })
    };
    let sco = || any::<u8>().prop_map(SingleCommand::from_bits);
    let dco = || any::<u8>().prop_map(DoubleCommand::from_bits);
    let rco = || any::<u8>().prop_map(StepCommand::from_bits);
    let snva = || (normalized(), qos()).prop_map(|(value, qualifier)| SetpointNormalized { value, qualifier });
    let ssva = || (any::<i16>(), qos()).prop_map(|(value, qualifier)| SetpointScaled { value, qualifier });
    let sflt = || (float(), qos()).prop_map(|(value, qualifier)| SetpointFloat { value, qualifier });
    let bsc = || any::<u32>().prop_map(BitstringCommand);
    let unit = || Just(());

    arm!(M_SP_NA_1, 1, siq(), unit());
    arm!(M_SP_TA_1, 4, siq(), cp24());
    arm!(M_SP_TB_1, 8, siq(), cp56());
    arm!(M_DP_NA_1, 1, diq(), unit());
    arm!(M_DP_TA_1, 4, diq(), cp24());
    arm!(M_DP_TB_1, 8, diq(), cp56());
    arm!(M_ST_NA_1, 2, step(), unit());
    arm!(M_ST_TA_1, 5, step(), cp24());
    arm!(M_ST_TB_1, 9, step(), cp56());
    arm!(M_BO_NA_1, 5, bits(), unit());
    arm!(M_BO_TA_1, 8, bits(), cp24());
    arm!(M_BO_TB_1, 12, bits(), cp56());
    arm!(M_ME_NA_1, 3, nva(), unit());
    arm!(M_ME_TA_1, 6, nva(), cp24());
    arm!(M_ME_TD_1, 10, nva(), cp56());
    arm!(M_ME_NB_1, 3, sva(), unit());
    arm!(M_ME_TB_1, 6, sva(), cp24());
    arm!(M_ME_TE_1, 10, sva(), cp56());
    arm!(M_ME_NC_1, 5, flt(), unit());
    arm!(M_ME_TC_1, 8, flt(), cp24());
    arm!(M_ME_TF_1, 12, flt(), cp56());
    arm!(M_IT_NA_1, 5, bcr(), unit());
    arm!(M_IT_TA_1, 8, bcr(), cp24());
    arm!(M_IT_TB_1, 12, bcr(), cp56());
    arm!(M_EP_TA_1, 6, sep(), cp24());
    arm!(M_EP_TD_1, 10, sep(), cp56());
    arm!(M_EP_TB_1, 7, spe(), cp24());
    arm!(M_EP_TE_1, 11, spe(), cp56());
    arm!(M_EP_TC_1, 7, oci(), cp24());
    arm!(M_EP_TF_1, 11, oci(), cp56());
    arm!(M_PS_NA_1, 5, (any::<u16>(), any::<u16>(), quality()).prop_map(|(status, change, quality)| PackedSinglePoints { status, change, quality }), unit());
    arm!(M_ME_ND_1, 2, normalized(), unit());
    arm!(C_SC_NA_1, 1, sco(), unit());
    arm!(C_SC_TA_1, 8, sco(), cp56());
    arm!(C_DC_NA_1, 1, dco(), unit());
    arm!(C_DC_TA_1, 8, dco(), cp56());
    arm!(C_RC_NA_1, 1, rco(), unit());
    arm!(C_RC_TA_1, 8, rco(), cp56());
    arm!(C_SE_NA_1, 3, snva(), unit());
    arm!(C_SE_TA_1, 10, snva(), cp56());
    arm!(C_SE_NB_1, 3, ssva(), unit());
    arm!(C_SE_TB_1, 10, ssva(), cp56());
    arm!(C_SE_NC_1, 5, sflt(), unit());
    arm!(C_SE_TC_1, 12, sflt(), cp56());
    arm!(C_BO_NA_1, 4, bsc(), unit());
    arm!(C_BO_TA_1, 11, bsc(), cp56());
    arm!(M_EI_NA_1, 1, any::<u8>().prop_map(EndOfInitialization), unit());
    arm!(C_IC_NA_1, 1, any::<u8>().prop_map(Interrogation), unit());
    arm!(C_CI_NA_1, 1, any::<u8>().prop_map(CounterInterrogation), unit());
    arm!(C_RD_NA_1, 0, Just(Read), unit());
    arm!(C_CS_NA_1, 7, Just(ClockSync), cp56());
    arm!(C_TS_NA_1, 2, any::<u16>().prop_map(TestCommand), unit());
    arm!(C_RP_NA_1, 1, any::<u8>().prop_map(ResetProcess), unit());
    arm!(C_CD_NA_1, 2, cp16().prop_map(DelayAcquisition), unit());
    arm!(C_TS_TA_1, 9, any::<u16>().prop_map(TestCounter), cp56());
    arm!(P_ME_NA_1, 3, (normalized(), qpm()).prop_map(|(value, qualifier)| ParameterNormalized { value, qualifier }), unit());
    arm!(P_ME_NB_1, 3, (any::<i16>(), qpm()).prop_map(|(value, qualifier)| ParameterScaled { value, qualifier }), unit());
    arm!(P_ME_NC_1, 5, (float(), qpm()).prop_map(|(value, qualifier)| ParameterFloat { value, qualifier }), unit());
    arm!(P_AC_NA_1, 1, any::<u8>().prop_map(ParameterActivation), unit());
    arm!(F_FR_NA_1, 6, (any::<u16>(), lof(), any::<u8>()).prop_map(|(name, length, qualifier)| FileReady { name, length, qualifier }), unit());
    arm!(
        F_SR_NA_1,
        7,
        (any::<u16>(), any::<u8>(), lof(), any::<u8>()).prop_map(|(name, section, length, qualifier)| SectionReady { name, section, length, qualifier }),
        unit()
    );
    arm!(F_SC_NA_1, 4, (any::<u16>(), any::<u8>(), any::<u8>()).prop_map(|(name, section, qualifier)| CallSelect { name, section, qualifier }), unit());
    arm!(
        F_LS_NA_1,
        5,
        (any::<u16>(), any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(name, section, qualifier, checksum)| LastSection {
            name,
            section,
            qualifier,
            checksum
        }),
        unit()
    );
    arm!(F_AF_NA_1, 4, (any::<u16>(), any::<u8>(), any::<u8>()).prop_map(|(name, section, qualifier)| FileAck { name, section, qualifier }), unit());
    {
        // A segment is variable: one object whose data fills what the ASDU has room for.
        let room = usize::from(profile.max_asdu_len) - profile.header_len() - profile.ioa.octets() - 4;
        let s = (any::<u32>(), any::<u16>(), any::<u8>(), vec(any::<u8>(), 0..=room), any::<u32>())
            .prop_map(move |(r, name, section, data, base)| Objects::from(place(vec![(r, Segment { name, section, data }, ())], base, max, sequence)));
        out.push((TypeId::F_SG_NA_1, s.boxed()));
    }
    arm!(F_DR_TA_1, 13, (any::<u16>(), lof(), any::<u8>()).prop_map(|(name, length, status)| DirectoryEntry { name, length, status }), cp56());
    arm!(F_SC_NB_1, 16, (any::<u16>(), cp56(), cp56()).prop_map(|(name, start, stop)| QueryLog { name, start, stop }), unit());
    out
}

/// Type identifications without a typed form: they round-trip as `Raw`.
pub fn untyped_ids() -> Vec<u8> {
    let typed: Vec<u8> = (1..=21).chain(30..=40).chain(45..=51).chain(58..=64).chain([70]).chain(100..=107).chain(110..=113).chain(120..=127).collect();
    (0..=255u8).filter(|id| !typed.contains(id)).collect()
}

pub fn raw(profile: &Profile) -> BoxedStrategy<Objects> {
    let room = usize::from(profile.max_asdu_len) - profile.header_len();
    (proptest::sample::select(untyped_ids()), 0u8..=127, vec(any::<u8>(), 0..=room))
        .prop_map(|(t, count, body)| Objects::Raw(Raw { type_id: TypeId(t), count, body }))
        .boxed()
}
