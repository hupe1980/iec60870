//! The edge cases, the refusals, and the wire constants — each constant here is the value
//! Wireshark's IEC 60870-5 dissector and lib60870 use, so a typo in the library fails a test
//! rather than an interoperability session.

#![allow(
    clippy::pedantic,
    clippy::complexity,
    clippy::manual_is_multiple_of,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use iec60870::asdu::{DecodeErrorKind, Field};
use iec60870::prelude::*;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

const P104: Profile = Profile::IEC104;

fn time() -> Cp56Time2a {
    Cp56Time2a::from_date_time(DateTime::new(2026, 11, 22, 14, 3, 7, 123)).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------

#[test]
fn type_identifications_are_the_standard_numbers() {
    let expected: &[(TypeId, u8, &str)] = &[
        (TypeId::M_SP_NA_1, 1, "M_SP_NA_1"),
        (TypeId::M_SP_TA_1, 2, "M_SP_TA_1"),
        (TypeId::M_DP_NA_1, 3, "M_DP_NA_1"),
        (TypeId::M_DP_TA_1, 4, "M_DP_TA_1"),
        (TypeId::M_ST_NA_1, 5, "M_ST_NA_1"),
        (TypeId::M_ST_TA_1, 6, "M_ST_TA_1"),
        (TypeId::M_BO_NA_1, 7, "M_BO_NA_1"),
        (TypeId::M_BO_TA_1, 8, "M_BO_TA_1"),
        (TypeId::M_ME_NA_1, 9, "M_ME_NA_1"),
        (TypeId::M_ME_TA_1, 10, "M_ME_TA_1"),
        (TypeId::M_ME_NB_1, 11, "M_ME_NB_1"),
        (TypeId::M_ME_TB_1, 12, "M_ME_TB_1"),
        (TypeId::M_ME_NC_1, 13, "M_ME_NC_1"),
        (TypeId::M_ME_TC_1, 14, "M_ME_TC_1"),
        (TypeId::M_IT_NA_1, 15, "M_IT_NA_1"),
        (TypeId::M_IT_TA_1, 16, "M_IT_TA_1"),
        (TypeId::M_EP_TA_1, 17, "M_EP_TA_1"),
        (TypeId::M_EP_TB_1, 18, "M_EP_TB_1"),
        (TypeId::M_EP_TC_1, 19, "M_EP_TC_1"),
        (TypeId::M_PS_NA_1, 20, "M_PS_NA_1"),
        (TypeId::M_ME_ND_1, 21, "M_ME_ND_1"),
        (TypeId::M_SP_TB_1, 30, "M_SP_TB_1"),
        (TypeId::M_DP_TB_1, 31, "M_DP_TB_1"),
        (TypeId::M_ST_TB_1, 32, "M_ST_TB_1"),
        (TypeId::M_BO_TB_1, 33, "M_BO_TB_1"),
        (TypeId::M_ME_TD_1, 34, "M_ME_TD_1"),
        (TypeId::M_ME_TE_1, 35, "M_ME_TE_1"),
        (TypeId::M_ME_TF_1, 36, "M_ME_TF_1"),
        (TypeId::M_IT_TB_1, 37, "M_IT_TB_1"),
        (TypeId::M_EP_TD_1, 38, "M_EP_TD_1"),
        (TypeId::M_EP_TE_1, 39, "M_EP_TE_1"),
        (TypeId::M_EP_TF_1, 40, "M_EP_TF_1"),
        (TypeId::S_IT_TC_1, 41, "S_IT_TC_1"),
        (TypeId::C_SC_NA_1, 45, "C_SC_NA_1"),
        (TypeId::C_DC_NA_1, 46, "C_DC_NA_1"),
        (TypeId::C_RC_NA_1, 47, "C_RC_NA_1"),
        (TypeId::C_SE_NA_1, 48, "C_SE_NA_1"),
        (TypeId::C_SE_NB_1, 49, "C_SE_NB_1"),
        (TypeId::C_SE_NC_1, 50, "C_SE_NC_1"),
        (TypeId::C_BO_NA_1, 51, "C_BO_NA_1"),
        (TypeId::C_SC_TA_1, 58, "C_SC_TA_1"),
        (TypeId::C_DC_TA_1, 59, "C_DC_TA_1"),
        (TypeId::C_RC_TA_1, 60, "C_RC_TA_1"),
        (TypeId::C_SE_TA_1, 61, "C_SE_TA_1"),
        (TypeId::C_SE_TB_1, 62, "C_SE_TB_1"),
        (TypeId::C_SE_TC_1, 63, "C_SE_TC_1"),
        (TypeId::C_BO_TA_1, 64, "C_BO_TA_1"),
        (TypeId::M_EI_NA_1, 70, "M_EI_NA_1"),
        (TypeId::S_CH_NA_1, 81, "S_CH_NA_1"),
        (TypeId::S_RP_NA_1, 82, "S_RP_NA_1"),
        (TypeId::S_AR_NA_1, 83, "S_AR_NA_1"),
        (TypeId::S_KR_NA_1, 84, "S_KR_NA_1"),
        (TypeId::S_KS_NA_1, 85, "S_KS_NA_1"),
        (TypeId::S_KC_NA_1, 86, "S_KC_NA_1"),
        (TypeId::S_ER_NA_1, 87, "S_ER_NA_1"),
        (TypeId::S_US_NA_1, 90, "S_US_NA_1"),
        (TypeId::S_UQ_NA_1, 91, "S_UQ_NA_1"),
        (TypeId::S_UR_NA_1, 92, "S_UR_NA_1"),
        (TypeId::S_UK_NA_1, 93, "S_UK_NA_1"),
        (TypeId::S_UA_NA_1, 94, "S_UA_NA_1"),
        (TypeId::S_UC_NA_1, 95, "S_UC_NA_1"),
        (TypeId::C_IC_NA_1, 100, "C_IC_NA_1"),
        (TypeId::C_CI_NA_1, 101, "C_CI_NA_1"),
        (TypeId::C_RD_NA_1, 102, "C_RD_NA_1"),
        (TypeId::C_CS_NA_1, 103, "C_CS_NA_1"),
        (TypeId::C_TS_NA_1, 104, "C_TS_NA_1"),
        (TypeId::C_RP_NA_1, 105, "C_RP_NA_1"),
        (TypeId::C_CD_NA_1, 106, "C_CD_NA_1"),
        (TypeId::C_TS_TA_1, 107, "C_TS_TA_1"),
        (TypeId::P_ME_NA_1, 110, "P_ME_NA_1"),
        (TypeId::P_ME_NB_1, 111, "P_ME_NB_1"),
        (TypeId::P_ME_NC_1, 112, "P_ME_NC_1"),
        (TypeId::P_AC_NA_1, 113, "P_AC_NA_1"),
        (TypeId::F_FR_NA_1, 120, "F_FR_NA_1"),
        (TypeId::F_SR_NA_1, 121, "F_SR_NA_1"),
        (TypeId::F_SC_NA_1, 122, "F_SC_NA_1"),
        (TypeId::F_LS_NA_1, 123, "F_LS_NA_1"),
        (TypeId::F_AF_NA_1, 124, "F_AF_NA_1"),
        (TypeId::F_SG_NA_1, 125, "F_SG_NA_1"),
        (TypeId::F_DR_TA_1, 126, "F_DR_TA_1"),
        (TypeId::F_SC_NB_1, 127, "F_SC_NB_1"),
    ];
    for (id, value, name) in expected {
        assert_eq!(id.0, *value);
        assert_eq!(id.name(), Some(*name));
    }
    assert_eq!(TypeSet::STANDARD.len(), expected.len());
    assert_eq!(TypeSet::STANDARD.iter().collect::<Vec<_>>(), expected.iter().map(|e| e.0).collect::<Vec<_>>());
    assert_eq!(TypeId(128).name(), None);
    assert!(!TypeId(42).is_standard());
}

/// The information-element octets per object (after the IOA), as in Wireshark's
/// `asdu_length` table and lib60870's `getElementDataSize`.
#[test]
fn element_lengths_match_the_reference_tables() {
    let expected: &[(u8, usize)] = &[
        (1, 1),
        (2, 4),
        (3, 1),
        (4, 4),
        (5, 2),
        (6, 5),
        (7, 5),
        (8, 8),
        (9, 3),
        (10, 6),
        (11, 3),
        (12, 6),
        (13, 5),
        (14, 8),
        (15, 5),
        (16, 8),
        (17, 6),
        (18, 7),
        (19, 7),
        (20, 5),
        (21, 2),
        (30, 8),
        (31, 8),
        (32, 9),
        (33, 12),
        (34, 10),
        (35, 10),
        (36, 12),
        (37, 12),
        (38, 10),
        (39, 11),
        (40, 11),
        (45, 1),
        (46, 1),
        (47, 1),
        (48, 3),
        (49, 3),
        (50, 5),
        (51, 4),
        (58, 8),
        (59, 8),
        (60, 8),
        (61, 10),
        (62, 10),
        (63, 12),
        (64, 11),
        (70, 1),
        (100, 1),
        (101, 1),
        (102, 0),
        (103, 7),
        (104, 2),
        (105, 1),
        (106, 2),
        (107, 9),
        (110, 3),
        (111, 3),
        (112, 5),
        (113, 1),
        (120, 6),
        (121, 7),
        (122, 4),
        (123, 5),
        (124, 4),
        (125, 4), // plus the segment octets
        (126, 13),
        (127, 16),
    ];
    let profile = Profile::IEC104.with_types(TypeSet::ALL).with_max_asdu_len(255);
    let mut runner = TestRunner::default();
    let arms = common::arms(&profile, false);
    assert_eq!(arms.len(), expected.len());
    for (id, strategy) in arms {
        let len = expected.iter().find(|(t, _)| *t == id.0).map(|(_, l)| *l).unwrap();
        let objects = loop {
            let o = strategy.new_tree(&mut runner).unwrap().current();
            if !o.is_empty() {
                break o;
            }
        };
        let n = objects.len();
        let segment = match &objects {
            Objects::Segment(s) => s.iter().map(|o| o.element.data.len()).sum(),
            _ => 0,
        };
        let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, objects);
        assert_eq!(asdu.encoded_len(&profile), 6 + n * (3 + len) + segment, "{id}");
    }
}

#[test]
fn causes_of_transmission_are_the_standard_numbers() {
    let expected: &[(Cause, u8)] = &[
        (Cause::PERIODIC, 1),
        (Cause::BACKGROUND_SCAN, 2),
        (Cause::SPONTANEOUS, 3),
        (Cause::INITIALIZED, 4),
        (Cause::REQUEST, 5),
        (Cause::ACTIVATION, 6),
        (Cause::ACTIVATION_CON, 7),
        (Cause::DEACTIVATION, 8),
        (Cause::DEACTIVATION_CON, 9),
        (Cause::ACTIVATION_TERMINATION, 10),
        (Cause::RETURN_REMOTE, 11),
        (Cause::RETURN_LOCAL, 12),
        (Cause::FILE_TRANSFER, 13),
        (Cause::AUTHENTICATION, 14),
        (Cause::SESSION_KEY, 15),
        (Cause::USER_ROLE_AND_UPDATE_KEY, 16),
        (Cause::INTERROGATED_BY_STATION, 20),
        (Cause::REQUESTED_BY_GENERAL_COUNTER, 37),
        (Cause::UNKNOWN_TYPE_ID, 44),
        (Cause::UNKNOWN_CAUSE, 45),
        (Cause::UNKNOWN_COMMON_ADDRESS, 46),
        (Cause::UNKNOWN_IOA, 47),
    ];
    for (cause, value) in expected {
        assert_eq!(cause.value(), *value);
        assert!(cause.is_standard());
    }
    assert_eq!(Cause::interrogated_by_group(1).unwrap().value(), 21);
    assert_eq!(Cause::interrogated_by_group(16).unwrap().value(), 36);
    assert_eq!(Cause::interrogated_by_group(17), None);
    assert_eq!(Cause::requested_by_counter_group(1).unwrap().value(), 38);
    assert_eq!(Cause::requested_by_counter_group(4).unwrap().value(), 41);
    assert_eq!(Cause::new(42).unwrap().to_string(), "cause 42");
    assert!(!Cause::new(42).unwrap().is_standard());
}

#[test]
fn cot_octet_layout() {
    // cause 0x3F, P/N 0x40, T 0x80
    assert_eq!(Cot::ACTIVATION_CON.negative().test().octet(), 0xC7);
    let cot = Cot::from_octets(0xC7, 9);
    assert_eq!((cot.cause, cot.negative, cot.test, cot.originator), (Cause::ACTIVATION_CON, true, true, 9));
    assert_eq!(Cot::from_octets(0x3F, 0).cause.value(), 63);
}

#[test]
fn element_bit_layouts() {
    assert_eq!(SinglePoint::new(true).with_quality(Quality::BLOCKED | Quality::SUBSTITUTED | Quality::NOT_TOPICAL | Quality::INVALID).bits(), 0xF1);
    assert_eq!(DoublePoint::new(DoublePointValue::On).bits(), 0x02);
    assert_eq!(Quality::OVERFLOW.bits(), 0x01);
    assert_eq!(ProtectionQuality::ELAPSED_INVALID.bits(), 0x08);
    assert_eq!(SingleEvent::new(DoublePointValue::Off).with_quality(ProtectionQuality::ELAPSED_INVALID).bits(), 0x09);
    assert_eq!((StartEvents::GENERAL | StartEvents::REVERSE).bits(), 0x21);
    assert_eq!((OutputCircuits::GENERAL | OutputCircuits::L3).bits(), 0x09);
    assert_eq!(SingleCommand::new(true).select().with_qualifier(CommandQualifier::LONG_PULSE).bits(), 0x89);
    assert_eq!(DoubleCommand::on().with_qualifier(CommandQualifier::PERSISTENT).bits(), 0x0E);
    assert_eq!(StepCommand::higher().select().bits(), 0x82);
    assert_eq!(StepCommand::from_bits(0x03).direction(), None);
    assert_eq!(SetpointQualifier::DEFAULT.select().with_ql(5).bits(), 0x85);
    assert_eq!(CounterInterrogation::GENERAL.with_freeze(CounterInterrogation::FREEZE_AND_RESET).0, 0x85);
    assert_eq!(EndOfInitialization::REMOTE_RESET.with_parameter_change(true).0, 0x82);
    assert_eq!(Interrogation::STATION.0, 20);
    assert_eq!(Interrogation::group(16).unwrap().0, 36);
    assert_eq!(ParameterQualifier::from_bits(0xC1).kind(), 1);
    assert!(ParameterQualifier::from_bits(0xC1).local_change() && ParameterQualifier::from_bits(0xC1).not_in_operation());
    let bcr = BinaryCounterReading::from_parts(1, 0xFF);
    assert_eq!((bcr.sequence(), bcr.carry(), bcr.adjusted(), bcr.invalid()), (31, true, true, true));
}

#[test]
fn profile_constants() {
    let p = Profile::IEC104;
    assert_eq!((p.cot, p.ca, p.ioa, p.max_asdu_len), (CotWidth::Two, CaWidth::Two, IoaWidth::Three, 249));
    let p = Profile::IEC101;
    assert_eq!((p.cot, p.ca, p.ioa, p.max_asdu_len), (CotWidth::One, CaWidth::One, IoaWidth::Two, 253));
    for id in [2, 4, 6, 8, 10, 12, 14, 16, 17, 18, 19, 104, 106] {
        assert!(!Profile::IEC104.permits(TypeId(id)), "{id}");
        assert!(Profile::IEC101.permits(TypeId(id)), "{id}");
    }
    assert!(!Profile::IEC101.permits(TypeId::C_TS_TA_1));
    assert!(Profile::IEC104.permits(TypeId::C_TS_TA_1));
    assert_eq!(TypeSet::IEC104.len(), TypeSet::STANDARD.len() - 13);
}

// ---------------------------------------------------------------------------------------------
// The spec's edge cases
// ---------------------------------------------------------------------------------------------

fn round_trip(profile: &Profile, asdu: &Asdu) -> Vec<u8> {
    let octets = asdu.to_vec(profile).unwrap();
    let back = Asdu::decode(&octets, profile).unwrap();
    assert_eq!(back.to_vec(profile).unwrap(), octets);
    assert_eq!(format!("{back:?}"), format!("{asdu:?}"));
    octets
}

#[test]
fn normalized_limits() {
    let asdu = Asdu::new(
        CommonAddress(1),
        Cot::SPONTANEOUS,
        [InformationObject::new(Ioa(1), MeasuredNormalized::new(Normalized::MIN)), InformationObject::new(Ioa(2), MeasuredNormalized::new(Normalized::MAX))],
    );
    let o = round_trip(&P104, &asdu);
    assert_eq!(&o[6..], &[1, 0, 0, 0x00, 0x80, 0x00, 2, 0, 0, 0xFF, 0x7F, 0x00]);
    assert_eq!(Normalized::MIN.to_f32(), -1.0);
    assert_eq!(Normalized::MAX.to_f32(), 1.0 - 2f32.powi(-15));
    assert_eq!(Normalized::from_f32(-1.0), Normalized::MIN);
    assert_eq!(Normalized::from_f32(1.0), Normalized::MAX);
    assert_eq!(Normalized::from_f32(f32::NAN), Normalized::ZERO);
}

#[test]
fn scaled_limits() {
    let asdu = Asdu::new(
        CommonAddress(1),
        Cot::SPONTANEOUS,
        [InformationObject::new(Ioa(1), MeasuredScaled::new(i16::MIN)), InformationObject::new(Ioa(2), MeasuredScaled::new(i16::MAX))],
    );
    let o = round_trip(&P104, &asdu);
    assert_eq!(&o[9..11], &[0x00, 0x80]);
    assert_eq!(&o[15..17], &[0xFF, 0x7F]);
}

#[test]
fn floats_nan_and_infinities_keep_their_bits() {
    let payload_nan = f32::from_bits(0x7FC0_1234);
    let values = [f32::NAN, payload_nan, f32::from_bits(0xFF80_0001), f32::INFINITY, f32::NEG_INFINITY, -0.0];
    let objects: Vec<_> = values.iter().enumerate().map(|(i, v)| InformationObject::new(Ioa(i as u32), MeasuredFloat::new(*v))).collect();
    let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, objects);
    let o = round_trip(&P104, &asdu);
    let Objects::MeasuredFloat(back) = Asdu::decode(&o, &P104).unwrap().objects else { panic!("type") };
    for (b, v) in back.iter().zip(values) {
        assert_eq!(b.element.value.to_bits(), v.to_bits());
    }
    assert_eq!(&o[9..13], &0x7FC0_0000u32.to_le_bytes());
}

#[test]
fn cp56_out_of_range_and_flags_are_kept_as_received() {
    // minute 61 + IV + the substituted/GEN bit 0x40; hour 25 + SU; day 0; month 13; year bit 7.
    let raw = [0x60, 0xEA, 0x80 | 0x40 | 61, 0x80 | 25, 0, 13, 0x80 | 99];
    let t = Cp56Time2a::from_octets(raw);
    assert!(!t.is_in_range() && t.is_invalid() && t.is_substituted() && t.is_summer_time());
    assert_eq!(t.minute(), 61);
    let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(5), SinglePoint::new(true)).at(t));
    let o = round_trip(&P104, &asdu);
    assert_eq!(&o[10..17], &raw);
    let Objects::SinglePointCp56(back) = Asdu::decode(&o, &P104).unwrap().objects else { panic!("type") };
    assert_eq!(back[0].time.octets(), raw);
    assert_eq!(back[0].time.to_date_time(), None);
}

#[test]
fn cp24_substituted_bit_survives() {
    let t = Cp24Time2a::from_octets([0x01, 0x02, 0x40 | 0x80 | 59]);
    let profile = Profile::IEC101;
    let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(5), SinglePoint::new(false)).at(t));
    let o = round_trip(&profile, &asdu);
    assert_eq!(&o[o.len() - 3..], &[0x01, 0x02, 0xFB]);
}

#[test]
fn packed_single_points_type_20() {
    let mut e = PackedSinglePoints::new(0xA55A, 0x00FF);
    e.quality = Quality::NOT_TOPICAL;
    let asdu = Asdu::new(CommonAddress(1), Cot::INTERROGATED_BY_STATION, InformationObject::new(Ioa(0x01_0203), e));
    let o = round_trip(&P104, &asdu);
    assert_eq!(o, [20, 1, 20, 0, 1, 0, 0x03, 0x02, 0x01, 0x5A, 0xA5, 0xFF, 0x00, 0x40]);
}

#[test]
fn bitstring32_is_little_endian() {
    let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(1), Bitstring32::new(0x1234_5678)));
    let o = round_trip(&P104, &asdu);
    assert_eq!(&o[9..], &[0x78, 0x56, 0x34, 0x12, 0x00]);
    let cmd = Asdu::new(CommonAddress(1), Cot::ACTIVATION, InformationObject::new(Ioa(1), BitstringCommand(0xDEAD_BEEF)).at(time()));
    let o = round_trip(&P104, &cmd);
    assert_eq!(o[0], 64);
    assert_eq!(&o[9..13], &[0xEF, 0xBE, 0xAD, 0xDE]);
}

#[test]
fn test_bit_and_negative_confirmation() {
    let asdu = Asdu::new(
        CommonAddress(7),
        Cot::ACTIVATION_CON.negative().test().with_originator(3),
        InformationObject::new(Ioa(2), SingleCommand::new(true).select()),
    );
    let o = round_trip(&P104, &asdu);
    assert_eq!(o, [45, 1, 0xC7, 3, 7, 0, 2, 0, 0, 0x81]);
    let back = Asdu::decode(&o, &P104).unwrap();
    assert!(back.cot.negative && back.cot.test);
    assert_eq!(back.to_string(), "C_SC_NA_1 (45) activation confirmation (7), negative, test, originator 3, CA 7, 1 object, IOA 2");
}

#[test]
fn test_command_pattern_and_gi_bytes() {
    let asdu = Asdu::new(CommonAddress(1), Cot::ACTIVATION, InformationObject::new(Ioa(0), TestCommand::PATTERN));
    assert_eq!(asdu.to_vec(&Profile::IEC101).unwrap(), [104, 1, 6, 1, 0, 0, 0xAA, 0x55]);
    let gi = Asdu::new(CommonAddress(0xFFFF), Cot::ACTIVATION, InformationObject::new(Ioa(0), Interrogation::STATION));
    assert_eq!(gi.to_vec(&P104).unwrap(), [100, 1, 6, 0, 0xFF, 0xFF, 0, 0, 0, 20]);
    let cs = Asdu::new(CommonAddress(1), Cot::ACTIVATION, InformationObject::new(Ioa(0), ClockSync).at(time()));
    assert_eq!(cs.to_vec(&P104).unwrap(), [103, 1, 6, 0, 1, 0, 0, 0, 0, 0xD3, 0x1B, 3, 14, 22, 11, 26]);
}

#[test]
fn sequence_form_writes_one_address() {
    let asdu = Asdu::new(CommonAddress(1), Cot::INTERROGATED_BY_STATION, [10, 11, 12].map(|i| InformationObject::new(Ioa(i), SinglePoint::new(i % 2 == 0))))
        .in_sequence();
    let o = round_trip(&P104, &asdu);
    assert_eq!(o, [1, 0x83, 20, 0, 1, 0, 10, 0, 0, 1, 0, 1]);
    assert_eq!(Asdu::decode(&o, &P104).unwrap().objects.ioas().collect::<Vec<_>>(), [Ioa(10), Ioa(11), Ioa(12)]);
}

// ---------------------------------------------------------------------------------------------
// Decode errors: field and offset
// ---------------------------------------------------------------------------------------------

#[test]
fn truncation_at_every_octet_names_the_field_and_its_offset() {
    let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS.with_originator(2), InformationObject::new(Ioa(9), MeasuredFloat::new(1.5)).at(time()));
    let o = asdu.to_vec(&P104).unwrap();
    assert_eq!(o.len(), 21);
    // The 104 layout of type 36: type 0, VSQ 1, COT 2, originator 3, CA 4–5, IOA 6–8,
    // float 9–12, QDS 13, CP56Time2a 14–20.
    let layout = [
        (0, Field::TypeId),
        (1, Field::Vsq),
        (2, Field::Cot),
        (3, Field::Originator),
        (4, Field::CommonAddress),
        (6, Field::Ioa),
        (9, Field::Float),
        (13, Field::Qds),
        (14, Field::Cp56Time2a),
    ];
    for len in 0..o.len() {
        let err = Asdu::decode(&o[..len], &P104).unwrap_err();
        let (start, field) = layout.iter().rev().find(|(s, _)| *s <= len).copied().unwrap();
        assert_eq!((err.field, err.offset), (field, start), "prefix {len}");
        let DecodeErrorKind::Truncated { available, .. } = err.kind else { panic!("{err}") };
        assert_eq!(available, len - start);
        assert_eq!(err.object, if start >= 6 { Some(0) } else { None });
    }
}

#[test]
fn vsq_overclaim_is_refused_at_the_first_missing_field() {
    // M_ME_TF_1 claiming 127 objects, one present.
    let mut o = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(9), MeasuredFloat::new(1.5)).at(time())).to_vec(&P104).unwrap();
    o[1] = 127;
    let err = Asdu::decode(&o, &P104).unwrap_err();
    assert_eq!((err.field, err.offset, err.object), (Field::Ioa, 21, Some(1)));
    assert_eq!(err.kind, DecodeErrorKind::Truncated { needed: 3, available: 0 });
    assert_eq!(err.to_string(), "truncated ASDU: information object 2: information object address (IOA) needs 3 octets at offset 21, 0 remain");
    // The same with SQ = 1: the element of object 2 is missing.
    o[1] = 0x80 | 127;
    let err = Asdu::decode(&o, &P104).unwrap_err();
    assert_eq!((err.field, err.offset, err.object), (Field::Float, 21, Some(1)));
}

#[test]
fn trailing_octets_and_too_long_are_refused() {
    let mut o = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(1), SinglePoint::new(true))).to_vec(&P104).unwrap();
    o.push(0xEE);
    let err = Asdu::decode(&o, &P104).unwrap_err();
    assert_eq!((err.kind, err.field, err.offset, err.object), (DecodeErrorKind::TrailingOctets { count: 1 }, Field::Asdu, 10, None));
    let long = vec![1u8; 250];
    let err = Asdu::decode(&long, &P104).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::TooLong { len: 250, max: 249 });
    assert_eq!(err.to_string(), "ASDU of 250 octets exceeds the profile's maximum of 249");
}

#[test]
fn sequence_address_overflow_is_refused() {
    let o = [1, 0x82, 3, 0, 1, 0, 0xFF, 0xFF, 0xFF, 1, 1];
    let err = Asdu::decode(&o, &P104).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::AddressOverflow { ioa: 0x100_0000, max: 0xFF_FFFF });
    assert_eq!((err.field, err.object), (Field::Ioa, Some(1)));
}

#[test]
fn zero_objects() {
    let empty = [1, 0, 3, 0, 1, 0];
    let asdu = Asdu::decode(&empty, &P104).unwrap();
    assert!(asdu.is_empty());
    assert_eq!(asdu.to_vec(&P104).unwrap(), empty);
    let err = Asdu::decode(&[1, 0, 3, 0, 1, 0, 9], &P104).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::TrailingOctets { count: 1 });
}

#[test]
fn unknown_private_forbidden_and_security_types_decode_raw() {
    let private = [200, 0x83, 3, 0, 0x34, 0x12, 1, 2, 3, 4, 5];
    let asdu = Asdu::decode(&private, &P104).unwrap();
    let Objects::Raw(raw) = &asdu.objects else { panic!("raw") };
    assert_eq!((raw.type_id, raw.count, raw.body.as_slice()), (TypeId(200), 3, &private[6..]));
    assert!(asdu.sequence);
    assert_eq!(asdu.common_address, CommonAddress(0x1234));
    assert_eq!(asdu.to_vec(&P104).unwrap(), private);
    assert_eq!(asdu.header().type_id, TypeId(200));
    // CP24Time2a type under 104: not permitted, so `Raw` — and still forwardable.
    let cp24 = [2, 1, 3, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0];
    assert!(matches!(Asdu::decode(&cp24, &P104).unwrap().objects, Objects::Raw(_)));
    assert!(matches!(Asdu::decode(&cp24, &P104.with_types(TypeSet::ALL)).unwrap().objects, Objects::SinglePointCp24(_)));
    // Security types are standard and permitted, but have no typed form yet.
    let challenge = [81, 1, 14, 0, 1, 0, 0xAB, 0xCD];
    assert!(matches!(Asdu::decode(&challenge, &P104).unwrap().objects, Objects::Raw(_)));
    // A raw body that is not even a whole object is still forwarded verbatim.
    assert_eq!(Asdu::decode(&challenge, &P104).unwrap().to_vec(&P104).unwrap(), challenge);
}

#[test]
fn header_decodes_alone() {
    let o = [36, 2, 3, 5, 0x10, 0x00];
    let h = AsduHeader::decode(&o, &P104).unwrap();
    assert_eq!((h.type_id, h.sequence, h.count, h.cot.originator, h.common_address), (TypeId::M_ME_TF_1, false, 2, 5, CommonAddress(16)));
    let err = AsduHeader::decode(&o[..4], &P104).unwrap_err();
    assert_eq!((err.field, err.offset), (Field::CommonAddress, 4));
}

// ---------------------------------------------------------------------------------------------
// Encode refusals
// ---------------------------------------------------------------------------------------------

#[test]
fn encode_refuses_what_the_profile_cannot_carry() {
    let sp = |ioa| InformationObject::new(Ioa(ioa), SinglePoint::new(true));
    let cp24 = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, sp(1).at(Cp24Time2a::default()));
    assert_eq!(cp24.to_vec(&P104), Err(EncodeError::TypeNotPermitted { type_id: TypeId::M_SP_TA_1 }));
    assert_eq!(cp24.to_vec(&P104).unwrap_err().to_string(), "the profile does not permit M_SP_TA_1 (2)");
    let ts = Asdu::new(CommonAddress(1), Cot::ACTIVATION, InformationObject::new(Ioa(0), TestCommand::PATTERN));
    assert_eq!(ts.to_vec(&P104), Err(EncodeError::TypeNotPermitted { type_id: TypeId::C_TS_NA_1 }));

    let narrow = P104.with_ioa(IoaWidth::Two);
    let err = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, sp(70_000)).to_vec(&narrow).unwrap_err();
    assert_eq!(err, EncodeError::ValueOutOfRange { field: Field::Ioa, object: Some(0), value: 70_000, max: 0xFFFF });
    assert_eq!(err.to_string(), "information object 1: information object address (IOA) 70000 exceeds 65535, the largest the profile can carry");

    let err = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS.with_originator(4), sp(1)).to_vec(&Profile::IEC101).unwrap_err();
    assert_eq!(err, EncodeError::ValueOutOfRange { field: Field::Originator, object: None, value: 4, max: 0 });
    assert_eq!(err.to_string(), "originator address 4 cannot be carried by a one-octet cause of transmission");

    let err = Asdu::new(CommonAddress(300), Cot::SPONTANEOUS, sp(1)).to_vec(&Profile::IEC101).unwrap_err();
    assert_eq!(err, EncodeError::ValueOutOfRange { field: Field::CommonAddress, object: None, value: 300, max: 255 });

    let many: Vec<_> = (0..128).map(sp).collect();
    assert_eq!(Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, many).to_vec(&P104), Err(EncodeError::TooManyObjects { count: 128 }));

    let gap = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, [sp(1), sp(3)]).in_sequence();
    assert_eq!(gap.to_vec(&P104), Err(EncodeError::NotInSequence { object: 1, expected: Ioa(2), found: Ioa(3) }));

    let step = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(1), StepPosition::new(64)));
    let err = step.to_vec(&P104).unwrap_err();
    assert_eq!(err, EncodeError::ValueOutOfRange { field: Field::Vti, object: Some(0), value: 64, max: 63 });
    assert_eq!(err.to_string(), "information object 1: step position 64 is outside −64…63");
    let step = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(1), StepPosition::new(-65)));
    assert!(matches!(step.to_vec(&P104), Err(EncodeError::ValueOutOfRange { field: Field::Vti, .. })));

    let lof = Asdu::new(CommonAddress(1), Cot::FILE_TRANSFER, InformationObject::new(Ioa(1), FileReady { name: 1, length: 0x100_0000, qualifier: 0 }));
    assert!(matches!(lof.to_vec(&P104), Err(EncodeError::ValueOutOfRange { field: Field::Lof, value: 0x100_0000, .. })));

    let seg = Asdu::new(CommonAddress(1), Cot::FILE_TRANSFER, InformationObject::new(Ioa(1), Segment { name: 1, section: 1, data: vec![0; 256] }));
    assert!(matches!(seg.to_vec(&P104.with_max_asdu_len(255)), Err(EncodeError::ValueOutOfRange { field: Field::Los, value: 256, max: 255, .. })));
    let seg = Asdu::new(CommonAddress(1), Cot::FILE_TRANSFER, InformationObject::new(Ioa(1), Segment { name: 1, section: 1, data: vec![0; 237] }));
    assert_eq!(seg.to_vec(&P104), Err(EncodeError::TooLong { len: 250, max: 249 }));

    let raw = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, Raw { type_id: TypeId(200), count: 128, body: vec![] });
    assert_eq!(raw.to_vec(&P104), Err(EncodeError::TooManyObjects { count: 128 }));
}

#[test]
fn a_short_buffer_reports_the_size_needed_and_is_not_written() {
    let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(9), MeasuredFloat::new(1.5)).at(time()));
    let needed = asdu.encoded_len(&P104);
    let mut buf = vec![0xEE; needed - 1];
    assert_eq!(asdu.encode(&P104, &mut buf), Err(EncodeError::BufferTooSmall { needed, available: needed - 1 }));
    assert!(buf.iter().all(|b| *b == 0xEE));
    // An error found after the size is known writes nothing either.
    let mut big = vec![0xEE; 300];
    let bad = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(1), StepPosition::new(100)));
    assert!(bad.encode(&P104, &mut big).is_err());
    assert!(big.iter().all(|b| *b == 0xEE));
    // A larger buffer: exactly `needed` octets written, the rest untouched.
    assert_eq!(asdu.encode(&P104, &mut big), Ok(needed));
    assert!(big[needed..].iter().all(|b| *b == 0xEE));
}

#[test]
fn errors_are_std_errors() {
    fn is_error<E: std::error::Error + Send + Sync + 'static>(_: &E) {}
    is_error(&Asdu::decode(&[], &P104).unwrap_err());
    is_error(&EncodeError::TooManyObjects { count: 200 });
    assert_eq!(Asdu::decode(&[], &P104).unwrap_err().to_string(), "truncated ASDU: type identification needs 1 octet at offset 0, 0 remain");
}

#[test]
fn debug_output_is_readable() {
    let asdu =
        Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, InformationObject::new(Ioa(4001), MeasuredFloat::new(21.5).with_quality(Quality::INVALID)).at(time()));
    assert_eq!(
        format!("{asdu:?}"),
        "Asdu { cot: Cot(spontaneous (3)), common_address: CommonAddress(1), sequence: false, objects: MeasuredFloatCp56([InformationObject { ioa: 4001, element: MeasuredFloat { value: 21.5, quality: Quality(IV) }, time: Cp56Time2a(2026-11-22 14:03:07.123) }]) }"
    );
    let gi = Asdu::new(CommonAddress(1), Cot::ACTIVATION, InformationObject::new(Ioa(0), Interrogation::STATION));
    assert_eq!(
        format!("{gi:?}"),
        "Asdu { cot: Cot(activation (6)), common_address: CommonAddress(1), sequence: false, objects: Interrogation([InformationObject { ioa: 0, element: Interrogation(20) }]) }"
    );
}
