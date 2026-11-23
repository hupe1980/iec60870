//! The controlled station: every acceptance scenario and edge case, sans-IO.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic, clippy::float_cmp)]
#![allow(clippy::assert_is_empty, clippy::too_many_lines, clippy::doc_markdown, clippy::cast_lossless, clippy::cast_precision_loss, clippy::similar_names)]

mod station_support;

use std::time::Duration;

use iec60870::prelude::*;
use iec60870::station::{GroupId, Parameter, ServerConfig, ServerEvent};
use station_support::{BASE_MS, Rig, database, points};

const CA: CommonAddress = CommonAddress(1);

fn act<E>(ioa: u32, e: E) -> Asdu
where
    Objects: From<InformationObject<E>>,
{
    Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(ioa), e))
}

fn started() -> Rig {
    let mut rig = Rig::default_rig();
    let m = rig.connect(GroupId(0));
    rig.start(m);
    rig
}

const ACTCON: u8 = 7;
const DEACTCON: u8 = 9;
const ACTTERM: u8 = 10;

// ---- select-before-operate (constitution V) -------------------------------------------------

#[test]
fn execute_without_select_is_refused_and_the_handler_is_not_called() {
    let mut rig = started();
    rig.send(0, &act(5000, SingleCommand::new(true)));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, ACTCON, true)]);
    assert!(rig.handler.executes.is_empty() && rig.handler.selects.is_empty());
}

#[test]
fn select_then_execute_confirms_and_terminates() {
    let mut rig = started();
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    let con = rig.take(0);
    assert_eq!((con[0].cot.cause, con[0].cot.negative), (Cause::ACTIVATION_CON, false));
    assert!(matches!(&con[0].objects, Objects::SingleCommand(o) if o[0].element.is_select()), "the select is mirrored");
    rig.send(0, &act(5000, SingleCommand::new(true)));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, ACTCON, false), (TypeId::C_SC_NA_1, ACTTERM, false)]);
    assert_eq!(rig.handler.selects.len(), 1);
    assert_eq!(rig.handler.executes.len(), 1);
    let e = rig.handler.executes[0];
    assert_eq!((e.phase, e.ioa, e.common_address, e.command), (Phase::Execute, Ioa(5000), CA, Command::single(true)));
    // The selection is consumed: a second execute is refused.
    rig.send(0, &act(5000, SingleCommand::new(true)));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, ACTCON, true)]);
}

#[test]
fn an_execute_after_the_select_timeout_is_refused() {
    let mut rig = started();
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    rig.take(0);
    rig.advance(Duration::from_secs(11));
    rig.send(0, &act(5000, SingleCommand::new(true)));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, ACTCON, true)]);
    assert!(rig.handler.executes.is_empty());
}

#[test]
fn an_execute_that_does_not_match_the_select_is_refused() {
    // Another value.
    let mut rig = started();
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    rig.take(0);
    rig.send(0, &act(5000, SingleCommand::new(false)));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, ACTCON, true)]);
    // Another originator.
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    rig.take(0);
    let mut other = act(5000, SingleCommand::new(true));
    other.cot = other.cot.with_originator(9);
    rig.send(0, &other);
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, ACTCON, true)]);
    // Another type (the time-tagged form).
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    rig.take(0);
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(5000), SingleCommand::new(true)).at(station_support::clock())));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_TA_1, ACTCON, true)]);
    assert!(rig.handler.executes.is_empty());
}

#[test]
fn an_execute_from_another_connection_is_refused() {
    let mut rig = Rig::default_rig();
    let a = rig.connect(GroupId(0));
    rig.start(a);
    rig.send(a, &act(5000, SingleCommand::new(true).select()));
    let g = rig.station.add_group();
    let b = rig.connect(g);
    rig.start(b);
    rig.send(b, &act(5000, SingleCommand::new(true)));
    assert_eq!(rig.causes(b), [(TypeId::C_SC_NA_1, ACTCON, true)]);
    assert!(rig.handler.executes.is_empty());
}

#[test]
fn a_second_select_by_another_originator_is_refused_but_the_same_one_reselects() {
    let mut rig = started();
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    let mut other = act(5000, SingleCommand::new(true).select());
    other.cot = other.cot.with_originator(3);
    rig.send(0, &other);
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, ACTCON, false), (TypeId::C_SC_NA_1, ACTCON, true), (TypeId::C_SC_NA_1, ACTCON, false)]);
}

#[test]
fn deactivation_cancels_a_select() {
    let mut rig = started();
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    let mut deact = act(5000, SingleCommand::new(true).select());
    deact.cot = Cot::DEACTIVATION;
    rig.send(0, &deact);
    rig.send(0, &deact);
    rig.send(0, &act(5000, SingleCommand::new(true)));
    assert_eq!(
        rig.causes(0),
        [(TypeId::C_SC_NA_1, ACTCON, false), (TypeId::C_SC_NA_1, DEACTCON, false), (TypeId::C_SC_NA_1, DEACTCON, true), (TypeId::C_SC_NA_1, ACTCON, true)]
    );
    assert_eq!(rig.handler.cancels.len(), 1);
}

#[test]
fn direct_points_execute_directly_and_refuse_a_select() {
    let mut rig = started();
    rig.send(0, &act(5001, DoubleCommand::on()));
    rig.send(0, &act(5001, DoubleCommand::on().select()));
    assert_eq!(rig.causes(0), [(TypeId::C_DC_NA_1, ACTCON, false), (TypeId::C_DC_NA_1, ACTTERM, false), (TypeId::C_DC_NA_1, ACTCON, true)]);
    assert_eq!(rig.handler.executes.len(), 1);
    assert!(rig.handler.selects.is_empty());
}

#[test]
fn direct_or_select_points_take_both() {
    let mut rig = started();
    rig.send(0, &act(5002, SetpointFloat::new(1.5)));
    rig.send(0, &act(5002, SetpointFloat::new(2.5).select()));
    rig.send(0, &act(5002, SetpointFloat::new(2.5)));
    // A select followed by a different execute is refused (the select protects the point).
    rig.send(0, &act(5002, SetpointFloat::new(3.0).select()));
    rig.send(0, &act(5002, SetpointFloat::new(9.0)));
    let causes = rig.causes(0);
    assert_eq!(
        causes,
        [
            (TypeId::C_SE_NC_1, ACTCON, false),
            (TypeId::C_SE_NC_1, ACTTERM, false),
            (TypeId::C_SE_NC_1, ACTCON, false),
            (TypeId::C_SE_NC_1, ACTCON, false),
            (TypeId::C_SE_NC_1, ACTTERM, false),
            (TypeId::C_SE_NC_1, ACTCON, false),
            (TypeId::C_SE_NC_1, ACTCON, true),
        ]
    );
    assert_eq!(rig.handler.executes.iter().map(|e| e.command).collect::<Vec<_>>(), [Command::setpoint_float(1.5), Command::setpoint_float(2.5)]);
}

#[test]
fn a_refused_command_is_confirmed_negatively_without_termination() {
    let mut rig = started();
    rig.handler.refuse = true;
    rig.send(0, &act(5001, DoubleCommand::off()));
    rig.send(0, &act(5000, SingleCommand::new(true).select()));
    assert_eq!(rig.causes(0), [(TypeId::C_DC_NA_1, ACTCON, true), (TypeId::C_SC_NA_1, ACTCON, true)]);
}

#[test]
fn bitstring_commands_are_direct() {
    let mut rig = started();
    rig.send(0, &act(5003, BitstringCommand(0xA5A5_0000)));
    assert_eq!(rig.causes(0), [(TypeId::C_BO_NA_1, ACTCON, false), (TypeId::C_BO_NA_1, ACTTERM, false)]);
}

#[test]
fn every_handler_call_carries_its_context() {
    let mut rig = started();
    let mut a = act(5001, DoubleCommand::on());
    a.cot = a.cot.with_originator(7).test();
    rig.send(0, &a);
    let r = rig.handler.executes[0];
    assert_eq!((r.connection, r.common_address, r.ioa, r.originator, r.test, r.phase), (rig.masters[0].id, CA, Ioa(5001), 7, true, Phase::Execute));
    assert!(r.to_string().contains("originator 7"), "{r}");
    // The confirmation mirrors the originator.
    assert_eq!(rig.take(0)[0].cot.originator, 7);
}

#[test]
fn time_tagged_commands_pass_their_time_to_the_handler() {
    let mut rig = started();
    let t = Cp56Time2a::from_unix_millis(BASE_MS + 5).unwrap();
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(5001), DoubleCommand::off()).at(t)));
    assert_eq!(rig.causes(0), [(TypeId::C_DC_TA_1, ACTCON, false), (TypeId::C_DC_TA_1, ACTTERM, false)]);
    assert_eq!(rig.handler.executes[0].time, Some(t));
}

// ---- negative confirmations COT 44–47 -------------------------------------------------------

#[test]
fn unknown_ioa_is_cot_47() {
    let mut rig = started();
    rig.send(0, &act(4242, SingleCommand::new(true)));
    // A known IOA with another command kind is unknown for that type.
    rig.send(0, &act(5000, DoubleCommand::on()));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, 47, true), (TypeId::C_DC_NA_1, 47, true)]);
    assert!(rig.handler.executes.is_empty());
}

#[test]
fn unknown_common_address_is_cot_46() {
    let mut rig = started();
    rig.send(0, &Asdu::new(CommonAddress(9), Cot::ACTIVATION, InformationObject::new(Ioa(5000), SingleCommand::new(true))));
    rig.send(0, &Asdu::new(CommonAddress(9), Cot::ACTIVATION, InformationObject::new(Ioa(0), Interrogation::STATION)));
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, 46, true), (TypeId::C_IC_NA_1, 46, true)]);
}

#[test]
fn unknown_type_is_cot_44() {
    let mut rig = started();
    // A monitor type sent to the outstation, a private type, and C_TS_NA_1 (excluded in 104).
    rig.send(0, &Asdu::new(CA, Cot::SPONTANEOUS, InformationObject::new(Ioa(1), SinglePoint::new(true))));
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, Raw { type_id: TypeId(200), count: 1, body: vec![0, 0, 0, 1, 2] }));
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, Raw { type_id: TypeId::C_TS_NA_1, count: 1, body: vec![0, 0, 0, 0xAA, 0x55] }));
    assert_eq!(rig.causes(0), [(TypeId::M_SP_NA_1, 44, true), (TypeId(200), 44, true), (TypeId::C_TS_NA_1, 44, true)]);
}

#[test]
fn unknown_cause_is_cot_45() {
    let mut rig = started();
    let mut a = act(5000, SingleCommand::new(true));
    a.cot = Cot::SPONTANEOUS;
    rig.send(0, &a);
    let mut gi = act(0, Interrogation::STATION);
    gi.cot = Cot::REQUEST;
    rig.send(0, &gi);
    let mut cs = Asdu::new(CA, Cot::SPONTANEOUS, InformationObject::new(Ioa(0), ClockSync).at(station_support::clock()));
    rig.send(0, &cs);
    cs.cot = Cot::ACTIVATION;
    let mut rd = Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(100), Read));
    rig.send(0, &rd);
    rd.cot = Cot::REQUEST;
    assert_eq!(rig.causes(0), [(TypeId::C_SC_NA_1, 45, true), (TypeId::C_IC_NA_1, 45, true), (TypeId::C_CS_NA_1, 45, true), (TypeId::C_RD_NA_1, 45, true)]);
}

#[test]
fn an_asdu_that_does_not_decode_is_dropped_and_counted() {
    let mut rig = started();
    rig.send_bytes(0, &[0x2D, 0x01, 0x06]);
    assert!(rig.take(0).is_empty());
    assert_eq!(rig.station.dropped_asdus(), 1);
}

#[test]
fn a_command_with_two_objects_is_refused() {
    let mut rig = started();
    let a = Asdu::new(CA, Cot::ACTIVATION, [InformationObject::new(Ioa(5001), DoubleCommand::on()), InformationObject::new(Ioa(5001), DoubleCommand::off())]);
    rig.send(0, &a);
    assert_eq!(rig.causes(0), [(TypeId::C_DC_NA_1, ACTCON, true)]);
    assert!(rig.handler.executes.is_empty());
}

// ---- clock synchronisation: the station's time comes from its clock -------------------------

#[test]
fn clock_sync_is_handed_to_the_handler_and_applied_to_later_time_tags() {
    let mut rig = started();
    let master_time = Cp56Time2a::from_unix_millis(BASE_MS + 3_600_000).unwrap();
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(0), ClockSync).at(master_time)));
    let con = rig.take(0);
    assert_eq!((con[0].cot.cause, con[0].cot.negative), (Cause::ACTIVATION_CON, false));
    assert!(matches!(&con[0].objects, Objects::ClockSync(o) if o[0].time == master_time));
    assert_eq!(rig.handler.clock_syncs, [master_time]);
    assert!(rig.events.iter().any(|e| matches!(e, ServerEvent::ClockSynchronized { time, .. } if *time == master_time)));
    assert_eq!(rig.station.time(), master_time);
    rig.station.update(CA, Ioa(100), true).unwrap();
    rig.tick();
    let p = points(&rig.take(0));
    assert_eq!(p[0].time, Some(iec60870::station::Timestamp::Cp56(master_time)));
}

#[test]
fn a_refused_clock_sync_is_negative_and_changes_nothing() {
    let mut rig = started();
    rig.handler.refuse = true;
    let t = Cp56Time2a::from_unix_millis(BASE_MS + 99_000).unwrap();
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(0), ClockSync).at(t)));
    assert_eq!(rig.causes(0), [(TypeId::C_CS_NA_1, ACTCON, true)]);
    assert_eq!(rig.station.time(), station_support::clock());
    rig.handler.refuse = false;
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(1), ClockSync).at(t)));
    assert_eq!(rig.causes(0), [(TypeId::C_CS_NA_1, 47, true)]);
}

// ---- test command, reset process, delay acquisition, parameters ------------------------------

#[test]
fn test_command_107_is_mirrored() {
    let mut rig = started();
    let t = station_support::clock();
    let tc = Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(0), TestCounter(0x1234)).at(t));
    rig.send(0, &tc);
    let con = rig.take(0);
    assert_eq!(con[0].cot.cause, Cause::ACTIVATION_CON);
    assert!(matches!(&con[0].objects, Objects::TestCommandCp56(o) if o[0].element == TestCounter(0x1234) && o[0].time == t));
    rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(1), TestCounter(1)).at(t)));
    rig.send(0, &Asdu::new(CommonAddress(0xFFFF), Cot::ACTIVATION, InformationObject::new(Ioa(0), TestCounter(1)).at(t)));
    rig.send(0, &Asdu::new(CA, Cot::DEACTIVATION, InformationObject::new(Ioa(0), TestCounter(1)).at(t)));
    assert_eq!(rig.causes(0), [(TypeId::C_TS_TA_1, 47, true), (TypeId::C_TS_TA_1, 46, true), (TypeId::C_TS_TA_1, 45, true)]);
}

#[test]
fn test_command_104_and_delay_acquisition_work_where_the_profile_permits_them() {
    let profile = Profile::IEC101;
    let mut rig = Rig::new(database(), ServerConfig { profile, end_of_initialization: None, ..ServerConfig::default() });
    let m = rig.connect(GroupId(0));
    rig.start(m);
    rig.send(m, &act(0, TestCommand::PATTERN));
    rig.send(m, &act(0, DelayAcquisition(Cp16Time2a(120))));
    assert_eq!(rig.causes(m), [(TypeId::C_TS_NA_1, ACTCON, false), (TypeId::C_CD_NA_1, ACTCON, false)]);
}

#[test]
fn reset_process_asks_the_handler_and_qrp_2_clears_the_event_buffer() {
    let mut rig = Rig::default_rig();
    let m = rig.connect(GroupId(0));
    rig.station.update(CA, Ioa(100), true).unwrap();
    assert_eq!(rig.station.pending_events(GroupId(0)), 1);
    rig.start(m);
    rig.take(m);
    rig.station.update(CA, Ioa(100), false).unwrap();
    rig.send(m, &act(0, ResetProcess::EVENT_BUFFER));
    // The event went out with the reset's confirmation; nothing is pending afterwards.
    rig.handler.refuse = true;
    rig.send(m, &act(0, ResetProcess::GENERAL));
    let causes = rig.causes(m);
    assert!(causes.contains(&(TypeId::C_RP_NA_1, ACTCON, false)) && causes.contains(&(TypeId::C_RP_NA_1, ACTCON, true)), "{causes:?}");
    assert_eq!(rig.handler.resets, [ResetProcess::EVENT_BUFFER, ResetProcess::GENERAL]);
}

#[test]
fn reset_process_qrp_2_drops_unsent_events() {
    let mut rig = Rig::default_rig();
    let m = rig.connect(GroupId(0));
    rig.start(m);
    for i in 0..20 {
        rig.station.update(CA, Ioa(200), i as f32).unwrap();
        rig.station.update(CA, Ioa(100), i % 2 == 0).unwrap();
    }
    let before = rig.station.pending_events(GroupId(0));
    assert_eq!(before, 40);
    rig.send(m, &act(0, ResetProcess::EVENT_BUFFER));
    rig.tick();
    // Only what had already been sent is still owed; the rest was cleared.
    assert!(rig.station.pending_events(GroupId(0)) < before);
}

#[test]
fn parameters_are_handed_to_the_handler_and_confirmed() {
    let mut rig = started();
    let p = ParameterFloat { value: 0.5, qualifier: ParameterQualifier::THRESHOLD };
    rig.send(0, &act(200, p));
    rig.send(0, &act(201, ParameterScaled { value: 3, qualifier: ParameterQualifier::SMOOTHING }));
    rig.send(0, &act(0, ParameterActivation::LOADED_PARAMETERS));
    rig.send(0, &act(200, ParameterActivation::OBJECT_PARAMETER));
    // A parameter for a single point (not a measured value) or an unknown IOA is COT 47.
    rig.send(0, &act(100, ParameterNormalized { value: Normalized(1), qualifier: ParameterQualifier::THRESHOLD }));
    rig.send(0, &act(999, ParameterActivation::OBJECT_PARAMETER));
    assert_eq!(
        rig.causes(0),
        [
            (TypeId::P_ME_NC_1, ACTCON, false),
            (TypeId::P_ME_NB_1, ACTCON, false),
            (TypeId::P_AC_NA_1, ACTCON, false),
            (TypeId::P_AC_NA_1, ACTCON, false),
            (TypeId::P_ME_NA_1, 47, true),
            (TypeId::P_AC_NA_1, 47, true),
        ]
    );
    assert_eq!(rig.handler.parameters.len(), 4);
    assert_eq!(rig.handler.parameters[0].parameter, Parameter::Float(p));
    rig.handler.refuse = true;
    rig.send(0, &act(200, p));
    assert_eq!(rig.causes(0), [(TypeId::P_ME_NC_1, ACTCON, true)]);
}

// ---- read -----------------------------------------------------------------------------------

#[test]
fn read_answers_with_the_current_value_or_cot_47() {
    let mut rig = started();
    rig.station.update(CA, Ioa(200), 30.25f32).unwrap();
    rig.tick();
    rig.take(0);
    rig.send(0, &Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(200), Read)));
    let r = rig.take(0);
    assert_eq!((r[0].type_id(), r[0].cot.cause), (TypeId::M_ME_NC_1, Cause::REQUEST));
    assert_eq!(points(&r)[0].value, Value::from(30.25f32));
    rig.send(0, &Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(7777), Read)));
    rig.send(0, &Asdu::new(CommonAddress(0xFFFF), Cot::REQUEST, InformationObject::new(Ioa(200), Read)));
    assert_eq!(rig.causes(0), [(TypeId::C_RD_NA_1, 47, true), (TypeId::C_RD_NA_1, 46, true)]);
}

// ---- interrogation --------------------------------------------------------------------------

#[test]
fn station_interrogation_answers_from_current_state() {
    let mut rig = started();
    rig.station.update(CA, Ioa(100), true).unwrap();
    rig.tick();
    rig.take(0);
    rig.send(0, &act(0, Interrogation::STATION));
    let replies = rig.take(0);
    let first = &replies[0];
    let last = replies.last().unwrap();
    assert_eq!((first.type_id(), first.cot.cause), (TypeId::C_IC_NA_1, Cause::ACTIVATION_CON));
    assert_eq!((last.type_id(), last.cot.cause), (TypeId::C_IC_NA_1, Cause::ACTIVATION_TERMINATION));
    let p = points(&replies);
    // Counters are not in station interrogation; every point's type has no time tag.
    assert_eq!(p.iter().map(|p| p.ioa.0).collect::<Vec<_>>(), [100, 101, 200, 201]);
    assert!(p.iter().all(|p| p.cause.cause == Cause::INTERROGATED_BY_STATION && p.time.is_none()));
    assert_eq!(p[0].value, Value::from(true));
}

#[test]
fn group_interrogation_answers_only_the_group_and_an_empty_group_only_confirms() {
    let mut rig = started();
    rig.send(0, &act(0, Interrogation::group(2).unwrap()));
    let p = points(&rig.take(0));
    assert_eq!(p.iter().map(|p| (p.ioa.0, p.cause.cause.value())).collect::<Vec<_>>(), [(101, 22), (200, 22)]);
    rig.send(0, &act(0, Interrogation::group(16).unwrap()));
    assert_eq!(rig.causes(0), [(TypeId::C_IC_NA_1, ACTCON, false), (TypeId::C_IC_NA_1, ACTTERM, false)]);
}

#[test]
fn a_bad_qualifier_or_ioa_is_refused() {
    let mut rig = started();
    rig.send(0, &act(0, Interrogation(0)));
    rig.send(0, &act(0, Interrogation(37)));
    rig.send(0, &act(5, Interrogation::STATION));
    let mut deact = act(0, Interrogation::STATION);
    deact.cot = Cot::DEACTIVATION;
    rig.send(0, &deact);
    assert_eq!(
        rig.causes(0),
        [(TypeId::C_IC_NA_1, ACTCON, true), (TypeId::C_IC_NA_1, ACTCON, true), (TypeId::C_IC_NA_1, 47, true), (TypeId::C_IC_NA_1, DEACTCON, true)]
    );
}

#[test]
fn a_gi_while_a_gi_is_in_progress_is_refused() {
    let mut rig = Rig::default_rig();
    // k = 1: the first GI's replies stay queued while the second GI arrives.
    let m = rig.connect_with(GroupId(0), iec60870::cs104::Config { k: 1, w: 1, ..iec60870::cs104::Config::default() });
    rig.start(m);
    let gi = act(0, Interrogation::STATION).to_vec(&Profile::IEC104).unwrap();
    // Two GIs in one TCP segment: the second arrives before the first is answered.
    rig.masters[m].link.submit(&gi, rig.now).unwrap();
    rig.masters[m].link.submit(&gi, rig.now).unwrap();
    rig.pump();
    for _ in 0..30 {
        rig.advance(Duration::from_secs(10));
    }
    let causes = rig.causes(m);
    assert_eq!(causes.iter().filter(|c| **c == (TypeId::C_IC_NA_1, ACTCON, true)).count(), 1, "{causes:?}");
    assert_eq!(causes.iter().filter(|c| **c == (TypeId::C_IC_NA_1, ACTTERM, false)).count(), 1, "{causes:?}");
}

#[test]
fn broadcast_gi_answers_every_common_address() {
    let mut db = database();
    let _ = db.insert(CommonAddress(2), Ioa(1), true);
    let mut rig = Rig::new(db, ServerConfig { end_of_initialization: None, ..ServerConfig::default() });
    let m = rig.connect(GroupId(0));
    rig.start(m);
    rig.send(m, &Asdu::new(CommonAddress(0xFFFF), Cot::ACTIVATION, InformationObject::new(Ioa(0), Interrogation::STATION)));
    let r = rig.take(m);
    let terms: Vec<_> = r.iter().filter(|a| a.cot.cause == Cause::ACTIVATION_TERMINATION).map(|a| a.common_address).collect();
    assert_eq!(terms, [CommonAddress(1), CommonAddress(2)]);
}

#[test]
fn large_interrogations_are_packed_up_to_the_maximum_length() {
    let db: std::collections::BTreeMap<_, _> = (0..1000).map(|i| ((CA, Ioa(i)), PointEntry::new(i % 3 == 0))).collect();
    let mut rig = Rig::new(db, ServerConfig { end_of_initialization: None, ..ServerConfig::default() });
    let m = rig.connect(GroupId(0));
    rig.start(m);
    rig.send(m, &act(0, Interrogation::STATION));
    for _ in 0..30 {
        rig.advance(Duration::from_secs(10));
    }
    let r = rig.take(m);
    let data: Vec<_> = r.iter().filter(|a| a.type_id() == TypeId::M_SP_NA_1).collect();
    // 4 octets per single point after a 6-octet header: 60 per ASDU of at most 249 octets.
    assert!(data.iter().all(|a| a.len() <= 60 && a.encoded_len(&Profile::IEC104) <= 249));
    assert_eq!(data.iter().map(|a| a.len()).sum::<usize>(), 1000);
    assert_eq!(data.len(), 17);
    assert_eq!(r.last().unwrap().cot.cause, Cause::ACTIVATION_TERMINATION);
}

// ---- counter interrogation ------------------------------------------------------------------

#[test]
fn counter_interrogation_reads_freezes_and_resets() {
    let mut rig = started();
    rig.send(0, &act(0, CounterInterrogation::GENERAL));
    let r = rig.take(0);
    assert_eq!((r[0].cot.cause, r.last().unwrap().cot.cause), (Cause::ACTIVATION_CON, Cause::ACTIVATION_TERMINATION));
    let p = points(&r);
    assert_eq!(p.iter().map(|p| (p.ioa.0, p.cause.cause.value())).collect::<Vec<_>>(), [(300, 37), (301, 37)]);

    // Freeze, then the counter moves on, and a read reports the frozen value.
    rig.send(0, &act(0, CounterInterrogation::GENERAL.with_freeze(CounterInterrogation::FREEZE)));
    assert_eq!(rig.causes(0), [(TypeId::C_CI_NA_1, ACTCON, false), (TypeId::C_CI_NA_1, ACTTERM, false)]);
    rig.station.update(CA, Ioa(300), BinaryCounterReading::new(1500)).unwrap();
    rig.send(0, &act(0, CounterInterrogation::group(1).unwrap()));
    let p = points(&rig.take(0));
    assert_eq!(p.len(), 1);
    assert_eq!((p[0].ioa, p[0].cause.cause.value(), p[0].value), (Ioa(300), 38, Value::from(BinaryCounterReading::new(1000))));

    // Freeze with reset: the frozen value is the count, the counter restarts at 0, sequence + 1.
    rig.send(0, &act(0, CounterInterrogation::group(1).unwrap().with_freeze(CounterInterrogation::FREEZE_AND_RESET)));
    rig.take(0);
    assert_eq!(rig.station.database().value(CA, Ioa(300)), Some(Value::from(BinaryCounterReading::new(0).with_sequence(1))));
    rig.send(0, &act(0, CounterInterrogation::group(1).unwrap()));
    assert_eq!(points(&rig.take(0))[0].value, Value::from(BinaryCounterReading::new(1500)));

    // Reset only.
    rig.send(0, &act(0, CounterInterrogation::group(2).unwrap().with_freeze(CounterInterrogation::RESET)));
    rig.take(0);
    assert_eq!(rig.station.database().value(CA, Ioa(301)).map(|v| matches!(v, Value::Counter(c) if c.value() == 0)), Some(true));
    assert_eq!(rig.handler.counters.len(), 6);

    // The handler can refuse; a bad request qualifier is refused.
    rig.handler.refuse = true;
    rig.send(0, &act(0, CounterInterrogation::GENERAL));
    rig.handler.refuse = false;
    rig.send(0, &act(0, CounterInterrogation(0)));
    assert_eq!(rig.causes(0), [(TypeId::C_CI_NA_1, ACTCON, true), (TypeId::C_CI_NA_1, ACTCON, true)]);
}

// ---- events ---------------------------------------------------------------------------------

#[test]
fn end_of_initialisation_comes_first_after_start() {
    let mut rig = Rig::new(database(), ServerConfig::default());
    let m = rig.connect(GroupId(0));
    rig.station.update(CA, Ioa(100), true).unwrap();
    rig.start(m);
    let r = rig.take(m);
    assert_eq!((r[0].type_id(), r[0].cot.cause), (TypeId::M_EI_NA_1, Cause::INITIALIZED));
    assert_eq!(r[1].type_id(), TypeId::M_SP_TB_1);
}

#[test]
fn spontaneous_events_carry_the_clock_time_in_the_configured_format() {
    let mut db = database();
    let _ = db.insert(CA, Ioa(400), 0i16).time_format(TimeFormat::None);
    let _ = db.insert(CA, Ioa(401), false).spontaneous(false);
    let mut rig = Rig::new(db, ServerConfig { end_of_initialization: None, ..ServerConfig::default() });
    let m = rig.connect(GroupId(0));
    rig.start(m);
    rig.station.update(CA, Ioa(200), 1.0f32).unwrap();
    rig.station.update(CA, Ioa(400), 3i16).unwrap();
    rig.station.update(CA, Ioa(401), true).unwrap();
    rig.tick();
    let r = rig.take(m);
    assert_eq!(r.iter().map(Asdu::type_id).collect::<Vec<_>>(), [TypeId::M_ME_TF_1, TypeId::M_ME_NB_1]);
    assert_eq!(points(&r)[0].time, Some(iec60870::station::Timestamp::Cp56(station_support::clock())));
    // Updates are checked against the point.
    assert!(rig.station.update(CA, Ioa(200), true).is_err());
    assert!(rig.station.update(CA, Ioa(999), true).is_err());
    let t = Cp56Time2a::from_unix_millis(BASE_MS - 1000).unwrap();
    rig.station.update_at(CA, Ioa(100), true, t).unwrap();
    rig.tick();
    assert_eq!(points(&rig.take(m))[0].time, Some(iec60870::station::Timestamp::Cp56(t)));
}

#[test]
fn events_are_kept_until_acknowledged_and_re_sent_after_reconnection() {
    let mut rig = Rig::default_rig();
    let a = rig.connect(GroupId(0));
    rig.start(a);
    for i in 0..3 {
        rig.station.update(CA, Ioa(200), i as f32).unwrap();
        rig.tick();
    }
    assert_eq!(points(&rig.take(a)).len(), 3);
    // The master received them but has not acknowledged (w = 8, t2 not expired).
    assert_eq!(rig.station.pending_events(GroupId(0)), 3);
    // The connection drops; a new one is started: the three come again, in order.
    let id = rig.masters[a].id;
    rig.station.handle_disconnect(id, rig.now);
    rig.pump();
    let b = rig.connect(GroupId(0));
    rig.start(b);
    let again: Vec<_> = points(&rig.take(b)).iter().map(|p| p.value).collect();
    assert_eq!(again, [Value::from(0f32), Value::from(1f32), Value::from(2f32)]);
    // Once acknowledged (t2), they are released.
    rig.advance(Duration::from_secs(11));
    assert_eq!(rig.station.pending_events(GroupId(0)), 0);
}

#[test]
fn an_update_storm_beyond_the_buffer_reports_the_loss_and_keeps_the_newest() {
    let mut rig = Rig::new(database(), ServerConfig { event_capacity: 10, end_of_initialization: None, ..ServerConfig::default() });
    let m = rig.connect(GroupId(0));
    for i in 0..25 {
        rig.station.update(CA, Ioa(201), i16::try_from(i).unwrap()).unwrap();
    }
    rig.pump();
    let lost: usize = rig.events.iter().filter_map(|e| if let ServerEvent::EventsLost { count, .. } = e { Some(*count) } else { None }).sum();
    assert_eq!(lost, 15);
    rig.start(m);
    let values: Vec<_> = points(&rig.take(m)).iter().map(|p| p.value).collect();
    assert_eq!(values, (15..25).map(|i: i16| Value::from(i)).collect::<Vec<_>>());
}

#[test]
fn cyclic_and_background_points_are_sent_periodically() {
    let mut db = Database::new();
    let _ = db.insert(CA, Ioa(1), 1.0f32).cyclic(true).spontaneous(false);
    let _ = db.insert(CA, Ioa(2), 2i16).background(true).spontaneous(false);
    let config = ServerConfig {
        cyclic_period: Duration::from_secs(5),
        background_period: Some(Duration::from_secs(30)),
        end_of_initialization: None,
        ..ServerConfig::default()
    };
    let mut rig = Rig::new(db, config);
    let m = rig.connect(GroupId(0));
    rig.start(m);
    for _ in 0..31 {
        rig.advance(Duration::from_secs(1));
    }
    let r = rig.take(m);
    let periodic = r.iter().filter(|a| a.cot.cause == Cause::PERIODIC && a.type_id() == TypeId::M_ME_NC_1).count();
    let background = r.iter().filter(|a| a.cot.cause == Cause::BACKGROUND_SCAN && a.type_id() == TypeId::M_ME_NB_1).count();
    assert_eq!((periodic, background), (6, 1));
}

#[test]
fn events_are_packed_by_type_up_to_the_maximum_length() {
    let mut rig = Rig::default_rig();
    let m = rig.connect(GroupId(0));
    for i in 0..50 {
        rig.station.update(CA, Ioa(100), i % 2 == 0).unwrap();
    }
    rig.station.update(CA, Ioa(200), 5.0f32).unwrap();
    rig.start(m);
    let r = rig.take(m);
    // M_SP_TB_1 is 11 octets per object: 22 fit after the header.
    assert_eq!(
        r.iter().map(|a| (a.type_id(), a.len())).collect::<Vec<_>>(),
        [(TypeId::M_SP_TB_1, 22), (TypeId::M_SP_TB_1, 22), (TypeId::M_SP_TB_1, 6), (TypeId::M_ME_TF_1, 1)]
    );
}

// ---- redundancy groups ----------------------------------------------------------------------

#[test]
fn a_switch_over_closes_the_old_connection_and_re_sends_its_unacknowledged_events_first() {
    let mut rig = Rig::default_rig();
    let a = rig.connect(GroupId(0));
    let b = rig.connect(GroupId(0));
    rig.start(a);
    for i in 0..4 {
        rig.station.update(CA, Ioa(201), i).unwrap();
        rig.tick();
    }
    assert_eq!(points(&rig.take(a)).len(), 4);
    assert!(rig.take(b).is_empty(), "the standby connection gets nothing");
    rig.start(b);
    assert!(rig.masters[a].closed, "the previously started connection is closed");
    assert!(rig.events.iter().any(|e| matches!(e, ServerEvent::SwitchedOver { .. })));
    assert_eq!(rig.station.started(GroupId(0)), Some(rig.masters[b].id));
    rig.station.update(CA, Ioa(201), 99).unwrap();
    rig.tick();
    let values: Vec<_> = points(&rig.take(b)).iter().map(|p| p.value).collect();
    assert_eq!(values, [0i16, 1, 2, 3, 99].map(Value::from));
}

#[test]
fn the_standby_connection_is_not_acted_on() {
    let mut rig = Rig::default_rig();
    let a = rig.connect(GroupId(0));
    let _b = rig.connect(GroupId(0));
    rig.start(a);
    // An I-frame on the never-started connection closes it at the link; the command never
    // reaches the handler.
    let bytes = act(5001, DoubleCommand::on()).to_vec(&Profile::IEC104).unwrap();
    let mut frame = vec![0x68, (bytes.len() + 4) as u8, 0, 0, 0, 0];
    frame.extend(&bytes);
    let id = rig.masters[1].id;
    rig.station.handle_input(id, &frame, rig.now, &mut rig.handler);
    rig.pump();
    assert!(rig.handler.executes.is_empty());
    assert!(rig.events.iter().any(|e| matches!(e, ServerEvent::Disconnected { connection, .. } if *connection == id)));
}

#[test]
fn groups_have_separate_buffers() {
    let mut rig = Rig::default_rig();
    let g1 = rig.station.add_group();
    let a = rig.connect(GroupId(0));
    let b = rig.connect(g1);
    rig.start(a);
    rig.start(b);
    rig.station.update(CA, Ioa(100), true).unwrap();
    rig.tick();
    assert_eq!(points(&rig.take(a)).len(), 1);
    assert_eq!(points(&rig.take(b)).len(), 1);
    assert_eq!(rig.station.connections().count(), 2);
}

#[test]
fn stopdt_keeps_the_events_for_the_next_start() {
    let mut rig = Rig::default_rig();
    let a = rig.connect(GroupId(0));
    rig.start(a);
    rig.masters[a].link.stop(rig.now).unwrap();
    rig.pump();
    rig.station.update(CA, Ioa(100), true).unwrap();
    rig.tick();
    assert!(rig.take(a).is_empty());
    assert!(rig.events.iter().any(|e| matches!(e, ServerEvent::Stopped(_))));
    rig.start(a);
    assert_eq!(points(&rig.take(a)).len(), 1);
}

// ---- the link seam: a polled, class-queued link (as an unbalanced 101 secondary) -------------

mod polled {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use iec60870::driver::Output;
    use iec60870::station::{Class, LinkError, LinkEvent, StationLink};
    use iec60870::time::Instant;

    /// A link that queues per class and is acknowledged per class; the test holds the other
    /// end of `wire`.
    pub type Sent = Rc<RefCell<Vec<(Class, Vec<u8>)>>>;

    #[derive(Default, Clone)]
    pub struct Wire {
        pub sent: Sent,
        pub events: Rc<RefCell<VecDeque<LinkEvent>>>,
    }

    pub struct PolledLink(pub Wire);

    impl StationLink for PolledLink {
        fn handle_input(&mut self, _: &[u8], _: Instant) {}
        fn handle_timeout(&mut self, _: Instant) {}
        fn handle_disconnect(&mut self, _: Instant) {}
        fn poll_output(&mut self) -> Option<Output<LinkEvent>> {
            self.0.events.borrow_mut().pop_front().map(Output::Event)
        }
        fn is_closed(&self) -> bool {
            false
        }
        fn is_started(&self) -> bool {
            true
        }
        fn can_send(&self, _: Class) -> bool {
            true
        }
        fn submit(&mut self, asdu: &[u8], class: Class, _: Instant) -> Result<(), LinkError> {
            self.0.sent.borrow_mut().push((class, asdu.to_vec()));
            Ok(())
        }
        fn start(&mut self, _: Instant) -> Result<(), LinkError> {
            Ok(())
        }
        fn stop(&mut self, _: Instant) -> Result<(), LinkError> {
            Ok(())
        }
        fn close(&mut self) {}
    }
}

#[test]
fn a_class_queued_link_acknowledges_per_class_and_unconfirmed_events_are_sent_again() {
    use iec60870::station::{Class, ControlledStation, LinkEvent};
    use polled::{PolledLink, Wire};
    let mut db = Database::new();
    let _ = db.insert(CA, Ioa(1), 0i16);
    let _ = db.insert(CA, Ioa(2), 0.0f32).cyclic(true).spontaneous(false);
    let config = ServerConfig { end_of_initialization: None, cyclic_period: Duration::from_secs(1), ..ServerConfig::default() };
    let mut st: ControlledStation<PolledLink> = ControlledStation::new(db, config, station_support::clock);
    let wire = Wire::default();
    let id = st.attach(PolledLink(wire.clone()), GroupId(0));
    let mut handler = station_support::Recorder::default();
    let mut now = Instant::ZERO;
    st.handle_timeout(now);
    wire.events.borrow_mut().push_back(LinkEvent::Started);
    st.handle_input(id, &[], now, &mut handler);
    st.update(CA, Ioa(1), 5i16).unwrap();
    now += Duration::from_millis(1500);
    st.handle_timeout(now);
    let classes: Vec<Class> = wire.sent.borrow().iter().map(|(c, _)| *c).collect();
    assert_eq!(classes, [Class::One, Class::Two], "the event as class 1, the cyclic data as class 2");
    // The class 2 reply is fetched first; the event stays owed until class 1 is acknowledged.
    wire.events.borrow_mut().push_back(LinkEvent::Acknowledged { class: Some(Class::Two), count: 1 });
    st.handle_timeout(now);
    assert_eq!(st.pending_events(GroupId(0)), 1);
    // The link gives up on the class 1 frame: the event is sent again, then acknowledged.
    wire.events.borrow_mut().push_back(LinkEvent::Unconfirmed { class: Some(Class::One) });
    st.handle_timeout(now);
    let sent = wire.sent.borrow().clone();
    assert_eq!(sent.len(), 3);
    assert_eq!(sent[2], sent[0], "the same event ASDU again");
    wire.events.borrow_mut().push_back(LinkEvent::Acknowledged { class: Some(Class::One), count: 1 });
    st.handle_timeout(now);
    assert_eq!(st.pending_events(GroupId(0)), 0);
}

#[test]
fn malformed_clock_sync_preserves_last_accepted_offset() {
    let mut rig = started();
    let accepted = Cp56Time2a::from_unix_millis(BASE_MS + 60_000).unwrap();
    for (timestamp, negative) in
        [(accepted, false), (accepted.with_invalid(true), true), (Cp56Time2a::default(), true), (Cp56Time2a::from_octets([0, 0, 0, 0, 1, 1, 100]), true)]
    {
        rig.send(0, &Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(0), ClockSync).at(timestamp)));
        assert_eq!(rig.causes(0), [(TypeId::C_CS_NA_1, ACTCON, negative)]);
        assert_eq!(rig.station.time(), accepted);
    }
    assert_eq!(rig.handler.clock_syncs, [accepted]);
    assert_eq!(rig.events.iter().filter(|e| matches!(e, ServerEvent::ClockSynchronized { .. })).count(), 1);
}

#[test]
fn station_clock_quality_and_calendar_limit_survive_applied_offset() {
    use std::sync::{Arc, Mutex};
    let mut rig = Rig::default_rig();
    let base = station_support::clock();
    let source = Arc::new(Mutex::new(base.with_invalid(true)));
    let reading = Arc::clone(&source);
    rig.station = iec60870::station::ControlledStation::new(database(), ServerConfig { end_of_initialization: None, ..ServerConfig::default() }, move || {
        *reading.lock().unwrap()
    });
    let m = rig.connect(GroupId(0));
    rig.start(m);
    let latest = Cp56Time2a::from_unix_millis(4_102_444_799_999).unwrap();
    let sync = Asdu::new(CA, Cot::ACTIVATION, InformationObject::new(Ioa(0), ClockSync).at(latest));
    rig.send(0, &sync);
    assert_eq!(rig.causes(0), [(TypeId::C_CS_NA_1, ACTCON, true)]);
    *source.lock().unwrap() = base;
    rig.send(0, &sync);
    assert_eq!(rig.causes(0), [(TypeId::C_CS_NA_1, ACTCON, false)]);
    *source.lock().unwrap() = base.with_substituted(true).with_summer_time(true);
    assert_eq!(rig.station.time(), latest.with_substituted(true).with_summer_time(true));
    *source.lock().unwrap() = base.with_invalid(true);
    assert!(rig.station.time().is_invalid());
    *source.lock().unwrap() = Cp56Time2a::from_unix_millis(BASE_MS + 1).unwrap();
    assert!(rig.station.time().is_invalid());
    assert_eq!(rig.handler.clock_syncs, [latest]);
}

#[test]
fn map_source_preserves_address_kind_and_current_reading() {
    use iec60870::station::{PointEntry, UpdateError};
    let store = std::collections::BTreeMap::from([((CA, Ioa(7)), PointEntry::new(20i16)), ((CommonAddress(2), Ioa(7)), PointEntry::new(false))]);
    let mut rig = Rig::new(store, ServerConfig::default());
    let m = rig.connect(GroupId(0));
    rig.start(m);
    rig.take(m);
    assert!(matches!(rig.station.update(CA, Ioa(8), 1i16), Err(UpdateError::UnknownPoint { .. })));
    assert!(matches!(rig.station.update(CA, Ioa(7), true), Err(UpdateError::KindMismatch { .. })));
    assert_eq!(rig.station.database().value(CA, Ioa(7)), Some(20i16.into()));
    rig.station.update(CA, Ioa(7), 21i16).unwrap();
    rig.tick();
    rig.take(m);
    rig.send(m, &Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(7), Read)));
    assert_eq!(points(&rig.take(m))[0].value, 21i16.into());
    assert_eq!(rig.station.database().value(CommonAddress(2), Ioa(7)), Some(false.into()));
}
