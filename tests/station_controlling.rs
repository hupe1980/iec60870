//! The controlling station: every acceptance scenario and edge case, sans-IO, against a
//! scripted outstation link.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::assert_is_empty, clippy::too_many_lines, clippy::doc_markdown, clippy::cast_lossless, clippy::cast_precision_loss, clippy::similar_names)]

mod station_support;

use std::time::Duration;

use iec60870::prelude::*;
use iec60870::station::{ClientConfig, Error, Parameter};
use station_support::{MasterRig, clock};

const CA: CommonAddress = CommonAddress(1);

fn rig() -> MasterRig {
    MasterRig::new(ClientConfig::default())
}

#[test]
fn gi_confirmed_answered_and_terminated_completes() {
    let mut r = rig();
    let id = r.master.interrogate(CA, Interrogation::STATION, r.now).unwrap();
    r.pump();
    assert_eq!(r.received[0].type_id(), TypeId::C_IC_NA_1);
    assert_eq!(r.received[0].cot, Cot::ACTIVATION);
    r.mirror(Cause::ACTIVATION_CON, false);
    r.reply(&Asdu::new(
        CA,
        Cot::INTERROGATED_BY_STATION,
        [InformationObject::new(Ioa(1), SinglePoint::new(true)), InformationObject::new(Ioa(2), SinglePoint::new(false))],
    ));
    r.reply(&Asdu::new(CA, Cot::INTERROGATED_BY_STATION, InformationObject::new(Ioa(3), MeasuredFloat::new(1.5))));
    let mut term = r.received[0].clone();
    term.cot = Cot::ACTIVATION_TERMINATION;
    r.reply(&term);
    assert_eq!(r.progress(id), ["Confirmed", "Completed"]);
    let points: Vec<_> = r.events.iter().filter_map(|e| if let Event::Point(p) = e { Some(p.ioa.0) } else { None }).collect();
    assert_eq!(points, [1, 2, 3]);
    assert!(
        r.events
            .iter()
            .any(|e| matches!(e, Event::InterrogationComplete { common_address, qualifier } if *common_address == CA && *qualifier == Interrogation::STATION))
    );
    assert!(!r.master.is_pending(id));
}

#[test]
fn gi_without_termination_times_out_naming_the_termination() {
    let mut r = rig();
    let id = r.master.interrogate(CA, Interrogation::STATION, r.now).unwrap();
    r.pump();
    r.mirror(Cause::ACTIVATION_CON, false);
    r.advance(Duration::from_secs(59));
    assert_eq!(r.progress(id), ["Confirmed"]);
    r.advance(Duration::from_secs(2));
    assert_eq!(r.progress(id), ["Confirmed", "Failed(timed out awaiting the activation termination)"]);
}

#[test]
fn no_confirmation_times_out_naming_the_confirmation() {
    let mut r = rig();
    let id = r.master.clock_sync(CA, r.now).unwrap();
    r.pump();
    // The outstation acknowledges at the link (t2) but never confirms.
    r.advance(Duration::from_secs(11));
    r.advance(Duration::from_secs(5));
    assert_eq!(r.progress(id), ["Failed(timed out awaiting the activation confirmation)"]);
}

#[test]
fn a_negative_confirmation_is_an_error_carrying_the_cot() {
    let mut r = rig();
    let id = r.master.command(CA, Ioa(5000), Command::single(true), r.now).unwrap();
    r.pump();
    r.mirror(Cause::ACTIVATION_CON, true);
    let failed = r.events.iter().find_map(|e| match e {
        Event::Request { id: i, progress: Progress::Failed(Error::Negative { cot }) } if *i == id => Some(*cot),
        _ => None,
    });
    assert_eq!(failed, Some(Cot::ACTIVATION_CON.negative()));
}

#[test]
fn cot_44_to_47_mirrors_are_negative() {
    for cause in [Cause::UNKNOWN_TYPE_ID, Cause::UNKNOWN_CAUSE, Cause::UNKNOWN_COMMON_ADDRESS, Cause::UNKNOWN_IOA] {
        let mut r = rig();
        let id = r.master.read(CA, Ioa(7), r.now).unwrap();
        r.pump();
        r.mirror(cause, true);
        assert_eq!(r.progress(id), [format!("Failed(negative confirmation: {})", Cot::new(cause).negative())]);
    }
}

#[test]
fn sbo_reports_selected_confirmed_completed() {
    let mut r = rig();
    let id = r.master.select_and_execute(CA, Ioa(5000), Command::double(DoublePointValue::On), r.now).unwrap();
    r.pump();
    assert!(matches!(&r.received[0].objects, Objects::DoubleCommand(o) if o[0].element.is_select()));
    r.mirror(Cause::ACTIVATION_CON, false);
    assert_eq!(r.received.len(), 2, "the execute follows the select's confirmation");
    assert!(matches!(&r.received[1].objects, Objects::DoubleCommand(o) if !o[0].element.is_select() && o[0].element.state() == DoublePointValue::On));
    r.mirror(Cause::ACTIVATION_CON, false);
    r.mirror(Cause::ACTIVATION_TERMINATION, false);
    assert_eq!(r.progress(id), ["Selected", "Confirmed", "Completed"]);
}

#[test]
fn a_refused_select_sends_no_execute() {
    let mut r = rig();
    let id = r.master.select_and_execute(CA, Ioa(5000), Command::single(true), r.now).unwrap();
    r.pump();
    r.mirror(Cause::ACTIVATION_CON, true);
    assert_eq!(r.received.len(), 1);
    assert_eq!(r.progress(id).len(), 1);
    assert!(r.progress(id)[0].starts_with("Failed(negative"));
    assert!(matches!(r.master.select_and_execute(CA, Ioa(1), Command::bitstring(1), r.now), Err(Error::InvalidArgument(_))));
}

#[test]
fn direct_commands_with_and_without_termination() {
    let mut r = rig();
    let id = r.master.command(CA, Ioa(5001), Command::setpoint_scaled(42), r.now).unwrap();
    r.pump();
    assert_eq!(r.received[0].type_id(), TypeId::C_SE_NB_1);
    r.mirror(Cause::ACTIVATION_CON, false);
    r.mirror(Cause::ACTIVATION_TERMINATION, false);
    assert_eq!(r.progress(id), ["Confirmed", "Completed"]);

    let mut r = MasterRig::new(ClientConfig { command_termination: false, time_tagged_commands: true, ..ClientConfig::default() });
    let id = r.master.command(CA, Ioa(5001), Command::setpoint_float(1.0), r.now).unwrap();
    r.pump();
    assert_eq!(r.received[0].type_id(), TypeId::C_SE_TC_1);
    assert!(matches!(&r.received[0].objects, Objects::SetpointFloatCp56(o) if o[0].time == clock()), "time from the clock");
    r.mirror(Cause::ACTIVATION_CON, false);
    assert_eq!(r.progress(id), ["Completed"]);
}

#[test]
fn counter_interrogation_completes_on_termination() {
    let mut r = rig();
    let id = r.master.counter_interrogate(CA, CounterInterrogation::GENERAL, r.now).unwrap();
    r.pump();
    r.mirror(Cause::ACTIVATION_CON, false);
    r.reply(&Asdu::new(CA, Cot::REQUESTED_BY_GENERAL_COUNTER, InformationObject::new(Ioa(300), BinaryCounterReading::new(5))));
    r.mirror(Cause::ACTIVATION_TERMINATION, false);
    assert_eq!(r.progress(id), ["Confirmed", "Completed"]);
    assert!(r.events.iter().any(|e| matches!(e, Event::CounterInterrogationComplete { .. })));
    assert!(r.events.iter().any(|e| matches!(e, Event::Point(p) if p.value == Value::from(BinaryCounterReading::new(5)))));
}

#[test]
fn read_completes_with_the_point() {
    let mut r = rig();
    let id = r.master.read(CA, Ioa(200), r.now).unwrap();
    r.pump();
    assert_eq!(r.received[0].cot.cause, Cause::REQUEST, "read uses COT 5");
    r.reply(&Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(200), MeasuredFloat::new(9.5))));
    assert_eq!(r.progress(id), ["Completed"]);
}

#[test]
fn clock_sync_carries_the_clock_time() {
    let mut r = rig();
    let id = r.master.clock_sync(CA, r.now).unwrap();
    r.pump();
    assert!(matches!(&r.received[0].objects, Objects::ClockSync(o) if o[0].time == clock()));
    r.mirror(Cause::ACTIVATION_CON, false);
    assert_eq!(r.progress(id), ["Completed"]);
}

#[test]
fn test_command_is_107_on_104() {
    let mut r = rig();
    let id = r.master.test_command(CA, r.now).unwrap();
    r.pump();
    assert!(matches!(&r.received[0].objects, Objects::TestCommandCp56(o) if o[0].time == clock() && o[0].element == TestCounter(1)));
    r.mirror(Cause::ACTIVATION_CON, false);
    assert_eq!(r.progress(id), ["Completed"]);
}

#[test]
fn reset_process_and_parameters() {
    let mut r = rig();
    let a = r.master.reset_process(CA, ResetProcess::GENERAL, r.now).unwrap();
    r.pump();
    r.mirror(Cause::ACTIVATION_CON, false);
    let b = r.master.parameter(CA, Ioa(200), ParameterFloat { value: 0.1, qualifier: ParameterQualifier::THRESHOLD }, r.now).unwrap();
    r.pump();
    assert_eq!(r.received.last().unwrap().type_id(), TypeId::P_ME_NC_1);
    r.mirror(Cause::ACTIVATION_CON, false);
    let c = r.master.parameter(CA, Ioa(0), Parameter::Activation(ParameterActivation::LOADED_PARAMETERS), r.now).unwrap();
    r.pump();
    r.mirror(Cause::ACTIVATION_CON, false);
    assert_eq!((r.progress(a), r.progress(b), r.progress(c)), (vec!["Completed".to_string()], vec!["Completed".to_string()], vec!["Completed".to_string()]));
}

#[test]
fn a_duplicate_request_is_busy_and_nothing_goes_before_start() {
    let mut r = rig();
    r.master.interrogate(CA, Interrogation::STATION, r.now).unwrap();
    assert!(matches!(r.master.interrogate(CA, Interrogation::STATION, r.now), Err(Error::Busy)));
    // Another CA is another request.
    r.master.interrogate(CommonAddress(2), Interrogation::STATION, r.now).unwrap();
}

#[test]
fn a_disconnect_fails_every_outstanding_request() {
    let mut r = rig();
    let a = r.master.interrogate(CA, Interrogation::STATION, r.now).unwrap();
    let b = r.master.command(CA, Ioa(1), Command::single(false), r.now).unwrap();
    r.pump();
    iec60870::driver::Protocol::handle_disconnect(&mut r.master, r.now);
    r.pump();
    assert!(r.progress(a)[0].starts_with("Failed(disconnected"));
    assert!(r.progress(b)[0].starts_with("Failed(disconnected"));
    assert!(r.events.iter().any(|e| matches!(e, Event::Disconnected(_))));
}

#[test]
fn requests_wait_while_the_window_is_full() {
    let mut r = rig();
    // k = 12: the 13th read waits in the station until the outstation acknowledges (w = 8).
    for i in 0..20 {
        r.master.read(CA, Ioa(i), r.now).unwrap();
    }
    assert_eq!(r.master.link().outstanding(), 12);
    r.pump();
    assert_eq!(r.received.len(), 20);
}

#[test]
fn spontaneous_data_and_end_of_initialisation_are_events() {
    let mut r = rig();
    r.reply(&Asdu::new(CA, Cot::new(Cause::INITIALIZED), InformationObject::new(Ioa(0), EndOfInitialization::REMOTE_RESET)));
    r.reply(&Asdu::new(CA, Cot::SPONTANEOUS, InformationObject::new(Ioa(9), DoublePoint::new(DoublePointValue::On)).at(clock())));
    r.reply(&Asdu::new(CA, Cot::ACTIVATION_CON, InformationObject::new(Ioa(0), ResetProcess::GENERAL)));
    assert!(matches!(r.events[0], Event::EndOfInitialization { cause: EndOfInitialization::REMOTE_RESET, .. }));
    assert!(matches!(&r.events[1], Event::Point(p) if p.ioa == Ioa(9) && p.time.is_some()));
    assert!(matches!(&r.events[2], Event::Asdu(a) if a.type_id() == TypeId::C_RP_NA_1), "an unexpected confirmation is passed on");
}

#[test]
fn an_unstarted_master_refuses_requests() {
    let mut m = iec60870::station::ControllingStation::new(iec60870::cs104::Cs104Link::controlling(), ClientConfig::default(), clock);
    assert!(matches!(m.read(CA, Ioa(1), Instant::ZERO), Err(Error::NotStarted)));
    assert!(matches!(m.send(&Asdu::new(CA, Cot::REQUEST, InformationObject::new(Ioa(1), Read)), Instant::ZERO), Err(Error::NotStarted)));
}

#[test]
fn event_diagnostics_stay_on_one_line() {
    use iec60870::station::{LinkClosed, Progress, RequestId};

    let reason = LinkClosed::new(std::io::Error::other("adapter\nfailed\x1b\u{2028}"));
    assert_eq!(Event::Disconnected(reason.clone()).to_string(), r"disconnected: adapter\nfailed\u{1b}\u{2028}");
    let request = Event::Request { id: RequestId(42), progress: Progress::Failed(Error::Disconnected(reason)) };
    assert_eq!(request.to_string(), r"request 42 failed: disconnected: adapter\nfailed\u{1b}\u{2028}");
}

#[cfg(feature = "file-transfer")]
#[test]
fn file_events_summarize_contents() {
    use iec60870::station::{FileInfo, FileName, FileStatus, RequestId};
    let id = RequestId(3);
    let file = Event::File { id, common_address: CA, ioa: Ioa(99), name: FileName::EVENTS, data: vec![42; 65_536] };
    assert_eq!(file.to_string(), "request 3 CA 1 IOA 99 file sequences of events (3) received (65536 bytes)");
    let entry = FileInfo { ioa: Ioa(99), name: FileName::EVENTS, length: 42, created: clock(), status: FileStatus(0) };
    let directory = Event::Directory { id, common_address: CA, files: vec![entry; 256] };
    assert_eq!(directory.to_string(), "request 3 CA 1 directory received (256 entries)");
}

#[test]
fn invalid_local_clock_fails_before_link_activation() {
    let mut master =
        iec60870::station::ControllingStation::new(iec60870::cs104::Cs104Link::controlling(), ClientConfig::default(), || clock().with_invalid(true));
    assert!(matches!(master.clock_sync(CA, Instant::ZERO), Err(Error::InvalidArgument(_))));
}
