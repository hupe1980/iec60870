//! The 104 link without I/O: every acceptance scenario and edge case, frame by frame.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
#![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::assert_is_empty, clippy::cast_lossless)]

use core::time::Duration;

use iec60870::cs104::{
    Apci, Apdu, Awaiting, CloseReason, CommandError, Config, Cs104Link, Event, FrameError, FrameSplitter, Role, SeqNo, State, SubmitError, UFunction,
};
use iec60870::driver::Output;
use iec60870::time::Instant;

const ASDU: &[u8] = &[0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14];

fn t(ms: u64) -> Instant {
    Instant::from_millis(ms)
}

fn sn(n: u16) -> SeqNo {
    SeqNo::new(n).unwrap()
}

fn i(send: u16, recv: u16) -> Vec<u8> {
    Apdu::i(sn(send), sn(recv), ASDU).to_vec().unwrap()
}

fn s(recv: u16) -> Vec<u8> {
    Apdu::s(sn(recv)).to_vec().unwrap()
}

fn u(f: UFunction) -> Vec<u8> {
    Apdu::u(f).to_vec().unwrap()
}

/// What one drain of a link produced.
#[derive(Debug, Default)]
struct Drained {
    sent: Vec<Apci>,
    events: Vec<Event>,
    deadline: Option<Instant>,
    transmits: usize,
}

fn drain(link: &mut Cs104Link) -> Drained {
    let mut d = Drained::default();
    while let Some(output) = link.poll_output() {
        match output {
            Output::Transmit(bytes) => {
                d.transmits += 1;
                let mut splitter = FrameSplitter::new();
                let mut input = &bytes[..];
                while let Some(frame) = splitter.next_frame(&mut input) {
                    d.sent.push(frame.unwrap().apci);
                }
                assert_eq!(splitter.buffered(), 0, "a transmit carries whole frames");
            }
            Output::Event(e) => d.events.push(e),
            Output::Deadline(at) => {
                assert!(d.deadline.is_none(), "one deadline per drain");
                d.deadline = Some(at);
            }
        }
    }
    d
}

fn closed_with(d: &Drained) -> Option<CloseReason> {
    d.events.iter().find_map(|e| if let Event::Closed(r) = e { Some(*r) } else { None })
}

fn quick() -> Config {
    Config { k: 3, w: 2, t0: Duration::from_secs(1), t1: Duration::from_millis(1500), t2: Duration::from_millis(1000), t3: Duration::from_millis(2000) }
}

fn started_controlled(config: Config) -> Cs104Link {
    let mut link = Cs104Link::new(Role::Controlled, config).unwrap();
    link.handle_input(&u(UFunction::StartDtAct), t(0));
    let d = drain(&mut link);
    assert_eq!(d.sent, [Apci::U(UFunction::StartDtCon)]);
    assert_eq!(d.events, [Event::Started]);
    link
}

fn started_controlling(config: Config) -> Cs104Link {
    let mut link = Cs104Link::new(Role::Controlling, config).unwrap();
    link.start(t(0)).unwrap();
    assert_eq!(drain(&mut link).sent, [Apci::U(UFunction::StartDtAct)]);
    assert_eq!(link.state(), State::Starting);
    link.handle_input(&u(UFunction::StartDtCon), t(0));
    assert_eq!(drain(&mut link).events, [Event::Started]);
    link
}

// --- Acceptance scenario 1: k back-pressure ---------------------------------------------

#[test]
fn k_outstanding_frames_refuse_the_next_submit_with_back_pressure() {
    let mut link = started_controlled(quick());
    for n in 0..3 {
        assert!(link.can_send());
        link.submit(ASDU, t(10)).unwrap();
        assert_eq!(drain(&mut link).sent, [Apci::I { send: sn(n), recv: sn(0) }]);
    }
    assert!(!link.can_send());
    assert_eq!(link.submit(ASDU, t(11)), Err(SubmitError::WindowFull));
    assert!(drain(&mut link).sent.is_empty(), "nothing is transmitted when refused");
    assert_eq!(link.outstanding(), 3);

    // The peer acknowledges two: the window reopens and the station is told how many.
    link.handle_input(&s(2), t(20));
    let d = drain(&mut link);
    assert_eq!(d.events, [Event::Acknowledged { count: 2 }]);
    assert!(link.can_send());
    assert_eq!(link.outstanding(), 1);
    link.submit(ASDU, t(21)).unwrap();
    assert_eq!(drain(&mut link).sent, [Apci::I { send: sn(3), recv: sn(0) }]);
}

// --- Acceptance scenario 2: t1 ------------------------------------------------------------

#[test]
fn an_unacknowledged_i_frame_closes_with_t1_expired_after_t1() {
    let mut link = started_controlled(quick());
    link.submit(ASDU, t(100)).unwrap();
    let d = drain(&mut link);
    assert_eq!(d.deadline, Some(t(1600)), "t1 from the send time is the next deadline");
    link.handle_timeout(t(1599));
    assert!(closed_with(&drain(&mut link)).is_none());
    link.handle_timeout(t(1600));
    let d = drain(&mut link);
    assert_eq!(closed_with(&d), Some(CloseReason::T1Expired(Awaiting::Acknowledgment)));
    assert_eq!(d.deadline, None, "a closed link has no deadline");
    assert!(link.is_closed());
    assert_eq!(link.outstanding(), 1, "the station can see what was never acknowledged");
    assert_eq!(link.submit(ASDU, t(1700)), Err(SubmitError::Closed));
}

#[test]
fn t1_runs_on_the_oldest_outstanding_frame() {
    let mut link = started_controlled(quick());
    link.submit(ASDU, t(0)).unwrap();
    link.submit(ASDU, t(1000)).unwrap();
    drain(&mut link);
    link.handle_input(&s(1), t(1400));
    assert_eq!(drain(&mut link).deadline, Some(t(2500)));
    link.handle_timeout(t(2000));
    assert!(!link.is_closed());
    link.handle_timeout(t(2500));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::T1Expired(Awaiting::Acknowledgment)));
}

#[test]
fn t1_runs_on_startdt_act_and_stopdt_act() {
    let mut link = Cs104Link::new(Role::Controlling, quick()).unwrap();
    link.start(t(0)).unwrap();
    assert_eq!(drain(&mut link).deadline, Some(t(1500)));
    link.handle_timeout(t(1500));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::T1Expired(Awaiting::StartDtCon)));

    let mut link = started_controlling(quick());
    link.stop(t(100)).unwrap();
    assert_eq!(drain(&mut link).sent, [Apci::U(UFunction::StopDtAct)]);
    link.handle_timeout(t(1600));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::T1Expired(Awaiting::StopDtCon)));
}

// --- Acceptance scenario 3: w and t2 --------------------------------------------------------

#[test]
fn w_received_frames_are_acknowledged_at_once() {
    let mut link = started_controlled(quick());
    link.handle_input(&i(0, 0), t(10));
    let d = drain(&mut link);
    assert!(d.sent.is_empty());
    assert_eq!(d.events, [Event::Asdu(ASDU.to_vec())]);
    link.handle_input(&i(1, 0), t(20));
    let d = drain(&mut link);
    assert_eq!(d.sent, [Apci::S { recv: sn(2) }]);
}

#[test]
fn fewer_than_w_frames_are_acknowledged_when_t2_elapses() {
    let mut link = started_controlled(Config { w: 8, ..quick() });
    link.handle_input(&i(0, 0), t(100));
    let d = drain(&mut link);
    assert_eq!(d.deadline, Some(t(1100)), "t2 runs from the first unacknowledged frame");
    link.handle_input(&i(1, 0), t(600));
    assert_eq!(drain(&mut link).deadline, Some(t(1100)));
    link.handle_timeout(t(1100));
    assert_eq!(drain(&mut link).sent, [Apci::S { recv: sn(2) }]);
}

#[test]
fn an_i_frame_sent_acknowledges_what_was_received() {
    let mut link = started_controlled(Config { w: 8, ..quick() });
    link.handle_input(&i(0, 0), t(100));
    drain(&mut link);
    link.submit(ASDU, t(200)).unwrap();
    assert_eq!(drain(&mut link).sent, [Apci::I { send: sn(0), recv: sn(1) }]);
    link.handle_timeout(t(1100));
    assert!(drain(&mut link).sent.is_empty(), "t2 was satisfied by the I-frame");
}

// --- Acceptance scenario 4: t3 and TESTFR ----------------------------------------------------

#[test]
fn an_idle_link_sends_testfr_act_after_t3_and_closes_without_a_con() {
    let mut link = started_controlled(quick());
    assert_eq!(drain(&mut link).deadline, None, "no change, no new deadline");
    link.handle_timeout(t(1999));
    assert!(drain(&mut link).sent.is_empty());
    link.handle_timeout(t(2000));
    let d = drain(&mut link);
    assert_eq!(d.sent, [Apci::U(UFunction::TestFrAct)]);
    assert_eq!(d.deadline, Some(t(3500)));
    link.handle_timeout(t(3500));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::T1Expired(Awaiting::TestFrCon)));
}

#[test]
fn a_testfr_con_keeps_the_link_open_and_any_frame_restarts_t3() {
    let mut link = started_controlled(quick());
    link.handle_timeout(t(2000));
    drain(&mut link);
    link.handle_input(&u(UFunction::TestFrCon), t(2100));
    let d = drain(&mut link);
    assert_eq!(d.deadline, Some(t(4100)), "t3 restarts on the received frame");
    link.handle_timeout(t(3600));
    assert!(!link.is_closed());
    // t3 also runs while stopped.
    let mut stopped = Cs104Link::new(Role::Controlled, quick()).unwrap();
    stopped.handle_timeout(t(0));
    stopped.handle_timeout(t(2000));
    assert_eq!(drain(&mut stopped).sent, [Apci::U(UFunction::TestFrAct)]);
}

#[test]
fn testfr_act_is_answered_in_every_state_and_role() {
    for mut link in [Cs104Link::controlled(), Cs104Link::controlling(), started_controlled(quick()), started_controlling(quick())] {
        link.handle_input(&u(UFunction::TestFrAct), t(5));
        assert_eq!(drain(&mut link).sent, [Apci::U(UFunction::TestFrCon)]);
        assert!(!link.is_closed());
    }
}

#[test]
fn an_unsolicited_testfr_con_is_ignored() {
    let mut link = started_controlled(quick());
    link.handle_input(&u(UFunction::TestFrCon), t(5));
    let d = drain(&mut link);
    assert!(d.sent.is_empty() && d.events.is_empty());
    assert!(!link.is_closed());
}

// --- Acceptance scenario 5: I-frames before STARTDT con --------------------------------------

#[test]
fn an_i_frame_before_startdt_is_not_delivered_and_closes() {
    for mut link in [Cs104Link::controlled(), Cs104Link::controlling()] {
        link.handle_input(&i(0, 0), t(0));
        let d = drain(&mut link);
        assert!(!d.events.iter().any(|e| matches!(e, Event::Asdu(_))));
        assert_eq!(closed_with(&d), Some(CloseReason::NotStarted));
    }
    // Controlling, STARTDT act sent but its con not yet received.
    let mut link = Cs104Link::controlling();
    link.start(t(0)).unwrap();
    drain(&mut link);
    link.handle_input(&i(0, 0), t(1));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::NotStarted));
}

#[test]
fn submit_before_start_is_refused() {
    let mut link = Cs104Link::controlled();
    assert_eq!(link.submit(ASDU, t(0)), Err(SubmitError::NotStarted));
    assert!(!link.can_send());
}

// --- Acceptance scenario 6: an N(R) of a frame never sent -------------------------------------

#[test]
fn an_acknowledgment_of_a_frame_never_sent_closes() {
    let mut link = started_controlled(quick());
    link.submit(ASDU, t(0)).unwrap();
    link.submit(ASDU, t(0)).unwrap();
    drain(&mut link);
    link.handle_input(&s(3), t(5));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::BadAcknowledgment { recv: sn(3), oldest: sn(0), next: sn(2) }));

    // In an I-frame too, and before anything was sent.
    let mut link = started_controlled(quick());
    link.handle_input(&i(0, 1), t(5));
    let d = drain(&mut link);
    assert_eq!(closed_with(&d), Some(CloseReason::BadAcknowledgment { recv: sn(1), oldest: sn(0), next: sn(0) }));
    assert!(!d.events.iter().any(|e| matches!(e, Event::Asdu(_))), "a frame with a bad N(R) is not delivered");
}

#[test]
fn a_repeated_acknowledgment_is_harmless() {
    let mut link = started_controlled(quick());
    link.submit(ASDU, t(0)).unwrap();
    drain(&mut link);
    link.handle_input(&s(1), t(1));
    link.handle_input(&s(1), t(2));
    let d = drain(&mut link);
    assert_eq!(d.events, [Event::Acknowledged { count: 1 }]);
    assert!(!link.is_closed());
}

#[test]
fn an_unexpected_send_sequence_number_closes() {
    let mut link = started_controlled(quick());
    for n in 0..5 {
        link.handle_input(&i(n, 0), t(1));
    }
    drain(&mut link);
    link.handle_input(&i(6, 0), t(2));
    let d = drain(&mut link);
    assert_eq!(closed_with(&d), Some(CloseReason::SequenceError { expected: sn(5), received: sn(6) }));
    assert!(!d.events.iter().any(|e| matches!(e, Event::Asdu(_))));
    let mut link = started_controlled(quick());
    link.handle_input(&i(0, 0), t(1));
    link.handle_input(&i(0, 0), t(1));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::SequenceError { expected: sn(1), received: sn(0) }));
}

// --- Edge cases --------------------------------------------------------------------------------

#[test]
fn sequence_numbers_wrap_at_32767_in_both_directions() {
    let config = Config { k: 32767, w: 32767, ..quick() };
    let mut link = started_controlled(config);
    // Send 32767 frames, acknowledged in batches; then cross the wrap.
    let mut acked = 0u16;
    for n in 0u32..32770 {
        link.submit(ASDU, t(1)).unwrap();
        if n % 1000 == 999 || n == 32766 {
            let next = ((n + 1) % 32768) as u16;
            link.handle_input(&s(next), t(1));
            acked = next;
        }
    }
    let d = drain(&mut link);
    let last = d.sent.iter().rev().find_map(|a| if let Apci::I { send, .. } = a { Some(*send) } else { None }).unwrap();
    assert_eq!(last, sn(1), "N(S) 32767 is followed by 0, 1");
    assert!(d.sent.contains(&Apci::I { send: SeqNo::MAX, recv: sn(0) }));
    assert!(d.sent.contains(&Apci::I { send: sn(0), recv: sn(0) }));
    assert_eq!(acked, 32767);
    link.handle_input(&s(2), t(2));
    let d = drain(&mut link);
    assert_eq!(d.events, [Event::Acknowledged { count: 3 }], "an N(R) past the wrap acknowledges 32767, 0, 1");
    assert!(!link.is_closed());

    // Receiving across the wrap.
    let mut link = started_controlled(config);
    for n in 0u32..32770 {
        link.handle_input(&i((n % 32768) as u16, 0), t(1));
    }
    let d = drain(&mut link);
    assert_eq!(d.events.iter().filter(|e| matches!(e, Event::Asdu(_))).count(), 32770);
    assert!(!link.is_closed());
}

#[test]
fn a_peer_acknowledging_only_every_32767_frames_is_served() {
    let config = Config { k: 32767, w: 32767, ..quick() };
    let mut link = started_controlled(config);
    for _ in 0..32767 {
        link.submit(ASDU, t(1)).unwrap();
    }
    assert_eq!(link.submit(ASDU, t(1)), Err(SubmitError::WindowFull));
    drain(&mut link);
    link.handle_input(&s(32767), t(2));
    assert_eq!(drain(&mut link).events, [Event::Acknowledged { count: 32767 }]);
    assert!(link.can_send());
    // And as receiver: w = 32767 means the S-frame comes at the 32767th frame.
    let mut link = started_controlled(config);
    for n in 0..32766 {
        link.handle_input(&i(n, 0), t(1));
    }
    assert!(drain(&mut link).sent.is_empty());
    link.handle_input(&i(32766, 0), t(1));
    assert_eq!(drain(&mut link).sent, [Apci::S { recv: SeqNo::MAX }]);
}

#[test]
fn stopdt_act_with_outstanding_frames_withholds_the_con_until_they_are_acknowledged() {
    let mut link = started_controlled(Config { w: 8, ..quick() });
    link.handle_input(&i(0, 0), t(1));
    link.submit(ASDU, t(2)).unwrap();
    link.submit(ASDU, t(3)).unwrap();
    link.handle_input(&i(1, 0), t(4));
    drain(&mut link);
    link.handle_input(&u(UFunction::StopDtAct), t(5));
    let d = drain(&mut link);
    assert_eq!(d.sent, [Apci::S { recv: sn(2) }], "received frames acknowledged, no con yet");
    assert_eq!(link.state(), State::Stopping);
    assert_eq!(link.submit(ASDU, t(6)), Err(SubmitError::NotStarted), "no new submissions while stopping");
    link.handle_input(&s(1), t(7));
    let d = drain(&mut link);
    assert!(d.sent.is_empty());
    assert_eq!(d.events, [Event::Acknowledged { count: 1 }]);
    link.handle_input(&s(2), t(8));
    let d = drain(&mut link);
    assert_eq!(d.sent, [Apci::U(UFunction::StopDtCon)]);
    assert_eq!(d.events, [Event::Acknowledged { count: 1 }, Event::Stopped]);
    assert_eq!(link.state(), State::Stopped);
    // After stopping, an I-frame closes.
    link.handle_input(&i(2, 2), t(9));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::NotStarted));
}

#[test]
fn stopdt_act_with_nothing_outstanding_is_confirmed_at_once_and_t1_still_bounds_a_drain() {
    let mut link = started_controlled(quick());
    link.handle_input(&u(UFunction::StopDtAct), t(5));
    let d = drain(&mut link);
    assert_eq!(d.sent, [Apci::U(UFunction::StopDtCon)]);
    assert_eq!(d.events, [Event::Stopped]);
    // STOPDT act while stopped: confirmed again; STARTDT act restarts.
    link.handle_input(&u(UFunction::StopDtAct), t(6));
    assert_eq!(drain(&mut link).sent, [Apci::U(UFunction::StopDtCon)]);
    link.handle_input(&u(UFunction::StartDtAct), t(7));
    let d = drain(&mut link);
    assert_eq!((d.sent, d.events), (vec![Apci::U(UFunction::StartDtCon)], vec![Event::Started]));

    let mut link = started_controlled(quick());
    link.submit(ASDU, t(0)).unwrap();
    link.handle_input(&u(UFunction::StopDtAct), t(5));
    link.handle_timeout(t(1500));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::T1Expired(Awaiting::Acknowledgment)));
}

#[test]
fn a_local_stop_acknowledges_and_still_accepts_in_flight_frames() {
    let mut link = started_controlling(Config { w: 8, ..quick() });
    link.handle_input(&i(0, 0), t(1));
    drain(&mut link);
    link.stop(t(2)).unwrap();
    assert_eq!(drain(&mut link).sent, [Apci::S { recv: sn(1) }, Apci::U(UFunction::StopDtAct)]);
    assert_eq!(link.submit(ASDU, t(3)), Err(SubmitError::NotStarted));
    // The peer's frame in flight is delivered and acknowledged at once.
    link.handle_input(&i(1, 0), t(4));
    let d = drain(&mut link);
    assert_eq!(d.events, [Event::Asdu(ASDU.to_vec())]);
    assert_eq!(d.sent, [Apci::S { recv: sn(2) }]);
    link.handle_input(&u(UFunction::StopDtCon), t(5));
    let d = drain(&mut link);
    assert_eq!(d.events, [Event::Stopped]);
    assert!(d.sent.is_empty(), "no S-frame after the con");
    // Restart.
    link.start(t(6)).unwrap();
    link.handle_input(&u(UFunction::StartDtCon), t(7));
    assert!(drain(&mut link).events.contains(&Event::Started));
}

#[test]
fn unexpected_u_frames_close_with_their_name() {
    let mut link = started_controlled(quick());
    link.handle_input(&u(UFunction::StartDtCon), t(1));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::UnexpectedFrame(UFunction::StartDtCon)));
    let mut link = started_controlling(quick());
    link.handle_input(&u(UFunction::StopDtCon), t(1));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::UnexpectedFrame(UFunction::StopDtCon)));
    let mut link = started_controlling(quick());
    link.handle_input(&u(UFunction::StartDtCon), t(1));
    assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::UnexpectedFrame(UFunction::StartDtCon)));
    for f in [UFunction::StartDtAct, UFunction::StopDtAct] {
        let mut link = Cs104Link::controlling();
        link.handle_input(&u(f), t(1));
        assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::UnexpectedFrame(f)));
    }
}

#[test]
fn malformed_octets_close_with_the_reason() {
    let cases: [(&[u8], FrameError); 5] = [
        (&[0x68, 3, 7, 0, 0], FrameError::BadLength(3)),
        (&[0x68, 254], FrameError::BadLength(254)),
        (&[0x69, 4, 7, 0, 0, 0], FrameError::BadStart(0x69)),
        (&[0x68, 4, 0, 0, 0, 0], FrameError::EmptyAsdu),
        (&[0x68, 4, 0x33, 0, 0, 0], FrameError::BadControl([0x33, 0, 0, 0])),
    ];
    for (bytes, error) in cases {
        let mut link = started_controlled(quick());
        link.handle_input(bytes, t(1));
        assert_eq!(closed_with(&drain(&mut link)), Some(CloseReason::Malformed(error)), "{bytes:02x?}");
        link.handle_input(&i(0, 0), t(2));
        assert!(drain(&mut link).events.is_empty(), "nothing after the close");
    }
}

#[test]
fn partial_reads_of_one_octet_are_reassembled() {
    let mut link = Cs104Link::controlled();
    let mut stream = u(UFunction::StartDtAct);
    for n in 0..5 {
        stream.extend(i(n, 0));
    }
    stream.extend(u(UFunction::TestFrAct));
    for octet in &stream {
        link.handle_input(core::slice::from_ref(octet), t(1));
    }
    let d = drain(&mut link);
    assert_eq!(d.events.iter().filter(|e| matches!(e, Event::Asdu(_))).count(), 5);
    assert_eq!(d.sent.last(), Some(&Apci::U(UFunction::TestFrCon)));
    assert!(!link.is_closed());
}

#[test]
fn outputs_of_one_chunk_are_bounded_by_its_frames_and_transmits_coalesce() {
    let mut link = started_controlled(quick());
    let stream: Vec<u8> = (0..100).flat_map(|_| u(UFunction::TestFrAct)).collect();
    link.handle_input(&stream, t(1));
    let d = drain(&mut link);
    assert_eq!(d.sent.len(), 100);
    assert_eq!(d.transmits, 1, "one write per drain");
}

#[test]
fn disconnect_and_close_name_their_reason_once() {
    let mut link = started_controlled(quick());
    link.handle_disconnect(t(1));
    link.handle_disconnect(t(2));
    link.close();
    let d = drain(&mut link);
    assert_eq!(d.events, [Event::Closed(CloseReason::PeerClosed)]);
    let mut link = started_controlled(quick());
    link.close();
    assert_eq!(drain(&mut link).events, [Event::Closed(CloseReason::Local)]);
    assert_eq!(link.state(), State::Closed);
}

#[test]
fn submit_refuses_empty_and_too_long_asdus() {
    let mut link = started_controlled(quick());
    assert_eq!(link.submit(&[], t(1)), Err(SubmitError::Empty));
    assert_eq!(link.submit(&[0; 250], t(1)), Err(SubmitError::TooLong(250)));
    link.submit(&[0; 249], t(1)).unwrap();
}

#[test]
fn only_the_controlling_role_starts_and_stops() {
    let mut link = Cs104Link::controlled();
    assert_eq!(link.start(t(0)), Err(CommandError::WrongRole));
    assert_eq!(link.stop(t(0)), Err(CommandError::WrongRole));
    let mut link = Cs104Link::controlling();
    link.start(t(0)).unwrap();
    link.start(t(0)).unwrap();
    assert_eq!(drain(&mut link).sent, [Apci::U(UFunction::StartDtAct)], "start is idempotent");
    assert_eq!(link.stop(t(0)), Err(CommandError::Busy(State::Starting)));
    link.close();
    assert_eq!(link.start(t(0)), Err(CommandError::Closed));
}

#[test]
fn an_invalid_configuration_is_refused() {
    assert!(Cs104Link::new(Role::Controlled, Config { k: 0, ..Config::default() }).is_err());
    assert_eq!(Cs104Link::controlled().config(), &Config::default());
    assert_eq!(Cs104Link::controlling().role(), Role::Controlling);
}

#[test]
fn the_clock_starts_at_the_first_now() {
    let mut link = Cs104Link::controlled();
    link.handle_timeout(t(5000));
    assert_eq!(drain(&mut link).deadline, Some(t(25_000)), "t3 = 20 s from the first now");
}
