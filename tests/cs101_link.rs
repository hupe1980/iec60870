//! The 101 link's acceptance scenarios and edge cases, without I/O.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, clippy::assert_is_empty)]

use std::time::Duration;

use iec60870::cs101::{
    AddressWidth, Class, CloseReason, Config, ConfigError, Control, Cs101Link, Event, Frame, LinkAddress, Mode, PrimaryFunction, Role, SecondaryFunction,
    StopReason, SubmitError,
};
use iec60870::driver::{Output, Protocol};
use iec60870::time::Instant;

const A: LinkAddress = LinkAddress(3);
const B: LinkAddress = LinkAddress(4);
const ASDU: &[u8] = &[0x01, 0x01, 0x03, 0x01, 0x10, 0x00, 0x01];

fn ms(n: u64) -> Instant {
    Instant::from_millis(n)
}

/// Everything a link transmitted (concatenated) and its events.
fn drain(link: &mut Cs101Link) -> (Vec<u8>, Vec<Event>) {
    let mut tx = Vec::new();
    let mut events = Vec::new();
    while let Some(o) = link.poll_output() {
        match o {
            Output::Transmit(b) => tx.extend(b),
            Output::Event(e) => events.push(e),
            Output::Deadline(_) => {}
        }
    }
    (tx, events)
}

fn primary_frame(width: AddressWidth, addr: LinkAddress, function: PrimaryFunction, fcb: bool, fcv: bool, data: &[u8]) -> Vec<u8> {
    let control = Control::Primary { dir: false, fcb, fcv, function };
    if data.is_empty() { Frame::Fixed { control, address: addr } } else { Frame::Variable { control, address: addr, user_data: data } }.to_vec(width).unwrap()
}

fn secondary_frame(addr: LinkAddress, function: SecondaryFunction, acd: bool, dfc: bool, data: &[u8]) -> Vec<u8> {
    let control = Control::Secondary { dir: false, acd, dfc, function };
    if data.is_empty() { Frame::Fixed { control, address: addr } } else { Frame::Variable { control, address: addr, user_data: data } }
        .to_vec(AddressWidth::One)
        .unwrap()
}

fn decode(bytes: &[u8]) -> Frame<'_> {
    Frame::decode(bytes, AddressWidth::One).unwrap()
}

/// A secondary at `A` whose link was reset; the reset's answer drained.
fn reset_secondary(config: Config) -> Cs101Link {
    let mut s = Cs101Link::secondary(A, config).unwrap();
    s.handle_input(&primary_frame(config.address_width, A, PrimaryFunction::ResetRemoteLink, false, false, &[]), ms(0));
    let (tx, events) = drain(&mut s);
    assert_eq!(tx, [0xE5]);
    assert_eq!(events, [Event::Started { station: A }]);
    s
}

/// A shared line: every transmission reaches every other station on it.
struct Line {
    links: Vec<Cs101Link>,
    events: Vec<Vec<Event>>,
    /// Stations whose transmissions are lost (a dead modem).
    mute: Vec<bool>,
}

impl Line {
    fn new(links: Vec<Cs101Link>) -> Self {
        let n = links.len();
        Line { links, events: vec![Vec::new(); n], mute: vec![false; n] }
    }

    /// Exchanges frames at `now` until nobody transmits.
    fn settle(&mut self, now: Instant) {
        for _ in 0..1000 {
            let mut any = false;
            for i in 0..self.links.len() {
                let (tx, ev) = drain(&mut self.links[i]);
                self.events[i].extend(ev);
                if tx.is_empty() || self.mute[i] {
                    continue;
                }
                any = true;
                for j in 0..self.links.len() {
                    if j != i {
                        self.links[j].handle_input(&tx, now);
                    }
                }
            }
            if !any {
                return;
            }
        }
        panic!("the line never settles");
    }

    /// Runs from `from` to `to` in steps of `step` ms.
    fn run(&mut self, from: u64, to: u64, step: u64) {
        let mut t = from;
        while t <= to {
            for link in &mut self.links {
                link.handle_timeout(ms(t));
            }
            self.settle(ms(t));
            t += step;
        }
    }

    fn asdus(&self, i: usize) -> Vec<(LinkAddress, Vec<u8>)> {
        self.events[i]
            .iter()
            .filter_map(|e| match e {
                Event::Asdu { station, asdu } => Some((*station, asdu.clone())),
                _ => None,
            })
            .collect()
    }
}

// ── acceptance scenario 1: ACD drives class 1 polling ───────────────────────

#[test]
fn class2_poll_with_class1_pending_sets_acd_and_master_polls_class1() {
    // The outstation half: class 1 data waiting, a class 2 poll answers "no data" with ACD.
    let mut s = reset_secondary(Config::default());
    s.submit(ASDU, Class::One, ms(1)).unwrap();
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::RequestClass2, true, true, &[]), ms(1));
    let (tx, _) = drain(&mut s);
    assert!(matches!(decode(&tx), Frame::Fixed { control: Control::Secondary { acd: true, function: SecondaryFunction::NoData, .. }, address: A }));

    // The master half: after that answer, the next request is class 1.
    let mut m = Cs101Link::primary(&[A], Config::default()).unwrap();
    m.handle_timeout(ms(0));
    let (tx, _) = drain(&mut m);
    assert!(matches!(decode(&tx), Frame::Fixed { control: Control::Primary { function: PrimaryFunction::RequestLinkStatus, fcv: false, .. }, .. }));
    m.handle_input(&secondary_frame(A, SecondaryFunction::LinkStatus, false, false, &[]), ms(1));
    let (tx, _) = drain(&mut m);
    assert!(matches!(decode(&tx), Frame::Fixed { control: Control::Primary { function: PrimaryFunction::ResetRemoteLink, fcb: false, fcv: false, .. }, .. }));
    m.handle_input(&[0xE5], ms(2));
    let (tx, events) = drain(&mut m);
    assert_eq!(events, [Event::Started { station: A }]);
    // First FCV frame after the reset carries FCB = 1.
    assert!(matches!(decode(&tx), Frame::Fixed { control: Control::Primary { function: PrimaryFunction::RequestClass2, fcb: true, fcv: true, .. }, .. }));
    m.handle_input(&secondary_frame(A, SecondaryFunction::NoData, true, false, &[]), ms(3));
    let (tx, _) = drain(&mut m);
    assert!(matches!(decode(&tx), Frame::Fixed { control: Control::Primary { function: PrimaryFunction::RequestClass1, fcb: false, fcv: true, .. }, .. }));
    m.handle_input(&secondary_frame(A, SecondaryFunction::UserData, false, false, ASDU), ms(4));
    let (_, events) = drain(&mut m);
    assert_eq!(events, [Event::Asdu { station: A, asdu: ASDU.to_vec() }]);
}

#[test]
fn end_to_end_class1_and_class2_arrive_and_are_acknowledged() {
    let mut line = Line::new(vec![Cs101Link::primary(&[A], Config::default()).unwrap(), Cs101Link::secondary(A, Config::default()).unwrap()]);
    line.links[1].submit(&[2, 1, 3, 1, 1, 0, 1], Class::Two, ms(0)).unwrap();
    line.links[1].submit(&[1, 1, 3, 1, 1, 0, 1], Class::One, ms(0)).unwrap();
    line.run(0, 500, 10);
    // Class 1 first, though submitted second.
    assert_eq!(line.asdus(0), [(A, vec![1, 1, 3, 1, 1, 0, 1]), (A, vec![2, 1, 3, 1, 1, 0, 1])]);
    let acks: Vec<_> = line.events[1].iter().filter(|e| matches!(e, Event::Acknowledged { .. })).collect();
    assert_eq!(acks, [&Event::Acknowledged { station: A, class: Class::One, count: 1 }, &Event::Acknowledged { station: A, class: Class::Two, count: 1 }]);
    assert!(line.links[0].is_up(A) && line.links[1].is_up(A));
}

// ── acceptance scenario 2: a lost response is repeated, not re-executed ─────

#[test]
fn repeated_fcb_gets_the_identical_response_and_nothing_is_dequeued() {
    let mut s = reset_secondary(Config::default());
    s.submit(&[1, 1, 3, 1, 1, 0, 1], Class::One, ms(0)).unwrap();
    s.submit(&[1, 1, 3, 1, 2, 0, 1], Class::One, ms(0)).unwrap();
    let request = primary_frame(AddressWidth::One, A, PrimaryFunction::RequestClass1, true, true, &[]);
    s.handle_input(&request, ms(1));
    let (first, events) = drain(&mut s);
    assert!(events.is_empty());
    // The answer is lost; the primary repeats with the same FCB.
    s.handle_input(&request, ms(600));
    let (second, events) = drain(&mut s);
    assert_eq!(first, second);
    assert!(events.is_empty());
    assert_eq!(s.queued(A, Class::One), 1);
    assert_eq!(s.stats().repeats_answered, 1);
    // A toggled FCB confirms the first answer and fetches the next.
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::RequestClass1, false, true, &[]), ms(700));
    let (third, events) = drain(&mut s);
    assert_eq!(events, [Event::Acknowledged { station: A, class: Class::One, count: 1 }]);
    assert!(matches!(decode(&third), Frame::Variable { user_data: [1, 1, 3, 1, 2, 0, 1], .. }));
}

#[test]
fn repeated_user_data_is_acknowledged_but_delivered_once() {
    let mut s = reset_secondary(Config::default());
    let frame = primary_frame(AddressWidth::One, A, PrimaryFunction::UserDataConfirmed, true, true, ASDU);
    s.handle_input(&frame, ms(1));
    let (ack1, events) = drain(&mut s);
    assert_eq!(events, [Event::Asdu { station: A, asdu: ASDU.to_vec() }]);
    s.handle_input(&frame, ms(600));
    let (ack2, events) = drain(&mut s);
    assert_eq!((ack1.as_slice(), ack2.as_slice()), (&[0xE5][..], &[0xE5][..]));
    assert!(events.is_empty(), "a repeated command must not be delivered twice");
}

#[test]
fn master_retransmits_byte_identical_frame_after_timeout() {
    let mut m = Cs101Link::primary(&[A], Config::default()).unwrap();
    let mut s = Cs101Link::secondary(A, Config::default()).unwrap();
    m.handle_timeout(ms(0));
    for t in 0..2 {
        let (tx, _) = drain(&mut m);
        s.handle_input(&tx, ms(t));
        let (tx, _) = drain(&mut s);
        m.handle_input(&tx, ms(t));
    }
    // Now the master has sent its first class 2 poll (FCB = 1). Lose the answer.
    let (poll, _) = drain(&mut m);
    assert!(matches!(decode(&poll), Frame::Fixed { control: Control::Primary { function: PrimaryFunction::RequestClass2, fcb: true, .. }, .. }));
    m.handle_timeout(ms(499));
    assert!(drain(&mut m).0.is_empty());
    m.handle_timeout(ms(503));
    let (repeat, _) = drain(&mut m);
    assert_eq!(poll, repeat);
    assert_eq!(m.stats().retransmissions, 1);
}

// ── acceptance scenario 3: balanced, both directions, DIR ───────────────────

#[test]
fn balanced_runs_both_directions_with_dir() {
    let config = Config::default();
    let mut line = Line::new(vec![
        Cs101Link::balanced(Role::Controlling, LinkAddress(1), LinkAddress(2), config).unwrap(),
        Cs101Link::balanced(Role::Controlled, LinkAddress(2), LinkAddress(1), config).unwrap(),
    ]);
    assert_eq!(line.links[0].mode(), Mode::Balanced(Role::Controlling));
    line.links[0].submit(&[0x2D, 1, 6, 1, 1, 0, 1], Class::One, ms(0)).unwrap();
    line.links[1].submit(&[0x01, 1, 3, 1, 1, 0, 1], Class::One, ms(0)).unwrap();
    line.run(0, 200, 10);
    assert_eq!(line.asdus(1), [(LinkAddress(1), vec![0x2D, 1, 6, 1, 1, 0, 1])]);
    assert_eq!(line.asdus(0), [(LinkAddress(2), vec![0x01, 1, 3, 1, 1, 0, 1])]);
    assert!(line.events[0].contains(&Event::Started { station: LinkAddress(2) }));
    assert!(line.events[1].contains(&Event::Started { station: LinkAddress(1) }));
    assert!(line.events[0].contains(&Event::Acknowledged { station: LinkAddress(2), class: Class::One, count: 1 }));

    // DIR: every frame of the controlling end has DIR = 1, of the controlled end DIR = 0.
    let mut c = Cs101Link::balanced(Role::Controlling, LinkAddress(1), LinkAddress(2), config).unwrap();
    c.handle_timeout(ms(0));
    let (tx, _) = drain(&mut c);
    assert!(decode(&tx).eq(&Frame::Fixed {
        control: Control::Primary { dir: true, fcb: false, fcv: false, function: PrimaryFunction::RequestLinkStatus },
        address: LinkAddress(2)
    }));
    let mut d = Cs101Link::balanced(Role::Controlled, LinkAddress(2), LinkAddress(1), config).unwrap();
    d.handle_input(&tx, ms(0));
    let (answer, _) = drain(&mut d);
    // The answer, then d's own request status (its primary half starts too).
    assert!(matches!(
        decode(&answer[..5]),
        Frame::Fixed { control: Control::Secondary { dir: false, function: SecondaryFunction::LinkStatus, .. }, address: LinkAddress(2) }
    ));

    // Echo: the controlling end hears its own request back (two-wire line) and ignores it.
    c.handle_input(&tx, ms(1));
    let (nothing, _) = drain(&mut c);
    assert!(nothing.is_empty());
    assert_eq!(c.stats().echoes, 1);
}

#[test]
fn balanced_sends_test_function_when_idle() {
    let config = Config { test_interval: Duration::from_millis(1000), ..Config::default() };
    let mut line = Line::new(vec![Cs101Link::balanced(Role::Controlling, A, A, config).unwrap(), Cs101Link::balanced(Role::Controlled, A, A, config).unwrap()]);
    line.run(0, 100, 10);
    let frames = line.links[1].stats().frames;
    line.run(110, 1200, 10);
    assert!(line.links[1].stats().frames > frames, "a test function crossed the idle line");
    assert!(line.links[0].is_up(A));
}

// ── acceptance scenario 4: corrupt frames are discarded and counted ─────────

#[test]
fn bad_checksum_end_and_length_are_discarded_and_counted() {
    let mut s = reset_secondary(Config::default());
    let mut frame = primary_frame(AddressWidth::One, A, PrimaryFunction::UserDataConfirmed, true, true, ASDU);
    let cs = frame.len() - 2;
    frame[cs] ^= 0x01;
    s.handle_input(&frame, ms(10));
    frame[cs] ^= 0x01;
    let last = frame.len() - 1;
    frame[last] = 0x17;
    s.handle_input(&frame, ms(20));
    frame[last] = 0x16;
    frame[2] = frame[1] + 1;
    s.handle_input(&frame, ms(30));
    let (tx, events) = drain(&mut s);
    assert!(tx.is_empty() && events.is_empty());
    let st = *s.stats();
    assert_eq!((st.bad_checksum, st.bad_end, st.bad_header), (1, 1, 1));
}

#[test]
fn an_interrupted_frame_is_discarded() {
    let mut s = reset_secondary(Config::default());
    let frame = primary_frame(AddressWidth::One, A, PrimaryFunction::UserDataConfirmed, true, true, ASDU);
    s.handle_input(&frame[..6], ms(10));
    s.handle_input(&frame[6..], ms(400));
    let (tx, events) = drain(&mut s);
    assert!(tx.is_empty() && events.is_empty());
    assert_eq!(s.stats().char_timeouts, 1);
}

// ── edge cases ──────────────────────────────────────────────────────────────

#[test]
fn every_address_width_works_end_to_end() {
    for (width, addr) in [(AddressWidth::Zero, LinkAddress(0)), (AddressWidth::One, LinkAddress(254)), (AddressWidth::Two, LinkAddress(0x1234))] {
        let config = Config { address_width: width, ..Config::default() };
        let mut line = Line::new(vec![Cs101Link::primary(&[addr], config).unwrap(), Cs101Link::secondary(addr, config).unwrap()]);
        line.links[1].submit(ASDU, Class::One, ms(0)).unwrap();
        line.links[0].submit(&[0x2D, 1, 6, 1, 1, 0, 1], Class::One, ms(0)).unwrap();
        line.run(0, 300, 10);
        assert_eq!(line.asdus(0), [(addr, ASDU.to_vec())], "{width:?}");
        assert_eq!(line.asdus(1), [(addr, vec![0x2D, 1, 6, 1, 1, 0, 1])], "{width:?}");
    }
    // The maximal user data per width.
    for width in [AddressWidth::Zero, AddressWidth::One, AddressWidth::Two] {
        let config = Config { address_width: width, ..Config::default() };
        let mut s = Cs101Link::secondary(LinkAddress(0), config).unwrap();
        let max = width.max_user_data();
        assert_eq!(s.submit(&vec![1; max], Class::Two, ms(0)), Ok(()));
        assert_eq!(s.submit(&vec![1; max + 1], Class::Two, ms(0)), Err(SubmitError::TooLong(max + 1)));
    }
}

#[test]
fn broadcast_is_delivered_and_never_answered() {
    let mut line = Line::new(vec![
        Cs101Link::primary(&[A, B], Config::default()).unwrap(),
        Cs101Link::secondary(A, Config::default()).unwrap(),
        Cs101Link::secondary(B, Config::default()).unwrap(),
    ]);
    line.run(0, 100, 10);
    let before = (line.links[1].stats().frames, line.links[2].stats().frames);
    line.links[0].submit_to(LinkAddress(255), &[0x67, 1, 6, 0xFF, 0, 0, 1, 2, 3, 4, 5, 6, 7], Class::One, ms(110)).unwrap();
    assert!(line.events[0].iter().all(|e| !matches!(e, Event::Acknowledged { station: LinkAddress(255), .. })));
    line.run(110, 300, 10);
    for i in [1, 2] {
        let own = if i == 1 { A } else { B };
        assert_eq!(line.asdus(i), [(own, vec![0x67, 1, 6, 0xFF, 0, 0, 1, 2, 3, 4, 5, 6, 7])]);
    }
    assert!(line.events[0].contains(&Event::Acknowledged { station: LinkAddress(255), class: Class::One, count: 1 }));
    assert!(line.links[1].stats().frames > before.0 && line.links[2].stats().frames > before.1);

    // A broadcast with any other function is ignored, and never answered.
    let mut s = reset_secondary(Config::default());
    s.handle_input(&primary_frame(AddressWidth::One, LinkAddress(255), PrimaryFunction::RequestClass2, true, true, &[]), ms(1));
    let (tx, events) = drain(&mut s);
    assert!(tx.is_empty() && events.is_empty());
    assert_eq!(s.stats().unexpected, 1);
    // A broadcast request in 2-octet width is 65535.
    assert_eq!(AddressWidth::Two.broadcast(), Some(LinkAddress(0xFFFF)));
    assert_eq!(AddressWidth::Zero.broadcast(), None);
}

#[test]
fn two_outstations_are_polled_round_robin() {
    let mut line = Line::new(vec![
        Cs101Link::primary(&[A, B], Config::default()).unwrap(),
        Cs101Link::secondary(A, Config::default()).unwrap(),
        Cs101Link::secondary(B, Config::default()).unwrap(),
    ]);
    for k in 0..5u8 {
        line.links[1].submit(&[1, 1, 3, 1, k, 0, 0xA], Class::Two, ms(0)).unwrap();
        line.links[2].submit(&[1, 1, 3, 1, k, 0, 0xB], Class::Two, ms(0)).unwrap();
    }
    line.run(0, 1000, 10);
    let got = line.asdus(0);
    assert_eq!(got.len(), 10);
    // Interleaved: neither outstation waits for the other's queue to drain.
    let first_four: Vec<_> = got.iter().take(4).map(|(s, _)| *s).collect();
    assert!(first_four.contains(&A) && first_four.contains(&B), "{first_four:?}");
    // Other secondaries' answers on the shared line are not taken for requests.
    assert!(line.links[1].stats().echoes > 0);
}

#[test]
fn a_silent_outstation_is_stopped_and_does_not_stall_the_other() {
    let config = Config { reset_interval: Duration::from_millis(2000), ..Config::default() };
    let mut line =
        Line::new(vec![Cs101Link::primary(&[A, B], config).unwrap(), Cs101Link::secondary(A, config).unwrap(), Cs101Link::secondary(B, config).unwrap()]);
    line.run(0, 200, 10);
    assert!(line.links[0].is_up(A) && line.links[0].is_up(B));
    // B's modem dies.
    line.mute[2] = true;
    line.links[0].submit_to(B, &[0x2D, 1, 6, 1, 1, 0, 1], Class::One, ms(210)).unwrap();
    for k in 0..20u8 {
        line.links[1].submit(&[1, 1, 3, 1, k, 0, 1], Class::Two, ms(210)).unwrap();
    }
    line.run(210, 3000, 10);
    let stopped: Vec<_> = line.events[0].iter().filter(|e| matches!(e, Event::Stopped { .. })).collect();
    assert_eq!(stopped, [&Event::Stopped { station: B, reason: StopReason::NoResponse }]);
    // B may or may not have received the user data: it is reported, not silently dropped.
    assert!(line.events[0].iter().any(|e| matches!(e, Event::Unconfirmed { station: B, class: Class::One, .. })));
    assert_eq!(line.asdus(0).len(), 20, "A kept being polled");
    // B comes back: the master resets it after reset_interval.
    line.mute[2] = false;
    line.run(3010, 6000, 10);
    assert!(line.links[0].is_up(B));
    assert_eq!(line.events[0].iter().filter(|e| **e == Event::Started { station: B }).count(), 2);
}

#[test]
fn single_char_e5_is_ack_and_no_data() {
    let mut s = reset_secondary(Config::default());
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::RequestClass2, true, true, &[]), ms(1));
    assert_eq!(drain(&mut s).0, [0xE5]);
    // Without single-character answers: fixed ACK and NoData frames.
    let mut s = Cs101Link::secondary(A, Config { single_char_ack: false, ..Config::default() }).unwrap();
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::ResetRemoteLink, false, false, &[]), ms(0));
    assert!(matches!(decode(&drain(&mut s).0), Frame::Fixed { control: Control::Secondary { function: SecondaryFunction::Ack, .. }, .. }));
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::RequestClass2, true, true, &[]), ms(1));
    assert!(matches!(decode(&drain(&mut s).0), Frame::Fixed { control: Control::Secondary { function: SecondaryFunction::NoData, .. }, .. }));
    // And the master takes E5 both as the reset ACK and as "no data".
    let mut line = Line::new(vec![Cs101Link::primary(&[A], Config::default()).unwrap(), Cs101Link::secondary(A, Config::default()).unwrap()]);
    line.run(0, 300, 10);
    assert!(line.links[0].is_up(A));
    assert_eq!(line.links[0].stats().unexpected, 0);
}

#[test]
fn fcv_frame_before_reset_is_answered_not_functioning() {
    let mut s = Cs101Link::secondary(A, Config::default()).unwrap();
    // Request status is fine before a reset.
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::RequestLinkStatus, false, false, &[]), ms(0));
    assert!(matches!(decode(&drain(&mut s).0), Frame::Fixed { control: Control::Secondary { function: SecondaryFunction::LinkStatus, .. }, .. }));
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::UserDataConfirmed, true, true, ASDU), ms(1));
    let (tx, events) = drain(&mut s);
    assert!(events.is_empty());
    assert!(matches!(decode(&tx), Frame::Fixed { control: Control::Secondary { function: SecondaryFunction::NotFunctioning, .. }, .. }));
    // A master told "not functioning" resets the link at once.
    let mut line = Line::new(vec![Cs101Link::primary(&[A], Config::default()).unwrap(), Cs101Link::secondary(A, Config::default()).unwrap()]);
    line.run(0, 100, 10);
    line.links[1] = Cs101Link::secondary(A, Config::default()).unwrap(); // the outstation restarted
    line.links[1].submit(ASDU, Class::One, ms(110)).unwrap();
    line.run(110, 400, 10);
    assert!(line.events[0].contains(&Event::Stopped { station: A, reason: StopReason::NotFunctioning }));
    assert_eq!(line.asdus(0), [(A, ASDU.to_vec())]);
}

#[test]
fn reserved_and_unsupported_functions_are_not_implemented() {
    let mut s = reset_secondary(Config::default());
    for function in [PrimaryFunction::Reserved(5), PrimaryFunction::ResetUserProcess] {
        s.handle_input(&primary_frame(AddressWidth::One, A, function, false, false, &[]), ms(1));
        assert!(matches!(decode(&drain(&mut s).0), Frame::Fixed { control: Control::Secondary { function: SecondaryFunction::NotImplemented, .. }, .. }));
    }
    // A balanced end has no class data.
    let mut b = Cs101Link::balanced(Role::Controlled, A, A, Config::default()).unwrap();
    let mut req = primary_frame(AddressWidth::One, A, PrimaryFunction::RequestClass1, true, true, &[]);
    req[1] |= 0x80; // from the controlling end
    let cs = req.len() - 2;
    req[cs] = req[cs].wrapping_add(0x80);
    b.handle_input(&req, ms(0));
    assert!(matches!(decode(&drain(&mut b).0[..5]), Frame::Fixed { control: Control::Secondary { function: SecondaryFunction::NotImplemented, .. }, .. }));
}

#[test]
fn foreign_address_is_ignored() {
    let mut s = reset_secondary(Config::default());
    s.handle_input(&primary_frame(AddressWidth::One, B, PrimaryFunction::RequestClass2, true, true, &[]), ms(1));
    let (tx, _) = drain(&mut s);
    assert!(tx.is_empty());
    assert_eq!(s.stats().foreign_address, 1);
}

#[test]
fn busy_secondary_sets_dfc_and_the_master_holds_user_data() {
    let mut s = reset_secondary(Config::default());
    s.set_busy(true);
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::UserDataConfirmed, true, true, ASDU), ms(1));
    let (tx, events) = drain(&mut s);
    assert!(events.is_empty());
    assert!(matches!(decode(&tx), Frame::Fixed { control: Control::Secondary { dfc: true, function: SecondaryFunction::Nack, .. }, .. }));

    let mut line = Line::new(vec![Cs101Link::primary(&[A], Config::default()).unwrap(), Cs101Link::secondary(A, Config::default()).unwrap()]);
    line.run(0, 100, 10);
    line.links[1].set_busy(true);
    line.links[0].submit(ASDU, Class::One, ms(110)).unwrap();
    line.run(110, 600, 10);
    assert!(line.asdus(1).is_empty());
    assert_eq!(line.links[0].queued(A, Class::One), 1, "held, not dropped");
    line.links[1].set_busy(false);
    line.run(610, 1200, 10);
    assert_eq!(line.asdus(1), [(A, ASDU.to_vec())]);
    assert!(line.events[0].contains(&Event::Acknowledged { station: A, class: Class::One, count: 1 }));
}

#[test]
fn submit_refusals_are_named() {
    let config = Config { queue_len: 2, ..Config::default() };
    let mut s = Cs101Link::secondary(A, config).unwrap();
    assert_eq!(s.submit(&[], Class::One, ms(0)), Err(SubmitError::Empty));
    s.submit(ASDU, Class::One, ms(0)).unwrap();
    assert!(s.can_send(Class::One));
    s.submit(ASDU, Class::One, ms(0)).unwrap();
    assert!(!s.can_send(Class::One));
    assert_eq!(s.submit(ASDU, Class::One, ms(0)), Err(SubmitError::QueueFull));
    assert_eq!(s.submit(ASDU, Class::Two, ms(0)), Ok(()));
    assert_eq!(s.submit_to(B, ASDU, Class::One, ms(0)), Err(SubmitError::UnknownStation(B)));
    let mut m = Cs101Link::primary(&[A, B], config).unwrap();
    assert_eq!(m.submit(ASDU, Class::One, ms(0)), Err(SubmitError::StationRequired));
    assert_eq!(m.submit_to(LinkAddress(9), ASDU, Class::One, ms(0)), Err(SubmitError::UnknownStation(LinkAddress(9))));
    m.close();
    assert_eq!(m.submit_to(A, ASDU, Class::One, ms(0)), Err(SubmitError::Closed));
    for e in [SubmitError::QueueFull, SubmitError::StationRequired, SubmitError::TooLong(300)] {
        assert!(!e.to_string().is_empty());
    }
}

#[test]
fn constructors_check_addresses() {
    let c = Config::default();
    assert_eq!(Cs101Link::primary(&[], c).err(), Some(ConfigError::NoSecondaries));
    assert_eq!(Cs101Link::primary(&[A, A], c).err(), Some(ConfigError::DuplicateSecondary(A)));
    assert_eq!(Cs101Link::secondary(LinkAddress(255), c).err(), Some(ConfigError::BroadcastAddress(LinkAddress(255))));
    assert_eq!(Cs101Link::secondary(LinkAddress(300), c).err(), Some(ConfigError::AddressOutOfRange(LinkAddress(300))));
    assert_eq!(Cs101Link::secondary(A, Config { queue_len: 0, ..c }).err(), Some(ConfigError::Zero("queue_len")));
}

#[test]
fn reset_with_a_response_in_flight_reports_it_unconfirmed() {
    let mut s = reset_secondary(Config::default());
    s.submit(ASDU, Class::One, ms(0)).unwrap();
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::RequestClass1, true, true, &[]), ms(1));
    drain(&mut s);
    s.handle_input(&primary_frame(AddressWidth::One, A, PrimaryFunction::ResetRemoteLink, false, false, &[]), ms(2));
    let (_, events) = drain(&mut s);
    assert_eq!(events, [Event::Unconfirmed { station: A, class: Class::One, asdu: ASDU.to_vec() }, Event::Started { station: A }]);
}

#[test]
fn retries_exhausted_reports_user_data_unconfirmed() {
    let config = Config { retries: 2, ..Config::default() };
    let mut m = Cs101Link::primary(&[A], config).unwrap();
    let mut s = Cs101Link::secondary(A, config).unwrap();
    m.handle_timeout(ms(0));
    for _ in 0..3 {
        let (tx, _) = drain(&mut m);
        s.handle_input(&tx, ms(0));
        let (tx, _) = drain(&mut s);
        m.handle_input(&tx, ms(0));
    }
    // Up, first class 2 poll answered; from here on the outstation is silent.
    m.submit(ASDU, Class::One, ms(1)).unwrap();
    let mut events = drain(&mut m).1;
    for t in (0..5000).step_by(50) {
        m.handle_timeout(ms(t));
        events.extend(drain(&mut m).1);
    }
    assert_eq!(m.stats().retransmissions, 2);
    assert!(events.contains(&Event::Stopped { station: A, reason: StopReason::NoResponse }));
    assert!(events.contains(&Event::Unconfirmed { station: A, class: Class::One, asdu: ASDU.to_vec() }));
    assert_eq!(m.queued(A, Class::One), 0);
}

#[test]
fn disconnect_and_close_end_the_link() {
    let mut s = Cs101Link::secondary(A, Config::default()).unwrap();
    Protocol::handle_disconnect(&mut s, ms(0));
    assert!(s.is_closed());
    assert_eq!(drain(&mut s).1, [Event::Closed(CloseReason::PeerClosed)]);
    s.close();
    assert!(drain(&mut s).1.is_empty(), "closed once");
    let mut m = Cs101Link::primary(&[A], Config::default()).unwrap();
    m.close();
    assert_eq!(drain(&mut m).1, [Event::Closed(CloseReason::Local)]);
    m.handle_input(&[0xE5], ms(1));
    m.handle_timeout(ms(1000));
    assert!(m.poll_output().is_none());
}

#[test]
fn deadlines_are_reported() {
    let mut m = Cs101Link::primary(&[A], Config::default()).unwrap();
    m.handle_timeout(ms(0));
    let mut deadline = None;
    while let Some(o) = m.poll_output() {
        if let Output::Deadline(d) = o {
            deadline = Some(d);
        }
    }
    assert_eq!(deadline, Some(ms(500)), "the response timeout of the status request");
}
