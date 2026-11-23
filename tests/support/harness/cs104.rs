//! The checks behind the `apci` and `cs104_link` fuzz targets, shared with
//! `tests/regressions_cs104.rs` so a committed crash input replays the same logic.

#![allow(dead_code)]

use core::time::Duration;

use iec60870::cs104::{Apdu, Config, Cs104Link, Event, FrameSplitter, Role};
use iec60870::driver::Output;
use iec60870::time::Instant;

/// The APCI decoder and the splitter on arbitrary octets: no panic; what decodes re-encodes
/// to the input; the splitter, fed in pieces, agrees with whole-frame decoding.
pub fn apci(data: &[u8]) {
    if let Ok(apdu) = Apdu::decode(data) {
        assert_eq!(apdu.to_vec().expect("a decoded APDU re-encodes"), data);
    }
    let step = usize::from(data.first().copied().unwrap_or(1) % 7) + 1;
    let mut splitter = FrameSplitter::new();
    let mut seen = Vec::new();
    for piece in data.chunks(step) {
        let mut input = piece;
        while let Some(frame) = splitter.next_frame(&mut input) {
            match frame {
                Ok(apdu) => seen.extend(apdu.to_vec().expect("a split APDU re-encodes")),
                Err(_) => break,
            }
            assert!(splitter.buffered() < 255);
        }
    }
    assert!(data.starts_with(&seen), "the splitter reproduces a prefix of the stream");
}

/// The link fed a script of chunks, ticks and commands: no panic; every transmit is whole,
/// valid APDUs; no event after `Closed`; the window is respected; at most one deadline per drain.
pub fn link(data: &[u8]) {
    let Some((&setup, mut script)) = data.split_first() else { return };
    let role = if setup & 1 == 0 { Role::Controlling } else { Role::Controlled };
    let k = u16::from(setup >> 1 & 0x07) + 1;
    let w = u16::from(setup >> 4 & 0x07) + 1;
    let config = Config { k, w, t0: Duration::from_secs(1), t1: Duration::from_millis(300), t2: Duration::from_millis(100), t3: Duration::from_millis(500) };
    let mut link = Cs104Link::new(role, config).expect("valid configuration");
    let mut now = 0u64;
    let mut closed = false;
    let asdu = [0x64u8, 1, 6, 0, 1, 0, 0, 0, 0, 0x14];
    while let Some((&op, rest)) = script.split_first() {
        script = rest;
        let at = Instant::from_millis(now);
        match op % 8 {
            0 | 1 => {
                let n = usize::from(op >> 3).min(script.len());
                let (chunk, rest) = script.split_at(n);
                script = rest;
                link.handle_input(chunk, at);
            }
            2 => {
                now += u64::from(op >> 3) * 25;
                link.handle_timeout(Instant::from_millis(now));
            }
            3 => {
                let _ = link.submit(&asdu[..=usize::from(op >> 3) % asdu.len()], at);
            }
            4 => {
                let _ = link.start(at);
            }
            5 => {
                let _ = link.stop(at);
            }
            6 => {
                if op >> 3 == 0 {
                    link.close();
                } else {
                    link.handle_disconnect(at);
                }
            }
            _ => {
                let _ = link.can_send();
            }
        }
        assert!(link.outstanding() <= k);
        let mut deadlines = 0;
        while let Some(out) = link.poll_output() {
            match out {
                Output::Transmit(bytes) => {
                    let mut splitter = FrameSplitter::new();
                    let mut input = &bytes[..];
                    while let Some(frame) = splitter.next_frame(&mut input) {
                        frame.expect("the link emits only valid APDUs");
                    }
                    assert_eq!(splitter.buffered(), 0, "a transmit carries whole APDUs");
                }
                Output::Event(event) => {
                    assert!(!closed, "event after Closed: {event:?}");
                    closed = matches!(event, Event::Closed(_));
                }
                Output::Deadline(d) => {
                    deadlines += 1;
                    assert!(d.as_nanos() >= Instant::from_millis(now).as_nanos(), "a deadline in the past");
                }
            }
        }
        assert!(deadlines <= 1);
        assert_eq!(closed, link.is_closed());
    }
}
