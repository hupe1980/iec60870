//! The checks behind the `ft12` and `cs101_link` fuzz targets, shared with
//! `tests/regressions_cs101.rs` so a committed crash input replays the same logic.

#![allow(dead_code)]

use core::time::Duration;

use iec60870::cs101::{AddressWidth, Class, Config, Cs101Link, Event, Frame, FrameSplitter, LinkAddress, MAX_FRAME_LEN, Role};
use iec60870::driver::Output;
use iec60870::time::Instant;

const WIDTHS: [AddressWidth; 3] = [AddressWidth::Zero, AddressWidth::One, AddressWidth::Two];

/// The FT 1.2 decoder and the splitter on arbitrary octets, under every address width: no
/// panic; what decodes re-encodes to the input; the splitter, fed in pieces at advancing
/// times, holds at most one frame and every frame it yields re-encodes to valid octets.
pub fn ft12(data: &[u8]) {
    for width in WIDTHS {
        if let Ok(frame) = Frame::decode(data, width) {
            assert_eq!(frame.to_vec(width).expect("a decoded frame re-encodes"), data, "{width:?}");
        }
        let step = usize::from(data.first().copied().unwrap_or(1) % 9) + 1;
        let mut splitter = FrameSplitter::new(width).with_timing(Duration::from_millis(5), Duration::from_millis(2));
        let mut now = Instant::ZERO;
        for (k, piece) in data.chunks(step).enumerate() {
            // Gaps of 0–7 ms between pieces, from the data itself.
            now += Duration::from_millis(u64::from(piece.first().copied().unwrap_or(0) >> 5) + (k as u64 & 1));
            let mut input = piece;
            while let Some(result) = splitter.next_frame(&mut input, now) {
                if let Ok(frame) = result {
                    let octets = frame.to_vec(width).expect("a split frame re-encodes");
                    assert_eq!(Frame::decode(&octets, width).expect("re-decodes"), frame);
                }
                assert!(splitter.buffered() <= MAX_FRAME_LEN);
            }
            assert!(splitter.buffered() <= MAX_FRAME_LEN);
        }
    }
}

/// A `Cs101Link` in a mode chosen by the first octet, fed a script: each step's low three
/// bits pick an action (input a chunk, advance time and tick, submit, set busy, disconnect),
/// the rest is its argument. Invariants: no panic, events are well formed, queues stay
/// within `queue_len`, nothing comes out after `Closed`.
pub fn link(data: &[u8]) {
    let Some((&selector, mut script)) = data.split_first() else { return };
    let width = WIDTHS[usize::from(selector & 0x03) % 3];
    let config = Config {
        address_width: width,
        retries: (selector >> 2) & 0x03,
        single_char_ack: selector & 0x10 != 0,
        queue_len: 4,
        response_timeout: Duration::from_millis(50),
        poll_interval: Duration::from_millis(10),
        reset_interval: Duration::from_millis(100),
        test_interval: Duration::from_millis(200),
        char_timeout: Duration::from_millis(20),
        idle_gap: Duration::from_millis(5),
    };
    let own = LinkAddress(width.max().min(1));
    let other = LinkAddress(width.max().min(2).saturating_sub(u16::from(width == AddressWidth::Zero)));
    let mut link = match (selector >> 5) % 4 {
        0 => Cs101Link::secondary(own, config),
        1 if width == AddressWidth::Zero => Cs101Link::primary(&[own], config),
        1 => Cs101Link::primary(&[own, other], config),
        2 => Cs101Link::balanced(Role::Controlling, own, own, config),
        _ => Cs101Link::balanced(Role::Controlled, own, own, config),
    }
    .expect("a valid configuration");
    let mut now = Instant::ZERO;
    let mut closed = false;
    while let Some((&op, rest)) = script.split_first() {
        script = rest;
        let arg = usize::from(op >> 3);
        match op & 0x07 {
            0..=2 => {
                let n = arg.min(script.len());
                let (chunk, rest) = script.split_at(n);
                script = rest;
                link.handle_input(chunk, now);
            }
            3 => {
                now += Duration::from_millis(arg as u64 * 3);
                link.handle_timeout(now);
            }
            4 => {
                let n = (arg % 12).min(script.len());
                let (asdu, rest) = script.split_at(n);
                script = rest;
                let class = if arg & 1 == 0 { Class::One } else { Class::Two };
                let station = if arg & 2 == 0 { own } else { width.broadcast().unwrap_or(own) };
                let _ = link.submit_to(station, asdu, class, now);
            }
            5 => link.set_busy(arg & 1 == 1),
            6 => {
                now += Duration::from_millis(arg as u64);
            }
            _ => {
                if arg == 31 {
                    link.handle_disconnect(now);
                }
            }
        }
        while let Some(output) = link.poll_output() {
            assert!(!closed, "output after Closed");
            match output {
                Output::Transmit(frame) => {
                    assert!(Frame::decode(&frame, width).is_ok(), "the link transmits valid frames");
                }
                Output::Event(Event::Closed(_)) => closed = true,
                Output::Event(Event::Asdu { asdu, .. } | Event::Unconfirmed { asdu, .. }) => assert_ne!(asdu.len(), 0),
                Output::Event(_) | Output::Deadline(_) => {}
            }
        }
        for class in [Class::One, Class::Two] {
            assert!(link.queued(own, class) <= 4);
        }
    }
}
