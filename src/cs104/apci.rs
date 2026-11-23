//! The APCI: the six-octet frame header of IEC 60870-5-104 and the frames it makes.
//!
//! An APDU is the start octet `0x68`, a length octet (the octets that follow, 4–253) and four
//! control octets, followed by an ASDU when the frame is in the I format:
//!
//! | Format | Control octets | Carries |
//! |---|---|---|
//! | I | octet 1 bit 0 = 0; N(S) in octets 1–2, N(R) in octets 3–4 | an ASDU of 1–249 octets |
//! | S | `01 00`, N(R) in octets 3–4 | an acknowledgment |
//! | U | one of `07 0B 13 23 43 83`, then `00 00 00` | STARTDT, STOPDT, TESTFR act/con |
//!
//! The decoder is exact — a control octet outside these forms is refused — and never panics.
//!
//! ```
//! use iec60870::cs104::{Apci, Apdu, FrameSplitter, SeqNo, UFunction};
//!
//! let frame = Apdu::u(UFunction::StartDtAct).to_vec().unwrap();
//! assert_eq!(frame, [0x68, 0x04, 0x07, 0x00, 0x00, 0x00]);
//!
//! // Frames arrive in arbitrary pieces; the splitter reassembles them.
//! let mut splitter = FrameSplitter::new();
//! let mut first = &frame[..3];
//! assert!(splitter.next_frame(&mut first).is_none());
//! let mut rest = &frame[3..];
//! let apdu = splitter.next_frame(&mut rest).unwrap().unwrap();
//! assert_eq!(apdu.apci, Apci::U(UFunction::StartDtAct));
//! # let _ = SeqNo::ZERO;
//! ```

use alloc::vec::Vec;
use core::fmt;

/// The start octet of every APDU.
pub const START: u8 = 0x68;
/// The largest APDU: start, length and 253 octets.
pub const MAX_APDU_LEN: usize = 255;
/// The largest ASDU an I-frame carries.
pub const MAX_ASDU_LEN: usize = 249;
/// The registered TCP port of IEC 60870-5-104.
pub const DEFAULT_PORT: u16 = 2404;
/// The registered TCP port of IEC 60870-5-104 over TLS.
pub const DEFAULT_TLS_PORT: u16 = 19998;

const MIN_LENGTH: u8 = 4;
const MAX_LENGTH: u8 = 253;

/// A send or receive sequence number, N(S) or N(R): 15 bits, counted modulo 32768.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct SeqNo(u16);

impl SeqNo {
    /// Sequence number 0, where every connection starts.
    pub const ZERO: SeqNo = SeqNo(0);
    /// Sequence number 32767, the last before the wrap.
    pub const MAX: SeqNo = SeqNo(0x7FFF);

    /// The sequence number `n`, or `None` above 32767.
    pub const fn new(n: u16) -> Option<Self> {
        if n <= 0x7FFF { Some(SeqNo(n)) } else { None }
    }

    /// The number, 0–32767.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// The next sequence number: 32767 wraps to 0.
    #[must_use]
    pub const fn next(self) -> Self {
        self.wrapping_add(1)
    }

    /// `self + n`, modulo 32768.
    #[must_use]
    pub const fn wrapping_add(self, n: u16) -> Self {
        SeqNo(self.0.wrapping_add(n) & 0x7FFF)
    }

    /// `self − n`, modulo 32768.
    #[must_use]
    pub const fn wrapping_sub(self, n: u16) -> Self {
        SeqNo(self.0.wrapping_sub(n) & 0x7FFF)
    }

    /// How many steps forward `self` is from `from`, modulo 32768 (0–32767).
    pub const fn distance(self, from: SeqNo) -> u16 {
        self.0.wrapping_sub(from.0) & 0x7FFF
    }

    /// From the two control octets that carry it: `(lo >> 1) | (hi << 7)`.
    const fn from_octets(lo: u8, hi: u8) -> Self {
        SeqNo(((lo as u16) >> 1) | ((hi as u16) << 7))
    }

    /// The two control octets: the number shifted left by one, little-endian.
    const fn to_octets(self) -> [u8; 2] {
        [((self.0 << 1) & 0xFE) as u8, (self.0 >> 7) as u8]
    }
}

impl fmt::Display for SeqNo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The function of a U-format frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UFunction {
    /// STARTDT act, control octet `0x07`: start data transfer.
    StartDtAct,
    /// STARTDT con, `0x0B`.
    StartDtCon,
    /// STOPDT act, `0x13`: stop data transfer.
    StopDtAct,
    /// STOPDT con, `0x23`.
    StopDtCon,
    /// TESTFR act, `0x43`: is the peer alive?
    TestFrAct,
    /// TESTFR con, `0x83`.
    TestFrCon,
}

impl UFunction {
    /// The first control octet.
    pub const fn octet(self) -> u8 {
        match self {
            UFunction::StartDtAct => 0x07,
            UFunction::StartDtCon => 0x0B,
            UFunction::StopDtAct => 0x13,
            UFunction::StopDtCon => 0x23,
            UFunction::TestFrAct => 0x43,
            UFunction::TestFrCon => 0x83,
        }
    }

    /// The function a first control octet names, if it is one of the six.
    pub const fn from_octet(octet: u8) -> Option<Self> {
        Some(match octet {
            0x07 => UFunction::StartDtAct,
            0x0B => UFunction::StartDtCon,
            0x13 => UFunction::StopDtAct,
            0x23 => UFunction::StopDtCon,
            0x43 => UFunction::TestFrAct,
            0x83 => UFunction::TestFrCon,
            _ => return None,
        })
    }
}

impl fmt::Display for UFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            UFunction::StartDtAct => "STARTDT act",
            UFunction::StartDtCon => "STARTDT con",
            UFunction::StopDtAct => "STOPDT act",
            UFunction::StopDtCon => "STOPDT con",
            UFunction::TestFrAct => "TESTFR act",
            UFunction::TestFrCon => "TESTFR con",
        })
    }
}

/// The four control octets, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Apci {
    /// Information transfer: an ASDU numbered `send`, acknowledging up to `recv`.
    I {
        /// N(S), this frame's number.
        send: SeqNo,
        /// N(R), the next number the sender expects to receive.
        recv: SeqNo,
    },
    /// Supervisory: an acknowledgment only.
    S {
        /// N(R), the next number the sender expects to receive.
        recv: SeqNo,
    },
    /// Unnumbered: link control.
    U(UFunction),
}

impl Apci {
    fn decode(control: [u8; 4]) -> Result<Self, FrameError> {
        let [c1, c2, c3, c4] = control;
        if c1 & 0x01 == 0 {
            if c3 & 0x01 != 0 {
                return Err(FrameError::BadControl(control));
            }
            return Ok(Apci::I { send: SeqNo::from_octets(c1, c2), recv: SeqNo::from_octets(c3, c4) });
        }
        if c1 & 0x03 == 0x01 {
            if c1 != 0x01 || c2 != 0 || c3 & 0x01 != 0 {
                return Err(FrameError::BadControl(control));
            }
            return Ok(Apci::S { recv: SeqNo::from_octets(c3, c4) });
        }
        match UFunction::from_octet(c1) {
            Some(function) if c2 == 0 && c3 == 0 && c4 == 0 => Ok(Apci::U(function)),
            _ => Err(FrameError::BadControl(control)),
        }
    }

    fn encode(self) -> [u8; 4] {
        match self {
            Apci::I { send, recv } => {
                let [a, b] = send.to_octets();
                let [c, d] = recv.to_octets();
                [a, b, c, d]
            }
            Apci::S { recv } => {
                let [c, d] = recv.to_octets();
                [0x01, 0x00, c, d]
            }
            Apci::U(function) => [function.octet(), 0, 0, 0],
        }
    }
}

/// One APDU: the control information and, for an I-frame, the ASDU it carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Apdu<'a> {
    /// The decoded control octets.
    pub apci: Apci,
    /// The ASDU octets (empty for S and U frames).
    pub asdu: &'a [u8],
}

impl<'a> Apdu<'a> {
    /// An I-frame.
    pub const fn i(send: SeqNo, recv: SeqNo, asdu: &'a [u8]) -> Self {
        Apdu { apci: Apci::I { send, recv }, asdu }
    }

    /// An S-frame.
    pub const fn s(recv: SeqNo) -> Self {
        Apdu { apci: Apci::S { recv }, asdu: &[] }
    }

    /// A U-frame.
    pub const fn u(function: UFunction) -> Self {
        Apdu { apci: Apci::U(function), asdu: &[] }
    }

    /// Decodes exactly one APDU; any octet before or after it is an error.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, FrameError> {
        let Some((&start, rest)) = bytes.split_first() else {
            return Err(FrameError::Truncated { needed: 2 });
        };
        if start != START {
            return Err(FrameError::BadStart(start));
        }
        let Some((&length, rest)) = rest.split_first() else {
            return Err(FrameError::Truncated { needed: 2 });
        };
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
            return Err(FrameError::BadLength(length));
        }
        let length = usize::from(length);
        if rest.len() < length {
            return Err(FrameError::Truncated { needed: 2 + length });
        }
        if rest.len() > length {
            return Err(FrameError::Trailing { extra: rest.len() - length });
        }
        let Some((&control, asdu)) = rest.split_first_chunk::<4>() else {
            return Err(FrameError::Truncated { needed: 6 });
        };
        let apci = Apci::decode(control)?;
        check_asdu(apci, asdu)?;
        Ok(Apdu { apci, asdu })
    }

    /// The encoded length: 6 + the ASDU.
    pub const fn len(&self) -> usize {
        6 + self.asdu.len()
    }

    /// Always false: an APDU has at least six octets.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Encodes into `out`, returning the octets written. Refuses an I-frame whose ASDU is
    /// empty or longer than 249 octets, an S or U frame with an ASDU, and a buffer too small
    /// (nothing is written then).
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, FrameError> {
        check_asdu(self.apci, self.asdu)?;
        let len = self.len();
        let Some(out) = out.get_mut(..len) else {
            return Err(FrameError::BufferTooSmall { needed: len });
        };
        let Some((header, body)) = out.split_first_chunk_mut::<6>() else {
            return Err(FrameError::BufferTooSmall { needed: len });
        };
        let [c1, c2, c3, c4] = self.apci.encode();
        *header = [START, (len - 2) as u8, c1, c2, c3, c4];
        body.copy_from_slice(self.asdu);
        Ok(len)
    }

    /// Encodes into a new vector (see [`encode`](Self::encode)).
    pub fn to_vec(&self) -> Result<Vec<u8>, FrameError> {
        let mut out = alloc::vec![0; self.len()];
        self.encode(&mut out)?;
        Ok(out)
    }
}

fn check_asdu(apci: Apci, asdu: &[u8]) -> Result<(), FrameError> {
    match apci {
        Apci::I { .. } if asdu.is_empty() => Err(FrameError::EmptyAsdu),
        Apci::I { .. } if asdu.len() > MAX_ASDU_LEN => Err(FrameError::AsduTooLong(asdu.len())),
        Apci::S { .. } | Apci::U(_) if !asdu.is_empty() => Err(FrameError::UnexpectedAsdu),
        Apci::I { .. } | Apci::S { .. } | Apci::U(_) => Ok(()),
    }
}

/// Why octets are not an APDU, or an APDU cannot be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// The first octet is not `0x68`.
    BadStart(u8),
    /// The length octet is outside 4–253.
    BadLength(u8),
    /// The octets end before the frame does; `needed` is the frame length known so far.
    Truncated {
        /// The octets the frame needs.
        needed: usize,
    },
    /// Octets follow the frame (only [`Apdu::decode`], which takes exactly one frame).
    Trailing {
        /// How many.
        extra: usize,
    },
    /// The control octets are none of the I, S or U forms (an unknown U function, a set
    /// bit 0 in an N(R), a non-zero reserved octet).
    BadControl([u8; 4]),
    /// An I-frame without an ASDU.
    EmptyAsdu,
    /// An S or U frame with octets after the control field.
    UnexpectedAsdu,
    /// An ASDU longer than 249 octets (encoding only).
    AsduTooLong(usize),
    /// The output buffer is too small (encoding only); nothing was written.
    BufferTooSmall {
        /// The octets the frame needs.
        needed: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::BadStart(b) => write!(f, "start octet {b:#04x}, expected 0x68"),
            FrameError::BadLength(l) => write!(f, "APDU length {l} outside 4..=253"),
            FrameError::Truncated { needed } => write!(f, "truncated APDU: {needed} octets needed"),
            FrameError::Trailing { extra } => write!(f, "{extra} octets after the APDU"),
            FrameError::BadControl([c1, c2, c3, c4]) => write!(f, "invalid control field {c1:02x} {c2:02x} {c3:02x} {c4:02x}"),
            FrameError::EmptyAsdu => f.write_str("I-frame without an ASDU"),
            FrameError::UnexpectedAsdu => f.write_str("S- or U-frame carrying octets after the control field"),
            FrameError::AsduTooLong(n) => write!(f, "ASDU of {n} octets, at most 249 fit an APDU"),
            FrameError::BufferTooSmall { needed } => write!(f, "buffer too small: {needed} octets needed"),
        }
    }
}

impl core::error::Error for FrameError {}

/// Reassembles APDUs from a byte stream that arrives in arbitrary pieces.
///
/// It holds at most one APDU (255 octets) and allocates nothing. An error is terminal: a 104
/// stream cannot be resynchronised, so after returning one error the splitter returns `None`
/// for ever ([`is_failed`](Self::is_failed) says so).
#[derive(Clone, Debug)]
pub struct FrameSplitter {
    buf: [u8; MAX_APDU_LEN],
    len: usize,
    complete: bool,
    failed: bool,
}

impl Default for FrameSplitter {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameSplitter {
    /// An empty splitter.
    pub const fn new() -> Self {
        FrameSplitter { buf: [0; MAX_APDU_LEN], len: 0, complete: false, failed: false }
    }

    /// Takes octets from the front of `input` (advancing it) until one APDU is complete and
    /// returns it, or returns `None` once `input` is exhausted mid-frame (call again with
    /// more input). Call it in a loop until `None` to take every frame of a chunk.
    pub fn next_frame<'s>(&'s mut self, input: &mut &[u8]) -> Option<Result<Apdu<'s>, FrameError>> {
        if self.failed {
            return None;
        }
        if self.complete {
            self.complete = false;
            self.len = 0;
        }
        if self.len == 0 {
            let (&start, rest) = input.split_first()?;
            *input = rest;
            if start != START {
                return Some(self.fail(FrameError::BadStart(start)));
            }
            self.put(start);
        }
        if self.len == 1 {
            let (&length, rest) = input.split_first()?;
            *input = rest;
            if !(MIN_LENGTH..=MAX_LENGTH).contains(&length) {
                return Some(self.fail(FrameError::BadLength(length)));
            }
            self.put(length);
        }
        let total = 2 + usize::from(self.buf.get(1).copied().unwrap_or(0));
        let take = (total - self.len).min(input.len());
        let (head, rest) = input.split_at(take);
        if let Some(dst) = self.buf.get_mut(self.len..self.len + take) {
            dst.copy_from_slice(head);
        }
        *input = rest;
        self.len += take;
        if self.len < total {
            return None;
        }
        self.complete = true;
        // Validate first, then borrow: the error path must mark the splitter failed.
        if let Err(e) = self.buf.get(..total).map_or(Err(FrameError::Truncated { needed: total }), |b| Apdu::decode(b).map(|_| ())) {
            self.failed = true;
            return Some(Err(e));
        }
        self.buf.get(..total).map(Apdu::decode)
    }

    /// The octets of an incomplete frame held so far (0–254).
    pub const fn buffered(&self) -> usize {
        if self.complete { 0 } else { self.len }
    }

    /// Whether the splitter returned an error and stopped.
    pub const fn is_failed(&self) -> bool {
        self.failed
    }

    fn put(&mut self, octet: u8) {
        if let Some(slot) = self.buf.get_mut(self.len) {
            *slot = octet;
            self.len += 1;
        }
    }

    fn fail<T>(&mut self, e: FrameError) -> Result<T, FrameError> {
        self.failed = true;
        Err(e)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    // Pinned to Wireshark `packet-iec104.c` (`APCI_START`, `APDU_MIN_LEN`, `APDU_MAX_LEN`,
    // `u_types`, `IEC104_PORT`) and lib60870-C (`STARTDT_ACT_MSG` … `TESTFR_CON_MSG`,
    // `IEC_60870_5_104_DEFAULT_PORT`, `IEC_60870_5_104_DEFAULT_TLS_PORT`, `maxSizeOfASDU`).
    #[test]
    fn constants_match_the_third_party_sources() {
        assert_eq!(START, 0x68);
        assert_eq!((MIN_LENGTH, MAX_LENGTH), (4, 253));
        assert_eq!((MAX_APDU_LEN, MAX_ASDU_LEN), (255, 249));
        assert_eq!((DEFAULT_PORT, DEFAULT_TLS_PORT), (2404, 19998));
        let codes: Vec<u8> =
            [UFunction::StartDtAct, UFunction::StartDtCon, UFunction::StopDtAct, UFunction::StopDtCon, UFunction::TestFrAct, UFunction::TestFrCon]
                .iter()
                .map(|f| f.octet())
                .collect();
        assert_eq!(codes, [0x07, 0x0B, 0x13, 0x23, 0x43, 0x83]);
        assert_eq!(Apdu::u(UFunction::StartDtAct).to_vec().unwrap(), [0x68, 4, 0x07, 0, 0, 0]);
        assert_eq!(Apdu::u(UFunction::TestFrCon).to_vec().unwrap(), [0x68, 4, 0x83, 0, 0, 0]);
        // lib60870 `_sendSMessage`: 0x01 0x00, then N(R) * 2 little-endian.
        assert_eq!(Apdu::s(SeqNo::new(300).unwrap()).to_vec().unwrap(), [0x68, 4, 0x01, 0, 0x58, 0x02]);
    }

    #[test]
    fn i_frame_numbers_follow_the_shift_rule() {
        // lib60870 `sendIMessage`: (count % 128) * 2, count / 128.
        for n in [0u16, 1, 127, 128, 16383, 32767] {
            let s = SeqNo::new(n).unwrap();
            let frame = Apdu::i(s, s, &[0xAA]).to_vec().unwrap();
            assert_eq!(frame[2], ((n % 128) * 2) as u8);
            assert_eq!(frame[3], (n / 128) as u8);
            let back = Apdu::decode(&frame).unwrap();
            assert_eq!(back.apci, Apci::I { send: s, recv: s });
            assert_eq!(back.asdu, &[0xAA]);
        }
    }

    #[test]
    fn sequence_numbers_wrap() {
        assert_eq!(SeqNo::MAX.next(), SeqNo::ZERO);
        assert_eq!(SeqNo::ZERO.wrapping_sub(1), SeqNo::MAX);
        assert_eq!(SeqNo::ZERO.distance(SeqNo::MAX), 1);
        assert_eq!(SeqNo::new(32768), None);
    }

    #[test]
    fn every_refusal_names_its_reason() {
        assert_eq!(Apdu::decode(&[]), Err(FrameError::Truncated { needed: 2 }));
        assert_eq!(Apdu::decode(&[0x69, 4, 7, 0, 0, 0]), Err(FrameError::BadStart(0x69)));
        assert_eq!(Apdu::decode(&[0x68, 3, 7, 0, 0]), Err(FrameError::BadLength(3)));
        assert_eq!(Apdu::decode(&[0x68, 254]), Err(FrameError::BadLength(254)));
        assert_eq!(Apdu::decode(&[0x68, 4, 7, 0, 0]), Err(FrameError::Truncated { needed: 6 }));
        assert_eq!(Apdu::decode(&[0x68, 4, 7, 0, 0, 0, 0]), Err(FrameError::Trailing { extra: 1 }));
        assert_eq!(Apdu::decode(&[0x68, 4, 0x0F, 0, 0, 0]), Err(FrameError::BadControl([0x0F, 0, 0, 0])));
        assert_eq!(Apdu::decode(&[0x68, 4, 0x07, 1, 0, 0]), Err(FrameError::BadControl([0x07, 1, 0, 0])));
        assert_eq!(Apdu::decode(&[0x68, 4, 0x01, 0, 1, 0]), Err(FrameError::BadControl([0x01, 0, 1, 0])));
        assert_eq!(Apdu::decode(&[0x68, 4, 0x05, 0, 0, 0]), Err(FrameError::BadControl([0x05, 0, 0, 0])));
        assert_eq!(Apdu::decode(&[0x68, 4, 0, 0, 1, 0]), Err(FrameError::BadControl([0, 0, 1, 0])));
        assert_eq!(Apdu::decode(&[0x68, 4, 0, 0, 0, 0]), Err(FrameError::EmptyAsdu));
        assert_eq!(Apdu::decode(&[0x68, 5, 0x43, 0, 0, 0, 9]), Err(FrameError::UnexpectedAsdu));
        assert_eq!(Apdu::i(SeqNo::ZERO, SeqNo::ZERO, &[0; 250]).to_vec(), Err(FrameError::AsduTooLong(250)));
        let mut small = [0u8; 5];
        assert_eq!(Apdu::u(UFunction::TestFrAct).encode(&mut small), Err(FrameError::BufferTooSmall { needed: 6 }));
        assert_eq!(small, [0; 5]);
    }

    #[test]
    fn the_largest_frame_round_trips() {
        let asdu = [0x5A; MAX_ASDU_LEN];
        let frame = Apdu::i(SeqNo::MAX, SeqNo::MAX, &asdu).to_vec().unwrap();
        assert_eq!(frame.len(), 255);
        assert_eq!(frame[1], 253);
        assert_eq!(Apdu::decode(&frame).unwrap().asdu, &asdu[..]);
    }

    #[test]
    fn the_splitter_reassembles_one_octet_at_a_time() {
        let mut stream = Vec::new();
        stream.extend(Apdu::u(UFunction::StartDtAct).to_vec().unwrap());
        stream.extend(Apdu::i(SeqNo::new(5).unwrap(), SeqNo::new(7).unwrap(), &[1, 2, 3]).to_vec().unwrap());
        stream.extend(Apdu::i(SeqNo::MAX, SeqNo::ZERO, &[0xEE; MAX_ASDU_LEN]).to_vec().unwrap());
        stream.extend(Apdu::s(SeqNo::MAX).to_vec().unwrap());
        let mut splitter = FrameSplitter::new();
        let mut seen = Vec::new();
        for octet in &stream {
            let mut input: &[u8] = core::slice::from_ref(octet);
            while let Some(frame) = splitter.next_frame(&mut input) {
                seen.push(frame.unwrap().to_vec().unwrap());
            }
            assert!(splitter.buffered() < MAX_APDU_LEN);
            assert_eq!(input, &[] as &[u8]);
        }
        assert_eq!(seen.concat(), stream);
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn the_splitter_takes_every_frame_of_one_chunk() {
        let one = Apdu::u(UFunction::TestFrAct).to_vec().unwrap();
        let stream: Vec<u8> = (0..10).flat_map(|_| one.clone()).collect();
        let mut splitter = FrameSplitter::new();
        let mut input = &stream[..];
        let mut n = 0;
        while let Some(frame) = splitter.next_frame(&mut input) {
            assert_eq!(frame.unwrap().apci, Apci::U(UFunction::TestFrAct));
            n += 1;
        }
        assert_eq!(n, 10);
    }

    #[test]
    fn a_splitter_error_is_terminal() {
        let mut splitter = FrameSplitter::new();
        let mut input: &[u8] = &[0x68, 0x02, 0x68, 4, 7, 0, 0, 0];
        assert_eq!(splitter.next_frame(&mut input).map(|r| r.map(|a| a.apci)), Some(Err(FrameError::BadLength(2))));
        assert!(splitter.next_frame(&mut input).is_none());
        assert!(splitter.is_failed());
        let mut bad: &[u8] = &[0x10];
        assert_eq!(FrameSplitter::new().next_frame(&mut bad).map(|r| r.map(|a| a.apci)), Some(Err(FrameError::BadStart(0x10))));
    }
}
