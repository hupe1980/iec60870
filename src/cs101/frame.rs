//! FT 1.2 frames: the single character, the fixed-length and the variable-length frame, and a
//! streaming splitter with inter-character timing.

use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use crate::time::Instant;

/// The single-character frame: an acknowledgment, or "no data" in answer to a request.
pub const SINGLE_CHAR: u8 = 0xE5;
/// The start octet of a fixed-length frame.
pub const START_FIXED: u8 = 0x10;
/// The start octet (both of them) of a variable-length frame.
pub const START_VARIABLE: u8 = 0x68;
/// The end octet of fixed- and variable-length frames.
pub const END: u8 = 0x16;
/// The longest frame: `0x68 L L 0x68`, 255 octets counted by L, checksum and end.
pub const MAX_FRAME_LEN: usize = 4 + 255 + 2;

/// The width of the link address field: 0, 1 or 2 octets (little-endian).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum AddressWidth {
    /// No address field (point-to-point only).
    Zero,
    /// One octet; 255 is the broadcast address.
    #[default]
    One,
    /// Two octets; 65535 is the broadcast address.
    Two,
}

impl AddressWidth {
    /// The number of octets.
    pub const fn octets(self) -> usize {
        match self {
            AddressWidth::Zero => 0,
            AddressWidth::One => 1,
            AddressWidth::Two => 2,
        }
    }

    /// The largest address the field holds (the broadcast address where there is one).
    pub const fn max(self) -> u16 {
        match self {
            AddressWidth::Zero => 0,
            AddressWidth::One => 0xFF,
            AddressWidth::Two => 0xFFFF,
        }
    }

    /// The broadcast address (all ones), or `None` without an address field.
    pub const fn broadcast(self) -> Option<LinkAddress> {
        match self {
            AddressWidth::Zero => None,
            AddressWidth::One | AddressWidth::Two => Some(LinkAddress(self.max())),
        }
    }

    /// The most user data a variable frame carries: 255 − 1 − the address octets.
    pub const fn max_user_data(self) -> usize {
        255 - 1 - self.octets()
    }

    /// The length of a fixed frame.
    pub const fn fixed_len(self) -> usize {
        4 + self.octets()
    }
}

/// A link address: which secondary station a frame is for or from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkAddress(pub u16);

impl fmt::Display for LinkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "link address {}", self.0)
    }
}

/// The function of a frame sent by a primary station (PRM = 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrimaryFunction {
    /// 0: reset of remote link.
    ResetRemoteLink,
    /// 1: reset of user process.
    ResetUserProcess,
    /// 2: test function for link (balanced).
    TestLink,
    /// 3: user data, confirm expected.
    UserDataConfirmed,
    /// 4: user data, no reply expected.
    UserDataNoReply,
    /// 7: reset of the frame count bit.
    ResetFcb,
    /// 8: request for access demand.
    RequestAccessDemand,
    /// 9: request status of link.
    RequestLinkStatus,
    /// 10: request user data class 1.
    RequestClass1,
    /// 11: request user data class 2.
    RequestClass2,
    /// A reserved code (5, 6, 12–15).
    Reserved(u8),
}

impl PrimaryFunction {
    /// The function for a code; only the low four bits count.
    pub const fn from_code(code: u8) -> Self {
        match code & 0x0F {
            0 => PrimaryFunction::ResetRemoteLink,
            1 => PrimaryFunction::ResetUserProcess,
            2 => PrimaryFunction::TestLink,
            3 => PrimaryFunction::UserDataConfirmed,
            4 => PrimaryFunction::UserDataNoReply,
            7 => PrimaryFunction::ResetFcb,
            8 => PrimaryFunction::RequestAccessDemand,
            9 => PrimaryFunction::RequestLinkStatus,
            10 => PrimaryFunction::RequestClass1,
            11 => PrimaryFunction::RequestClass2,
            other => PrimaryFunction::Reserved(other),
        }
    }

    /// The four-bit code.
    pub const fn code(self) -> u8 {
        match self {
            PrimaryFunction::ResetRemoteLink => 0,
            PrimaryFunction::ResetUserProcess => 1,
            PrimaryFunction::TestLink => 2,
            PrimaryFunction::UserDataConfirmed => 3,
            PrimaryFunction::UserDataNoReply => 4,
            PrimaryFunction::ResetFcb => 7,
            PrimaryFunction::RequestAccessDemand => 8,
            PrimaryFunction::RequestLinkStatus => 9,
            PrimaryFunction::RequestClass1 => 10,
            PrimaryFunction::RequestClass2 => 11,
            PrimaryFunction::Reserved(code) => code & 0x0F,
        }
    }
}

/// The function of a frame sent by a secondary station (PRM = 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SecondaryFunction {
    /// 0: positive acknowledgment.
    Ack,
    /// 1: negative acknowledgment — message not accepted, link busy.
    Nack,
    /// 8: user data.
    UserData,
    /// 9: negative acknowledgment — requested data not available.
    NoData,
    /// 11: status of link or access demand.
    LinkStatus,
    /// 14: link service not functioning.
    NotFunctioning,
    /// 15: link service not implemented.
    NotImplemented,
    /// A reserved code.
    Reserved(u8),
}

impl SecondaryFunction {
    /// The function for a code; only the low four bits count.
    pub const fn from_code(code: u8) -> Self {
        match code & 0x0F {
            0 => SecondaryFunction::Ack,
            1 => SecondaryFunction::Nack,
            8 => SecondaryFunction::UserData,
            9 => SecondaryFunction::NoData,
            11 => SecondaryFunction::LinkStatus,
            14 => SecondaryFunction::NotFunctioning,
            15 => SecondaryFunction::NotImplemented,
            other => SecondaryFunction::Reserved(other),
        }
    }

    /// The four-bit code.
    pub const fn code(self) -> u8 {
        match self {
            SecondaryFunction::Ack => 0,
            SecondaryFunction::Nack => 1,
            SecondaryFunction::UserData => 8,
            SecondaryFunction::NoData => 9,
            SecondaryFunction::LinkStatus => 11,
            SecondaryFunction::NotFunctioning => 14,
            SecondaryFunction::NotImplemented => 15,
            SecondaryFunction::Reserved(code) => code & 0x0F,
        }
    }
}

const DIR: u8 = 0x80;
const PRM: u8 = 0x40;
const FCB_ACD: u8 = 0x20;
const FCV_DFC: u8 = 0x10;

/// The control field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Control {
    /// From a primary station.
    Primary {
        /// The direction bit (balanced mode; 0 in unbalanced mode).
        dir: bool,
        /// The frame count bit.
        fcb: bool,
        /// Whether the frame count bit is valid.
        fcv: bool,
        /// The function.
        function: PrimaryFunction,
    },
    /// From a secondary station.
    Secondary {
        /// The direction bit (balanced mode; 0 in unbalanced mode).
        dir: bool,
        /// Access demand: class 1 data is waiting (unbalanced mode).
        acd: bool,
        /// Data flow control: further user data would overflow the secondary.
        dfc: bool,
        /// The function.
        function: SecondaryFunction,
    },
}

impl Control {
    /// Decodes a control octet; every octet is a control field.
    pub const fn from_octet(octet: u8) -> Self {
        let dir = octet & DIR != 0;
        let a = octet & FCB_ACD != 0;
        let b = octet & FCV_DFC != 0;
        if octet & PRM != 0 {
            Control::Primary { dir, fcb: a, fcv: b, function: PrimaryFunction::from_code(octet) }
        } else {
            Control::Secondary { dir, acd: a, dfc: b, function: SecondaryFunction::from_code(octet) }
        }
    }

    /// The control octet.
    pub const fn octet(self) -> u8 {
        let (prm, dir, a, b, code) = match self {
            Control::Primary { dir, fcb, fcv, function } => (PRM, dir, fcb, fcv, function.code()),
            Control::Secondary { dir, acd, dfc, function } => (0, dir, acd, dfc, function.code()),
        };
        prm | if dir { DIR } else { 0 } | if a { FCB_ACD } else { 0 } | if b { FCV_DFC } else { 0 } | code
    }

    /// The direction bit.
    pub const fn dir(self) -> bool {
        match self {
            Control::Primary { dir, .. } | Control::Secondary { dir, .. } => dir,
        }
    }
}

/// One FT 1.2 frame.
///
/// ```
/// use iec60870::cs101::{AddressWidth, Control, Frame, LinkAddress, PrimaryFunction};
///
/// // Request status of link to station 1: 10 49 01 4A 16.
/// let control = Control::Primary { dir: false, fcb: false, fcv: false, function: PrimaryFunction::RequestLinkStatus };
/// let octets = Frame::Fixed { control, address: LinkAddress(1) }.to_vec(AddressWidth::One)?;
/// assert_eq!(octets, [0x10, 0x49, 0x01, 0x4A, 0x16]);
/// assert_eq!(Frame::decode(&octets, AddressWidth::One)?, Frame::Fixed { control, address: LinkAddress(1) });
/// # Ok::<(), iec60870::cs101::FrameError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Frame<'a> {
    /// `0xE5`.
    SingleChar,
    /// `0x10 C A CS 0x16`.
    Fixed {
        /// The control field.
        control: Control,
        /// The link address (0 without an address field).
        address: LinkAddress,
    },
    /// `0x68 L L 0x68 C A user-data CS 0x16`.
    Variable {
        /// The control field.
        control: Control,
        /// The link address (0 without an address field).
        address: LinkAddress,
        /// The user data — an ASDU; never empty.
        user_data: &'a [u8],
    },
}

/// The FT 1.2 checksum: the sum of the octets modulo 256.
pub fn checksum(octets: &[u8]) -> u8 {
    octets.iter().fold(0u8, |sum, &o| sum.wrapping_add(o))
}

fn read_address(octets: &[u8], width: AddressWidth) -> LinkAddress {
    match (width, octets) {
        (AddressWidth::One, [lo, ..]) => LinkAddress(u16::from(*lo)),
        (AddressWidth::Two, [lo, hi, ..]) => LinkAddress(u16::from_le_bytes([*lo, *hi])),
        _ => LinkAddress(0),
    }
}

impl<'a> Frame<'a> {
    /// Decodes exactly one frame occupying all of `bytes`.
    pub fn decode(bytes: &'a [u8], width: AddressWidth) -> Result<Self, FrameError> {
        let (&start, rest) = bytes.split_first().ok_or(FrameError::Truncated { needed: 1 })?;
        let aw = width.octets();
        match start {
            SINGLE_CHAR => match rest.len() {
                0 => Ok(Frame::SingleChar),
                extra => Err(FrameError::Trailing { extra }),
            },
            START_FIXED => {
                let total = width.fixed_len();
                check_total(bytes.len(), total)?;
                // C A… CS END
                let body = rest.get(..1 + aw).unwrap_or_default();
                let (&control, address) = body.split_first().ok_or(FrameError::Truncated { needed: total })?;
                check_tail(body, rest.get(1 + aw..).unwrap_or_default())?;
                Ok(Frame::Fixed { control: Control::from_octet(control), address: read_address(address, width) })
            }
            START_VARIABLE => {
                let [first, second, start2, ..] = *rest else {
                    return Err(FrameError::Truncated { needed: 4 });
                };
                check_variable_header(first, second, start2, width)?;
                let total = usize::from(first) + 6;
                check_total(bytes.len(), total)?;
                let body = bytes.get(4..4 + usize::from(first)).unwrap_or_default();
                check_tail(body, bytes.get(4 + usize::from(first)..).unwrap_or_default())?;
                let (&control, rest) = body.split_first().ok_or(FrameError::BadLength(first))?;
                let (address, user_data) = rest.split_at(aw.min(rest.len()));
                Ok(Frame::Variable { control: Control::from_octet(control), address: read_address(address, width), user_data })
            }
            other => Err(FrameError::BadStart(other)),
        }
    }

    /// The encoded length.
    pub fn encoded_len(&self, width: AddressWidth) -> usize {
        match self {
            Frame::SingleChar => 1,
            Frame::Fixed { .. } => width.fixed_len(),
            Frame::Variable { user_data, .. } => 6 + 1 + width.octets() + user_data.len(),
        }
    }

    /// Encodes into `out`, returning the number of octets written.
    pub fn encode(&self, width: AddressWidth, out: &mut [u8]) -> Result<usize, FrameError> {
        let len = self.encoded_len(width);
        let (control, address) = match *self {
            Frame::SingleChar => {
                let slot = out.first_mut().ok_or(FrameError::Truncated { needed: 1 })?;
                *slot = SINGLE_CHAR;
                return Ok(1);
            }
            Frame::Fixed { control, address } | Frame::Variable { control, address, .. } => (control, address),
        };
        if address.0 > width.max() {
            return Err(FrameError::AddressTooWide(address));
        }
        let user_data: &[u8] = match self {
            Frame::Variable { user_data, .. } => {
                if user_data.is_empty() {
                    return Err(FrameError::EmptyUserData);
                }
                if user_data.len() > width.max_user_data() {
                    return Err(FrameError::UserDataTooLong(user_data.len()));
                }
                user_data
            }
            _ => &[],
        };
        let out = out.get_mut(..len).ok_or(FrameError::Truncated { needed: len })?;
        let l = (1 + width.octets() + user_data.len()) as u8;
        let variable = [START_VARIABLE, l, l, START_VARIABLE];
        let header: &[u8] = if matches!(self, Frame::Variable { .. }) { &variable } else { &[START_FIXED] };
        let addr = address.0.to_le_bytes();
        let addr = addr.get(..width.octets()).unwrap_or_default();
        let control = [control.octet()];
        let tail = [checksum(&control).wrapping_add(checksum(addr)).wrapping_add(checksum(user_data)), END];
        let octets = header.iter().chain(&control).chain(addr).chain(user_data).chain(&tail);
        for (slot, &octet) in out.iter_mut().zip(octets) {
            *slot = octet;
        }
        Ok(len)
    }

    /// Encodes into a new vector.
    pub fn to_vec(&self, width: AddressWidth) -> Result<Vec<u8>, FrameError> {
        let mut buf = alloc::vec![0; self.encoded_len(width)];
        let n = self.encode(width, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

fn check_total(len: usize, total: usize) -> Result<(), FrameError> {
    match len.cmp(&total) {
        core::cmp::Ordering::Less => Err(FrameError::Truncated { needed: total }),
        core::cmp::Ordering::Greater => Err(FrameError::Trailing { extra: len - total }),
        core::cmp::Ordering::Equal => Ok(()),
    }
}

/// Checks the checksum over `body` and the end octet in `tail` (`[CS, END]`).
fn check_tail(body: &[u8], tail: &[u8]) -> Result<(), FrameError> {
    let [cs, end] = *tail else {
        return Err(FrameError::Truncated { needed: body.len() + 2 });
    };
    let computed = checksum(body);
    if cs != computed {
        return Err(FrameError::BadChecksum { computed, received: cs });
    }
    if end != END {
        return Err(FrameError::BadEnd(end));
    }
    Ok(())
}

fn check_variable_header(first: u8, second: u8, start2: u8, width: AddressWidth) -> Result<(), FrameError> {
    if first != second {
        return Err(FrameError::LengthMismatch { first, second });
    }
    if start2 != START_VARIABLE {
        return Err(FrameError::BadSecondStart(start2));
    }
    if usize::from(first) <= 1 + width.octets() {
        return Err(if usize::from(first) == 1 + width.octets() { FrameError::EmptyUserData } else { FrameError::BadLength(first) });
    }
    Ok(())
}

/// Why octets are not an FT 1.2 frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameError {
    /// An octet that starts no frame (`0xE5`, `0x10` and `0x68` do).
    BadStart(u8),
    /// The fourth octet of a variable frame is not `0x68`.
    BadSecondStart(u8),
    /// The two L fields of a variable frame differ.
    LengthMismatch {
        /// The first L.
        first: u8,
        /// The second L.
        second: u8,
    },
    /// An L field too small to hold the control field and the address.
    BadLength(u8),
    /// The checksum octet does not match the sum of the frame.
    BadChecksum {
        /// The sum of the octets received.
        computed: u8,
        /// The checksum octet received.
        received: u8,
    },
    /// The last octet is not `0x16`.
    BadEnd(u8),
    /// Fewer octets than the frame needs.
    Truncated {
        /// The octets the frame needs.
        needed: usize,
    },
    /// Octets after the end of the frame.
    Trailing {
        /// How many.
        extra: usize,
    },
    /// A variable frame without user data.
    EmptyUserData,
    /// More user data than a variable frame carries (255 − 1 − address octets).
    UserDataTooLong(usize),
    /// An address the address field cannot hold.
    AddressTooWide(LinkAddress),
    /// A frame was interrupted: its next octet came later than the inter-character timeout.
    InterCharacterTimeout {
        /// The octets of the partial frame thrown away.
        discarded: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::BadStart(o) => write!(f, "octet {o:#04x} starts no FT 1.2 frame"),
            FrameError::BadSecondStart(o) => write!(f, "second start octet {o:#04x}, expected 0x68"),
            FrameError::LengthMismatch { first, second } => write!(f, "L fields differ: {first} and {second}"),
            FrameError::BadLength(l) => write!(f, "L = {l} cannot hold the control field and the address"),
            FrameError::BadChecksum { computed, received } => write!(f, "checksum {received:#04x}, computed {computed:#04x}"),
            FrameError::BadEnd(o) => write!(f, "end octet {o:#04x}, expected 0x16"),
            FrameError::Truncated { needed } => write!(f, "truncated frame, {needed} octets needed"),
            FrameError::Trailing { extra } => write!(f, "{extra} octets after the end of the frame"),
            FrameError::EmptyUserData => f.write_str("variable frame without user data"),
            FrameError::UserDataTooLong(n) => write!(f, "{n} octets of user data do not fit a variable frame"),
            FrameError::AddressTooWide(a) => write!(f, "{a} does not fit the address field"),
            FrameError::InterCharacterTimeout { discarded } => write!(f, "inter-character timeout, {discarded} octets discarded"),
        }
    }
}

impl core::error::Error for FrameError {}

/// The default inter-character timeout of [`FrameSplitter`].
pub const DEFAULT_CHAR_TIMEOUT: Duration = Duration::from_millis(300);
/// The default line idle that ends error recovery in [`FrameSplitter`].
pub const DEFAULT_IDLE_GAP: Duration = Duration::from_millis(10);

/// Cuts a serial byte stream into FT 1.2 frames, without allocating.
///
/// Feed it what arrived with the time it arrived. It holds at most one maximal frame
/// ([`MAX_FRAME_LEN`] octets). A partial frame whose next octet comes later than the
/// inter-character timeout is thrown away ([`FrameError::InterCharacterTimeout`]). After an
/// octet that starts no frame, a variable-frame header that cannot be right, or a frame with a
/// wrong checksum or end octet, it discards octets until the line has been idle for the idle
/// gap: the octets after a broken frame may be its own user data (one octet lost or inserted
/// shifts every boundary), and a single `0xE5` or an additive checksum inside them would pass
/// for a frame.
///
/// ```
/// use iec60870::cs101::{AddressWidth, Frame, FrameSplitter};
/// use iec60870::time::Instant;
///
/// let mut splitter = FrameSplitter::new(AddressWidth::One);
/// let mut input: &[u8] = &[0x10, 0x5B, 0x01, 0x5C, 0x16, 0xE5];
/// let now = Instant::ZERO;
/// assert!(matches!(splitter.next_frame(&mut input, now), Some(Ok(Frame::Fixed { .. }))));
/// assert!(matches!(splitter.next_frame(&mut input, now), Some(Ok(Frame::SingleChar))));
/// assert!(splitter.next_frame(&mut input, now).is_none());
/// ```
#[derive(Clone, Debug)]
pub struct FrameSplitter {
    width: AddressWidth,
    char_timeout: Duration,
    idle_gap: Duration,
    buf: [u8; MAX_FRAME_LEN],
    len: usize,
    /// Octets of the frame returned last, removed on the next call.
    consumed: usize,
    last_octet: Option<Instant>,
    resync: bool,
}

impl FrameSplitter {
    /// A splitter for `width` with the default timing (300 ms inter-character timeout, 10 ms
    /// idle gap).
    pub const fn new(width: AddressWidth) -> Self {
        FrameSplitter {
            width,
            char_timeout: DEFAULT_CHAR_TIMEOUT,
            idle_gap: DEFAULT_IDLE_GAP,
            buf: [0; MAX_FRAME_LEN],
            len: 0,
            consumed: 0,
            last_octet: None,
            resync: false,
        }
    }

    /// The same splitter with another inter-character timeout and idle gap.
    #[must_use]
    pub const fn with_timing(mut self, char_timeout: Duration, idle_gap: Duration) -> Self {
        self.char_timeout = char_timeout;
        self.idle_gap = idle_gap;
        self
    }

    /// The octets of an incomplete frame held so far (at most [`MAX_FRAME_LEN`]).
    pub const fn buffered(&self) -> usize {
        if self.consumed > 0 { 0 } else { self.len }
    }

    /// Original wire octets of the frame most recently returned by `next_frame`.
    /// Available until the next call to `next_frame`.
    pub fn frame_bytes(&self) -> &[u8] {
        self.buf.get(..self.consumed).unwrap_or_default()
    }

    /// Whether the splitter is discarding octets until the line goes idle.
    pub const fn is_resyncing(&self) -> bool {
        self.resync
    }

    /// Takes octets from the front of `input` (advancing it), which arrived at `now`, until
    /// a frame is complete or an error is found; `None` once `input` is used up. Call it in a
    /// loop until `None`. Octets discarded while resynchronising are not reported.
    pub fn next_frame<'s>(&'s mut self, input: &mut &[u8], now: Instant) -> Option<Result<Frame<'s>, FrameError>> {
        if self.consumed > 0 {
            self.consumed = 0;
            self.len = 0;
        }
        if !input.is_empty()
            && let Some(last) = self.last_octet
        {
            let gap = now.saturating_duration_since(last);
            if self.resync && gap >= self.idle_gap {
                self.resync = false;
            }
            if self.len > 0 && gap > self.char_timeout {
                let discarded = self.len;
                self.len = 0;
                self.last_octet = Some(now);
                return Some(Err(FrameError::InterCharacterTimeout { discarded }));
            }
        }
        while let Some((&octet, rest)) = input.split_first() {
            *input = rest;
            self.last_octet = Some(now);
            if self.resync {
                continue;
            }
            if let Some(slot) = self.buf.get_mut(self.len) {
                *slot = octet;
                self.len += 1;
            }
            match self.status() {
                Status::More => {}
                Status::Header(e) => {
                    self.len = 0;
                    self.resync = true;
                    return Some(Err(e));
                }
                Status::Complete(total) => {
                    let width = self.width;
                    if let Err(e) = Frame::decode(self.buf.get(..total).unwrap_or_default(), width) {
                        // What follows a corrupted frame in the same burst may be its own
                        // user data (an octet lost or inserted shifts the boundary): wait for idle.
                        self.len = 0;
                        self.resync = true;
                        return Some(Err(e));
                    }
                    self.consumed = total;
                    return Some(Frame::decode(self.buf.get(..total).unwrap_or_default(), width));
                }
            }
        }
        None
    }

    fn status(&self) -> Status {
        let held = self.buf.get(..self.len).unwrap_or_default();
        match *held {
            [SINGLE_CHAR] => Status::Complete(1),
            [START_FIXED, ..] if held.len() >= self.width.fixed_len() => Status::Complete(self.width.fixed_len()),
            [START_VARIABLE, first, second, start2, ..] => match check_variable_header(first, second, start2, self.width) {
                Err(e) => Status::Header(e),
                Ok(()) if held.len() >= usize::from(first) + 6 => Status::Complete(usize::from(first) + 6),
                Ok(()) => Status::More,
            },
            [START_VARIABLE, first, second] if first != second => Status::Header(FrameError::LengthMismatch { first, second }),
            [] | [START_FIXED | START_VARIABLE, ..] => Status::More,
            [other, ..] => Status::Header(FrameError::BadStart(other)),
        }
    }
}

enum Status {
    More,
    Header(FrameError),
    Complete(usize),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;

    const WIDTHS: [AddressWidth; 3] = [AddressWidth::Zero, AddressWidth::One, AddressWidth::Two];

    /// The checksum as lib60870-C computes it, written out independently of the encoder.
    fn reference_sum(bytes: &[u8]) -> u8 {
        let mut s: u32 = 0;
        for b in bytes {
            s += u32::from(*b);
        }
        (s % 256) as u8
    }

    #[test]
    fn constants_match_wireshark_and_lib60870() {
        // Wireshark IEC101_SINGLE_CHAR, IEC101_FIXED_LEN, IEC101_VAR_LEN, IEC101_STOP_CHAR;
        // lib60870-C SendSingleCharCharacter, SendFixedFrame, SendVariableLengthFrame.
        assert_eq!((SINGLE_CHAR, START_FIXED, START_VARIABLE, END), (0xE5, 0x10, 0x68, 0x16));
        assert_eq!(MAX_FRAME_LEN, 261);
        // Control bits: DIR 0x80, PRM 0x40, FCB/ACD 0x20, FCV/DFC 0x10.
        let c = Control::Primary { dir: true, fcb: true, fcv: true, function: PrimaryFunction::RequestClass2 };
        assert_eq!(c.octet(), 0x80 | 0x40 | 0x20 | 0x10 | 0x0B);
        let s = Control::Secondary { dir: false, acd: true, dfc: true, function: SecondaryFunction::LinkStatus };
        assert_eq!(s.octet(), 0x20 | 0x10 | 0x0B);
        // Function codes (lib60870-C LL_FC_*).
        let primary = [(0, "reset"), (1, ""), (2, ""), (3, ""), (4, ""), (7, ""), (8, ""), (9, ""), (10, ""), (11, "")];
        for (code, _) in primary {
            assert_eq!(PrimaryFunction::from_code(code).code(), code);
            assert!(!matches!(PrimaryFunction::from_code(code), PrimaryFunction::Reserved(_)));
        }
        for code in [5, 6, 12, 13, 14, 15] {
            assert_eq!(PrimaryFunction::from_code(code), PrimaryFunction::Reserved(code));
        }
        for code in [0, 1, 8, 9, 11, 14, 15] {
            assert_eq!(SecondaryFunction::from_code(code).code(), code);
            assert!(!matches!(SecondaryFunction::from_code(code), SecondaryFunction::Reserved(_)));
        }
        assert_eq!(PrimaryFunction::RequestLinkStatus.code(), 9);
        assert_eq!(SecondaryFunction::NoData.code(), 9);
    }

    #[test]
    fn control_octet_round_trips_for_every_octet() {
        for octet in 0..=255u8 {
            assert_eq!(Control::from_octet(octet).octet(), octet);
        }
    }

    #[test]
    fn known_frames_from_lib60870() {
        // Request status of link to address 1: 10 49 01 4A 16.
        let f = Frame::Fixed { control: Control::from_octet(0x49), address: LinkAddress(1) };
        assert_eq!(f.to_vec(AddressWidth::One).unwrap(), [0x10, 0x49, 0x01, 0x4A, 0x16]);
        assert_eq!(reference_sum(&[0x49, 0x01]), 0x4A);
        // A variable frame: checksum over C, A and user data.
        let data = [0x64, 0x01, 0x06, 0x01, 0x00, 0x00, 0x14];
        let f = Frame::Variable { control: Control::from_octet(0x73), address: LinkAddress(0x0201), user_data: &data };
        let bytes = f.to_vec(AddressWidth::Two).unwrap();
        assert_eq!(&bytes[..5], &[0x68, 10, 10, 0x68, 0x73]);
        assert_eq!(&bytes[5..7], &[0x01, 0x02]);
        assert_eq!(bytes[bytes.len() - 2], reference_sum(&bytes[4..bytes.len() - 2]));
        assert_eq!(*bytes.last().unwrap(), 0x16);
        assert_eq!(Frame::decode(&bytes, AddressWidth::Two).unwrap(), f);
    }

    #[test]
    fn every_kind_round_trips_under_every_width() {
        for width in WIDTHS {
            let addr = LinkAddress(width.max().min(0x1234));
            let data: Vec<u8> = (0..width.max_user_data()).map(|i| i as u8).collect();
            for frame in [
                Frame::SingleChar,
                Frame::Fixed { control: Control::from_octet(0x5B), address: addr },
                Frame::Variable { control: Control::from_octet(0x08), address: addr, user_data: &data[..1] },
                Frame::Variable { control: Control::from_octet(0x08), address: addr, user_data: &data },
            ] {
                let bytes = frame.to_vec(width).unwrap();
                assert_eq!(bytes.len(), frame.encoded_len(width));
                assert!(bytes.len() <= MAX_FRAME_LEN);
                assert_eq!(Frame::decode(&bytes, width).unwrap(), frame, "{width:?}");
            }
        }
    }

    #[test]
    fn every_error_is_named() {
        let w = AddressWidth::One;
        assert_eq!(Frame::decode(&[], w), Err(FrameError::Truncated { needed: 1 }));
        assert_eq!(Frame::decode(&[0x11], w), Err(FrameError::BadStart(0x11)));
        assert_eq!(Frame::decode(&[0xE5, 0xE5], w), Err(FrameError::Trailing { extra: 1 }));
        assert_eq!(Frame::decode(&[0x10, 0x49, 0x01, 0x4B, 0x16], w), Err(FrameError::BadChecksum { computed: 0x4A, received: 0x4B }));
        assert_eq!(Frame::decode(&[0x10, 0x49, 0x01, 0x4A, 0x17], w), Err(FrameError::BadEnd(0x17)));
        assert_eq!(Frame::decode(&[0x10, 0x49, 0x01, 0x4A], w), Err(FrameError::Truncated { needed: 5 }));
        assert_eq!(Frame::decode(&[0x68, 5, 6, 0x68], w), Err(FrameError::LengthMismatch { first: 5, second: 6 }));
        assert_eq!(Frame::decode(&[0x68, 5, 5, 0x69], w), Err(FrameError::BadSecondStart(0x69)));
        assert_eq!(Frame::decode(&[0x68, 1, 1, 0x68], w), Err(FrameError::BadLength(1)));
        assert_eq!(Frame::decode(&[0x68, 2, 2, 0x68, 0x08, 0x01, 0x09, 0x16], w), Err(FrameError::EmptyUserData));
        assert_eq!(Frame::decode(&[0x68, 3, 3], w), Err(FrameError::Truncated { needed: 4 }));
        let big = Frame::Fixed { control: Control::from_octet(0x49), address: LinkAddress(256) };
        assert_eq!(big.to_vec(w), Err(FrameError::AddressTooWide(LinkAddress(256))));
        let long = [0u8; 254];
        let f = Frame::Variable { control: Control::from_octet(0x08), address: LinkAddress(1), user_data: &long };
        assert_eq!(f.to_vec(w), Err(FrameError::UserDataTooLong(254)));
        let f = Frame::Variable { control: Control::from_octet(0x08), address: LinkAddress(1), user_data: &[] };
        assert_eq!(f.to_vec(w), Err(FrameError::EmptyUserData));
        let mut small = [0u8; 3];
        assert_eq!(Frame::Fixed { control: Control::from_octet(0), address: LinkAddress(1) }.encode(w, &mut small), Err(FrameError::Truncated { needed: 5 }));
        for e in [FrameError::InterCharacterTimeout { discarded: 3 }, FrameError::BadStart(1)] {
            assert_ne!(alloc::format!("{e}"), "");
        }
    }

    fn sample(width: AddressWidth) -> Vec<u8> {
        let mut out = Frame::SingleChar.to_vec(width).unwrap();
        out.extend(Frame::Fixed { control: Control::from_octet(0x5A), address: LinkAddress(width.max().min(3)) }.to_vec(width).unwrap());
        out.extend(
            Frame::Variable { control: Control::from_octet(0x53), address: LinkAddress(width.max().min(3)), user_data: &[1, 2, 0x16, 0x68, 0x10] }
                .to_vec(width)
                .unwrap(),
        );
        out
    }

    #[test]
    fn splitter_handles_every_chunking() {
        for width in WIDTHS {
            let stream = sample(width);
            for cut in 0..=stream.len() {
                let mut s = FrameSplitter::new(width);
                let mut kinds = Vec::new();
                for part in [&stream[..cut], &stream[cut..]] {
                    let mut input = part;
                    while let Some(r) = s.next_frame(&mut input, Instant::ZERO) {
                        kinds.push(r.unwrap().encoded_len(width));
                    }
                }
                assert_eq!(kinds.len(), 3, "{width:?} cut {cut}");
            }
            // One octet at a time.
            let mut s = FrameSplitter::new(width);
            let mut n = 0;
            for b in &stream {
                let mut input = core::slice::from_ref(b);
                while let Some(r) = s.next_frame(&mut input, Instant::ZERO) {
                    r.unwrap();
                    n += 1;
                }
                assert!(s.buffered() <= MAX_FRAME_LEN);
            }
            assert_eq!(n, 3);
        }
    }

    #[test]
    fn inter_character_timeout_discards_the_partial_frame() {
        let mut s = FrameSplitter::new(AddressWidth::One);
        let frame = [0x10, 0x49, 0x01, 0x4A, 0x16];
        let mut input = &frame[..2];
        assert!(s.next_frame(&mut input, Instant::ZERO).is_none());
        assert_eq!(s.buffered(), 2);
        let mut input = &frame[2..];
        let late = Instant::from_millis(301);
        assert_eq!(s.next_frame(&mut input, late), Some(Err(FrameError::InterCharacterTimeout { discarded: 2 })));
        // The rest (01 4A 16) is not a frame: 0x01 starts nothing, and the splitter resyncs.
        assert_eq!(s.next_frame(&mut input, late), Some(Err(FrameError::BadStart(0x01))));
        assert!(s.next_frame(&mut input, late).is_none());
        // Within the timeout the frame completes.
        let mut s = FrameSplitter::new(AddressWidth::One);
        let mut input = &frame[..2];
        assert!(s.next_frame(&mut input, Instant::ZERO).is_none());
        let mut input = &frame[2..];
        assert!(matches!(s.next_frame(&mut input, Instant::from_millis(300)), Some(Ok(Frame::Fixed { .. }))));
    }

    #[test]
    fn resync_waits_for_line_idle() {
        let mut s = FrameSplitter::new(AddressWidth::One);
        // A broken header (L fields differ), followed in the same burst by octets that happen
        // to form a valid fixed frame: they are user data of the broken frame, not a frame.
        let mut input: &[u8] = &[0x68, 0x09, 0x08, 0x10, 0x49, 0x01, 0x4A, 0x16];
        let t = Instant::from_millis(5);
        assert_eq!(s.next_frame(&mut input, t), Some(Err(FrameError::LengthMismatch { first: 9, second: 8 })));
        assert!(s.next_frame(&mut input, t).is_none());
        assert!(s.is_resyncing());
        // Still within the idle gap: discarded.
        let mut input: &[u8] = &[0x10, 0x49, 0x01, 0x4A, 0x16];
        assert!(s.next_frame(&mut input, Instant::from_millis(9)).is_none());
        // After 10 ms of silence the next frame is taken.
        let mut input: &[u8] = &[0x10, 0x49, 0x01, 0x4A, 0x16];
        assert!(matches!(s.next_frame(&mut input, Instant::from_millis(19)), Some(Ok(Frame::Fixed { .. }))));
    }

    #[test]
    fn bad_checksum_discards_the_rest_of_the_burst() {
        let mut s = FrameSplitter::new(AddressWidth::One);
        let mut input: &[u8] = &[0x10, 0x49, 0x01, 0x4B, 0x16, 0xE5];
        assert!(matches!(s.next_frame(&mut input, Instant::ZERO), Some(Err(FrameError::BadChecksum { .. }))));
        assert_eq!(s.next_frame(&mut input, Instant::ZERO), None, "an 0xE5 inside a broken burst is not an ACK");
        let mut input: &[u8] = &[0xE5];
        assert_eq!(s.next_frame(&mut input, Instant::from_millis(10)), Some(Ok(Frame::SingleChar)));
    }

    #[test]
    fn splitter_never_holds_more_than_one_frame() {
        let mut s = FrameSplitter::new(AddressWidth::Two);
        let mut n = 0u32;
        for i in 0..10_000u32 {
            let octets = [0x68, 0xFF, 0xFF, 0x68, (i % 251) as u8];
            let mut input = &octets[..];
            while let Some(_r) = s.next_frame(&mut input, Instant::ZERO) {
                n += 1;
            }
            assert!(s.buffered() <= MAX_FRAME_LEN);
        }
        assert!(n > 0);
    }
}
