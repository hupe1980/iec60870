//! The seam between a station and its link: [`StationLink`].

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use crate::driver::Output;
use crate::time::Instant;

/// The class of data an ASDU belongs to.
///
/// 104 ignores it; an unbalanced 101 secondary keeps one queue per class and the master polls
/// them separately.
///
/// ```
/// use iec60870::station::Class;
/// assert!(Class::One < Class::Two);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Class {
    /// Class 1: responses, confirmations and spontaneous events.
    One,
    /// Class 2: cyclic and background data.
    Two,
}

/// Why a link closed its connection: the link's own reason, kept as an error value.
///
#[cfg_attr(feature = "cs104", doc = "```")]
#[cfg_attr(not(feature = "cs104"), doc = "```ignore")]
/// use iec60870::cs104::CloseReason;
/// use iec60870::station::LinkClosed;
///
/// let closed = LinkClosed::new(CloseReason::PeerClosed);
/// assert_eq!(closed.to_string(), "the peer closed the connection");
/// assert_eq!(closed.downcast_ref::<CloseReason>(), Some(&CloseReason::PeerClosed));
/// ```
#[derive(Clone)]
pub struct LinkClosed(Arc<dyn core::error::Error + Send + Sync>);

impl LinkClosed {
    /// Wraps the link's reason.
    pub fn new(reason: impl core::error::Error + Send + Sync + 'static) -> Self {
        LinkClosed(Arc::new(reason))
    }

    /// The link's reason as its own type, for example `cs104::CloseReason`.
    pub fn downcast_ref<E: core::error::Error + 'static>(&self) -> Option<&E> {
        let reason: &(dyn core::error::Error + 'static) = &*self.0;
        reason.downcast_ref::<E>()
    }
}

impl fmt::Debug for LinkClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkClosed({:?})", self.0)
    }
}

impl fmt::Display for LinkClosed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl core::error::Error for LinkClosed {}

/// What a link reports to the station above it.
///
/// ```
/// use iec60870::station::LinkEvent;
///
/// let event = LinkEvent::Acknowledged { class: None, count: 2 };
/// assert!(matches!(event, LinkEvent::Acknowledged { count: 2, .. }));
/// ```
#[derive(Clone, Debug)]
pub enum LinkEvent {
    /// Data transfer started (104: STARTDT; 101: the link was reset).
    Started,
    /// Data transfer stopped (104: STOPDT); the connection stays open.
    Stopped,
    /// An ASDU received, in order, exactly once.
    Asdu(Vec<u8>),
    /// The peer confirmed `count` submitted ASDUs: with `class: None` the oldest `count` in
    /// submission order (104), with `Some(class)` the oldest `count` of that class (101
    /// unbalanced).
    Acknowledged {
        /// Which queue, or `None` for submission order.
        class: Option<Class>,
        /// How many.
        count: u16,
    },
    /// The link gave up on the oldest ASDU submitted in `class` (or, with `None`, in
    /// submission order): it may or may not have arrived. The controlled station sends the
    /// events it carried again (at-least-once); a 104 link never reports this — it closes
    /// the connection instead.
    Unconfirmed {
        /// Which queue, or `None` for submission order.
        class: Option<Class>,
    },
    /// The connection is closed; the last event. Nothing still unacknowledged was confirmed.
    Closed(LinkClosed),
}

/// Why a link refused a command or an ASDU. The ASDU stays with the caller.
///
/// ```
/// use iec60870::station::LinkError;
/// assert_eq!(LinkError::Busy.to_string(), "the link has no room");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LinkError {
    /// No room now (the window or the queue is full); retry after an acknowledgment.
    Busy,
    /// Data transfer is not started.
    NotStarted,
    /// The connection is closed.
    Closed,
    /// The request is invalid for this link (an empty or over-long ASDU, the wrong role).
    Rejected,
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            LinkError::Busy => "the link has no room",
            LinkError::NotStarted => "data transfer is not started",
            LinkError::Closed => "the connection is closed",
            LinkError::Rejected => "the link rejected the request",
        })
    }
}

impl core::error::Error for LinkError {}

/// A link a station runs over: the 104 `Cs104Link`, or a 101 link.
///
/// The first five methods are the [`Protocol`](crate::driver::Protocol) contract with the link's
/// events mapped to [`LinkEvent`]; the rest command it. A link carries ASDUs as opaque octets
/// and numbers, windows and acknowledges them; everything above — the meaning of an ASDU, what
/// to send when — is the station's.
///
/// A 101 link plugs in the same way: a balanced link behaves like 104; an unbalanced secondary
/// keeps one queue per [`Class`], answers the master's class 1 and class 2 polls from them and
/// reports [`LinkEvent::Acknowledged`] with the class.
///
#[cfg_attr(feature = "cs104", doc = "```")]
#[cfg_attr(not(feature = "cs104"), doc = "```ignore")]
/// use iec60870::cs104::Cs104Link;
/// use iec60870::station::{Class, StationLink};
/// use iec60870::time::Instant;
///
/// let mut link = Cs104Link::controlling();
/// assert!(!StationLink::is_started(&link));
/// assert!(!StationLink::can_send(&link, Class::One));
/// StationLink::start(&mut link, Instant::ZERO).unwrap(); // STARTDT act
/// ```
pub trait StationLink {
    /// Maximum ASDU size accepted by this link, in octets.
    fn max_asdu_len(&self) -> usize {
        usize::from(u8::MAX)
    }
    /// Octets received from the peer.
    fn handle_input(&mut self, bytes: &[u8], now: Instant);
    /// Time has passed; act on expired timers.
    fn handle_timeout(&mut self, now: Instant);
    /// The transport is gone.
    fn handle_disconnect(&mut self, now: Instant);
    /// The next output: octets to write, a link event, or the next deadline.
    fn poll_output(&mut self) -> Option<Output<LinkEvent>>;
    /// Whether the connection is closed for good.
    fn is_closed(&self) -> bool;
    /// Whether data transfer is started.
    fn is_started(&self) -> bool;
    /// Whether [`submit`](Self::submit) of an ASDU of `class` would be accepted now.
    fn can_send(&self, class: Class) -> bool;
    /// Sends `asdu` (or queues it, for a polled link), or refuses it — never drops it.
    fn submit(&mut self, asdu: &[u8], class: Class, now: Instant) -> Result<(), LinkError>;
    /// Starts data transfer (controlling side).
    fn start(&mut self, now: Instant) -> Result<(), LinkError>;
    /// Stops data transfer (controlling side).
    fn stop(&mut self, now: Instant) -> Result<(), LinkError>;
    /// Closes the connection.
    fn close(&mut self);
}

#[cfg(feature = "cs104")]
mod cs104_impl {
    use super::{Class, LinkClosed, LinkError, LinkEvent, StationLink};
    use crate::cs104::{CommandError, Cs104Link, Event, State, SubmitError};
    use crate::driver::Output;
    use crate::time::Instant;

    fn submit_error(e: SubmitError) -> LinkError {
        match e {
            SubmitError::WindowFull => LinkError::Busy,
            SubmitError::NotStarted => LinkError::NotStarted,
            SubmitError::Closed => LinkError::Closed,
            SubmitError::Empty | SubmitError::TooLong(_) => LinkError::Rejected,
        }
    }

    fn command_error(e: CommandError) -> LinkError {
        match e {
            CommandError::WrongRole => LinkError::Rejected,
            CommandError::Busy(_) => LinkError::Busy,
            CommandError::Closed => LinkError::Closed,
        }
    }

    /// The 104 link as a station link: every ASDU is acknowledged in submission order.
    impl StationLink for Cs104Link {
        fn max_asdu_len(&self) -> usize {
            crate::cs104::MAX_ASDU_LEN
        }
        fn handle_input(&mut self, bytes: &[u8], now: Instant) {
            Cs104Link::handle_input(self, bytes, now);
        }

        fn handle_timeout(&mut self, now: Instant) {
            Cs104Link::handle_timeout(self, now);
        }

        fn handle_disconnect(&mut self, now: Instant) {
            Cs104Link::handle_disconnect(self, now);
        }

        fn poll_output(&mut self) -> Option<Output<LinkEvent>> {
            Cs104Link::poll_output(self).map(|output| match output {
                Output::Transmit(bytes) => Output::Transmit(bytes),
                Output::Deadline(at) => Output::Deadline(at),
                Output::Event(event) => Output::Event(match event {
                    Event::Started => LinkEvent::Started,
                    Event::Stopped => LinkEvent::Stopped,
                    Event::Asdu(asdu) => LinkEvent::Asdu(asdu),
                    Event::Acknowledged { count } => LinkEvent::Acknowledged { class: None, count },
                    Event::Closed(reason) => LinkEvent::Closed(LinkClosed::new(reason)),
                }),
            })
        }

        fn is_closed(&self) -> bool {
            Cs104Link::is_closed(self)
        }

        fn is_started(&self) -> bool {
            self.state() == State::Started
        }

        fn can_send(&self, _class: Class) -> bool {
            Cs104Link::can_send(self)
        }

        fn submit(&mut self, asdu: &[u8], _class: Class, now: Instant) -> Result<(), LinkError> {
            Cs104Link::submit(self, asdu, now).map_err(submit_error)
        }

        fn start(&mut self, now: Instant) -> Result<(), LinkError> {
            Cs104Link::start(self, now).map_err(command_error)
        }

        fn stop(&mut self, now: Instant) -> Result<(), LinkError> {
            Cs104Link::stop(self, now).map_err(command_error)
        }

        fn close(&mut self) {
            Cs104Link::close(self);
        }
    }
}

#[cfg(all(test, feature = "cs104"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::cs104::{CloseReason, Cs104Link};

    fn events(link: &mut Cs104Link) -> Vec<LinkEvent> {
        let mut v = Vec::new();
        while let Some(o) = StationLink::poll_output(link) {
            if let Output::Event(e) = o {
                v.push(e);
            }
        }
        v
    }

    #[test]
    fn cs104_events_map_one_to_one() {
        let now = Instant::ZERO;
        let mut link = Cs104Link::controlled();
        assert_eq!(StationLink::submit(&mut link, &[1], Class::One, now), Err(LinkError::NotStarted));
        assert_eq!(StationLink::start(&mut link, now), Err(LinkError::Rejected));
        StationLink::handle_input(&mut link, &[0x68, 0x04, 0x07, 0, 0, 0], now);
        assert!(matches!(events(&mut link)[..], [LinkEvent::Started]));
        assert!(StationLink::is_started(&link) && StationLink::can_send(&link, Class::Two));
        StationLink::submit(&mut link, &[1, 2, 3], Class::One, now).unwrap();
        assert_eq!(StationLink::submit(&mut link, &[], Class::One, now), Err(LinkError::Rejected));
        StationLink::handle_input(&mut link, &[0x68, 0x04, 0x01, 0, 0x02, 0], now);
        assert!(matches!(events(&mut link)[..], [LinkEvent::Acknowledged { class: None, count: 1 }]));
        StationLink::close(&mut link);
        match &events(&mut link)[..] {
            [LinkEvent::Closed(reason)] => assert_eq!(reason.downcast_ref::<CloseReason>(), Some(&CloseReason::Local)),
            other => panic!("{other:?}"),
        }
        assert!(StationLink::is_closed(&link));
        assert_eq!(StationLink::submit(&mut link, &[1], Class::One, now), Err(LinkError::Closed));
    }
}
