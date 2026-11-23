//! `Cs101Link` as a [`StationLink`]: the stations run over 101 unchanged.

use crate::driver::Output;
use crate::station::{self, LinkClosed, LinkError, LinkEvent, StationLink};
use crate::time::Instant;

use super::config::Class;
use super::link::{Cs101Link, Event, SubmitError};

const fn class(c: station::Class) -> Class {
    match c {
        station::Class::One => Class::One,
        station::Class::Two => Class::Two,
    }
}

const fn station_class(c: Class) -> station::Class {
    match c {
        Class::One => station::Class::One,
        Class::Two => station::Class::Two,
    }
}

const fn submit_error(e: SubmitError) -> LinkError {
    match e {
        SubmitError::QueueFull => LinkError::Busy,
        SubmitError::Closed => LinkError::Closed,
        SubmitError::Empty | SubmitError::TooLong(_) | SubmitError::UnknownStation(_) | SubmitError::StationRequired => LinkError::Rejected,
    }
}

/// The link of a point-to-point station: a balanced link, an unbalanced secondary, or an
/// unbalanced primary with one secondary (a master polling several outstations runs one
/// station per outstation above its own events, or uses the link directly).
///
/// Events map one to one, with two 101 specifics: `Started` is the link reset (101 has no
/// STARTDT, so [`start`](StationLink::start) is a no-op and [`stop`](StationLink::stop) is
/// refused), and an [`Event::Unconfirmed`] ASDU — given up on, never re-sent by the link —
/// becomes [`LinkEvent::Unconfirmed`] of its class: the controlled station puts the events it
/// carried back at the head of its buffer and sends them again (at-least-once), so nothing is
/// lost silently.
impl StationLink for Cs101Link {
    fn max_asdu_len(&self) -> usize {
        self.config().address_width.max_user_data()
    }
    fn handle_input(&mut self, bytes: &[u8], now: Instant) {
        Cs101Link::handle_input(self, bytes, now);
    }

    fn handle_timeout(&mut self, now: Instant) {
        Cs101Link::handle_timeout(self, now);
    }

    fn handle_disconnect(&mut self, now: Instant) {
        Cs101Link::handle_disconnect(self, now);
    }

    fn poll_output(&mut self) -> Option<Output<LinkEvent>> {
        Some(match Cs101Link::poll_output(self)? {
            Output::Transmit(bytes) => Output::Transmit(bytes),
            Output::Deadline(at) => Output::Deadline(at),
            Output::Event(event) => Output::Event(match event {
                Event::Started { .. } => LinkEvent::Started,
                Event::Stopped { .. } => LinkEvent::Stopped,
                Event::Asdu { asdu, .. } => LinkEvent::Asdu(asdu),
                Event::Acknowledged { class, count, .. } => LinkEvent::Acknowledged { class: Some(station_class(class)), count },
                Event::Unconfirmed { class, .. } => LinkEvent::Unconfirmed { class: Some(station_class(class)) },
                Event::Closed(reason) => LinkEvent::Closed(LinkClosed::new(reason)),
            }),
        })
    }

    fn is_closed(&self) -> bool {
        Cs101Link::is_closed(self)
    }

    fn is_started(&self) -> bool {
        match self.mode() {
            super::Mode::Secondary => self.is_up(self.own_address()),
            super::Mode::Primary | super::Mode::Balanced(_) => self.peer_address().is_some_and(|p| self.is_up(p)),
        }
    }

    fn can_send(&self, c: station::Class) -> bool {
        Cs101Link::can_send(self, class(c))
    }

    fn submit(&mut self, asdu: &[u8], c: station::Class, now: Instant) -> Result<(), LinkError> {
        Cs101Link::submit(self, asdu, class(c), now).map_err(submit_error)
    }

    fn start(&mut self, now: Instant) -> Result<(), LinkError> {
        if self.is_closed() {
            return Err(LinkError::Closed);
        }
        Cs101Link::handle_timeout(self, now);
        Ok(())
    }

    fn stop(&mut self, _now: Instant) -> Result<(), LinkError> {
        Err(if self.is_closed() { LinkError::Closed } else { LinkError::Rejected })
    }

    fn close(&mut self) {
        Cs101Link::close(self);
    }
}
