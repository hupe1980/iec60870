//! The one interface every protocol core offers, and the runners that drive it over a byte
//! stream.
//!
//! A core — the 104 link `Cs104Link`, and the 101 link and the
//! stations as they arrive — implements [`Protocol`]: it is fed the bytes that arrived and
//! the current [`Instant`], and yields [`Output`]s: bytes to transmit, events for the
//! application, and the deadline at which it next wants [`handle_timeout`](Protocol::handle_timeout).
//! It never touches a socket or a clock.
//!
//! A runner owns the transport and the clock and does the loop: write what the core
//! transmits, sleep until the next deadline or until bytes arrive, feed them in, hand the
//! events to the application. `BlockingDriver` runs any core over a std stream (a
//! `TcpStream`, a serial port, a TLS stream); `TokioDriver` does the same over Tokio's
//! `AsyncRead + AsyncWrite` (feature `tokio`).
//!
#![cfg_attr(feature = "cs104", doc = "```")]
#![cfg_attr(not(feature = "cs104"), doc = "```ignore")]
//! use iec60870::driver::{Output, Protocol};
//! use iec60870::time::Instant;
//!
//! /// Drains a core the way every runner does.
//! fn drain<P: Protocol>(core: &mut P, wire: &mut Vec<u8>, deadline: &mut Option<Instant>) -> Vec<P::Event> {
//!     let mut events = Vec::new();
//!     while let Some(output) = core.poll_output() {
//!         match output {
//!             Output::Transmit(bytes) => wire.extend(bytes),
//!             Output::Event(event) => events.push(event),
//!             Output::Deadline(at) => *deadline = Some(at),
//!         }
//!     }
//!     events
//! }
//! # let _ = drain::<iec60870::cs104::Cs104Link>;
//! ```

use alloc::vec::Vec;

use crate::time::Instant;

#[cfg(feature = "std")]
mod blocking;
#[cfg(feature = "tokio")]
mod tokio_driver;

#[cfg(feature = "std")]
pub use blocking::{BlockingDriver, Transport};
#[cfg(feature = "tokio")]
pub use tokio_driver::TokioDriver;

/// What a core yields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Output<E> {
    /// Octets to write to the transport: one or more whole frames, in order.
    Transmit(Vec<u8>),
    /// Something for the application.
    Event(E),
    /// Call [`Protocol::handle_timeout`] at this instant (or earlier — early calls are
    /// harmless). It is the last output of a drain that follows a call that changed the
    /// core, and supersedes every earlier deadline.
    Deadline(Instant),
}

/// A sans-IO protocol core.
///
/// The contract, for runners and tests alike:
///
/// - Feed every received octet to [`handle_input`](Self::handle_input), in order, in pieces
///   of any size.
/// - Call [`handle_timeout`](Self::handle_timeout) once when the transport is ready (the core
///   starts its clock from the first `now` it sees) and whenever the last
///   [`Output::Deadline`] passes.
/// - Call [`handle_disconnect`](Self::handle_disconnect) when the transport ends.
/// - After each of these, and after any command on the core, drain
///   [`poll_output`](Self::poll_output) until it returns `None`, writing every
///   [`Output::Transmit`] in order.
/// - Once [`is_closed`](Self::is_closed) is true and the outputs are drained, the transport
///   can be shut down; the core will not produce anything else.
///
/// `now` never goes backwards.
pub trait Protocol {
    /// The events this core reports.
    type Event;

    /// Octets received from the peer.
    fn handle_input(&mut self, bytes: &[u8], now: Instant);

    /// Time has passed; act on any expired timer.
    fn handle_timeout(&mut self, now: Instant);

    /// The transport is gone (EOF, a reset, a write error).
    fn handle_disconnect(&mut self, now: Instant);

    /// The next output, or `None` when there is nothing more for now.
    fn poll_output(&mut self) -> Option<Output<Self::Event>>;

    /// Whether the core has closed the connection for good.
    fn is_closed(&self) -> bool;
}
