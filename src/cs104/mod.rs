//! IEC 60870-5-104: the APCI and the link over TCP.
//!
//! [`Cs104Link`] is the link of one TCP connection, in either [`Role`], as a sans-IO state
//! machine: it numbers the ASDUs it is given, enforces the `k` and `w` windows, runs t1, t2
//! and t3, starts, stops and tests the connection, and closes it with a named
//! [`CloseReason`] on every violation. ASDUs are opaque octets here — the station layer
//! encodes and decodes them with [`Asdu`](crate::Asdu).
//!
//! With `std`, `connect` and `accept` put a link on a TCP connection under a
//! `BlockingDriver`; with the `tokio` feature, `connect_async` and
//! `accept_async` do the same under a `TokioDriver`.
//!
//! Without I/O — two links wired back to back, as in a test or a simulation:
//!
//! ```
//! use iec60870::cs104::{Cs104Link, Event};
//! use iec60870::driver::Output;
//! use iec60870::time::Instant;
//!
//! /// Moves everything `from` transmits into `to`; returns `from`'s events.
//! fn pump(from: &mut Cs104Link, to: &mut Cs104Link, now: Instant) -> Vec<Event> {
//!     let mut events = Vec::new();
//!     while let Some(output) = from.poll_output() {
//!         match output {
//!             Output::Transmit(bytes) => to.handle_input(&bytes, now),
//!             Output::Event(event) => events.push(event),
//!             Output::Deadline(_) => {}
//!         }
//!     }
//!     events
//! }
//!
//! let now = Instant::ZERO;
//! let mut master = Cs104Link::controlling();
//! let mut outstation = Cs104Link::controlled();
//!
//! master.start(now)?;
//! pump(&mut master, &mut outstation, now);
//! assert_eq!(pump(&mut outstation, &mut master, now), [Event::Started]);
//! assert_eq!(pump(&mut master, &mut outstation, now), [Event::Started]);
//!
//! outstation.submit(&[0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14], now)?;
//! pump(&mut outstation, &mut master, now);
//! assert!(matches!(&pump(&mut master, &mut outstation, now)[..], [Event::Asdu(a)] if a[0] == 0x64));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

mod apci;
mod config;
mod link;
#[cfg(feature = "std")]
mod tcp;
#[cfg(feature = "tls")]
mod tls;

pub use apci::{Apci, Apdu, DEFAULT_PORT, DEFAULT_TLS_PORT, FrameError, FrameSplitter, MAX_APDU_LEN, MAX_ASDU_LEN, START, SeqNo, UFunction};
pub use config::{Config, ConfigError, Role, Timer};
pub use link::{Awaiting, CloseReason, CommandError, Cs104Link, Event, State, SubmitError};
#[cfg(feature = "std")]
pub use tcp::{accept, connect};
#[cfg(feature = "tokio")]
pub use tcp::{accept_async, connect_async};
#[cfg(feature = "tls")]
pub use tls::{accept_tls, connect_tls};
#[cfg(all(feature = "tls", feature = "tokio"))]
pub use tls::{accept_tls_async, connect_tls_async};
