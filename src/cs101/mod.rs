//! IEC 60870-5-101: FT 1.2 frames and the link over a serial line.
//!
//! [`Cs101Link`] is the link of one serial line as a sans-IO state machine, in one of three
//! [`Mode`]s:
//!
//! - **unbalanced primary** ([`Cs101Link::primary`]) — the controlling station: it resets
//!   each secondary's link, polls class 1 and class 2 data round-robin (class 1 at once when a
//!   secondary signals ACD), sends user data with confirmation, repeats a frame whose answer is
//!   lost with the same frame count bit, and gives up on a silent station without stalling the
//!   others;
//! - **unbalanced secondary** ([`Cs101Link::secondary`]) — the controlled station: it answers
//!   polls from its class 1 and class 2 queues, signals ACD and DFC, and answers a repeated
//!   frame with its stored response instead of acting twice;
//! - **balanced** ([`Cs101Link::balanced`]) — point to point, both ends primary and
//!   secondary, the DIR bit telling the directions apart.
//!
//! Byte timing is part of the protocol on a serial line: every input carries the `now` it
//! arrived at, and the [`FrameSplitter`] throws away a frame interrupted for longer than the
//! inter-character timeout and resynchronises on line idle. ASDUs are opaque octets here —
//! the station layer encodes and decodes them with [`Asdu`](crate::Asdu) and
//! [`Profile::IEC101`](crate::Profile::IEC101).
//!
//! FT 1.2 protects a frame with an 8-bit sum (and the line with a parity bit per character),
//! against noise, not against an attacker: anyone who can drive the line can forge frames.
//! The link runs over any `Transport`, so an authenticated bridge
//! can carry it unchanged.
//!
//! # Running it
//!
//! With feature `serial`, `open_serial` opens a port and returns a
//! `BlockingDriver`. Any other byte stream works the same way
//! — `BlockingDriver::new(link, tcp_stream)` for a terminal server. Under Tokio,
//! `TokioDriver` runs the link over any `AsyncRead +
//! AsyncWrite`, `tokio-serial`'s `SerialStream` included:
//!
//! ```ignore
//! let port = tokio_serial::new("/dev/ttyUSB0", 9600).parity(tokio_serial::Parity::Even).open_native_async()?;
//! let mut driver = iec60870::driver::TokioDriver::new(link, port);
//! while let Some(event) = driver.next_event().await? { /* … */ }
//! ```
//!
//! # A master and an outstation back to back
//!
//! ```
//! use iec60870::cs101::{Class, Config, Cs101Link, Event, LinkAddress};
//! use iec60870::driver::Output;
//! use iec60870::time::Instant;
//!
//! let rtu = LinkAddress(3);
//! let mut master = Cs101Link::primary(&[rtu], Config::default())?;
//! let mut outstation = Cs101Link::secondary(rtu, Config::default())?;
//! outstation.submit(&[0x01, 0x01, 0x03, 0x01, 0x10, 0x00, 0x01], Class::One, Instant::ZERO)?;
//!
//! let mut got = None;
//! for step in 0..10 {
//!     let now = Instant::from_millis(step * 10);
//!     master.handle_timeout(now);
//!     for _ in 0..4 {
//!         while let Some(Output::Transmit(bytes)) = master.poll_output() {
//!             outstation.handle_input(&bytes, now);
//!         }
//!         while let Some(output) = outstation.poll_output() {
//!             if let Output::Transmit(bytes) = output {
//!                 master.handle_input(&bytes, now);
//!             }
//!         }
//!         while let Some(output) = master.poll_output() {
//!             match output {
//!                 Output::Transmit(bytes) => outstation.handle_input(&bytes, now),
//!                 Output::Event(Event::Asdu { asdu, .. }) => got = Some(asdu),
//!                 _ => {}
//!             }
//!         }
//!     }
//! }
//! assert_eq!(got.as_deref(), Some(&[0x01, 0x01, 0x03, 0x01, 0x10, 0x00, 0x01][..]));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

mod config;
mod frame;
mod link;
#[cfg(feature = "serial")]
mod serial;
mod station_link;

pub use config::{Class, Config, ConfigError, Mode, Role};
pub use frame::{
    AddressWidth, Control, DEFAULT_CHAR_TIMEOUT, DEFAULT_IDLE_GAP, END, Frame, FrameError, FrameSplitter, LinkAddress, MAX_FRAME_LEN, PrimaryFunction,
    SINGLE_CHAR, START_FIXED, START_VARIABLE, SecondaryFunction, checksum,
};
pub use link::{CloseReason, Cs101Link, Event, Stats, StopReason, SubmitError};
#[cfg(feature = "serial")]
pub use serial::{SerialTransport, open_serial};
