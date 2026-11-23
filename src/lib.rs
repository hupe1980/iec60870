//! IEC 60870-5 telecontrol in Rust.
//!
//! The ASDU application layer shared by the companion standards, IEC 60870-5-104 over TCP and
//! IEC 60870-5-101 over serial links, in both roles — the controlling station (master) and the
//! controlled station (outstation).
//!
//! Every protocol core is a sans-IO state machine: it is fed bytes and the current
//! [`Instant`], and yields bytes to transmit, events and the next deadline. It
//! never touches a socket, a serial port or a clock, so it runs the same under Tokio, a
//! blocking loop, a deterministic simulation or an embedded executor. Decoding is panic-free
//! and bounded on every input.
//!
//! # Quick start
//!
//! An outstation builds a typed ASDU in one expression — the type identification follows from
//! the objects — and encodes it into its own buffer; a master or a sniffer decodes and matches:
//!
//! ```
//! use iec60870::prelude::*;
//!
//! let now = Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap(); // from a `Clock`
//! let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, [
//!     InformationObject::new(Ioa(4001), MeasuredFloat::new(21.5)).at(now),
//! ]);
//!
//! let mut buf = [0u8; 249];
//! let n = asdu.encode(&Profile::IEC104, &mut buf)?;
//!
//! match Asdu::decode(&buf[..n], &Profile::IEC104)?.objects {
//!     Objects::MeasuredFloatCp56(objects) => assert_eq!(objects[0].element.value, 21.5),
//!     other => panic!("unexpected {}", other.type_id()),
//! }
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! The field widths, the maximum length and the permitted types are a [`Profile`] value:
//! [`Profile::IEC104`], [`Profile::IEC101`], or a vendor dialect built from either.
//!
//! # Cargo features
//!
//! | Feature | Capability |
//! | --- | --- |
//! | `std` (default) | Blocking adapters and system clock |
//! | `cs104` (default) | IEC 104 link |
//! | `cs101` | FT 1.2 link |
//! | `serial` | Blocking serial port for IEC 101 |
//! | `tls` | IEC 104 over mutually authenticated TLS |
//! | `tokio` | Async adapters for the enabled links |
//! | `file-transfer` | Station file transfers and in-memory record storage |
//! | `file-store-fs` | Directory-backed record storage |
//! | `cli` | Frame and capture inspection, station simulator and IEC 104 client |
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod asdu;
#[cfg(all(feature = "std", feature = "cs104"))]
mod client;
#[cfg(feature = "cs101")]
pub mod cs101;
#[cfg(feature = "cs104")]
pub mod cs104;
pub mod driver;
pub mod prelude;
#[cfg(all(feature = "std", feature = "cs104"))]
mod server;
pub mod station;
pub mod time;
#[cfg(feature = "tls")]
pub mod tls;
// `tls` brings `tokio-rustls` for the async entry points, which exist only with `tokio` too
// (Cargo has no feature conjunction); without `tokio` it is linked but unused.
#[cfg(all(feature = "tls", not(feature = "tokio")))]
use tokio_rustls as _;
#[cfg(all(feature = "tokio", feature = "cs104"))]
mod tokio_station;
#[cfg(all(feature = "std", feature = "cs104"))]
mod transport;
pub mod types;

pub use asdu::{Asdu, AsduHeader, DecodeError, EncodeError, InformationObject, Objects, Profile, Raw};
#[cfg(all(feature = "std", feature = "cs104"))]
pub use client::{Client, ClientBuilder, CommandSteps, Replies};
#[cfg(feature = "cs101")]
pub use cs101::Cs101Link;
#[cfg(feature = "cs104")]
pub use cs104::Cs104Link;
pub use driver::Protocol;
#[cfg(all(feature = "std", feature = "cs104"))]
pub use server::{Server, ServerBuilder, ServerHandle};
pub use station::{Command, CommandRequest, Database, Decision, Error};
pub use time::{Clock, Cp16Time2a, Cp24Time2a, Cp56Time2a, DateTime, Instant};
#[cfg(all(feature = "tokio", feature = "cs104"))]
pub use tokio_station::{AsyncClient, AsyncCommandSteps, AsyncReplies, AsyncServer, AsyncServerHandle};
pub use types::{Cause, CommonAddress, Cot, Ioa, Quality, TypeId};
