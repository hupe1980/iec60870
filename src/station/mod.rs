//! The application layer of both roles: the controlled station (outstation) and the
//! controlling station (master), as sans-IO state machines over a [`StationLink`].
//!
//! - [`ControlledStation`] owns a [`PointSource`] such as [`Database`], answers general, group and counter
//!   interrogation, read, clock synchronisation, test, reset and parameter requests, buffers
//!   spontaneous events until the master acknowledges them (re-sending them after a
//!   reconnection or a redundancy switch-over), and enforces select-before-operate before the
//!   application's [`CommandHandler`] is asked.
//! - [`ControllingStation`] offers one method per procedure, reports each request's
//!   [`Progress`], and turns every monitor ASDU into typed [`Event::Point`]s.
//!
//! Neither touches a socket, a thread or the system clock: octets and the monotonic
//! [`Instant`](crate::time::Instant) go in, octets, events and deadlines come out, and every time
//! tag comes from the [`Clock`](crate::time::Clock) they are given. `Client` and
//! `Server` run them over TCP with the `std` and `cs104` features.
//!
//! The two cores, wired back to back without any I/O:
//!
#![cfg_attr(feature = "cs104", doc = "```")]
#![cfg_attr(not(feature = "cs104"), doc = "```ignore")]
//! use iec60870::cs104::Cs104Link;
//! use iec60870::driver::{Output, Protocol};
//! use iec60870::prelude::*;
//! use iec60870::station::{self, ClientConfig, ControlledStation, ControllingStation, Database, Event, GroupId, ServerConfig};
//!
//! let clock = || Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap();
//! let ca = CommonAddress(1);
//! let mut db = Database::new();
//! db.insert(ca, Ioa(100), true);
//! db.insert(ca, Ioa(200), 21.5f32);
//!
//! let mut outstation = ControlledStation::new(db, ServerConfig::default(), clock);
//! let conn = outstation.attach(Cs104Link::controlled(), GroupId(0));
//! let mut master = ControllingStation::new(Cs104Link::controlling(), ClientConfig::default(), clock);
//! let mut handler = |_: &CommandRequest| Decision::Refuse;
//!
//! let now = Instant::ZERO;
//! master.start(now)?;
//! let mut events = Vec::new();
//! for _ in 0..4 {
//!     while let Some(o) = master.poll_output() {
//!         match o {
//!             Output::Transmit(bytes) => outstation.handle_input(conn, &bytes, now, &mut handler),
//!             Output::Event(Event::Started) => { master.interrogate(ca, Interrogation::STATION, now)?; }
//!             Output::Event(e) => events.push(e),
//!             Output::Deadline(_) => {}
//!         }
//!     }
//!     while let Some(o) = outstation.poll_output() {
//!         if let station::Output::Transmit { bytes, .. } = o {
//!             master.handle_input(&bytes, now);
//!         }
//!     }
//! }
//! let points: Vec<_> = events.iter().filter_map(|e| match e { Event::Point(p) => Some(p.ioa), _ => None }).collect();
//! assert_eq!(points, [Ioa(100), Ioa(200)]);
//! assert!(events.iter().any(|e| matches!(e, Event::InterrogationComplete { .. })));
//! # Ok::<(), iec60870::Error>(())
//! ```

mod command;
mod controlled;
mod controlling;
mod database;
#[cfg(feature = "file-store-fs")]
mod directory_store;
#[cfg(feature = "file-transfer")]
mod download;
#[cfg(feature = "file-transfer")]
mod file_store;
#[cfg(feature = "file-store-fs")]
pub use directory_store::DirectoryFileStore;
#[cfg(feature = "file-transfer")]
pub use file_store::{FileConfig, FileError, FileInfo, FileName, FileStatus, FileStore, MemoryFileStore, TransferOutcome, checksum};
mod error;
mod link;
mod value;

pub use command::{Command, CommandHandler, CommandKind, CommandMode, CommandRequest, Decision, Parameter, ParameterRequest, Phase, RefuseCommands};
pub use controlled::{ConnectionId, ControlledStation, GroupId, Output, ServerConfig, ServerEvent};
pub use controlling::{ClientConfig, ControllingStation, Event, Progress, RequestId};
pub use database::{CommandOptions, Database, PointEntry, PointOptions, PointSource, UpdateError};
pub use error::{Awaiting, Error};
pub use link::{Class, LinkClosed, LinkError, LinkEvent, StationLink};
pub use value::{Point, TimeFormat, Timestamp, Value, ValueKind};
