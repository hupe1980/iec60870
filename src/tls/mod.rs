//! IEC 62351-3: TLS for IEC 60870-5-104 (feature `tls`).
//!
//! TLS is an adapter under the runners: the 104 link and the stations do not change. A
//! [`TlsClientConfig`] or [`TlsServerConfig`] is built in one call from PEM files — the trust
//! anchors, the station's own certificate chain and its key — and mutual authentication is
//! the only mode: the server requires a client certificate that chains to its trust anchors,
//! and the client verifies the server's chain and the name (or IP address) it dialled. Every
//! refusal happens during the handshake, before any 104 frame, and is reported as a named
//! [`TlsError`] and, when a callback is set with `on_event`, as a [`SecurityEvent`].
//!
//! ```no_run
//! use iec60870::cs104::{self, Config, Event};
//! use iec60870::tls::TlsClientConfig;
//!
//! let tls = TlsClientConfig::from_pem_files("ca.pem", "master.pem", "master.key")?
//!     .on_event(|event| eprintln!("security: {event:?}"));
//! let mut link = cs104::connect_tls(("10.0.0.5", cs104::DEFAULT_TLS_PORT), "10.0.0.5", &tls, Config::default())?;
//! link.start()?;
//! while let Some(event) = link.next_event()? {
//!     if let Event::Asdu(asdu) = event {
//!         println!("{asdu:02x?}");
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! The station level takes the same configurations: `Client::connect_tls` and
//! `Server::builder().tls(..)`, and their async twins.
//!
//! # Implementation
//!
//! rustls with the `ring` crypto provider (no OpenSSL; `ring` builds with a C compiler alone,
//! on every target rustls supports). The provider is given to each configuration, never
//! installed process-wide, so an application that uses another provider elsewhere is not
//! affected. [`TlsClientConfig::from_rustls`] and [`TlsServerConfig::from_rustls`] accept a
//! configuration the application built itself — certificate pinning, revocation lists, a
//! hardware key, another provider.
//!
//! Offered: TLS 1.3 and TLS 1.2 ([`PROTOCOL_VERSIONS`]), the suites of [`CIPHER_SUITES`]
//! (TLS 1.3 AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305; TLS 1.2 ECDHE-ECDSA and ECDHE-RSA with
//! AES-256-GCM and AES-128-GCM), key exchange over X25519, P-256 and P-384. The registered port
//! is [`DEFAULT_TLS_PORT`](crate::cs104::DEFAULT_TLS_PORT) (19998).
//!
//! # Deviations from IEC 62351-3 (PIXIT)
//!
//! rustls deliberately omits some mechanisms that the IEC 62351-3 / IEC 62351-4 profile lists,
//! so a conformance statement for this crate must say:
//!
#![doc = include_str!("deviations.md")]
//!
//! A peer that offers only what this table lists as missing fails the handshake with a named
//! [`TlsError`]. A peer that renegotiates on a timer (TLS 1.2) sees the refusal; whether it
//! then closes the connection is the peer's choice. In the lib60870-C / mbedTLS 3.6.6
//! interop test, repeated TLS 1.2 renegotiation requests ended the session with a rustls
//! protocol error.
//!
//! Over TLS 1.3 the client completes its side of the handshake before the server has judged
//! the client's certificate; a client the server refuses learns it from the server's alert on
//! its first read. The server never attaches a link to an unverified connection.

mod config;
mod error;
mod stream;
mod subject;
#[cfg(feature = "tokio")]
mod tokio;

pub use config::{CIPHER_SUITES, PROTOCOL_VERSIONS, TlsClientConfig, TlsServerConfig};
pub use error::{SecurityEvent, TlsError};
pub use stream::TlsStream;
#[cfg(feature = "tokio")]
pub use tokio::AsyncTlsStream;

/// The rustls version this crate builds with, for [`TlsClientConfig::from_rustls`] and
/// [`TlsServerConfig::from_rustls`].
pub use rustls;
