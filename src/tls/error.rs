//! What went wrong in a handshake, and the events an application logs.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::string::{String, ToString};

use rustls::{CertificateError, Error as RustlsError};

/// Why a TLS connection was refused, or a TLS configuration could not be built.
///
/// A refused handshake comes back from the connect and accept functions as an
/// [`io::Error`] whose [`get_ref`](io::Error::get_ref) downcasts to this type:
///
/// ```
/// # use iec60870::tls::TlsError;
/// fn cause(e: &std::io::Error) -> Option<&TlsError> {
///     e.get_ref()?.downcast_ref::<TlsError>()
/// }
/// # let e: std::io::Error = TlsError::UnknownIssuer.into();
/// # assert_eq!(cause(&e), Some(&TlsError::UnknownIssuer));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlsError {
    /// The peer sent no certificate (a client connecting without one).
    NoPeerCertificate,
    /// The peer's certificate does not chain to the configured trust anchors.
    UnknownIssuer,
    /// The server's certificate is not valid for the name or address that was dialled.
    NameMismatch,
    /// The peer's certificate has expired.
    Expired,
    /// The peer's certificate is not valid yet.
    NotYetValid,
    /// The peer's certificate is revoked.
    Revoked,
    /// The peer's certificate was refused for another reason.
    BadCertificate(String),
    /// The peer refused us with this TLS alert (for instance our certificate).
    AlertReceived(String),
    /// The handshake failed: no common version or suite, a protocol violation.
    Handshake(String),
    /// The handshake did not complete within the timeout.
    Timeout,
    /// The server name is neither a DNS name nor an IP address.
    InvalidServerName(String),
    /// A certificate, key or trust-anchor file could not be used.
    Pem {
        /// What was being read: "trust anchors", "certificate chain" or "private key".
        what: &'static str,
        /// The file name, or "memory".
        source: String,
        /// What was wrong.
        reason: String,
    },
    /// The configuration was refused (for example a key that does not match the certificate).
    Config(String),
    /// The connection failed underneath TLS.
    Io(io::ErrorKind),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsError::NoPeerCertificate => f.write_str("the peer presented no certificate"),
            TlsError::UnknownIssuer => f.write_str("the peer certificate does not chain to a trusted CA"),
            TlsError::NameMismatch => f.write_str("the server certificate is not valid for the name dialled"),
            TlsError::Expired => f.write_str("the peer certificate has expired"),
            TlsError::NotYetValid => f.write_str("the peer certificate is not valid yet"),
            TlsError::Revoked => f.write_str("the peer certificate is revoked"),
            TlsError::BadCertificate(why) => write!(f, "the peer certificate was refused: {why}"),
            TlsError::AlertReceived(alert) => write!(f, "the peer refused the handshake: {alert}"),
            TlsError::Handshake(why) => write!(f, "TLS handshake failed: {why}"),
            TlsError::Timeout => f.write_str("TLS handshake timed out"),
            TlsError::InvalidServerName(name) => write!(f, "invalid TLS server name {name:?}"),
            TlsError::Pem { what, source, reason } => write!(f, "cannot use the {what} from {source}: {reason}"),
            TlsError::Config(why) => write!(f, "invalid TLS configuration: {why}"),
            TlsError::Io(kind) => write!(f, "connection failed during the TLS handshake: {kind}"),
        }
    }
}

impl std::error::Error for TlsError {}

impl From<TlsError> for io::Error {
    fn from(e: TlsError) -> io::Error {
        let kind = match e {
            TlsError::Timeout => io::ErrorKind::TimedOut,
            TlsError::InvalidServerName(_) | TlsError::Pem { .. } | TlsError::Config(_) => io::ErrorKind::InvalidInput,
            TlsError::Io(kind) => kind,
            TlsError::AlertReceived(_) | TlsError::Handshake(_) => io::ErrorKind::ConnectionAborted,
            _ => io::ErrorKind::PermissionDenied,
        };
        io::Error::new(kind, e)
    }
}

impl From<RustlsError> for TlsError {
    fn from(e: RustlsError) -> TlsError {
        match e {
            RustlsError::NoCertificatesPresented => TlsError::NoPeerCertificate,
            RustlsError::InvalidCertificate(c) => match c {
                CertificateError::UnknownIssuer => TlsError::UnknownIssuer,
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. } => TlsError::NameMismatch,
                CertificateError::Expired | CertificateError::ExpiredContext { .. } => TlsError::Expired,
                CertificateError::NotValidYet | CertificateError::NotValidYetContext { .. } => TlsError::NotYetValid,
                CertificateError::Revoked => TlsError::Revoked,
                other => TlsError::BadCertificate(other.to_string()),
            },
            RustlsError::AlertReceived(alert) => TlsError::AlertReceived(alert.as_str().map_or_else(|| std::format!("{alert:?}"), str::to_string)),
            other => TlsError::Handshake(other.to_string()),
        }
    }
}

impl TlsError {
    /// Classifies an I/O error from a handshake: a rustls error inside, a timeout, or the
    /// transport.
    pub(crate) fn from_io(e: &io::Error) -> TlsError {
        if let Some(inner) = e.get_ref() {
            if let Some(tls) = inner.downcast_ref::<TlsError>() {
                return tls.clone();
            }
            if let Some(rustls) = inner.downcast_ref::<RustlsError>() {
                return rustls.clone().into();
            }
        }
        match e.kind() {
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => TlsError::Timeout,
            kind => TlsError::Io(kind),
        }
    }
}

/// A security event for the application's log (in the spirit of IEC 62351-7): one per
/// handshake, delivered to the callback set with `on_event` on the TLS configuration.
///
/// ```
/// use iec60870::tls::SecurityEvent;
///
/// fn log(event: &SecurityEvent) {
///     match event {
///         SecurityEvent::Established { peer, version, suite, peer_subject, .. } => {
///             println!("TLS {version} {suite} with {peer} ({})", peer_subject.as_deref().unwrap_or("-"));
///         }
///         SecurityEvent::Rejected { peer, error, .. } => eprintln!("refused {peer}: {error}"),
///         _ => {}
///     }
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityEvent {
    /// A handshake completed and the peer was verified.
    Established {
        /// The peer's address.
        peer: SocketAddr,
        /// The negotiated version, e.g. `"TLSv1_3"`.
        version: &'static str,
        /// The negotiated cipher suite, e.g. `"TLS13_AES_256_GCM_SHA384"`.
        suite: &'static str,
        /// The subject of the peer's end-entity certificate, e.g. `"CN=master-1, O=Grid"`.
        peer_subject: Option<String>,
    },
    /// A handshake failed; the connection was closed before any 104 frame.
    Rejected {
        /// The peer's address.
        peer: SocketAddr,
        /// Why.
        error: TlsError,
    },
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use rustls::AlertDescription;

    #[test]
    fn rustls_errors_are_classified() {
        assert_eq!(TlsError::from(RustlsError::NoCertificatesPresented), TlsError::NoPeerCertificate);
        assert_eq!(TlsError::from(RustlsError::InvalidCertificate(CertificateError::UnknownIssuer)), TlsError::UnknownIssuer);
        assert_eq!(TlsError::from(RustlsError::InvalidCertificate(CertificateError::NotValidForName)), TlsError::NameMismatch);
        assert_eq!(TlsError::from(RustlsError::InvalidCertificate(CertificateError::Expired)), TlsError::Expired);
        assert_eq!(TlsError::from(RustlsError::InvalidCertificate(CertificateError::Revoked)), TlsError::Revoked);
        assert!(
            matches!(TlsError::from(RustlsError::AlertReceived(AlertDescription::CertificateRequired)), TlsError::AlertReceived(a) if a == "CertificateRequired")
        );
    }

    #[test]
    fn io_errors_round_trip() {
        let e: io::Error = TlsError::UnknownIssuer.into();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(TlsError::from_io(&e), TlsError::UnknownIssuer);
        let wrapped = io::Error::new(io::ErrorKind::InvalidData, RustlsError::NoCertificatesPresented);
        assert_eq!(TlsError::from_io(&wrapped), TlsError::NoPeerCertificate);
        assert_eq!(TlsError::from_io(&io::Error::from(io::ErrorKind::WouldBlock)), TlsError::Timeout);
        assert_eq!(TlsError::from_io(&io::Error::from(io::ErrorKind::ConnectionReset)), TlsError::Io(io::ErrorKind::ConnectionReset));
    }
}
