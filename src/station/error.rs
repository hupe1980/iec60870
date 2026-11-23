//! The error of every station procedure.

use core::fmt;

use super::link::LinkClosed;
use crate::asdu::EncodeError;
use crate::types::Cot;

/// What a request was waiting for when its timeout expired.
///
/// ```
/// use iec60870::station::{Awaiting, Error};
///
/// let e = Error::Timeout(Awaiting::Termination);
/// assert!(matches!(e, Error::Timeout(Awaiting::Termination)));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Awaiting {
    /// The activation confirmation (ACTCON).
    Confirmation,
    /// The activation termination (ACTTERM) or the last reply.
    Termination,
    /// The response to a read or directory request.
    Response,
    /// The start of data transfer (STARTDT con).
    Start,
}

impl fmt::Display for Awaiting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Awaiting::Confirmation => "the activation confirmation",
            Awaiting::Termination => "the activation termination",
            Awaiting::Response => "the response",
            Awaiting::Start => "the start of data transfer",
        })
    }
}

/// Why a station procedure failed.
///
/// ```
/// use iec60870::station::{Awaiting, Error};
/// use iec60870::Cot;
///
/// let e = Error::Negative { cot: Cot::UNKNOWN_IOA.negative() };
/// assert_eq!(e.to_string(), "negative confirmation: unknown information object address (47), negative");
/// assert_eq!(Error::Timeout(Awaiting::Termination).to_string(), "timed out awaiting the activation termination");
/// ```
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Error {
    /// The controlled station confirmed negatively; `cot` is the cause it sent (activation
    /// confirmation with P/N, or 44–47 for an unknown type, cause, common address or IOA).
    Negative {
        /// The cause of transmission received.
        cot: Cot,
    },
    /// No answer within the configured timeout.
    Timeout(Awaiting),
    /// The same request (type, common address, IOA) is still outstanding.
    Busy,
    /// Data transfer is not started.
    NotStarted,
    /// The connection closed before the request completed.
    Disconnected(LinkClosed),
    /// The request does not encode under the profile (an address wider than its field, …).
    Encode(EncodeError),
    /// The arguments are not valid for this request.
    InvalidArgument(&'static str),
    /// A directory exceeded the entry limit or contained an invalid end marker.
    #[cfg(feature = "file-transfer")]
    InvalidDirectory,
    /// A file download failed.
    #[cfg(feature = "file-transfer")]
    File(super::FileError),
    /// The transport failed.
    #[cfg(feature = "std")]
    Io(alloc::sync::Arc<std::io::Error>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Negative { cot } => write!(f, "negative confirmation: {cot}"),
            Error::Timeout(a) => write!(f, "timed out awaiting {a}"),
            Error::Busy => f.write_str("the same request is still outstanding"),
            Error::NotStarted => f.write_str("data transfer is not started"),
            Error::Disconnected(reason) => write!(f, "disconnected: {reason}"),
            #[cfg(feature = "file-transfer")]
            Error::InvalidDirectory => f.write_str("invalid or oversized file directory"),
            #[cfg(feature = "file-transfer")]
            Error::File(e) => e.fmt(f),
            Error::Encode(e) => write!(f, "cannot encode the request: {e}"),
            Error::InvalidArgument(what) => write!(f, "invalid argument: {what}"),
            #[cfg(feature = "std")]
            Error::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Error::Disconnected(reason) => Some(reason),
            #[cfg(feature = "file-transfer")]
            Error::File(e) => Some(e),
            Error::Encode(e) => Some(e),
            #[cfg(feature = "std")]
            Error::Io(e) => Some(&**e),
            _ => None,
        }
    }
}

impl From<EncodeError> for Error {
    fn from(e: EncodeError) -> Self {
        Error::Encode(e)
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(alloc::sync::Arc::new(e))
    }
}
