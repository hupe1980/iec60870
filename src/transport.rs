//! The streams the station-level clients run over: plain TCP, or TLS (feature `tls`).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use crate::driver::Transport;

/// A blocking client connection: TCP, or TLS over TCP.
#[derive(Debug)]
pub(crate) enum ClientStream {
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(std::boxed::Box<crate::tls::TlsStream>),
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ClientStream::Tcp(s) => s.read(buf),
            #[cfg(feature = "tls")]
            ClientStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ClientStream::Tcp(s) => s.write(buf),
            #[cfg(feature = "tls")]
            ClientStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ClientStream::Tcp(s) => s.flush(),
            #[cfg(feature = "tls")]
            ClientStream::Tls(s) => s.flush(),
        }
    }
}

impl Transport for ClientStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        match self {
            ClientStream::Tcp(s) => Transport::set_read_timeout(s, timeout),
            #[cfg(feature = "tls")]
            ClientStream::Tls(s) => Transport::set_read_timeout(&mut **s, timeout),
        }
    }

    fn shutdown(&mut self) -> io::Result<()> {
        match self {
            ClientStream::Tcp(s) => Transport::shutdown(s),
            #[cfg(feature = "tls")]
            ClientStream::Tls(s) => Transport::shutdown(&mut **s),
        }
    }
}

/// An async client connection: anything Tokio can read and write (TCP, TLS over TCP).
#[cfg(feature = "tokio")]
pub(crate) trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + core::fmt::Debug {}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + core::fmt::Debug> AsyncStream for T {}

/// The boxed async client connection.
#[cfg(feature = "tokio")]
pub(crate) type BoxedAsyncStream = std::boxed::Box<dyn AsyncStream>;
