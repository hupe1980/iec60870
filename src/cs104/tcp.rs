//! Connecting and accepting 104 links over TCP, and the link's commands on the runners.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};

use super::config::{Config, Role};
use super::link::{CommandError, Cs104Link, SubmitError};
use crate::driver::{BlockingDriver, Transport};

fn invalid(e: impl Into<std::boxed::Box<dyn core::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e)
}

/// Connects to a controlled station as the controlling station, within `config.t0` per
/// address tried, and returns the link over a blocking runner. Data transfer is not started
/// yet: call [`BlockingDriver::start`].
///
/// ```no_run
/// use iec60870::cs104::{self, Config, Event};
///
/// let mut link = cs104::connect("10.0.0.5:2404", Config::default())?;
/// link.start()?;
/// while let Some(event) = link.next_event()? {
///     match event {
///         Event::Asdu(asdu) => println!("received {asdu:02x?}"),
///         Event::Closed(reason) => println!("closed: {reason}"),
///         _ => {}
///     }
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn connect(addr: impl ToSocketAddrs, config: Config) -> io::Result<BlockingDriver<Cs104Link, TcpStream>> {
    let link = Cs104Link::new(Role::Controlling, config).map_err(invalid)?;
    let mut last = io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to");
    for addr in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, config.t0) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(BlockingDriver::new(link, stream));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Accepts the next connection on `listener` as the controlled station and returns the link
/// over a blocking runner, with the peer's address. The link answers STARTDT by itself.
pub fn accept(listener: &TcpListener, config: Config) -> io::Result<(BlockingDriver<Cs104Link, TcpStream>, SocketAddr)> {
    let link = Cs104Link::new(Role::Controlled, config).map_err(invalid)?;
    let (stream, peer) = listener.accept()?;
    stream.set_nodelay(true)?;
    Ok((BlockingDriver::new(link, stream), peer))
}

impl<T: Transport> BlockingDriver<Cs104Link, T> {
    /// [`Cs104Link::start`] now.
    pub fn start(&mut self) -> Result<(), CommandError> {
        self.with(Cs104Link::start)
    }

    /// [`Cs104Link::stop`] now.
    pub fn stop(&mut self) -> Result<(), CommandError> {
        self.with(Cs104Link::stop)
    }

    /// [`Cs104Link::submit`] now; the frame is written by the next `next_event`/`poll_event`.
    pub fn submit(&mut self, asdu: &[u8]) -> Result<(), SubmitError> {
        self.with(|link, now| link.submit(asdu, now))
    }

    /// [`Cs104Link::can_send`].
    pub fn can_send(&self) -> bool {
        self.protocol().can_send()
    }
}

#[cfg(feature = "tokio")]
mod tokio_io {
    use std::io;
    use std::net::SocketAddr;

    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

    use super::invalid;
    use crate::cs104::{CommandError, Config, Cs104Link, Role, SubmitError};
    use crate::driver::TokioDriver;

    /// [`connect`](super::connect) over Tokio: connects within `config.t0`.
    pub async fn connect_async(addr: impl ToSocketAddrs, config: Config) -> io::Result<TokioDriver<Cs104Link, TcpStream>> {
        let link = Cs104Link::new(Role::Controlling, config).map_err(invalid)?;
        let stream = tokio::time::timeout(config.t0, TcpStream::connect(addr)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        Ok(TokioDriver::new(link, stream))
    }

    /// [`accept`](super::accept) over Tokio.
    pub async fn accept_async(listener: &TcpListener, config: Config) -> io::Result<(TokioDriver<Cs104Link, TcpStream>, SocketAddr)> {
        let link = Cs104Link::new(Role::Controlled, config).map_err(invalid)?;
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        Ok((TokioDriver::new(link, stream), peer))
    }

    impl<T: AsyncRead + AsyncWrite + Unpin> TokioDriver<Cs104Link, T> {
        /// [`Cs104Link::start`] now.
        pub fn start(&mut self) -> Result<(), CommandError> {
            self.with(Cs104Link::start)
        }

        /// [`Cs104Link::stop`] now.
        pub fn stop(&mut self) -> Result<(), CommandError> {
            self.with(Cs104Link::stop)
        }

        /// [`Cs104Link::submit`] now; the frame is written by the next `next_event`.
        pub fn submit(&mut self, asdu: &[u8]) -> Result<(), SubmitError> {
            self.with(|link, now| link.submit(asdu, now))
        }

        /// [`Cs104Link::can_send`].
        pub fn can_send(&self) -> bool {
            self.protocol().can_send()
        }
    }
}

#[cfg(feature = "tokio")]
pub use tokio_io::{accept_async, connect_async};
