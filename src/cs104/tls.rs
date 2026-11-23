//! Connecting and accepting 104 links over TLS (IEC 62351-3).

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};

use super::config::{Config, Role};
use super::link::Cs104Link;
use crate::driver::BlockingDriver;
use crate::tls::{TlsClientConfig, TlsServerConfig, TlsStream};

fn invalid(e: impl Into<std::boxed::Box<dyn core::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e)
}

/// [`connect`](super::connect) over TLS: connects within `config.t0` per address tried, runs
/// the handshake within `config.t0`, verifying the server's certificate against the trust
/// anchors and `server_name` (the DNS name or IP address in its certificate), and returns the
/// link over a blocking runner. Data transfer is not started yet: call
/// [`BlockingDriver::start`].
///
/// A refused handshake is an [`io::Error`] whose source is a [`TlsError`](crate::tls::TlsError).
///
/// ```no_run
/// use iec60870::cs104::{self, Config};
/// use iec60870::tls::TlsClientConfig;
///
/// let tls = TlsClientConfig::from_pem_files("ca.pem", "master.pem", "master.key")?;
/// let mut link = cs104::connect_tls("rtu1.example:19998", "rtu1.example", &tls, Config::default())?;
/// link.start()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn connect_tls(addr: impl ToSocketAddrs, server_name: &str, tls: &TlsClientConfig, config: Config) -> io::Result<BlockingDriver<Cs104Link, TlsStream>> {
    let link = Cs104Link::new(Role::Controlling, config).map_err(invalid)?;
    let mut last = io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to");
    for addr in addr.to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, config.t0) {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                let stream = tls.connect(stream, server_name, config.t0)?;
                return Ok(BlockingDriver::new(link, stream));
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// [`accept`](super::accept) over TLS: accepts the next connection on `listener`, runs the
/// handshake within `config.t0` — the client must present a certificate that chains to the
/// trust anchors — and returns the link with the peer's address. A refused handshake is an
/// error; the next call accepts the next connection.
///
/// The handshake runs on the calling thread. An accept loop that must not wait for a slow
/// client accepts the TCP connection itself and calls
/// [`TlsServerConfig::accept`] on the connection's thread.
pub fn accept_tls(listener: &TcpListener, tls: &TlsServerConfig, config: Config) -> io::Result<(BlockingDriver<Cs104Link, TlsStream>, SocketAddr)> {
    let link = Cs104Link::new(Role::Controlled, config).map_err(invalid)?;
    let (stream, peer) = listener.accept()?;
    stream.set_nodelay(true)?;
    let stream = tls.accept(stream, config.t0)?;
    Ok((BlockingDriver::new(link, stream), peer))
}

#[cfg(feature = "tokio")]
mod tokio_io {
    use std::io;
    use std::net::SocketAddr;

    use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

    use super::invalid;
    use crate::cs104::{Config, Cs104Link, Role};
    use crate::driver::TokioDriver;
    use crate::tls::{AsyncTlsStream, TlsClientConfig, TlsServerConfig};

    /// [`connect_tls`](super::connect_tls) over Tokio: TCP connect and handshake each within
    /// `config.t0`.
    pub async fn connect_tls_async(
        addr: impl ToSocketAddrs,
        server_name: &str,
        tls: &TlsClientConfig,
        config: Config,
    ) -> io::Result<TokioDriver<Cs104Link, AsyncTlsStream>> {
        let link = Cs104Link::new(Role::Controlling, config).map_err(invalid)?;
        let stream = tokio::time::timeout(config.t0, TcpStream::connect(addr)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        let stream = tls.connect_async(stream, server_name, config.t0).await?;
        Ok(TokioDriver::new(link, stream))
    }

    /// [`accept_tls`](super::accept_tls) over Tokio.
    pub async fn accept_tls_async(
        listener: &TcpListener,
        tls: &TlsServerConfig,
        config: Config,
    ) -> io::Result<(TokioDriver<Cs104Link, AsyncTlsStream>, SocketAddr)> {
        let link = Cs104Link::new(Role::Controlled, config).map_err(invalid)?;
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?;
        let stream = tls.accept_async(stream, config.t0).await?;
        Ok((TokioDriver::new(link, stream), peer))
    }
}

#[cfg(feature = "tokio")]
pub use tokio_io::{accept_tls_async, connect_tls_async};
