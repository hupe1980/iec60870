//! The async handshake over Tokio (features `tls` and `tokio`).

use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::config::{EventHook, TlsClientConfig, TlsServerConfig, emit};
use super::error::{SecurityEvent, TlsError};
use super::stream::{established, server_name};

/// A TLS connection over a Tokio `TcpStream` after a verified handshake, client or server
/// side — `AsyncRead + AsyncWrite`, so a [`TokioDriver`](crate::driver::TokioDriver) runs any
/// core over it.
pub type AsyncTlsStream = tokio_rustls::TlsStream<TcpStream>;

async fn bounded<T>(
    peer: std::net::SocketAddr,
    timeout: Duration,
    hook: Option<&EventHook>,
    handshake: impl Future<Output = io::Result<T>>,
    state: impl FnOnce(&T) -> &rustls::CommonState,
) -> io::Result<T> {
    let result = match tokio::time::timeout(timeout, handshake).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(TlsError::from_io(&e)),
        Err(_) => Err(TlsError::Timeout),
    };
    match result {
        Ok(stream) => {
            emit(hook, || established(state(&stream), peer));
            Ok(stream)
        }
        Err(error) => {
            emit(hook, || SecurityEvent::Rejected { peer, error: error.clone() });
            Err(error.into())
        }
    }
}

impl TlsClientConfig {
    /// [`connect`](Self::connect) over Tokio.
    pub async fn connect_async(&self, tcp: TcpStream, server_name: &str, timeout: Duration) -> io::Result<AsyncTlsStream> {
        let peer = tcp.peer_addr()?;
        let name = match self::server_name(server_name) {
            Ok(name) => name,
            Err(error) => {
                emit(self.on_event.as_ref(), || SecurityEvent::Rejected { peer, error: error.clone() });
                return Err(error.into());
            }
        };
        let connector = TlsConnector::from(Arc::clone(&self.config));
        let stream = bounded(peer, timeout, self.on_event.as_ref(), connector.connect(name, tcp), |s| s.get_ref().1).await?;
        Ok(tokio_rustls::TlsStream::Client(stream))
    }
}

impl TlsServerConfig {
    /// [`accept`](Self::accept) over Tokio.
    pub async fn accept_async(&self, tcp: TcpStream, timeout: Duration) -> io::Result<AsyncTlsStream> {
        let peer = tcp.peer_addr()?;
        let acceptor = TlsAcceptor::from(Arc::clone(&self.config));
        let stream = bounded(peer, timeout, self.on_event.as_ref(), acceptor.accept(tcp), |s| s.get_ref().1).await?;
        Ok(tokio_rustls::TlsStream::Server(stream))
    }
}
