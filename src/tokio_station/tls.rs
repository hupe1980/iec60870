//! [`AsyncClient`] and [`AsyncServer`] over TLS (IEC 62351-3, features `tls` and `tokio`).

use std::boxed::Box;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::vec::Vec;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::sync::mpsc;

use super::{AsyncClient, AsyncServer, TaskWriter};
use crate::client::{BoxedClock, system_clock};
use crate::cs104::{self, Cs104Link, Role};
use crate::driver::TokioDriver;
use crate::server::State;
use crate::station::{ClientConfig, ControllingStation, Error, GroupId};
use crate::time::Clock;
use crate::tls::{TlsClientConfig, TlsServerConfig};

impl AsyncClient {
    /// [`Client::connect_tls`](crate::Client::connect_tls) over Tokio.
    pub async fn connect_tls(addr: impl ToSocketAddrs, server_name: &str, tls: &TlsClientConfig) -> Result<AsyncClient, Error> {
        Self::connect_tls_with(addr, server_name, tls, cs104::Config::default(), ClientConfig::default(), system_clock()).await
    }

    /// [`connect_tls`](Self::connect_tls) with a link configuration, a station configuration
    /// and a clock. TCP connect and handshake are each bounded by the link's t0.
    pub async fn connect_tls_with(
        addr: impl ToSocketAddrs,
        server_name: &str,
        tls: &TlsClientConfig,
        link: cs104::Config,
        config: ClientConfig,
        clock: impl Clock + Send + 'static,
    ) -> Result<AsyncClient, Error> {
        let core = Cs104Link::new(Role::Controlling, link).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let stream = tokio::time::timeout(link.t0, TcpStream::connect(addr)).await.map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        stream.set_nodelay(true)?;
        let stream = tls.connect_async(stream, server_name, link.t0).await?;
        let station = ControllingStation::new(core, config, BoxedClock(Box::new(clock)));
        Ok(AsyncClient { driver: TokioDriver::new(station, Box::new(stream)), backlog: VecDeque::new() })
    }
}

impl AsyncServer {
    pub(super) fn serve_tls(&self, stream: TcpStream, peer: SocketAddr, tls: &TlsServerConfig) {
        let _ = stream.set_nodelay(true);
        let group = self.groups.iter().find(|(_, peers)| peers.contains(&peer.ip())).map_or(GroupId(0), |(g, _)| *g);
        let Ok(link) = Cs104Link::new(Role::Controlled, self.link) else { return };
        let (shared, tls, t0) = (Arc::clone(&self.shared), tls.clone(), self.link.t0);
        tokio::spawn(async move {
            // A refused handshake was reported to the callback and closed; nothing is attached.
            let Ok(stream) = tls.accept_async(stream, t0).await else { return };
            if shared.shutdown.load(Ordering::SeqCst) {
                return;
            }
            let (mut read, mut write) = tokio::io::split(stream);
            let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
            let id = shared.with(|state, now| {
                let id = state.station.attach(link, group);
                state.station.handle_timeout(now);
                id
            });
            tokio::spawn(async move {
                while let Some(bytes) = rx.recv().await {
                    if bytes.is_empty() || write.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                // Sends close_notify, then shuts the TCP stream down.
                let _ = write.shutdown().await;
            });
            let abort = Arc::new(std::sync::Mutex::new(None));
            shared.writers().insert(id, (peer, Box::new(TaskWriter { tx, reader: Arc::clone(&abort) })));
            let reader_shared = Arc::clone(&shared);
            let reader = tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match read.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => reader_shared.with(|state, now| {
                            let State { station, handler, .. } = state;
                            station.handle_input(id, buf.get(..n).unwrap_or_default(), now, &mut **handler);
                        }),
                    }
                }
                reader_shared.with(|state, now| state.station.handle_disconnect(id, now));
            });
            if let Ok(mut slot) = abort.lock() {
                *slot = Some(reader.abort_handle());
            }
        });
    }
}
