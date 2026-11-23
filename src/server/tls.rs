//! [`Server`] over TLS (IEC 62351-3, feature `tls`): the handshake runs on each connection's
//! own thread, and only a verified connection is attached to the station.

use std::boxed::Box;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::vec::Vec;

use super::{ConnWriter, Server, ServerBuilder, State};
use crate::cs104::{Cs104Link, Role};
use crate::station::GroupId;
use crate::tls::TlsServerConfig;

impl ServerBuilder {
    /// Serves IEC 62351-3 TLS instead of plain TCP: every client must present a certificate
    /// that chains to the trust anchors of `tls`, and the handshake must complete within the
    /// link's t0, before the connection is attached to the station. Refusals reach the
    /// configuration's `on_event` callback. Bind to [`DEFAULT_TLS_PORT`](crate::cs104::DEFAULT_TLS_PORT)
    /// (19998) unless the deployment says otherwise.
    ///
    /// ```no_run
    /// use iec60870::prelude::*;
    /// use iec60870::tls::TlsServerConfig;
    ///
    /// let tls = TlsServerConfig::from_pem_files("ca.pem", "rtu1.pem", "rtu1.key")?
    ///     .on_event(|event| eprintln!("security: {event:?}"));
    /// let server = iec60870::Server::builder().tls(tls).bind("0.0.0.0:19998", Database::new())?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn tls(mut self, tls: TlsServerConfig) -> Self {
        self.tls = Some(tls);
        self
    }
}

/// The writer of a TLS connection: an empty buffer ends it with `close_notify`.
struct TlsThreadWriter {
    tx: Sender<Vec<u8>>,
}

impl ConnWriter for TlsThreadWriter {
    fn send(&self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            let _ = self.tx.send(bytes);
        }
    }

    fn close(&self) {
        let _ = self.tx.send(Vec::new());
    }
}

impl Server {
    pub(super) fn serve_tls(&self, stream: TcpStream, tls: &TlsServerConfig) -> io::Result<()> {
        stream.set_nodelay(true)?;
        let peer = stream.peer_addr()?;
        let group = self.groups.iter().find(|(_, peers)| peers.contains(&peer.ip())).map_or(GroupId(0), |(g, _)| *g);
        let link = Cs104Link::new(Role::Controlled, self.link).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let (shared, tls, t0) = (Arc::clone(&self.shared), tls.clone(), self.link.t0);
        thread::Builder::new().name("iec60870-tls".into()).spawn(move || {
            // A refused handshake was reported to the callback and closed; nothing is attached.
            let Ok(stream) = tls.accept(stream, t0) else { return };
            if shared.shutdown.load(Ordering::SeqCst) {
                return;
            }
            let Ok((mut reader, mut writer)) = stream.split() else { return };
            let (tx, rx) = mpsc::channel::<Vec<u8>>();
            let id = shared.with(|state, now| {
                let id = state.station.attach(link, group);
                state.station.handle_timeout(now);
                id
            });
            shared.writers().insert(id, (peer, Box::new(TlsThreadWriter { tx })));
            let spawned = thread::Builder::new().name("iec60870-write".into()).spawn(move || {
                for bytes in rx {
                    if bytes.is_empty() || writer.write_all(&bytes).and_then(|()| writer.flush()).is_err() {
                        break;
                    }
                }
                writer.shutdown();
            });
            if spawned.is_err() {
                shared.with(|state, now| state.station.handle_disconnect(id, now));
                return;
            }
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => shared.with(|state, now| {
                        let State { station, handler, .. } = state;
                        station.handle_input(id, buf.get(..n).unwrap_or_default(), now, &mut **handler);
                    }),
                }
            }
            shared.with(|state, now| state.station.handle_disconnect(id, now));
        })?;
        Ok(())
    }
}
