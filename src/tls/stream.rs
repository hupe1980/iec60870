//! The blocking TLS stream: a handshake with a deadline, then `Read + Write + Transport`.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::string::{String, ToString};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConnection, Connection, ServerConnection};

use super::config::{EventHook, TlsClientConfig, TlsServerConfig, emit};
use super::error::{SecurityEvent, TlsError};
use super::subject::subject;
use crate::driver::Transport;

/// A TLS connection over a [`TcpStream`], after a completed and verified handshake.
///
/// It is a [`driver::Transport`](Transport), so a [`BlockingDriver`](crate::driver::BlockingDriver)
/// runs any core over it exactly as over a plain `TcpStream`. Built by
/// [`TlsClientConfig::connect`] and [`TlsServerConfig::accept`], or by
/// [`cs104::connect_tls`](crate::cs104::connect_tls) and [`cs104::accept_tls`](crate::cs104::accept_tls).
///
/// A TCP close without a TLS `close_notify` reads as the end of the stream, as for plain TCP
/// (the APCI framing makes a truncated frame visible).
#[derive(Debug)]
pub struct TlsStream {
    conn: Connection,
    sock: TcpStream,
    peer: SocketAddr,
}

/// Facts about an established session, shared by the blocking and the async streams.
pub(crate) fn established(conn: &rustls::CommonState, peer: SocketAddr) -> SecurityEvent {
    SecurityEvent::Established {
        peer,
        version: version(conn),
        suite: suite(conn),
        peer_subject: conn.peer_certificates().and_then(<[_]>::first).and_then(|c| subject(c)),
    }
}

fn version(conn: &rustls::CommonState) -> &'static str {
    conn.protocol_version().and_then(|v| v.as_str()).unwrap_or("unknown")
}

fn suite(conn: &rustls::CommonState) -> &'static str {
    conn.negotiated_cipher_suite().and_then(|s| s.suite().as_str()).unwrap_or("unknown")
}

pub(crate) fn server_name(name: &str) -> Result<ServerName<'static>, TlsError> {
    ServerName::try_from(String::from(name)).map_err(|_| TlsError::InvalidServerName(name.into()))
}

/// rustls may perform several socket operations inside one call to `complete_io`.
struct HandshakeIo<'a> {
    socket: &'a mut TcpStream,
    started: Instant,
    timeout: Duration,
}

impl HandshakeIo<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.timeout.checked_sub(self.started.elapsed()).filter(|d| !d.is_zero()).ok_or_else(|| TlsError::Timeout.into())
    }
}

impl Read for HandshakeIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}

impl Write for HandshakeIo<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

/// Runs the handshake to completion within one shared timeout.
fn handshake(conn: &mut Connection, sock: &mut TcpStream, timeout: Duration) -> io::Result<()> {
    let mut io = HandshakeIo { socket: sock, started: Instant::now(), timeout };
    while conn.is_handshaking() || conn.wants_write() {
        conn.complete_io(&mut io)?;
    }
    io.remaining()?;
    sock.set_read_timeout(None)?;
    sock.set_write_timeout(None)?;
    Ok(())
}

fn finish(
    conn: Result<Connection, rustls::Error>,
    mut sock: TcpStream,
    peer: SocketAddr,
    timeout: Duration,
    hook: Option<&EventHook>,
) -> io::Result<TlsStream> {
    let result = conn.map_err(|e| io::Error::from(TlsError::Config(e.to_string()))).and_then(|mut conn| {
        handshake(&mut conn, &mut sock, timeout)?;
        Ok(conn)
    });
    match result {
        Ok(conn) => {
            emit(hook, || established(&conn, peer));
            Ok(TlsStream { conn, sock, peer })
        }
        Err(e) => {
            let error = TlsError::from_io(&e);
            emit(hook, || SecurityEvent::Rejected { peer, error: error.clone() });
            let _ = sock.shutdown(Shutdown::Both);
            Err(error.into())
        }
    }
}

impl TlsClientConfig {
    /// Runs the client handshake on a connected `tcp` within `timeout`, verifying the server's
    /// certificate against the trust anchors and `server_name` (a DNS name, or an IP address
    /// in the certificate's subjectAltName). Reports one [`SecurityEvent`].
    pub fn connect(&self, tcp: TcpStream, server_name: &str, timeout: Duration) -> io::Result<TlsStream> {
        let peer = tcp.peer_addr()?;
        let name = match self::server_name(server_name) {
            Ok(name) => name,
            Err(error) => {
                emit(self.on_event.as_ref(), || SecurityEvent::Rejected { peer, error: error.clone() });
                return Err(error.into());
            }
        };
        let conn = ClientConnection::new(Arc::clone(&self.config), name).map(Connection::from);
        finish(conn, tcp, peer, timeout, self.on_event.as_ref())
    }
}

impl TlsServerConfig {
    /// Runs the server handshake on an accepted `tcp` within `timeout`, requiring and
    /// verifying the client's certificate. Reports one [`SecurityEvent`].
    ///
    /// Call it on the connection's own thread when the accept loop must not wait for a slow
    /// or silent client.
    pub fn accept(&self, tcp: TcpStream, timeout: Duration) -> io::Result<TlsStream> {
        let peer = tcp.peer_addr()?;
        let conn = ServerConnection::new(Arc::clone(&self.config)).map(Connection::from);
        finish(conn, tcp, peer, timeout, self.on_event.as_ref())
    }
}

/// Reads plaintext: drains what rustls holds, else reads one batch of records.
fn read_plain(conn: &mut Connection, buf: &mut [u8]) -> Option<io::Result<usize>> {
    match conn.reader().read(buf) {
        Ok(n) => Some(Ok(n)),
        Err(e) if e.kind() == ErrorKind::WouldBlock => None,
        // The TCP connection closed without close_notify: the end of the stream, as for TCP.
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => Some(Ok(0)),
        Err(e) => Some(Err(e)),
    }
}

/// Feeds received TLS octets to rustls and writes whatever it must answer.
fn absorb(conn: &mut Connection, mut input: &[u8], out: &mut TcpStream) -> io::Result<()> {
    loop {
        let n = conn.read_tls(&mut input)?;
        if let Err(e) = conn.process_new_packets() {
            let _ = conn.write_tls(out);
            return Err(io::Error::new(ErrorKind::InvalidData, e));
        }
        if input.is_empty() || n == 0 {
            break;
        }
    }
    while conn.wants_write() {
        conn.write_tls(out)?;
    }
    Ok(())
}

impl TlsStream {
    /// The peer's address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// The negotiated protocol version, e.g. `"TLSv1_3"`.
    pub fn protocol_version(&self) -> &'static str {
        version(&self.conn)
    }

    /// The negotiated cipher suite, e.g. `"TLS13_AES_256_GCM_SHA384"`.
    pub fn cipher_suite(&self) -> &'static str {
        suite(&self.conn)
    }

    /// The peer's certificate chain, end-entity first.
    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.conn.peer_certificates()
    }

    /// The subject of the peer's end-entity certificate, e.g. `"CN=master-1, O=Grid"`.
    pub fn peer_subject(&self) -> Option<String> {
        self.peer_certificates().and_then(<[_]>::first).and_then(|c| subject(c))
    }

    /// Refreshes the traffic keys in both directions (a TLS 1.3 `KeyUpdate`) — this crate's
    /// substitute for TLS 1.2 renegotiation, which rustls does not implement. The update is
    /// sent with the next write. Fails on a TLS 1.2 session.
    pub fn refresh_keys(&mut self) -> io::Result<()> {
        self.conn.refresh_traffic_keys().map_err(|e| io::Error::new(ErrorKind::Unsupported, e))?;
        self.flush()
    }

    /// The socket underneath.
    pub fn get_ref(&self) -> &TcpStream {
        &self.sock
    }

    /// Splits into a reader and a writer for two threads; records are written under one lock,
    /// so they never interleave.
    pub(crate) fn split(self) -> io::Result<(TlsReader, TlsWriter)> {
        let read_sock = self.sock.try_clone()?;
        let shared = Arc::new(Mutex::new(self.conn));
        Ok((
            TlsReader { shared: Arc::clone(&shared), sock: read_sock, out: self.sock.try_clone()?, raw: std::vec![0; 4096] },
            TlsWriter { shared, sock: self.sock },
        ))
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut raw = [0u8; 4096];
        loop {
            while self.conn.wants_write() {
                self.conn.write_tls(&mut self.sock)?;
            }
            if let Some(result) = read_plain(&mut self.conn, buf) {
                return result;
            }
            let n = self.sock.read(&mut raw)?;
            absorb(&mut self.conn, raw.get(..n).unwrap_or_default(), &mut self.sock)?;
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.conn.writer().write(buf)?;
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.conn.writer().flush()?;
        while self.conn.wants_write() {
            self.conn.write_tls(&mut self.sock)?;
        }
        self.sock.flush()
    }
}

impl Transport for TlsStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.sock.set_read_timeout(timeout)
    }

    /// Sends `close_notify`, then shuts the socket down.
    fn shutdown(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        let _ = self.flush();
        match self.sock.shutdown(Shutdown::Both) {
            Err(e) if e.kind() == ErrorKind::NotConnected => Ok(()),
            other => other,
        }
    }
}

fn lock(shared: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The reading half of a split [`TlsStream`].
#[derive(Debug)]
pub(crate) struct TlsReader {
    shared: Arc<Mutex<Connection>>,
    sock: TcpStream,
    out: TcpStream,
    raw: std::vec::Vec<u8>,
}

impl Read for TlsReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(result) = read_plain(&mut lock(&self.shared), buf) {
                return result;
            }
            // Block on the socket without the lock, so the writer keeps writing.
            let n = self.sock.read(&mut self.raw)?;
            absorb(&mut lock(&self.shared), self.raw.get(..n).unwrap_or_default(), &mut self.out)?;
        }
    }
}

/// The writing half of a split [`TlsStream`].
#[derive(Debug)]
pub(crate) struct TlsWriter {
    shared: Arc<Mutex<Connection>>,
    sock: TcpStream,
}

impl TlsWriter {
    /// Sends `close_notify` and shuts the socket down (both halves end).
    pub(crate) fn shutdown(&mut self) {
        let mut conn = lock(&self.shared);
        conn.send_close_notify();
        while conn.wants_write() {
            if conn.write_tls(&mut self.sock).is_err() {
                break;
            }
        }
        let _ = self.sock.shutdown(Shutdown::Both);
    }
}

impl Write for TlsWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut conn = lock(&self.shared);
        let n = conn.writer().write(buf)?;
        while conn.wants_write() {
            conn.write_tls(&mut self.sock)?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut conn = lock(&self.shared);
        while conn.wants_write() {
            conn.write_tls(&mut self.sock)?;
        }
        self.sock.flush()
    }
}
