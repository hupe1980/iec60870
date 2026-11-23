//! [`Client`] over TLS (IEC 62351-3, feature `tls`).

use std::boxed::Box;
use std::collections::VecDeque;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};

use super::{Client, ClientBuilder};
use crate::cs104::{Cs104Link, Role};
use crate::driver::BlockingDriver;
use crate::station::{ControllingStation, Error};
use crate::tls::TlsClientConfig;
use crate::transport::ClientStream;

impl ClientBuilder {
    /// Connects over TLS: TCP within the link's t0 per address tried, then the handshake
    /// within t0, verifying the outstation's certificate against the trust anchors and
    /// `server_name` (the DNS name or IP address in its certificate) and presenting the
    /// client's own. Data transfer is not started yet.
    pub fn connect_tls(self, addr: impl ToSocketAddrs, server_name: &str, tls: &TlsClientConfig) -> Result<Client, Error> {
        let link = Cs104Link::new(Role::Controlling, self.link).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut last = io::Error::new(io::ErrorKind::InvalidInput, "no address to connect to");
        for addr in addr.to_socket_addrs()? {
            match TcpStream::connect_timeout(&addr, self.link.t0) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    let stream = tls.connect(stream, server_name, self.link.t0)?;
                    let station = ControllingStation::new(link, self.config, self.clock);
                    return Ok(Client { driver: BlockingDriver::new(station, ClientStream::Tls(Box::new(stream))), backlog: Some(VecDeque::new()) });
                }
                Err(e) => last = e,
            }
        }
        Err(last.into())
    }
}

impl Client {
    /// Connects to an outstation over TLS with the default configuration.
    ///
    /// ```no_run
    /// use iec60870::prelude::*;
    /// use iec60870::tls::TlsClientConfig;
    ///
    /// let tls = TlsClientConfig::from_pem_files("ca.pem", "master.pem", "master.key")?;
    /// let mut client = iec60870::Client::connect_tls("rtu1.example:19998", "rtu1.example", &tls)?;
    /// client.start()?;
    /// for event in client.interrogate(CommonAddress(1))? {
    ///     println!("{:?}", event?);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn connect_tls(addr: impl ToSocketAddrs, server_name: &str, tls: &TlsClientConfig) -> Result<Client, Error> {
        Self::builder().connect_tls(addr, server_name, tls)
    }
}
