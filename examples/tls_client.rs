//! Interrogate an in-process outstation using a fresh test certificate authority.
#[path = "../tests/tls_support/mod.rs"]
mod tls_support;

use iec60870::prelude::*;
use iec60870::station::RefuseCommands;
use iec60870::tls::{TlsClientConfig, TlsServerConfig};
use iec60870::{Client, Server};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pki = tls_support::Pki::new();
    let ca = pki.ca.cert.as_bytes();
    let server_tls = TlsServerConfig::from_pem(ca, pki.server.cert.as_bytes(), pki.server.key.as_bytes())?;
    let client_tls = TlsClientConfig::from_pem(ca, pki.client.cert.as_bytes(), pki.client.key.as_bytes())?;
    let mut database = Database::new();
    database.insert(CommonAddress(1), Ioa(200), 21.5f32);
    let server = Server::builder().tls(server_tls).bind("127.0.0.1:0", database)?;
    let addr = server.local_addr()?;
    let handle = server.spawn(RefuseCommands)?;
    let mut client = Client::connect_tls(addr, "localhost", &client_tls)?;
    client.start()?;
    for event in client.interrogate(CommonAddress(1))? {
        println!("{:?}", event?);
    }
    client.stop()?;
    drop(client);
    handle.shutdown();
    Ok(())
}
