+++
title = "Connect over mutual TLS"
description = "Run a local authenticated station and load identities for your own peers."
weight = 6
+++

Run a complete interrogation against a loopback outstation with fresh certificates.

```sh
cargo run --features tls --example tls_client
```

From a checkout, query a station directly with the CLI:

```sh
cargo run --locked --features cli,tls -- client rtu.example --tls ca.pem master.pem master.key gi
```

For an existing outstation in a Rust application, load the trusted CA, the client's certificate chain and its private key. Pass the expected DNS name or IP address from the server certificate separately from the TCP destination.

```rust
use iec60870::{Client, tls::TlsClientConfig};

let tls = TlsClientConfig::from_pem_files("ca.pem", "master.pem", "master.key")?;
let mut client = Client::connect_tls("127.0.0.1:19998", "rtu.example", &tls)?;
client.start()?;
```

On the outstation, load its identity with `TlsServerConfig::from_pem_files` and pass it to `Server::builder().tls(config)` before binding. Set `on_event` before connecting or binding to record accepted and rejected handshakes. The built-in PEM configurations negotiate TLS 1.2 or 1.3 and require peer authentication.

## Tested interoperability

The integration suite runs lib60870-C with mbedTLS 3.6.6 as both master and outstation. It checks STARTDT, general interrogation and command completion with each peer restricted to TLS 1.2 and then TLS 1.3. The peer trusts a temporary CA and uses ECDSA P-256 certificates.

The lib60870-C client received some interrogation replies only after further socket activity. The fixture sets the Rust outstation's idle test interval (t3) to one second. The library default is 20 seconds.
