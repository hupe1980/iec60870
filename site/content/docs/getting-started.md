+++
title = "Getting started"
description = "Inspect an ASDU and run a local IEC 104 interrogation."
weight = 1
+++

A controlling station (client) asks an outstation (server) for its current points. IEC 104 carries these messages over TCP. Each application service data unit (ASDU) identifies the station, the type of data and why it was sent.

## Run a loopback interrogation

From a source checkout with Rust 1.88 or newer, run the codec example and then the station example.

```sh
cargo run --example asdu
cargo run --example client
```

With no address argument, the client starts an outstation on loopback, starts data transfer and prints the points returned by a general interrogation. To inspect the public API and examples for every feature locally, run `cargo doc --all-features --no-deps --open`.

The demo reports these points among its events:

```text
CA 1 IOA 100 = ON, interrogated by station (20)
CA 1 IOA 101 = OFF, interrogated by station (20)
CA 1 IOA 200 = 21.5, interrogated by station (20)
```

Print a station event with `println!("{event}")`. A value such as `21.5 [NT IV]` carries both the not-topical and invalid flags. A nonzero originator, test or negative indication, and a time tag appear on the same point line when present. This point carries all three cause indicators and a station time tag.

```text
CA 1 IOA 200 = 21.5 [NT IV], interrogated by station (20), negative, test, originator 3 at 2026-11-18 09:46:40.000
CA 1 station interrogation complete
```

Use the typed event fields for filtering, storage and serialization.

Enable `cs101` for the FT 1.2 link, `serial` for a serial port, and `tokio` for async station adapters.

## Serve a point on an embedded board

The embedded example registers temperature at common address 1, information object address 200. From the checkout, cross-compile the library and run the same station logic on your development machine.

```sh
rustup target add thumbv7em-none-eabihf
cargo build --locked --manifest-path examples/embedded/Cargo.toml --target thumbv7em-none-eabihf
cargo test --locked --manifest-path examples/embedded/Cargo.toml
```

The host test starts data transfer, sends a read and verifies a 21.5 °C reply. In firmware, supply the allocator, panic handler, clock and transport. The board loop feeds received bytes to the station and drains its outputs. See `examples/embedded/README.md` in the checkout for the firmware integration steps.

## Gateway point sources

Both blocking and Tokio servers accept a `PointSource`. A map is enough for a monitoring gateway.

```rust
use iec60870::{Server, prelude::*};
use std::collections::BTreeMap;

let ca = CommonAddress(1);
let points = BTreeMap::from([((ca, Ioa(200)), PointEntry::new(21.5_f32))]);
let server = Server::bind("127.0.0.1:0", points)?;
let handle = server.spawn(iec60870::station::RefuseCommands)?;
handle.update(ca, Ioa(200), 22.0_f32)?;
handle.shutdown();
```

Keep the point addresses and kinds fixed while serving. Fetch slow upstream data outside the station thread. Submit readings through the handle so the station timestamps each update and queues spontaneous events. For a custom source, implement ordered enumeration and lookup against the same local process image.

A server command handler can use `handle.peer(request.connection)` to include the remote socket address in its audit log. Blocking and Tokio handles both return `Option<SocketAddr>`. Use `ServerHandle::next_event_with_peer` when a blocking event consumer also needs the address after disconnection.
