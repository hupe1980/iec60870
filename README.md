# iec60870

IEC 60870-5-101 and -104 telecontrol for Rust. Build a controlling station that reads and commands remote points, or an outstation that serves them. The ASDU codec and link state machines run on `no_std` with an allocator. The default build adds blocking IEC 104 stations over TCP.

[Getting started](https://hupe1980.github.io/iec60870/docs/getting-started/) · [CLI guide](https://hupe1980.github.io/iec60870/docs/cli/) · [Interoperability statement](https://hupe1980.github.io/iec60870/docs/pics/)

## Run a station

From a source checkout with Rust 1.88 or newer, run a client and outstation together on loopback.

```sh
cargo run --locked --example client
```

A general interrogation asks the outstation for its current values. In the response `CA 1 IOA 200 = 21.5`, common address 1 identifies the station and information object address 200 identifies the point.

## Encode and decode a measurement

```rust
use iec60870::prelude::*;

let now = SystemClock.now();
let asdu = Asdu::new(CommonAddress(1), Cot::SPONTANEOUS, [
    InformationObject::new(Ioa(4001), MeasuredFloat::new(21.5)).at(now),
]);

let mut buf = [0u8; 249];
let n = asdu.encode(&Profile::IEC104, &mut buf)?;
let decoded = Asdu::decode(&buf[..n], &Profile::IEC104)?;
println!("{decoded}"); // M_ME_TF_1 (36) spontaneous (3), CA 1, 1 object, IOA 4001
```

The codec preserves received values, including out-of-range time fields. Decode errors identify the field and octet offset. Encoding uses the caller’s buffer and checks the selected profile.

## Inspect a frame or query the simulator

```sh
cargo install --locked --path . --features cli
iec60870 decode 680407000000
iec60870 sim --demo
```

The six-byte frame decodes to `STARTDT act`, a request to start IEC 104 data transfer. With the simulator running, open another terminal and run `iec60870 client 127.0.0.1:2404 read 110`. The demo’s initial reading is `step 5`. The [CLI guide](https://hupe1980.github.io/iec60870/docs/cli/) covers packet captures, JSON output, station files and serial monitoring.

## Choose Cargo features

| Feature | Capability |
| --- | --- |
| `std`, `cs104` (defaults) | System clock, IEC 104 link and blocking TCP stations |
| `cs101` | Balanced and unbalanced FT 1.2 serial link state machines |
| `serial` | Blocking serial port adapter for IEC 101 |
| `tokio` | Async adapters for enabled transports |
| `tls` | IEC 104 with [mutual TLS](https://hupe1980.github.io/iec60870/docs/tls/) |
| `file-transfer` | Station file listings, downloads and an in-memory record store |
| `file-store-fs` | Directory-backed [file store](https://hupe1980.github.io/iec60870/docs/file-stores/) |
| `cli` | Decoder, capture reader, simulator and IEC 104 client |

For bare metal, disable default features and enable the links you need. The [embedded example](examples/embedded/README.md) serves a temperature point and includes a host-side read test.

## Development and verification

Run `just` to list recipes. Use `just check` for formatting, Clippy and tests, `just docs` to build the all-features Rust API reference, and `just serve` to preview the Zola site in `site/`.

The [conformance report](https://hupe1980.github.io/iec60870/docs/conformance/) maps protocol procedures to tests, independent peers and remaining gaps. Run `just interop` with Docker and tshark 4.6 or newer for peer and dissector checks. After an intentional behavior change, run `just refresh-conformance` and review the generated changes.

### Publishing a release

Run the **Release** workflow manually for a rehearsal. It builds the crate and CLI archives, runs CI, and installs and tests the generated Homebrew formula. On a tag matching the manifest version (for example, `v0.2.0`), the workflow stages and verifies the GitHub Release assets in a draft, publishes the crate to crates.io, then makes the draft public. If publication is interrupted, rerun the failed jobs for the same tag. Stable tags also update `hupe1980/tap/iec60870` for Apple Silicon and Linux (x86-64 and ARM64).

Configure the crate’s trusted publisher as `hupe1980/iec60870`, workflow `release.yml`, environment `crates-io`. Store `HOMEBREW_APP_ID` and `HOMEBREW_APP_PRIVATE_KEY` in the repository’s `homebrew` environment. The GitHub App needs contents write access to `hupe1980/homebrew-tap`.

## License

Available under the [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) license, at your option.
