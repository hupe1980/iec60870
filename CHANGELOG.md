# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0 a minor release may
break the API. A change to what goes on the wire is marked ⚠.

## 0.2.0 — 2026-11-23

First implementation release. It includes the shared ASDU codec, IEC 101 and 104 station support, and the command-line tools.

### Added

- The CLI accepts finite captures on stdin and monitors a serial tap or raw FT 1.2 stream with `serial-monitor`.
- Gateways can implement `PointSource` or supply an ordered point map to the station and server constructors. `ControlledStation::database` and the `CommandHandler::feedback` callback now expose `&dyn PointSource`.

- CLI record downloads check the local output directory before connecting and flush verified data before publishing the file.

- `client files` lists station file records. `client get IOA NAME --output PATH` verifies and saves a record without overwriting an existing path. `--max-bytes` sets the receive limit. Both actions support mutual TLS. They discard unrelated station events during file requests. Blocking library callers can opt into the same behavior with `Client::set_event_buffering(false)`.

- The CLI client supports mutual TLS with `--features cli,tls`. It verifies the station identity and presents the configured client chain. File-based client and server TLS configurations now require regular PEM files of at most 1 MiB each.

- Live watch filters points by station and displays per-point update counts, average update rate and the latest event in a terminal.
- `pcap --utc` and `client HOST --utc` follow the decoder’s timestamp contract. Client JSON now uses `time_text` for station readings and reserves `time` for explicitly qualified UTC timestamps. Untagged points omit both fields.

- `sim --preview IOA KIND VALUE` evaluates one local configuration and reports the decision and predicted status change. Simulator files now reject the broadcast address 65535 as an individual station.

- `iec60870 client HOST clock` synchronizes one station to host UTC and reports its confirmation in text or JSON.
- ⚠ Stations reject clock synchronization when either reading is invalid or outside the CP56 calendar. Rejected requests preserve the previous offset.

- `iec60870 client` supports station and counter interrogation, individual point reads, and a bounded live watch with terminal and JSON output.

- `iec60870 sim` serves the bundled demo or a TOML point file, with seeded walks, simulated status feedback and structured command and connection logs. Server observers receive command decisions and a loss count when their notification queue overflows.

- Blocking and Tokio server handles expose `peer(connection)` for logging the remote socket address while a connection is open, including TLS connections.

- `iec60870 sim --check` validates simulator TOML files offline and reports station, point and command counts. The packaged demo is also available as `examples/demo-bay.toml`.

- `iec60870 pcap` reads saved pcap and pcapng files, reassembles IEC 104 traffic and reports a timeline or connection summaries in text or JSON lines.

- The optional `iec60870 decode` command reads IEC 101 and 104 hex from arguments or stdin and reports frame fields, byte ranges and JSON lines.

- Station events and request progress implement `Display`. Point output includes the full cause, quality flags and time tag when present. Protection events display all four typed states and retain reserved bits.

- ⚠ File downloads can be cancelled by request ID. Dropping an in-progress Tokio download queues file deactivation and releases the local selection.

- ⚠ Blocking, Tokio and sans-I/O stations can retrieve file contents. Outstations serve bounded segments, and clients verify section and file checksums before returning bytes.

- ⚠ With `file-transfer`, servers can answer station directory calls from a configured file store. Blocking and Tokio clients can list a station’s records with `files(common_address)`.

- Optional local file-record catalogs with bounded reads by common address, IOA and name of file. The filesystem adapter reads regular files relative to an opened directory.

- A generated PICS/PIXIT page with per-profile station probes, link and station defaults, TLS deviations and procedure evidence. The all-features suite checks the published page for drift.

- A standalone embedded IEC 104 point-table example, cross-compiled for Cortex-M4F and exercised by a host-side temperature read.

- A pinned Wireshark CI check compares fields for all 54 typed IEC 104 ASDUs, including packed status, protection events and file-transfer payloads.

- Conformance coverage by procedure, including gaps and independent peer evidence, in the documentation and CI job summary. CI checks the feature matrix, minimum Rust version, embedded builds, simulations, dependency policy, and fuzz targets.

- ⚠ Optional mutual TLS (port 19998) for IEC 104 clients and servers, with blocking and Tokio adapters, handshake events, and a loopback interrogation example.

- ⚠ The ASDU wire format, encode and decode, for every standard type identification with a
  typed form: 1–21, 30–40, 45–51, 58–64, 70, 100–107, 110–113 and the file-transfer types
  120–127. Private (128–255), security (41, 81–87, 90–95) and reserved types, and types the
  profile does not permit, decode to `Raw` with the header parsed and the body byte for byte.
- `Profile`: the cause-of-transmission, common-address and information-object-address widths
  (`CotWidth`, `CaWidth`, `IoaWidth`), the maximum ASDU length and the permitted `TypeSet`;
  `Profile::IEC104` (2/2/3 octets, 249) and `Profile::IEC101` (1/1/2 octets, 253), and `const`
  builders for vendor dialects.
- `Asdu::new(common_address, cot, objects)`: one expression builds a typed ASDU, its type
  identification inferred from the objects (`InformationObject::new(ioa, element).at(time)`).
  `Asdu::decode`, `Asdu::encode` into a caller's buffer (octets written, or the size needed;
  nothing written past the buffer or on any error), `Asdu::to_vec`, `AsduHeader::decode`.
- Decoding is panic-free and structural: `DecodeError` names the field, the octet offset and
  the information object; values (reserved bits, out-of-range qualifiers, a minute of 61) are
  kept as received. Encoding refuses what the profile cannot carry with an `EncodeError` that
  names the field.
- `types`: `TypeId` with the standard mnemonics, `Cause` and `Cot` (P/N, test, originator),
  `CommonAddress`, `Ioa`, the quality descriptors (`Quality`, `ProtectionQuality`,
  `SingleEvent`, `StartEvents`, `OutputCircuits`), `Normalized`, `BinaryCounterReading`, the
  commands (`SingleCommand`, `DoubleCommand`, `StepCommand` with select/execute and
  `CommandQualifier`), `SetpointQualifier`, `ParameterQualifier`, and every information element.
- `time`: `Cp56Time2a`, `Cp24Time2a`, `Cp16Time2a` kept as received with validity accessors and
  civil/Unix conversions (no time-zone logic); the monotonic `Instant` with saturating
  arithmetic; the `Clock` trait and the UTC `SystemClock` (`std`).
- `prelude`, readable `Debug` and one-line `Display` for ASDUs, `examples/asdu.rs`.
- Fuzz targets for the decoder under the 104, the 101 and arbitrary profiles, with crash inputs
  replayed by `tests/regressions.rs`; a Wireshark (`tshark`) oracle over every 104-permitted
  type.
- ⚠ IEC 60870-5-104 link (feature `cs104`, default): the APCI codec (`Apdu`, `Apci`,
  `UFunction`, `SeqNo`) — I, S and U frames, start `0x68`, length 4–253, the six U functions,
  decoded exactly and panic-free with a `FrameError` naming the reason — and an
  allocation-free `FrameSplitter` for partial reads.
- ⚠ `Cs104Link`, the sans-IO link of one TCP connection in either `Role`: numbers ASDUs
  modulo 32768, enforces `k` and `w`, runs t1/t2/t3, sends and answers STARTDT, STOPDT and
  TESTFR, and closes with a named `CloseReason` on every violation (`T1Expired`,
  `BadAcknowledgment`, `SequenceError`, `NotStarted`, `UnexpectedFrame`, `Malformed`, …).
  `submit` refuses with back-pressure (`SubmitError::WindowFull`) instead of dropping;
  `Event::Acknowledged { count }` reports confirmed I-frames. STOPDT with frames outstanding
  follows lib60870-C: acknowledge what was received, confirm only once everything sent is
  acknowledged. `Config` defaults k = 12, w = 8, t0 = 30 s, t1 = 15 s, t2 = 10 s, t3 = 20 s,
  checked by `Config::validate`.
- `driver`: the `Protocol` trait every sans-IO core implements (`handle_input`,
  `handle_timeout`, `handle_disconnect`, `poll_output`, `is_closed`) and `Output`; the
  `BlockingDriver` runner over any `Transport` (`TcpStream` included, `std`) and the
  cancel-safe `TokioDriver` over any `AsyncRead + AsyncWrite` (new feature `tokio`).
  `cs104::connect` / `accept` and `connect_async` / `accept_async` put a link on TCP.
- `examples/cs104_link.rs`; a 1000-seed deterministic simulation over a lossy, reordering,
  reconnecting network; a tshark oracle for every APCI frame type; fuzz targets `apci` and
  `cs104_link`; interop with lib60870-C in both roles (Docker, `IEC60870_REQUIRE_INTEROP=1`).
- ⚠ IEC 60870-5-101 link (feature `cs101`, `no_std` + `alloc`): FT 1.2 frames (`Frame` —
  the single character `0xE5`, the fixed `0x10 C A CS 0x16` and the variable
  `0x68 L L 0x68 C A data CS 0x16` frame; `Control` with PRM, FCB/FCV, ACD/DFC, DIR and both
  function tables; link addresses of 0, 1 or 2 octets and the broadcast address), decoded
  exactly and panic-free with a `FrameError` naming the reason, and an allocation-free
  `FrameSplitter` that takes the arrival time of each read: it drops a frame interrupted for
  longer than the inter-character timeout and, after any framing error, waits for line idle
  before it accepts a new frame.
- ⚠ `Cs101Link`, the sans-IO link of one serial line in one of three modes —
  `Cs101Link::primary` (unbalanced controlling station: resets each secondary, polls class 1
  and class 2 round-robin, class 1 at once on ACD, sends user data with confirmation, repeats
  a frame byte for byte with the same FCB, gives up after `retries` and re-resets after
  `reset_interval` without stalling the other secondaries, broadcasts with no reply),
  `Cs101Link::secondary` (unbalanced controlled station: class 1 and class 2 queues, ACD,
  DFC via `set_busy`, the stored response repeated on an unchanged FCB so a lost answer never
  executes a command twice, FC 14 before a reset, FC 15 for what it does not implement) and
  `Cs101Link::balanced` (both directions, DIR by `Role`, a two-wire echo discarded, the test
  function when idle). Every ASDU it accepts ends in `Event::Acknowledged`,
  `Event::Unconfirmed` (given up on, delivery unknown, never re-sent) or `Event::Closed`;
  `submit` refuses with `SubmitError::QueueFull`. Malformed and misaddressed frames are
  discarded and counted in `Stats`, never fatal. `Config` defaults: 1-octet address, response
  timeout 500 ms × 3 retries, poll interval 100 ms, reset interval 5 s, test interval 5 s,
  inter-character timeout 300 ms, idle gap 10 ms, single-character ACK on, 64 ASDUs per queue.
  `Cs101Link` implements `Protocol`, so `BlockingDriver` and `TokioDriver` run it over any
  byte stream; it implements `station::StationLink`, so `ControllingStation` and
  `ControlledStation` run over 101 (balanced, or unbalanced with class 1/2 queues) unchanged.
- Feature `serial`: `cs101::open_serial(path, baud_rate, link)` opens a port 8E1 through the
  `serialport` crate (no default features) and returns a `BlockingDriver`;
  `cs101::SerialTransport` makes any `serialport` port a `Transport`.
- `examples/cs101_link.rs`; a 1000-seed deterministic simulation of both modes over a lossy,
  bit-flipping, truncating, noisy byte stream with timing; a tshark (Decode As) oracle for
  every fixed and variable frame; fuzz targets `ft12` and `cs101_link`; interop with
  lib60870-C's 101 master and slave, balanced and unbalanced, over TCP-as-serial in Docker.
- ⚠ The stations (`station`, `no_std` + `alloc`): the application layer of both roles as
  sans-IO cores over the new `StationLink` trait, which `Cs104Link` implements (a 101 link
  plugs in the same way, with class 1/2 queues for unbalanced operation).
  - `ControlledStation`: a point `Database` keyed by common address and IOA (value, quality,
    time, spontaneous/cyclic/background transmission, interrogation group, counter group);
    `update(ca, ioa, value)` time-tags from the `Clock`; general, group (1–16) and counter
    interrogation (read, freeze, freeze with reset, reset) answered from current state with
    ACTCON and ACTTERM; read; clock synchronisation handed to the handler and applied as an
    offset to the station's clock; test command (107; 104 where the profile permits it);
    reset process; delay acquisition (where permitted); parameter loading and activation
    (110–113); commands of every type (45–51, 58–64) direct and select-before-operate, with the
    station enforcing the select → execute order, the select timeout (10 s) and matching
    connection, CA, IOA, type, originator and value before the `CommandHandler` is asked;
    negative confirmations with COT 44, 45, 46 and 47; end of initialisation (M_EI_NA_1)
    first after start.
  - Spontaneous events in a bounded buffer per redundancy group (1024 by default): kept until
    the master acknowledges them, re-sent first and in order after a reconnection; on overflow
    the oldest unsent event is dropped and `ServerEvent::EventsLost` reports how many.
  - Redundancy groups: several connections share one buffer, one is started at a time; when
    another starts, the old one is closed and its unacknowledged events are re-sent on the new
    one. Delivery is at-least-once: nothing is lost, and an event is repeated only if it was
    sent and not acknowledged before the switch-over or the cut.
  - `ControllingStation` (implements `driver::Protocol`): one method per procedure
    (`interrogate`, `counter_interrogate`, `read`, `clock_sync`, `command`,
    `select_and_execute`, `test_command`, `reset_process`, `parameter`, `send`); each returns a
    `RequestId` whose `Progress` (`Selected`, `Confirmed`, `Completed`, `Failed`) arrives as an
    event; a negative confirmation is `Error::Negative { cot }`, a missing confirmation or
    termination `Error::Timeout(Awaiting::…)`; every monitor ASDU becomes typed `Event::Point`s.
- `Client` and `Server` (blocking, `std` + `cs104`) and `AsyncClient` and `AsyncServer`
  (`tokio` + `cs104`) at the crate root: the ten-line client (`Client::connect`, `start`,
  `for event in client.interrogate(ca)?`), interrogations as iterators, commands as
  `CommandSteps`, a `ServerHandle` for updates from any thread (also from inside the command
  handler), redundancy groups by peer address (`Server::builder().group(…)`).
- `examples/client.rs`, `examples/server.rs` and `examples/sbo.rs`, each runnable without a
  network (they serve themselves on loopback when no address is given).
- Tests: every acceptance scenario of both roles, a 1000-seed simulation of reconnection and
  of redundancy switch-over with events in flight, the `controlled_station` fuzz target, a
  tshark oracle over every APDU the stations emit, and interop with lib60870-C in both roles
  (its client running every procedure against `Server`; `Client` against its server).
- The `tokio` feature now enables Tokio's `rt` and `sync` (the async server spawns tasks).
- `LinkEvent::Unconfirmed { class }`: a link that gave up on an ASDU (101 after its retries)
  says so, and the controlled station sends the events it carried again instead of counting
  them delivered; `Cs101Link`'s `StationLink` impl now maps its `Unconfirmed` to it.

### Changed

- Cause and value text has changed. Applications that parse station output should use typed fields. The wire encoding is unchanged.
