+++
title = "Command-line tools"
description = "Decode frames, inspect captures and query a simulated or live IEC 104 station."
weight = 2
+++

## Install the CLI

For Apple Silicon Macs and Linux (x86-64 or ARM64), install the prebuilt CLI with Homebrew:

```sh
brew install hupe1980/tap/iec60870
```

The formula includes TLS and serial monitoring. To build the same CLI from crates.io, run `cargo install --locked iec60870 --features cli,tls,serial`.

## Decode a frame

```sh
iec60870 decode 68:04:07:00:00:00
```

```text
U        STARTDT act
```

The U-format control frame requests the start of data transfer. For a frame that carries station data, use `--explain` to locate each field. The first command below shows a general interrogation for common address 1.

```sh
iec60870 decode --explain 680e0000000064010600010000000014
iec60870 decode --profile 101 e5
iec60870 decode --asdu 64010600010000000014
printf '680407000000\n68040b000000\n' | iec60870 --json decode -
```

Supply hex as arguments or use `-` (or omit the argument) for one record per stdin
line. Whitespace, colon, hyphen, comma and per-token `0x` prefixes are accepted;
`#` starts a comment. Blank lines are ignored. Records are limited to 65,536 input
bytes excluding the line ending. Oversized and invalid lines report errors, and
processing continues. Concatenated 104 APDUs are reported individually.

The default profile is 104; `--profile 101` selects 101 defaults. Use `--cot`,
`--ca`, `--ioa` and `--link-addr` to override field widths (respectively 1–2,
1–2, 1–3 and 0–2 octets). `--asdu` forces bare ASDU interpretation. `--explain`
shows ordered byte offsets and fields; sequential object addresses can be derived
without corresponding address bytes. `--help` describes all options.

`--json` emits one JSON object per frame or failed record, with `kind` equal to
`frame` or `error` and a 1-based `input` number. Frames include `octets`, `format`,
control fields and, when present, `asdu` with typed addresses, values, quality
arrays and object metadata. Explanations appear in `explain`; unknown data is
hex in `raw`. Station clock readings appear in `time_text`. If the station clock runs on UTC, pass `--utc` to also emit an RFC 3339 `time` for valid CP56 timestamps.
Keys may be added; existing keys and types are stable within the release series.
Diagnostics go to stderr. Exit status is 0 for success, 1 for input or runtime
failure, and 2 for usage errors.

### Option reference

| Command | Options | Purpose |
|---|---|---|
| All | `--json`, `--color auto\|always\|never` | Emit JSON lines or control color in human output. |
| `decode` | `--explain`, `--asdu`, `--profile`, `--link-addr` | Annotate bytes, force bare ASDU decoding or select framing. |
| `decode`, `pcap` | `--cot`, `--ca`, `--ioa` | Set the encoded field widths in octets. |
| `decode`, `pcap`, `client` | `--utc` | Interpret valid CP56 station timestamps as UTC in JSON. |
| `pcap` | `--port`, `--summary`, `--profile` | Choose server ports, show totals or select ASDU defaults. |
| `client` | `--ca`, `--timeout`, `--ca-width`, `--cot`, `--ioa`, `--profile` | Address a station, bound procedure waits or configure field widths. |
| `client` | `--tls CA CERT KEY`, `--tls-server-name NAME` | Configure mutual TLS and the expected station identity. |
| `client get` | `--output PATH`, `--max-bytes N` | Save a verified record to a new file and limit its size. |
| `sim` | `--demo` or `--points FILE` | Choose the initial process image. |
| `sim` | `--check`, `--preview IOA KIND VALUE` | Validate the image or predict one command offline. |
| `sim` | `--bind`, `--seed` | Select a listening socket or reproduce simulated point changes. |

## Follow a captured connection

Read a local classic pcap or pcapng file. The timeline shows which direction each frame traveled, its control fields and decoded ASDU. Connection summaries count I, S and U frames, ASDU types, sequence gaps, skipped octets and decode errors.

```sh
iec60870 pcap session.pcapng
iec60870 pcap session.pcap --summary
iec60870 --json pcap session.pcapng --port 2404 --port 12404
```

The default server port is 2404. Supplying ports replaces the default. Use `--cot`, `--ca` and `--ioa` when the capture uses custom address widths. JSON lines carry `kind` values of `apdu`, `connection` and `capture`. Add `--summary` to omit individual frames. For example, a checked capture with 105 packets reports `0 N(S) gaps, 0 TCP gaps, 0 skipped octets, 0 decode errors`. Capture totals count all packets in the file.

The outer record’s `t` is elapsed capture time in seconds from the first timestamped packet. Inside decoded objects, `time_text` is the station reading. Pass `--utc` only when the source stations use UTC. This adds an RFC 3339 `time` to valid CP56 objects. A frame is timestamped when enough data becomes available to decode it. Simple packet blocks have no timestamp and appear as `null` in JSON. Retransmissions contribute only fresh bytes. When a gap persists to the queue limit, connection close or end of file, decoding resumes at the next recognizable frame. A missing STARTDT confirmation can indicate that recording began after the session started.

Files are limited to 512 MiB, packets to 256 KiB, sessions to 1,024 and queued segments to 64 per direction. The final record counts fragments, truncated packets, unsupported link types and packets excluded by the session limit (`dropped_connection_packets`). IP fragments are skipped. Endpoints are displayed numerically and inspection operates entirely on the local file.

## Validate a simulator point file

From a source checkout, validate the example file with the following command.

```sh
cargo run --locked --features cli -- sim --check --points examples/demo-bay.toml
```

An installed binary also includes the demo. Run `iec60870 --json sim --check --demo` to get its validation summary.

```json
{"kind":"validation","stations":1,"points":15,"commands":5}
```

A point file is UTF-8 TOML, up to 1 MiB. Each station has a unique common address (0–65534). Monitored points and commands each have their own IOA table (0–16777215). A command’s optional `status` refers to a compatible monitored point in the same station, including one declared later in the file.

```toml
[[station]]
ca = 1

[[station.point]]
ioa = 100
kind = "single"
value = true
group = 1
time = "cp56"

[[station.command]]
ioa = 5000
kind = "single"
status = 100
mode = "sbo"
accept = true
```

| Point kind | Accepted initial value |
|---|---|
| `single` | Boolean |
| `double` | `"on"`, `"off"`, `"intermediate"`, `"indeterminate"` |
| `step`, `scaled`, `counter` | Whole number in the signed 7-, 16- or 32-bit range respectively |
| `bitstring` | Unsigned 32-bit TOML integer |
| `normalized` | Number from −1 through 1 |
| `float` | Number within the finite 32-bit float range |

Point groups range from 1 to 16. Counter groups range from 1 to 4. Time settings are `"none"` and `"cp56"`. Numeric points can declare a walk, for example `walk = { step = 0.5, min = 220, max = 240, every = "1s" }` on a float initially set to 230. Bounds must include the initial value. Use a positive integer duration in milliseconds (`ms`), seconds (`s` or bare), or minutes (`m`). Integer-valued points take whole-number steps.

Command kinds are `single`, `double`, `step`, `scaled`, `normalized`, `setpoint` (float status) and `bits` (bitstring status). Modes are `sbo`, `direct` and `both`. Validation is offline. A bad file exits with status 1 and a diagnostic on stderr. Invalid CLI arguments exit with status 2.

## Serve a simulated station

Start the demo on loopback. The first line prints the actual listening address and the number of configured points. Use Ctrl-C to stop.

```sh
iec60870 sim --demo
iec60870 --json sim --points examples/demo-bay.toml --bind 127.0.0.1:0 --seed 42
```

The default address is `127.0.0.1:2404`. Port `0` asks the operating system for an available port. With an explicit non-loopback address, the startup record flags network exposure. Configuration errors are reported before binding. [Rust listener documentation](https://doc.rust-lang.org/std/net/struct.TcpListener.html#method.bind)

The demo has 15 monitored points. General interrogation returns 14 of them. The energy counter at IOA 4100 is available through counter interrogation. An accepted execute updates its linked status point. Selecting a command leaves the status unchanged. The demo tap changer clamps feedback to positions 1 through 19 using `step_range = [1, 19]` on its step command. Numeric walks follow per-point sequences. Reuse a seed to reproduce the sequence of values for each point.

JSON output begins with a `listening` record. `connection`, `command` and `clock` records include the originating socket address. A command record includes its phase, decision, CA and IOA. A `closed` record retains its peer address after disconnection. `events_lost` counts dropped station data events in a redundancy group. `log_gap` reports how many notifications a slow log reader missed from the server's 1,024-entry queue.

## Preview a simulator command offline

To check how a configured point will respond, run:

```sh
iec60870 sim --demo --preview 5002 step up
# Preview CA 1 IOA 5002 step Higher (sbo): accepted, status IOA 110: step 5 → step 6
```

Use `--points FILE` for your own TOML image and `--ca N` to select a station (default 1). Each invocation starts from the file’s initial values. It opens no socket and writes no changes. Address 65535 is reserved for broadcast and cannot identify a simulator station.

| Command kind | Accepted value |
|---|---|
| `single`, `double` | `on` or `off` |
| `step` | `up` or `down` |
| `setpoint` | Finite 32-bit floating-point value |
| `normalized` | A number from −1 through 1 |
| `scaled` | An integer from −32768 through 32767 |
| `bits` | Unsigned 32-bit integer in decimal or with a `0x` hexadecimal prefix |

The preview evaluates select-before-operate by default. Use `--direct` to evaluate direct mode. Bitstring commands always use direct mode. Both predicted decisions exit with status 0. For scripts, read the `decision` field of the single `--json` record. A refusal includes a `reason`. An accepted command with linked status includes the status IOA and its `before` and `after` values in `feedback`. Invalid arguments exit with status 2 and invalid TOML exits with status 1.

## Read and watch a station

Start `iec60870 sim --demo` in one terminal. In another, run `gi` to list the 14 monitored points or `ci` to read the energy counter at IOA 4100.

```sh
iec60870 client 127.0.0.1 gi
iec60870 client 127.0.0.1 ci
iec60870 client 127.0.0.1 read 110
iec60870 --json client 127.0.0.1 watch --for 5s
```

The target accepts a hostname, IPv4 address or bracketed IPv6 address with an optional port. The default port is 2404 for plain TCP and 19998 for mutual TLS. Use `--ca` for the station common address (default 1) and `--ca-width` for its encoded width. `--profile`, `--cot` and `--ioa` select the other ASDU decoding settings.

`gi --group 1` requests one interrogation group (1–16). `ci --group 1` reads one counter group (1–4). For a broadcast GI or CI, each responding station sends its own termination. The CLI collects additional replies for one `--timeout` window after the first termination. A specific common address returns as soon as its reply completes. JSON queries emit one `point` record per value followed by a `done` record with the action, count and elapsed seconds. For a tagged point, `time_text` preserves the station clock reading and its flags. With `client HOST --utc`, valid CP56 readings also have an RFC 3339 `time` ending in `Z`. Untagged points omit both fields. Partial CP24 dates and invalid CP56 readings retain only `time_text`.

`watch` starts with a general interrogation. Use `--no-gi` for subsequent changes only. The selected common address filters point updates, including spontaneous changes. To watch every station on the connection, use the broadcast address for the configured width (65535 for two octets, 255 for one). A terminal shows a sorted, height-limited table with per-point update counts and recently updated points highlighted. The footer shows the average update rate and the latest link or procedure event. A pipe or `--json` streams one record at a time. The display retains up to 65,536 addresses and counts additional observations. Use `LINES` and `COLUMNS` to set display dimensions when needed.

`--timeout` bounds connection and protocol waits. Its default is 10 seconds, and the link supports up to 255 seconds. A negative station reply exits with status 3. Connection failure, timeout or disconnection exits with status 4. Invalid arguments exit with status 2.

## List and download station files

List the directory first. Each entry identifies a record by common address, IOA and numeric file name. Use the IOA and name from the listing to retrieve that record:

```sh
iec60870 --json client rtu.example --ca 1 files
iec60870 client rtu.example --ca 1 get 30000 2 --output disturbance.bin --max-bytes 1048576
```

Both actions use a single station address and support the same TLS options as point queries. Name `0` requests the station’s default record at that IOA. The directory supports up to 4096 entries. In JSON mode it emits one `file` record per entry with `ca`, `ioa`, `name`, `bytes`, the raw status octet, and the station creation timestamp. A final `done` record gives the entry count, including zero for an empty directory.

`get` checks the peer’s announced length against `--max-bytes` (default 16,777,215) and verifies section and file checksums. The output directory must already exist and allow temporary files. The CLI checks this before connecting. It saves the verified bytes under the path you chose and preserves existing files. A successful JSON receipt includes `action=get`, the addresses, `requested_name`, `bytes` and `output`. Binary data goes only to the file.

A refused selection exits 3. Oversized, malformed or aborted transfers and local save errors exit 1. A connection failure or timeout exits 4. Pick a fresh destination for a retry.

## Read a station over mutual TLS

Supply the paths to your trust anchors, client certificate chain and private key.

```sh
iec60870 --json client rtu.example --tls ca.pem operator.pem operator.key read 200
```

The TLS default port is 19998. An explicit port takes precedence. The client verifies the certificate against the hostname or IP address you entered. When dialing an IP for a certificate issued to a DNS name, supply that expected identity with `--tls-server-name`:

```sh
iec60870 client 192.0.2.10:19998 --tls ca.pem operator.pem operator.key --tls-server-name rtu.example gi
```

Each PEM input must be a regular file of at most 1 MiB. The client reads credentials before connecting. Invalid or unreadable credentials exit with status 1. Incomplete options or a build missing the TLS feature exit with status 2. A failed handshake or certificate check exits with status 4. The client never retries in plaintext. Point records and exit codes for station replies use the same format as a plain connection.

## Synchronize a station clock

Start the demo with `iec60870 sim --demo`, then run:

```sh
iec60870 client 127.0.0.1 --ca 1 clock
# CA 1 confirmed UTC clock synchronization
```

The client samples the host's UTC wall clock and waits for the addressed station to confirm the request. Use this with stations configured for UTC. The simulator applies the offset to its own time tags. Its host clock stays unchanged.

With `--json`, success produces one record, for example `{"kind":"done","action":"clock","ca":1,"seconds":0.002}`. A broadcast address exits with status 2 before connecting. A negative station reply exits with status 3. A connection or confirmation timeout exits with status 4.

## Capture from an interface

`pcap -` reads a finite binary pcap or pcapng stream. It produces the timeline at end of input and applies the same 512 MiB limit as a saved capture. Use an installed capture tool to select a local interface for which your account has capture permission. `dumpcap -D` lists available interfaces. For example, capture five seconds from a local simulator on macOS with the command below. Use `lo` on Linux.

```sh
dumpcap -p -i lo0 -f 'tcp port 2404' -a duration:5 -w - | iec60870 --json pcap -
```

Dumpcap reports capture statistics and any available kernel drop counts on stderr. The CLI reports TCP gaps, truncated packets and packets discarded at its connection limit. Capture loss can precede the decoder. A zero decoder count alone cannot establish lossless capture. In scripts, enable the shell’s pipeline failure reporting to catch capture permission errors. [Dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html)

## Monitor a serial tap

Connect a receive-only tap to a line already carrying IEC 101 traffic. The monitor emits observed frames as they arrive. It uses eight data bits, one stop bit, even parity and 9600 baud by default.

```sh
iec60870 --json serial-monitor /dev/ttyUSB0 --baud 19200 --parity even --link-addr 2
iec60870 --json serial-monitor - < frames.ft12
```

Set `--cot`, `--ca` and `--ioa` to the ASDU field widths for the line. `--link-addr` selects zero, one or two link-address octets. macOS pseudo-terminals use `--baud 0`. Binary stdin also works in a CLI-only build. Bad frames produce a diagnostic and a failed exit status. Clean pipe EOF succeeds, a partial frame at EOF fails, and device disconnection ends the monitor with an error. A serial adapter can only report the bytes and arrival timing exposed by its driver.
