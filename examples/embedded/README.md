# Read a temperature on bare metal

This standalone library registers one read-only temperature point at common address (station) 1, information object address (point) 200. It enables only the IEC 104 core. From the repository root, build it for a Cortex-M4F and exercise its read procedure on the host.

```sh
rustup target add thumbv7em-none-eabihf
cargo build --locked --manifest-path examples/embedded/Cargo.toml --target thumbv7em-none-eabihf
cargo test --locked --manifest-path examples/embedded/Cargo.toml
```

The test starts data transfer, encodes a read into a caller-owned buffer, feeds the frame to the controlled station and decodes its temperature reply.

## Connect it to firmware

Call `temperature_station(initial_celsius, clock)` when the board accepts a connection. Supply a wall clock returning CP56Time2a for event timestamps and a monotonic instant for the link timers. Feed received TCP bytes to `handle_input` with the connection ID and `RefuseCommands`. Drain `poll_output` after each input, timeout or update. Write transmit bytes in order, schedule the latest deadline with `handle_timeout`, and call `handle_disconnect` when TCP closes. Use `station.update(STATION, TEMPERATURE, reading)` for subsequent sensor samples.

The final firmware supplies the global allocator, panic handler, startup code and transport. The cross-build produces a Rust library. The host test exercises the protocol exchange in memory. [Rust target support](https://doc.rust-lang.org/rustc/platform-support/thumbv7em-none-eabi.html)
