//! The blocking serial adapter (feature `serial`).

use std::boxed::Box;
use std::io::{self, Read, Write};
use std::time::Duration;

use super::link::Cs101Link;
use crate::driver::{BlockingDriver, Transport};

/// A serial port as a [`Transport`] for [`BlockingDriver`].
///
/// Any `serialport` port works; [`open_serial`] opens one with the FT 1.2 character format.
pub struct SerialTransport(pub Box<dyn serialport::SerialPort>);

impl core::fmt::Debug for SerialTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SerialTransport").field(&self.0.name()).finish()
    }
}

/// A read timeout long enough to stand for "block until data arrives".
const FOREVER: Duration = Duration::from_secs(3600);

impl Read for SerialTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for SerialTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    /// Does not wait for the line: written octets are already queued in the driver, and
    /// waiting for them to drain (`tcdrain`) never returns on some pseudo-terminals.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Transport for SerialTransport {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_timeout(timeout.unwrap_or(FOREVER)).map_err(io::Error::from)
    }
}

/// Opens the serial port at `path` with `baud_rate`, 8 data bits, even parity and one stop
/// bit — the FT 1.2 character format — and puts `link` on it under a [`BlockingDriver`].
///
/// ```no_run
/// use iec60870::cs101::{self, Config, Cs101Link, LinkAddress};
///
/// let link = Cs101Link::primary(&[LinkAddress(1)], Config::default())?;
/// let mut master = cs101::open_serial("/dev/ttyUSB0", 9600, link)?;
/// while let Some(event) = master.next_event()? {
///     println!("{event:?}");
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn open_serial(path: &str, baud_rate: u32, link: Cs101Link) -> io::Result<BlockingDriver<Cs101Link, SerialTransport>> {
    let port = serialport::new(path, baud_rate)
        .data_bits(serialport::DataBits::Eight)
        .parity(serialport::Parity::Even)
        .stop_bits(serialport::StopBits::One)
        .flow_control(serialport::FlowControl::None)
        .timeout(FOREVER)
        .open()
        .map_err(io::Error::from)?;
    Ok(BlockingDriver::new(link, SerialTransport(port)))
}
