//! A read-only station for a board with a temperature sensor.
#![no_std]
#![forbid(unsafe_code)]

use iec60870::cs104::Cs104Link;
use iec60870::prelude::*;
use iec60870::station::{ConnectionId, ControlledStation, GroupId, ServerConfig};

/// Station address used by the board and by the offline read example.
pub const STATION: CommonAddress = CommonAddress(1);
/// Short floating-point measurement in degrees Celsius.
pub const TEMPERATURE: Ioa = Ioa(200);

/// Set up the point table and attach one controlled link for an accepted connection.
pub fn temperature_station(celsius: f32, clock: impl Clock + Send + 'static) -> (ControlledStation<Cs104Link>, ConnectionId) {
    let mut points = Database::new();
    points.insert(STATION, TEMPERATURE, celsius);
    let mut station = ControlledStation::new(points, ServerConfig::default(), clock);
    let connection = station.attach(Cs104Link::controlled(), GroupId(0));
    (station, connection)
}

/// Encode a read request for the same point into caller-owned storage.
pub fn encode_temperature_read(out: &mut [u8]) -> Result<usize, EncodeError> {
    Asdu::new(STATION, Cot::new(Cause::REQUEST), InformationObject::new(TEMPERATURE, Read)).encode(&Profile::IEC104, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iec60870::cs104::{Apci, Apdu, SeqNo, UFunction};
    use iec60870::station::{Output, RefuseCommands};

    #[test]
    fn reads_the_configured_temperature() {
        let now = Instant::ZERO;
        let (mut station, connection) = temperature_station(21.5, || Cp56Time2a::from_unix_millis(1_795_000_000_000).unwrap());
        let start = Apdu::u(UFunction::StartDtAct).to_vec().unwrap();
        station.handle_input(connection, &start, now, &mut RefuseCommands);
        while station.poll_output().is_some() {}

        let mut asdu = [0; 9];
        let n = encode_temperature_read(&mut asdu).unwrap();
        let read = Apdu::i(SeqNo::ZERO, SeqNo::ZERO, &asdu[..n]).to_vec().unwrap();
        station.handle_input(connection, &read, now, &mut RefuseCommands);
        while let Some(output) = station.poll_output() {
            let Output::Transmit { bytes, .. } = output else { continue };
            let frame = Apdu::decode(&bytes).unwrap();
            if matches!(frame.apci, Apci::I { .. }) {
                let response = Asdu::decode(frame.asdu, &Profile::IEC104).unwrap();
                assert_eq!(response.common_address, STATION);
                assert_eq!(response.cot.cause, Cause::REQUEST);
                let Objects::MeasuredFloat(points) = response.objects else { panic!("expected temperature") };
                assert_eq!(points.len(), 1);
                assert_eq!(points[0].ioa, TEMPERATURE);
                assert_eq!(points[0].element.value, 21.5);
                return;
            }
        }
        panic!("the station did not answer the read");
    }
}
