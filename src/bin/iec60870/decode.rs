//! Frame selection and envelope decoding, using the library's wire codecs.
use super::{Decode, render::Record};
use iec60870::{
    Asdu,
    cs101::{Control, Frame, PrimaryFunction, SecondaryFunction},
    cs104::{Apci, Apdu},
};
use serde_json::json;
use std::{fmt::Write as _, io};

pub enum Failure {
    Input(String),
    Asdu(iec60870::asdu::DecodeError, usize),
    Output(io::Error),
}

#[allow(clippy::too_many_lines)]
pub fn frames(options: &Decode, mut bytes: &[u8], mut emit: impl FnMut(Record, &[u8]) -> io::Result<()>) -> Result<(), Failure> {
    let (profile, width) = options.widths();
    let mut in_apdus = false;
    while let Some(&start) = bytes.first() {
        let mut record = Record::new(options.explain);
        let mut consumed = bytes.len();
        let size = bytes.get(1).map_or(bytes.len(), |&l| usize::from(l) + 2);
        let first_apdu = bytes.get(..size).unwrap_or(bytes);
        let variable_link = start == 0x68
            && !in_apdus
            && if options.profile.profile == "101" {
                Frame::decode(bytes, width).is_ok() || Apdu::decode(first_apdu).is_err()
            } else {
                Apdu::decode(first_apdu).is_err() && Frame::decode(bytes, width).is_ok()
            };
        let ft = !options.asdu && !in_apdus && (matches!(start, 0xe5 | 0x10) || variable_link);
        let mut footer = false;
        let payload = if ft {
            let frame = Frame::decode(bytes, width).map_err(|e| Failure::Input(e.to_string()))?;
            record.meta.insert("format".into(), json!("FT1.2"));
            record.line = "FT1.2".into();
            match frame {
                Frame::SingleChar => {
                    record.line.push_str("    single-character acknowledgement");
                    record.field(1, "ack", "single-character acknowledgement");
                    None
                }
                Frame::Fixed { control, address } | Frame::Variable { control, address, .. } => {
                    let variable = matches!(frame, Frame::Variable { .. });
                    record.field(1, "start", "FT 1.2 frame start");
                    if variable {
                        record.field(1, "length", "user data length including link header");
                        record.field(1, "length", "repeated length");
                        record.field(1, "start", "repeated start");
                    }
                    let description = match control {
                        Control::Primary { function, .. } => format!("primary {function:?}"),
                        Control::Secondary { function, .. } => format!("secondary {function:?}"),
                    };
                    let _ = write!(record.line, "    {description}, address {}", address.0);
                    record.meta.insert("control".into(), json!(control.octet()));
                    record.meta.insert("address".into(), json!(address.0));
                    record.field(1, "control", description);
                    record.field(width.octets(), "address", address.to_string());
                    footer = true;
                    if let Frame::Variable { user_data, .. } = frame {
                        let carries_asdu = matches!(
                            control,
                            Control::Primary { function: PrimaryFunction::UserDataConfirmed | PrimaryFunction::UserDataNoReply, .. }
                                | Control::Secondary { function: SecondaryFunction::UserData, .. }
                        );
                        if carries_asdu {
                            Some(user_data)
                        } else {
                            record.raw(user_data);
                            None
                        }
                    } else {
                        None
                    }
                }
            }
        } else if !options.asdu && (start == 0x68 || in_apdus) {
            in_apdus = true;
            let apdu = Apdu::decode(first_apdu).map_err(|e| Failure::Input(e.to_string()))?;
            consumed = first_apdu.len();
            control(&mut record, &apdu, consumed);
            matches!(apdu.apci, Apci::I { .. }).then_some(apdu.asdu)
        } else {
            record.meta.insert("format".into(), json!("ASDU"));
            record.line = "ASDU".into();
            Some(bytes)
        };
        if let Some(payload) = payload {
            let asdu = Asdu::decode(payload, &profile).map_err(|e| {
                Failure::Asdu(
                    e,
                    if ft {
                        5 + width.octets()
                    } else if in_apdus {
                        6
                    } else {
                        0
                    },
                )
            })?;
            record.asdu(&asdu, &profile, payload, options.utc);
        }
        if footer {
            record.field(1, "checksum", "verified link checksum");
            record.field(1, "end", "FT 1.2 frame end");
        }
        let (frame, rest) = bytes.split_at(consumed);
        emit(record, frame).map_err(Failure::Output)?;
        bytes = rest;
    }
    Ok(())
}

pub fn control(record: &mut Record, apdu: &Apdu, size: usize) {
    record.field(1, "start", "APDU start");
    record.field(1, "length", format!("{} octets follow", size - 2));
    match apdu.apci {
        Apci::I { send, recv } => {
            record.meta.insert("format".into(), json!("I"));
            record.meta.insert("send".into(), json!(send.get()));
            record.meta.insert("recv".into(), json!(recv.get()));
            record.line = format!("I({send},{recv})");
        }
        Apci::S { recv } => {
            record.meta.insert("format".into(), json!("S"));
            record.meta.insert("recv".into(), json!(recv.get()));
            record.line = format!("S({recv})");
        }
        Apci::U(function) => {
            record.meta.insert("format".into(), json!("U"));
            record.meta.insert("function".into(), json!(function.to_string()));
            record.line = format!("U        {function}");
        }
    }
    record.field(4, "control", record.line.clone());
}
