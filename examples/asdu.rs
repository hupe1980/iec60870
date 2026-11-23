//! Build an ASDU in one expression, encode it for IEC 60870-5-104, decode it back, and show it.
//!
//! ```text
//! cargo run --example asdu
//! ```

use iec60870::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The time tag comes from a clock, never from the protocol's monotonic timers.
    let now = SystemClock.now();

    // An outstation reports two measured values spontaneously.
    let asdu = Asdu::new(
        CommonAddress(1),
        Cot::SPONTANEOUS,
        [
            InformationObject::new(Ioa(4001), MeasuredFloat::new(21.5)).at(now),
            InformationObject::new(Ioa(4002), MeasuredFloat::new(-3.25).with_quality(Quality::NOT_TOPICAL)).at(now),
        ],
    );

    let mut buf = [0u8; 249];
    let n = asdu.encode(&Profile::IEC104, &mut buf)?;
    let (octets, _) = buf.split_at(n);
    println!("encoded {n} octets: {octets:02x?}");

    // A master (or a sniffer) decodes and matches on the typed objects.
    let decoded = Asdu::decode(octets, &Profile::IEC104)?;
    println!("{decoded}");
    match &decoded.objects {
        Objects::MeasuredFloatCp56(objects) => {
            for o in objects {
                println!("  IOA {:>5} = {:>6} {:?} at {}", o.ioa, o.element.value, o.element.quality, o.time);
            }
        }
        other => println!("  {} objects of {}", other.len(), other.type_id()),
    }
    println!("{decoded:#?}");

    // The same bytes under a vendor dialect with a one-octet cause of transmission are refused
    // field by field, not misread.
    let dialect = Profile::IEC104.with_cot(CotWidth::One);
    match Asdu::decode(octets, &dialect) {
        Ok(a) => println!("as the dialect: {a}"),
        Err(e) => println!("as the dialect: {e}"),
    }
    Ok(())
}
