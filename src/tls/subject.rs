//! The subject of an X.509 certificate as a log string ("CN=master-1, O=Grid"), by a minimal
//! DER walk — panic-free, for logging only (the chain was verified by rustls before).

use std::string::{String, ToString};
use std::vec::Vec;

/// One DER element: (tag, contents), and the rest of the input.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = rest.get(..n)?;
        let len = bytes.iter().fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, rest.get(n..)?)
    };
    Some((tag, rest.get(..len)?, rest.get(len..)?))
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;

fn short_name(oid: &[u8]) -> Option<&'static str> {
    Some(match oid {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x0A] => "O",
        [0x55, 0x04, 0x0B] => "OU",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xF2, 0x2C, 0x64, 0x01, 0x19] => "DC",
        _ => return None,
    })
}

fn dotted(oid: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    for &b in oid {
        value = (value << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = (value / 40).min(2);
                parts.push(first);
                parts.push(value - first * 40);
            } else {
                parts.push(value);
            }
            value = 0;
        }
    }
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// The subject distinguished name of a DER certificate, or `None` when it cannot be read.
pub(crate) fn subject(cert: &[u8]) -> Option<String> {
    let (tag, certificate, _) = tlv(cert)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, tbs, _) = tlv(certificate)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs;
    // [0] version (optional), serialNumber, signature, issuer, validity, subject.
    let (tag, _, after) = tlv(rest)?;
    if tag == 0xA0 {
        rest = after;
    }
    for _ in 0..4 {
        let (_, _, after) = tlv(rest)?;
        rest = after;
    }
    let (tag, mut name, _) = tlv(rest)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut out: Vec<String> = Vec::new();
    while !name.is_empty() {
        let (tag, mut set, after) = tlv(name)?;
        name = after;
        if tag != SET {
            return None;
        }
        while !set.is_empty() {
            let (tag, attr, after) = tlv(set)?;
            set = after;
            if tag != SEQUENCE {
                return None;
            }
            let (tag, oid, value) = tlv(attr)?;
            if tag != OID {
                return None;
            }
            let (_, value, _) = tlv(value)?;
            let key = short_name(oid).map_or_else(|| dotted(oid), String::from);
            out.push(std::format!("{key}={}", String::from_utf8_lossy(value)));
        }
    }
    Some(out.join(", "))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn reads_the_subject_of_a_generated_certificate() {
        let mut params = rcgen::CertificateParams::new(std::vec!["rtu1.example".into()]).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "master-1");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Grid");
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let s = subject(cert.der()).unwrap();
        assert!(s.contains("CN=master-1") && s.contains("O=Grid"), "{s}");
        for n in 0..cert.der().len() {
            let _ = subject(&cert.der()[..n]);
        }
        assert_eq!(subject(&[]), None);
        assert_eq!(subject(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]), None);
    }

    #[test]
    fn unknown_attributes_print_as_dotted_oids() {
        assert_eq!(dotted(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]), "1.2.840.113549");
    }
}
