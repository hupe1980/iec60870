//! A throw-away PKI for the TLS tests: a CA, a server certificate and a client certificate,
//! generated with rcgen at test time (nothing is committed).

#![allow(dead_code, clippy::unwrap_used, clippy::missing_panics_doc)]

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};

/// A certificate and its key, PEM.
pub struct Identity {
    pub cert: String,
    pub key: String,
}

/// A CA that issues identities.
pub struct Ca {
    pub cert: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    pub fn new(name: &str) -> Ca {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca { cert: cert.pem(), issuer: Issuer::new(params, key) }
    }

    /// An end-entity certificate with `names` as subjectAltNames (IP strings become IP SANs)
    /// and `cn` as common name, valid for client and server authentication.
    pub fn issue(&self, cn: &str, names: &[&str]) -> Identity {
        let mut params = CertificateParams::new(names.iter().map(|s| (*s).to_string()).collect::<Vec<_>>()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        params.distinguished_name.push(DnType::OrganizationName, "iec60870 tests");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        Identity { cert: cert.pem(), key: key.serialize_pem() }
    }
}

/// The usual set: one CA, the outstation `localhost`/127.0.0.1, the master, and a stranger
/// from another CA.
pub struct Pki {
    pub ca: Ca,
    pub server: Identity,
    pub client: Identity,
    pub other_ca: Ca,
    pub stranger: Identity,
}

impl Pki {
    pub fn new() -> Pki {
        let ca = Ca::new("iec60870 test CA");
        let server = ca.issue("rtu-1", &["localhost", "127.0.0.1"]);
        let client = ca.issue("master-1", &["master-1.example"]);
        let other_ca = Ca::new("another CA");
        let stranger = other_ca.issue("intruder", &["localhost", "127.0.0.1"]);
        Pki { ca, server, client, other_ca, stranger }
    }
}
