//! The client and server TLS configurations: one call from PEM, mutual authentication.

use std::fmt;
use std::io::Read;
use std::path::Path;
use std::string::{String, ToString};
use std::sync::Arc;
use std::vec::Vec;

use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedCipherSuite, SupportedProtocolVersion};

use super::error::{SecurityEvent, TlsError};

/// The protocol versions the crate's configurations offer: TLS 1.3 and TLS 1.2.
pub const PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13, &rustls::version::TLS12];

/// The cipher suites the crate's configurations offer, in preference order: the AEAD suites
/// of the IEC 62351-3 / 62351-4 lists that rustls implements.
pub const CIPHER_SUITES: &[SupportedCipherSuite] = &[
    ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
    ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/// The `ring` provider restricted to [`CIPHER_SUITES`].
fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider { cipher_suites: CIPHER_SUITES.to_vec(), ..ring::default_provider() })
}

pub(crate) type EventHook = Arc<dyn Fn(&SecurityEvent) + Send + Sync>;

/// One PEM input: a file or bytes, named for error messages.
struct Pem<'a> {
    bytes: std::borrow::Cow<'a, [u8]>,
    source: String,
}

impl Pem<'_> {
    fn file(path: &Path, what: &'static str) -> Result<Pem<'static>, TlsError> {
        const MAX_PEM_BYTES: u64 = 1024 * 1024;
        let source = path.display().to_string();
        let error = |reason: String| TlsError::Pem { what, source: source.clone(), reason };
        let meta = std::fs::metadata(path).map_err(|e| error(e.to_string()))?;
        if !meta.is_file() {
            return Err(error("expected a regular PEM file".into()));
        }
        if meta.len() > MAX_PEM_BYTES {
            return Err(error("PEM file exceeds 1 MiB".into()));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path).and_then(|f| f.take(MAX_PEM_BYTES + 1).read_to_end(&mut bytes)).map_err(|e| error(e.to_string()))?;
        if bytes.len() as u64 > MAX_PEM_BYTES {
            return Err(error("PEM file exceeds 1 MiB".into()));
        }
        Ok(Pem { bytes: bytes.into(), source })
    }

    fn memory(bytes: &[u8]) -> Pem<'_> {
        Pem { bytes: bytes.into(), source: "memory".into() }
    }

    fn error(&self, what: &'static str, reason: &(impl ToString + ?Sized)) -> TlsError {
        TlsError::Pem { what, source: self.source.clone(), reason: reason.to_string() }
    }

    fn pem_error(&self, what: &'static str, error: &rustls::pki_types::pem::Error) -> TlsError {
        use rustls::pki_types::pem::Error;
        // Parser diagnostics can include the original PEM line.
        self.error(
            what,
            match error {
                Error::MissingSectionEnd { .. } => "missing PEM end marker",
                Error::IllegalSectionStart { .. } => "invalid PEM start marker",
                Error::Base64Decode(_) => "invalid base64 data",
                Error::NoItemsFound => "no matching PEM section",
                _ => "invalid PEM data",
            },
        )
    }

    fn certificates(&self, what: &'static str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
        let certs = CertificateDer::pem_slice_iter(&self.bytes).collect::<Result<Vec<_>, _>>().map_err(|e| self.pem_error(what, &e))?;
        if certs.is_empty() {
            return Err(self.error(what, "no CERTIFICATE section"));
        }
        Ok(certs)
    }

    fn key(&self) -> Result<PrivateKeyDer<'static>, TlsError> {
        PrivateKeyDer::from_pem_slice(&self.bytes).map_err(|e| self.pem_error("private key", &e))
    }

    fn roots(&self) -> Result<Arc<RootCertStore>, TlsError> {
        let mut roots = RootCertStore::empty();
        for cert in self.certificates("trust anchors")? {
            roots.add(cert).map_err(|e| self.error("trust anchors", &e))?;
        }
        Ok(Arc::new(roots))
    }
}

/// The TLS configuration of a controlling station (client): the trust anchors that the
/// server's certificate must chain to, and the station's own certificate chain and key.
///
/// The server's certificate is verified against the trust anchors and against the name (or
/// IP address) the client dials, and the client presents its own certificate — mutual
/// authentication is the only mode. TLS 1.3 and 1.2 with the AEAD suites of
/// [`CIPHER_SUITES`]; the `ring` provider, passed to this configuration only.
///
/// ```no_run
/// use iec60870::tls::TlsClientConfig;
///
/// let tls = TlsClientConfig::from_pem_files("ca.pem", "master.pem", "master.key")?
///     .on_event(|event| println!("{event:?}"));
/// let mut link = iec60870::cs104::connect_tls("rtu1.example:19998", "rtu1.example", &tls, Default::default())?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct TlsClientConfig {
    pub(crate) config: Arc<ClientConfig>,
    pub(crate) on_event: Option<EventHook>,
}

impl TlsClientConfig {
    /// Reads the trust anchors (one or more CA certificates), the client's certificate chain
    /// (end-entity first) and its private key (PKCS#8, PKCS#1 or SEC1) from PEM files. Each input must be a regular file of at most 1 MiB.
    pub fn from_pem_files(ca: impl AsRef<Path>, cert: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<Self, TlsError> {
        Self::build(&Pem::file(ca.as_ref(), "trust anchors")?, &Pem::file(cert.as_ref(), "certificate chain")?, &Pem::file(key.as_ref(), "private key")?)
    }

    /// Like [`from_pem_files`](Self::from_pem_files), from PEM bytes.
    pub fn from_pem(ca: &[u8], cert: &[u8], key: &[u8]) -> Result<Self, TlsError> {
        Self::build(&Pem::memory(ca), &Pem::memory(cert), &Pem::memory(key))
    }

    fn build(ca: &Pem<'_>, cert: &Pem<'_>, key: &Pem<'_>) -> Result<Self, TlsError> {
        let config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(PROTOCOL_VERSIONS)
            .map_err(|e| TlsError::Config(e.to_string()))?
            .with_root_certificates(ca.roots()?)
            .with_client_auth_cert(cert.certificates("certificate chain")?, key.key()?)
            .map_err(|e| TlsError::Config(e.to_string()))?;
        Ok(Self::from_rustls(Arc::new(config)))
    }

    /// Uses a rustls configuration built by the application — for certificate pinning, CRLs,
    /// a hardware key or another crypto provider. The crate adds nothing to it.
    pub fn from_rustls(config: Arc<ClientConfig>) -> Self {
        TlsClientConfig { config, on_event: None }
    }

    /// Calls `f` with a [`SecurityEvent`] for every handshake, established or rejected.
    #[must_use]
    pub fn on_event(mut self, f: impl Fn(&SecurityEvent) + Send + Sync + 'static) -> Self {
        self.on_event = Some(Arc::new(f));
        self
    }

    /// The rustls configuration in use.
    pub fn rustls_config(&self) -> &Arc<ClientConfig> {
        &self.config
    }
}

impl fmt::Debug for TlsClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsClientConfig")
            .field("client_auth", &self.config.client_auth_cert_resolver.has_certs())
            .field("on_event", &self.on_event.is_some())
            .finish_non_exhaustive()
    }
}

/// The TLS configuration of a controlled station (server): the trust anchors that every
/// client's certificate must chain to, and the station's own certificate chain and key.
///
/// A client without a certificate, or with one that does not chain to the trust anchors, is
/// refused during the handshake, before any 104 frame. TLS 1.3 and 1.2 with the AEAD suites of
/// [`CIPHER_SUITES`]; the `ring` provider, passed to this configuration only.
///
/// ```no_run
/// use iec60870::tls::TlsServerConfig;
///
/// let tls = TlsServerConfig::from_pem_files("ca.pem", "rtu1.pem", "rtu1.key")?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone)]
pub struct TlsServerConfig {
    pub(crate) config: Arc<ServerConfig>,
    pub(crate) on_event: Option<EventHook>,
}

impl TlsServerConfig {
    /// Reads the trust anchors for client certificates, the server's certificate chain
    /// (end-entity first) and its private key from PEM files. Each input must be a regular file of at most 1 MiB.
    pub fn from_pem_files(ca: impl AsRef<Path>, cert: impl AsRef<Path>, key: impl AsRef<Path>) -> Result<Self, TlsError> {
        Self::build(&Pem::file(ca.as_ref(), "trust anchors")?, &Pem::file(cert.as_ref(), "certificate chain")?, &Pem::file(key.as_ref(), "private key")?)
    }

    /// Like [`from_pem_files`](Self::from_pem_files), from PEM bytes.
    pub fn from_pem(ca: &[u8], cert: &[u8], key: &[u8]) -> Result<Self, TlsError> {
        Self::build(&Pem::memory(ca), &Pem::memory(cert), &Pem::memory(key))
    }

    fn build(ca: &Pem<'_>, cert: &Pem<'_>, key: &Pem<'_>) -> Result<Self, TlsError> {
        let provider = provider();
        let verifier = WebPkiClientVerifier::builder_with_provider(ca.roots()?, Arc::clone(&provider)).build().map_err(|e| TlsError::Config(e.to_string()))?;
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(PROTOCOL_VERSIONS)
            .map_err(|e| TlsError::Config(e.to_string()))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(cert.certificates("certificate chain")?, key.key()?)
            .map_err(|e| TlsError::Config(e.to_string()))?;
        Ok(Self::from_rustls(Arc::new(config)))
    }

    /// Uses a rustls configuration built by the application. The crate adds nothing to it —
    /// in particular, whether client certificates are required is then that configuration's.
    pub fn from_rustls(config: Arc<ServerConfig>) -> Self {
        TlsServerConfig { config, on_event: None }
    }

    /// Calls `f` with a [`SecurityEvent`] for every handshake, established or rejected.
    #[must_use]
    pub fn on_event(mut self, f: impl Fn(&SecurityEvent) + Send + Sync + 'static) -> Self {
        self.on_event = Some(Arc::new(f));
        self
    }

    /// The rustls configuration in use.
    pub fn rustls_config(&self) -> &Arc<ServerConfig> {
        &self.config
    }
}

impl fmt::Debug for TlsServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsServerConfig").field("on_event", &self.on_event.is_some()).finish_non_exhaustive()
    }
}

pub(crate) fn emit(hook: Option<&EventHook>, event: impl FnOnce() -> SecurityEvent) {
    if let Some(hook) = hook {
        hook(&event());
    }
}
