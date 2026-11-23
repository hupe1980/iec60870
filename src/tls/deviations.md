| Profile item | This crate | Instead |
|---|---|---|
| TLS 1.2 renegotiation for session-key refresh | not supported; a renegotiation request from the peer is refused with a `no_renegotiation` alert | a new connection with session resumption, or a TLS 1.3 key update (`TlsStream::refresh_keys`) |
| `TLS_RSA_WITH_AES_128_CBC_SHA256` (RSA key transport, CBC) | not offered | the ECDHE suites |
| `TLS_DHE_RSA_WITH_AES_128_GCM_SHA256` (finite-field DHE) | not offered | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` |
| TLS 1.3 `TLS_AES_128_CCM_SHA256`, `TLS_AES_128_CCM_8_SHA256` | not offered | `TLS_AES_128_GCM_SHA256` |
| TLS 1.1 and older | refused | TLS 1.2 or 1.3 |
| Certificate revocation lists | not loaded by the PEM constructors | a rustls verifier with CRLs through `from_rustls` |
