/* TLS configuration shared by the two station interop peers. */
#include "tls_config.h"

static TLSConfiguration peer_tls(const char *cert, const char *key)
{
    const char *version = getenv("PEER_TLS_VERSION");
    TLSConfigVersion v = version && strcmp(version, "1.2") == 0 ? TLS_VERSION_TLS_1_2 : TLS_VERSION_TLS_1_3;
    TLSConfiguration cfg = TLSConfiguration_create();
    TLSConfiguration_setMinTlsVersion(cfg, v);
    TLSConfiguration_setMaxTlsVersion(cfg, v);
    const char *policy = getenv("PEER_TLS_POLICY");
    if (policy && strcmp(policy, "cbc") == 0) {
        TLSConfiguration_clearCipherSuiteList(cfg);
        TLSConfiguration_addCipherSuite(cfg, 0x003c); /* TLS_RSA_WITH_AES_128_CBC_SHA256 */
    }
    if (policy && strcmp(policy, "renegotiate") == 0)
        TLSConfiguration_setRenegotiationTime(cfg, 1000);
    /* The disposable identities use ECDSA P-256. */
    TLSConfiguration_setMinimumKeyLength(cfg, 256);
    TLSConfiguration_setChainValidation(cfg, true);
    TLSConfiguration_setAllowOnlyKnownCertificates(cfg, false);
    if (!TLSConfiguration_setOwnCertificateFromFile(cfg, cert) ||
        !TLSConfiguration_setOwnKeyFromFile(cfg, key, NULL) ||
        !TLSConfiguration_addCACertificateFromFile(cfg, "/pki/ca.pem"))
        exit(2);
    return cfg;
}
