/**
 * TLSVerifier.cpp — OpenSSL handshake + certificate inspection.
 *
 * Opens a TCP socket via NetworkUtils, wraps it in an OpenSSL SSL*,
 * runs TLS with SNI and peer verification, then reads the leaf cert's
 * subject CN and notAfter. Always returns a populated VerifyResult —
 * failures surface through `valid=false` and a one-line `error`, so the
 * UI can show a red badge instead of crashing or blocking.
 */

#include "TLSVerifier.hpp"
#include "NetworkUtils.hpp"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <memory>
#include <mutex>

#ifdef _WIN32
// windows.h must precede wincrypt.h. Undef the X509_NAME macro Windows defines,
// which collides with OpenSSL's X509_NAME typedef.
#include <windows.h>
#include <wincrypt.h>
#ifdef X509_NAME
#undef X509_NAME
#endif
#endif

namespace {

void ensureOpenSSL()
{
    static std::once_flag once;
    std::call_once(once, [] {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    });
}

std::string asn1TimeToString(const ASN1_TIME* t)
{
    if (!t) return {};
    tm tmv{};
    if (ASN1_TIME_to_tm(t, &tmv) != 1) return {};
    char buf[32] = {0};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tmv);
    return buf;
}

std::string extractCN(X509* cert)
{
    if (!cert) return {};
    X509_NAME* subj = X509_get_subject_name(cert);
    if (!subj) return {};

    char buf[256] = {0};
    if (X509_NAME_get_text_by_NID(subj, NID_commonName, buf, sizeof(buf)) <= 0) {
        return {};
    }
    return buf;
}

#ifdef _WIN32
// Load Windows root CAs into the OpenSSL trust store. SSL_CTX_set_default_verify_paths
// looks at OpenSSL's compiled-in path, which on Windows builds is typically empty —
// without this, no public CAs are trusted and every handshake fails verification.
void loadWindowsRootCerts(SSL_CTX* ctx)
{
    X509_STORE* store = SSL_CTX_get_cert_store(ctx);
    if (!store) return;

    for (const char* storeName : {"ROOT", "CA"}) {
        HCERTSTORE hStore = CertOpenSystemStoreA(0, storeName);
        if (!hStore) continue;

        PCCERT_CONTEXT pCtx = nullptr;
        while ((pCtx = CertEnumCertificatesInStore(hStore, pCtx)) != nullptr) {
            const unsigned char* encoded = pCtx->pbCertEncoded;
            X509* x509 = d2i_X509(nullptr, &encoded, static_cast<long>(pCtx->cbCertEncoded));
            if (x509) {
                X509_STORE_add_cert(store, x509);
                X509_free(x509);
            }
        }
        CertCloseStore(hStore, 0);
    }
}
#endif

#ifdef __APPLE__
// On macOS, OpenSSL builds (Homebrew, MacPorts) don't ship a bundled CA store
// and the system keychain isn't directly readable by OpenSSL. /etc/ssl/cert.pem
// is the curl-maintained bundle present on every supported macOS, so point the
// trust store at it explicitly.
void loadMacRootCerts(SSL_CTX* ctx)
{
    SSL_CTX_load_verify_locations(ctx, "/etc/ssl/cert.pem", nullptr);
}
#endif

} // namespace

TLSVerifier::VerifyResult TLSVerifier::verify(const std::string& hostname, uint16_t port)
{
    VerifyResult res;
    ensureOpenSSL();
    NetworkUtils::initialize();

    const socket_t fd = NetworkUtils::tcpConnect(hostname, port);
    if (fd == NetworkUtils::invalidSocket()) {
        res.error = "TCP connect failed";
        return res;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        NetworkUtils::closeSocket(fd);
        res.error = "SSL_CTX_new failed";
        return res;
    }
    // Hardening: TLS 1.2 floor, peer verification with the platform default CAs.
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx);
#ifdef _WIN32
    loadWindowsRootCerts(ctx);
#endif
#ifdef __APPLE__
    loadMacRootCerts(ctx);
#endif

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        NetworkUtils::closeSocket(fd);
        res.error = "SSL_new failed";
        return res;
    }

    // SNI — many shared-IP hosts (including TLS terminators) refuse
    // handshakes without it.
    SSL_set_tlsext_host_name(ssl, hostname.c_str());
    // Bind hostname into hostname-verification, on top of chain validation.
    SSL_set1_host(ssl, hostname.c_str());
    SSL_set_fd(ssl, static_cast<int>(fd));

    if (SSL_connect(ssl) != 1) {
        res.error = "TLS handshake failed";
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        NetworkUtils::closeSocket(fd);
        return res;
    }

    const long verifyCode = SSL_get_verify_result(ssl);
    X509* peer = SSL_get_peer_certificate(ssl);

    if (peer) {
        res.commonName = extractCN(peer);
        res.expiryDate = asn1TimeToString(X509_get0_notAfter(peer));
    }

    if (verifyCode != X509_V_OK) {
        res.error = X509_verify_cert_error_string(verifyCode);
    } else if (!peer) {
        res.error = "no peer certificate";
    } else {
        // Check expiry too — a chain may technically validate moments before
        // notAfter, but we want to warn the user.
        if (X509_cmp_current_time(X509_get0_notAfter(peer)) <= 0) {
            res.error = "certificate has expired";
        } else {
            res.valid = true;
        }
    }

    if (peer) X509_free(peer);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    NetworkUtils::closeSocket(fd);
    return res;
}
