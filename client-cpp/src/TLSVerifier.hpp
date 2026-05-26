#pragma once

/**
 * TLSVerifier.hpp — OpenSSL-driven TLS server certificate verifier.
 *
 * Standalone of libcurl: opens a raw TCP socket, wraps it in an OpenSSL
 * SSL*, runs the handshake with peer-cert verification and SNI, and
 * reports back what it found. The UI calls this once at startup to
 * display a padlock indicator that is independent of libcurl's own TLS
 * stack — a cross-check that the server certificate validates under the
 * platform's default CA bundle.
 */

#include <cstdint>
#include <string>

class TLSVerifier
{
public:
    struct VerifyResult
    {
        bool        valid = false;       ///< true iff X509_V_OK and cert is in-date
        std::string error;               ///< Empty when valid; one-line summary otherwise
        std::string commonName;          ///< Subject CN of the peer cert
        std::string expiryDate;          ///< notAfter as "YYYY-MM-DD HH:MM:SS UTC"
    };

    /**
     * Perform a full TLS handshake against (`hostname`, `port`), validate
     * the peer certificate chain, extract the leaf cert's CN and expiry,
     * tear down the connection, and return what was observed. Never
     * throws — returns a VerifyResult with `valid=false` and a populated
     * `error` on any failure (DNS, connect, handshake, validation).
     */
    static VerifyResult verify(const std::string& hostname, uint16_t port = 443);
};
