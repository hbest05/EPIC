#pragma once

/**
 * CryptoDaemonClient.hpp — Synchronous JSON-over-TCP client for the
 * SecureMsg Python crypto daemon.
 *
 * The daemon owns every private key and performs every cryptographic
 * operation; this class is the only path the C++ UI uses to invoke it.
 * Each public method sends one newline-delimited JSON request, blocks
 * until the matching response arrives, and either returns a parsed
 * result or throws a CryptoDaemonError on a non-ok status. The daemon
 * processes requests in order over a single TCP connection on
 * 127.0.0.1:DAEMON_PORT (default 47291) — see crypto-daemon/README.md for
 * the wire protocol. DAEMON_PORT is set at build time via the CMake cache
 * variable of the same name; pass -DDAEMON_PORT=<n> to bind a second exe
 * to a second daemon for running two clients on one host.
 */

#include <QtCore/QByteArray>
#include <QtCore/QJsonObject>
#include <QtCore/QList>
#include <QtCore/QString>
#include <stdexcept>
#include <cstdint>
#include <memory>

#ifndef DAEMON_PORT
#  define DAEMON_PORT 47291
#endif

class QTcpSocket;

/** Thrown when the daemon returns status != "ok" or the transport fails. */
class CryptoDaemonError : public std::runtime_error
{
public:
    CryptoDaemonError(QString code, QString msg)
        : std::runtime_error(msg.toStdString())
        , m_code(std::move(code))
        , m_message(std::move(msg))
    {
    }

    /** Stable error code string from the daemon (e.g. "bad_passphrase"). */
    const QString& code() const { return m_code; }
    /** Human-readable error message — safe to surface in the UI. */
    const QString& message() const { return m_message; }

private:
    QString m_code;
    QString m_message;
};

/** Result of generate_prekeys — public halves only; the daemon keeps the privates. */
struct PrekeyBundle
{
    QByteArray spkPub;            ///< Signed prekey public (raw 32 bytes)
    QByteArray spkSig;            ///< Ed25519 signature over spkPub (raw 64 bytes)
    QList<QByteArray> opks;       ///< One-time prekey publics (raw 32 bytes each)
};

/** Bob's bundle as fetched from /auth/user/<username>/keybundle. */
struct PeerKeyBundle
{
    QByteArray ikPub;             ///< Long-term X25519 IK
    QByteArray signPub;           ///< Long-term Ed25519 signing key
    QByteArray spkPub;
    QByteArray spkSig;
    QByteArray opkPub;            ///< Empty if no OPK was issued
};

/** Result of x3dh_send — header fields go on the wire alongside the first ciphertext. */
struct X3dhSendResult
{
    QString    sessionId;         ///< Hex string returned by the daemon
    QByteArray ikPub;             ///< Sender IK (for the X3DH header on the wire)
    QByteArray ekPub;             ///< Sender ephemeral
    QByteArray usedOpkPub;        ///< Empty if no OPK was consumed
    QByteArray ciphertext;
    QByteArray nonce;
    QByteArray ratchetPub;        ///< Double Ratchet header
    int        pn = 0;
    int        n  = 0;
    QByteArray aad;               ///< Diagnostic only — server doesn't need it
};

/** Result of encrypt_message — Double Ratchet header to ship with the ciphertext. */
struct EncryptedMessage
{
    QByteArray ciphertext;
    QByteArray nonce;
    QByteArray ratchetPub;
    int        pn = 0;
    int        n  = 0;
    QByteArray aad;
};

/** Fields a recipient pulls from the wire and hands to decryptMessage. */
struct EncryptedMessageFields
{
    QByteArray ciphertext;
    QByteArray nonce;
    QByteArray ratchetPub;
    int        pn = 0;
    int        n  = 0;
};

/** X3DH initiator header that travels on the first message of a new session. */
struct X3dhInboundHeader
{
    QByteArray ikA;
    QByteArray ekA;
    QByteArray usedOpkPub;        ///< Empty when sender did not consume an OPK
};

class CryptoDaemonClient
{
public:
    /**
     * Construct and immediately connect to the daemon.
     * @throws CryptoDaemonError if the TCP connection cannot be established
     *         within `connectTimeoutMs`.
     */
    explicit CryptoDaemonClient(const QString& host = QStringLiteral("127.0.0.1"),
                                uint16_t port = DAEMON_PORT,
                                int connectTimeoutMs = 2000);

    ~CryptoDaemonClient();

    CryptoDaemonClient(const CryptoDaemonClient&) = delete;
    CryptoDaemonClient& operator=(const CryptoDaemonClient&) = delete;

    /** True after a successful connect — false after disconnect/error. */
    bool isConnected() const;

    /** Long-term identity public keys returned by generate_identity / load_identity. */
    struct Identity
    {
        QByteArray ikPub;            ///< X25519 identity public key
        QByteArray signPub;          ///< Ed25519 signing public key
    };

    /** One restored Double Ratchet session, as reported by list_sessions. */
    struct SessionInfo
    {
        QString sessionId;
        QString peerUserId;       ///< Peer username this session talks to
        QString role;             ///< "initiator" or "responder"
    };

    // --- Identity ---

    /** Generate a fresh identity (X25519 IK + Ed25519 signing key). */
    Identity generateIdentity(const QString& passphrase);

    /** Decrypt the on-disk identity file and load any saved sessions. */
    Identity loadIdentity(const QString& passphrase);

    /** List the sessions restored by loadIdentity so the UI can rebuild its
     *  peer-username -> session-id map across restarts. */
    QList<SessionInfo> listSessions();

    // --- Prekeys ---

    /** Generate a new Signed Prekey and 10 One-Time Prekeys.
     *  Pass the Ed25519 signPub returned by generateIdentity so the daemon
     *  can detect an identity-overwrite race and fail fast. Omit it (empty)
     *  for steady-state OPK replenishment where no fresh identity claim exists. */
    PrekeyBundle generatePrekeys(const QByteArray& signPub = QByteArray());

    // --- X3DH session establishment ---

    /** Initiator side — derive SK from bob's bundle and encrypt the first message. */
    X3dhSendResult x3dhSend(const QString& peerUsername,
                            const QString& plaintext,
                            const PeerKeyBundle& bobBundle);

    /** Responder side — derive SK from the inbound header. */
    QString x3dhReceive(const QString& peerUsername,
                        const X3dhInboundHeader& header);

    // --- Steady-state message ops ---

    /** Encrypt under an established Double Ratchet session. */
    EncryptedMessage encryptMessage(const QString& sessionId,
                                    const QString& plaintext);

    /** Decrypt under an established Double Ratchet session. */
    QString decryptMessage(const QString& sessionId,
                           const EncryptedMessageFields& fields);

private:
    /** Send one request, wait for one response. Throws CryptoDaemonError on
     *  transport failure or `status != "ok"`. */
    QJsonObject call(const QString& op, const QJsonObject& params);

    std::unique_ptr<QTcpSocket> m_socket;
    QByteArray  m_recvBuf;
};
