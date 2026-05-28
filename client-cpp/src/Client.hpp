#pragma once

/**
 * Client.hpp — REST controller for the SecureMsg backend.
 *
 * Owns the libcurl handle, the session cookie jar, the CSRF token, and a
 * pointer to the CryptoDaemonClient that handles all key material. The
 * Qt windows (LoginWindow, MainWindow) talk to the backend only through
 * this class so HTTP, JSON, and crypto-daemon concerns stay out of the
 * UI layer.
 *
 * All HTTP calls go to a single fixed HTTPS base URL with peer + host
 * verification on. The cookie jar plus the CSRF cookie installed by
 * /auth/login give us the cookie+CSRF auth flow the backend requires.
 */

#include <QtCore/QByteArray>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QList>
#include <QtCore/QString>
#include <memory>
#include <string>

class CryptoDaemonClient;

class Client
{
public:
    explicit Client(std::shared_ptr<CryptoDaemonClient> daemon);
    ~Client();

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    /** One-time global init (libcurl, cookie jar path). Safe to call once. */
    void initialize();

    // --- Auth ---

    /** POST /auth/register. @returns empty string on success, error on failure. */
    QString registerUser(const QString& username,
                         const QString& email,
                         const QString& password,
                         const QByteArray& x25519PubKey,
                         const QByteArray& ed25519PubKey);

    /** POST /auth/login. On success: cookies are saved, CSRF token captured. */
    QString login(const QString& username, const QString& password);

    /** POST /auth/logout — best-effort; always clears local session state. */
    void logout();

    /** POST /auth/prekeys — upload SPK + OPK batch. */
    QString uploadPrekeys(const QByteArray& spkPub,
                          const QByteArray& spkSig,
                          const QList<QByteArray>& opks);

    /** GET /auth/user/<username>/keybundle. */
    QString fetchKeybundle(const QString& username, QJsonObject* out);

    // --- Messages ---

    /** POST /messages/send with Double Ratchet header fields. */
    QString sendMessage(const QString& recipient,
                        const QByteArray& ciphertext,
                        const QByteArray& nonce,
                        const QByteArray& ratchetPub,
                        int pn, int n,
                        const QJsonObject* x3dhHeader);

    /** GET /messages/inbox with optional pagination.
     *  @param limit     max messages to return (server caps at 100)
     *  @param before    return messages older than this id (empty = ignore)
     *  @param after     return messages newer than this id (empty = ignore)
     *  @param withUser  restrict to messages from this sender (empty = all) */
    QString fetchInbox(QJsonArray* out,
                       int limit = 30,
                       const QString& before = QString(),
                       const QString& after = QString(),
                       const QString& withUser = QString());

    /** GET /messages/sent with optional pagination. */
    QString fetchSent(QJsonArray* out,
                      int limit = 30,
                      const QString& before = QString(),
                      const QString& withUser = QString());

    // --- Accessors ---
    const QString& username()     const { return m_username; }
    const QString& baseHostname() const { return m_baseHostname; }
    bool isAuthenticated()        const { return !m_csrfToken.isEmpty(); }
    CryptoDaemonClient* daemon()  const { return m_daemon.get(); }

    /** wss:// URL of the real-time delivery socket on the same host as the API. */
    QString websocketUrl() const { return QStringLiteral("wss://") + m_baseHostname + QStringLiteral("/ws"); }

    /** Value of the httpOnly access_token cookie from libcurl's jar, used to
     *  authenticate the WebSocket handshake. Empty if not logged in. */
    QString accessTokenCookie() const;

private:
    /** Perform a libcurl HTTP request; returns response body on success.
     *  Stores HTTP status in m_lastStatus and any libcurl error in
     *  m_lastError. Adds the X-CSRF-Token header on POST/DELETE/PUT. */
    QByteArray httpRequest(const QString& method,
                           const QString& path,
                           const QByteArray& jsonBody);

    /** Pull the csrf_token cookie out of libcurl's cookie jar. */
    void refreshCsrfToken();

    QString m_baseUrl      = QStringLiteral("https://alpha-and-the-cryptmunks.theburkenator.com");
    QString m_baseHostname = QStringLiteral("alpha-and-the-cryptmunks.theburkenator.com");

    std::shared_ptr<CryptoDaemonClient> m_daemon;

    QString m_username;
    QString m_csrfToken;
    std::string m_cookieJarPath;

    long    m_lastStatus = 0;
    QString m_lastError;
};
