/**
 * Client.cpp — REST controller implementation.
 *
 * libcurl with: TLS 1.2 floor, peer + hostname verification on, JSON body
 * for every request, and a per-process cookie jar so the backend's
 * httpOnly access_token cookie persists across calls. After /auth/login,
 * refreshCsrfToken() extracts the readable csrf_token cookie and
 * httpRequest() echoes it in X-CSRF-Token on every mutating call.
 */

#include "Client.hpp"
#include "CryptoDaemonClient.hpp"

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonDocument>
#include <QtCore/QStandardPaths>
#include <QtCore/QStringList>
#include <QtCore/QUrl>
#include <QtCore/QUuid>

#include <curl/curl.h>

namespace {

size_t writeToByteArray(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* buf = static_cast<QByteArray*>(userdata);
    buf->append(ptr, static_cast<qsizetype>(size * nmemb));
    return size * nmemb;
}

QString utf8(const QByteArray& b) { return QString::fromUtf8(b); }

} // namespace

Client::Client(std::shared_ptr<CryptoDaemonClient> daemon)
    : m_daemon(std::move(daemon))
{
}

Client::~Client()
{
    if (!m_cookieJarPath.empty()) {
        QFile::remove(QString::fromStdString(m_cookieJarPath));
    }
}

void Client::initialize()
{
    static bool curlInitialized = false;
    if (!curlInitialized) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curlInitialized = true;
    }

    // Per-process cookie jar — keeps the access_token + csrf_token cookies
    // alive across calls without persisting between runs.
    const QString tmpDir = QStandardPaths::writableLocation(QStandardPaths::TempLocation);
    QDir().mkpath(tmpDir);
    const QString jar = tmpDir + QStringLiteral("/securemsg-cookies-") +
                        QUuid::createUuid().toString(QUuid::WithoutBraces) +
                        QStringLiteral(".txt");
    m_cookieJarPath = jar.toStdString();
}

QByteArray Client::httpRequest(const QString& method,
                                const QString& path,
                                const QByteArray& jsonBody)
{
    m_lastStatus = 0;
    m_lastError.clear();

    CURL* curl = curl_easy_init();
    if (!curl) {
        m_lastError = QStringLiteral("curl_easy_init failed");
        return {};
    }

    QByteArray response;
    const std::string url = (m_baseUrl + path).toStdString();

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeToByteArray);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    // TLS hardening — explicit floor, full peer + hostname verification.
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    // Persistent cookie jar so backend's session cookie survives between calls.
    curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_cookieJarPath.c_str());
    curl_easy_setopt(curl, CURLOPT_COOKIEJAR,  m_cookieJarPath.c_str());

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");

    // Send CSRF echo header on mutating calls — matches the backend's
    // double-submit cookie pattern.
    const bool mutating = (method == QStringLiteral("POST") ||
                           method == QStringLiteral("PUT")  ||
                           method == QStringLiteral("DELETE"));
    QByteArray csrfHeader;
    if (mutating && !m_csrfToken.isEmpty()) {
        csrfHeader = "X-CSRF-Token: " + m_csrfToken.toUtf8();
        headers = curl_slist_append(headers, csrfHeader.constData());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    if (method == QStringLiteral("GET")) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else if (method == QStringLiteral("POST")) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.constData());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonBody.size());
    } else {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method.toUtf8().constData());
        if (!jsonBody.isEmpty()) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonBody.constData());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, jsonBody.size());
        }
    }

    const CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &m_lastStatus);

    if (rc != CURLE_OK) {
        m_lastError = QStringLiteral("curl: %1").arg(QString::fromUtf8(curl_easy_strerror(rc)));
        response.clear();
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

void Client::refreshCsrfToken()
{
    if (m_cookieJarPath.empty()) return;

    // libcurl writes a Netscape-format cookies.txt only on handle teardown,
    // so the file is current right after the login curl_easy_cleanup() ran.
    QFile f(QString::fromStdString(m_cookieJarPath));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;

    while (!f.atEnd()) {
        const QByteArray line = f.readLine();
        if (line.startsWith('#') || line.trimmed().isEmpty()) continue;
        // Netscape cookie format: domain TAB flag TAB path TAB secure TAB
        //                         expires TAB name TAB value
        const QList<QByteArray> cols = line.split('\t');
        if (cols.size() < 7) continue;
        if (cols[5].trimmed() == "csrf_token") {
            m_csrfToken = QString::fromUtf8(cols[6]).trimmed();
            return;
        }
    }
}

QString Client::accessTokenCookie() const
{
    if (m_cookieJarPath.empty()) return {};

    QFile f(QString::fromStdString(m_cookieJarPath));
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return {};

    while (!f.atEnd()) {
        QByteArray line = f.readLine();
        // libcurl writes httpOnly cookies (like access_token) with a
        // "#HttpOnly_" prefix on the domain column. Strip it so the line parses
        // like any other; genuine comment/blank lines are still skipped.
        if (line.startsWith("#HttpOnly_")) {
            line = line.mid(static_cast<int>(qstrlen("#HttpOnly_")));
        } else if (line.startsWith('#') || line.trimmed().isEmpty()) {
            continue;
        }
        // Netscape cookie format: domain flag path secure expires name value
        const QList<QByteArray> cols = line.split('\t');
        if (cols.size() < 7) continue;
        if (cols[5].trimmed() == "access_token") {
            return QString::fromUtf8(cols[6]).trimmed();
        }
    }
    return {};
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

QString Client::registerUser(const QString& username,
                             const QString& email,
                             const QString& password,
                             const QByteArray& x25519PubKey,
                             const QByteArray& ed25519PubKey)
{
    QJsonObject body;
    body.insert(QStringLiteral("username"), username);
    body.insert(QStringLiteral("email"),    email);
    body.insert(QStringLiteral("password"), password);
    body.insert(QStringLiteral("x25519_public_key"),  QString::fromUtf8(x25519PubKey.toBase64()));
    body.insert(QStringLiteral("ed25519_public_key"), QString::fromUtf8(ed25519PubKey.toBase64()));

    const QByteArray resp = httpRequest(QStringLiteral("POST"),
                                        QStringLiteral("/api/auth/register"),
                                        QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (m_lastStatus == 201) return {};
    if (!m_lastError.isEmpty()) return m_lastError;

    const QJsonObject obj = QJsonDocument::fromJson(resp).object();
    const QJsonValue detail = obj.value(QStringLiteral("detail"));
    // FastAPI Pydantic errors return detail as an array of {loc, msg, type} objects.
    if (detail.isArray()) {
        const QJsonArray arr = detail.toArray();
        if (!arr.isEmpty())
            return arr.first().toObject().value(QStringLiteral("msg")).toString(
                QStringLiteral("registration failed (HTTP %1)").arg(m_lastStatus));
    }
    return detail.toString(QStringLiteral("registration failed (HTTP %1)").arg(m_lastStatus));
}

QString Client::login(const QString& username, const QString& password)
{
    QJsonObject body;
    body.insert(QStringLiteral("username"), username);
    body.insert(QStringLiteral("password"), password);

    const QByteArray resp = httpRequest(QStringLiteral("POST"),
                                        QStringLiteral("/api/auth/login"),
                                        QJsonDocument(body).toJson(QJsonDocument::Compact));

    if (m_lastStatus != 200) {
        if (!m_lastError.isEmpty()) return m_lastError;
        const QJsonObject obj = QJsonDocument::fromJson(resp).object();
        return obj.value(QStringLiteral("detail")).toString(
            QStringLiteral("login failed (HTTP %1)").arg(m_lastStatus));
    }

    refreshCsrfToken();
    if (m_csrfToken.isEmpty()) {
        return QStringLiteral("login succeeded but no CSRF cookie was issued");
    }

    m_username = username;
    return {};
}

void Client::logout()
{
    (void)httpRequest(QStringLiteral("POST"),
                      QStringLiteral("/api/auth/logout"),
                      QByteArrayLiteral("{}"));
    m_csrfToken.clear();
    m_username.clear();
    if (!m_cookieJarPath.empty()) {
        QFile::remove(QString::fromStdString(m_cookieJarPath));
    }
}

QString Client::uploadPrekeys(const QByteArray& spkPub,
                              const QByteArray& spkSig,
                              const QList<QByteArray>& opks)
{
    // Backend expects integer key_ids; the daemon doesn't allocate them, so
    // the client owns the numbering. Use the current Unix second as the SPK
    // key_id and sequential ids for each OPK in this batch.
    const qint64 spkKeyId = QDateTime::currentSecsSinceEpoch();

    QJsonObject spk;
    spk.insert(QStringLiteral("key_id"),    static_cast<double>(spkKeyId));
    spk.insert(QStringLiteral("public_key"), QString::fromUtf8(spkPub.toBase64()));
    spk.insert(QStringLiteral("signature"),  QString::fromUtf8(spkSig.toBase64()));

    QJsonArray opkArr;
    for (int i = 0; i < opks.size(); ++i) {
        QJsonObject o;
        o.insert(QStringLiteral("key_id"),     static_cast<double>(spkKeyId * 100 + i));
        o.insert(QStringLiteral("public_key"), QString::fromUtf8(opks[i].toBase64()));
        opkArr.append(o);
    }

    QJsonObject body;
    body.insert(QStringLiteral("signed_prekey"),    spk);
    body.insert(QStringLiteral("one_time_prekeys"), opkArr);

    const QByteArray resp = httpRequest(QStringLiteral("POST"),
                                        QStringLiteral("/api/auth/prekeys"),
                                        QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (m_lastStatus == 204 || m_lastStatus == 200) return {};
    if (!m_lastError.isEmpty()) return m_lastError;
    const QJsonObject obj = QJsonDocument::fromJson(resp).object();
    return obj.value(QStringLiteral("detail")).toString(
        QStringLiteral("prekey upload failed (HTTP %1)").arg(m_lastStatus));
}

QString Client::fetchKeybundle(const QString& username, QJsonObject* out)
{
    const QByteArray resp = httpRequest(QStringLiteral("GET"),
                                        QStringLiteral("/api/auth/user/") + username + QStringLiteral("/keybundle"),
                                        {});
    if (m_lastStatus != 200) {
        if (!m_lastError.isEmpty()) return m_lastError;
        const QJsonObject obj = QJsonDocument::fromJson(resp).object();
        return obj.value(QStringLiteral("detail")).toString(
            QStringLiteral("keybundle fetch failed (HTTP %1)").arg(m_lastStatus));
    }
    if (out) *out = QJsonDocument::fromJson(resp).object();
    return {};
}

QString Client::fetchMe(QJsonObject* out)
{
    const QByteArray resp = httpRequest(QStringLiteral("GET"),
                                        QStringLiteral("/api/auth/me"),
                                        {});
    if (m_lastStatus != 200) {
        if (!m_lastError.isEmpty()) return m_lastError;
        const QJsonObject obj = QJsonDocument::fromJson(resp).object();
        return obj.value(QStringLiteral("detail")).toString(
            QStringLiteral("profile fetch failed (HTTP %1)").arg(m_lastStatus));
    }
    if (out) *out = QJsonDocument::fromJson(resp).object();
    return {};
}

QString Client::revokeAccess(const QString& messageId)
{
    const QByteArray resp = httpRequest(
        QStringLiteral("POST"),
        QStringLiteral("/api/messages/") + messageId + QStringLiteral("/revoke"),
        QByteArrayLiteral("{}"));
    if (m_lastStatus == 200 || m_lastStatus == 201) return {};
    if (!m_lastError.isEmpty()) return m_lastError;
    const QJsonObject obj = QJsonDocument::fromJson(resp).object();
    return obj.value(QStringLiteral("detail")).toString(
        QStringLiteral("revoke failed (HTTP %1)").arg(m_lastStatus));
}

QString Client::sendMessage(const QString& recipient,
                            const QByteArray& ciphertext,
                            const QByteArray& nonce,
                            const QByteArray& ratchetPub,
                            int pn, int n,
                            const QJsonObject* x3dhHeader,
                            QString* outId)
{
    QJsonObject body;
    body.insert(QStringLiteral("recipient_username"), recipient);
    body.insert(QStringLiteral("ciphertext"),         QString::fromUtf8(ciphertext.toBase64()));
    body.insert(QStringLiteral("nonce"),              QString::fromUtf8(nonce.toBase64()));
    body.insert(QStringLiteral("ratchet_pub"),        QString::fromUtf8(ratchetPub.toBase64()));
    body.insert(QStringLiteral("pn"),                 pn);
    body.insert(QStringLiteral("n"),                  n);
    if (x3dhHeader) {
        body.insert(QStringLiteral("x3dh_header"), *x3dhHeader);
    }

    const QByteArray resp = httpRequest(QStringLiteral("POST"),
                                        QStringLiteral("/api/messages/send"),
                                        QJsonDocument(body).toJson(QJsonDocument::Compact));
    if (m_lastStatus == 201 || m_lastStatus == 200) {
        if (outId) {
            *outId = QJsonDocument::fromJson(resp).object()
                         .value(QStringLiteral("id")).toString();
        }
        return {};
    }
    if (!m_lastError.isEmpty()) return m_lastError;
    const QJsonObject obj = QJsonDocument::fromJson(resp).object();
    return obj.value(QStringLiteral("detail")).toString(
        QStringLiteral("send failed (HTTP %1)").arg(m_lastStatus));
}

QString Client::deleteMessage(const QString& messageId)
{
    const QByteArray resp = httpRequest(QStringLiteral("DELETE"),
                                        QStringLiteral("/api/messages/") + messageId,
                                        {});
    if (m_lastStatus == 204) return {};
    if (!m_lastError.isEmpty()) return m_lastError;
    const QJsonObject obj = QJsonDocument::fromJson(resp).object();
    return obj.value(QStringLiteral("detail")).toString(
        QStringLiteral("delete failed (HTTP %1)").arg(m_lastStatus));
}

namespace {

QString buildMessagesQuery(int limit,
                           const QString& before,
                           const QString& after,
                           const QString& withUser)
{
    QStringList parts;
    parts << QStringLiteral("limit=%1").arg(limit);
    if (!before.isEmpty())
        parts << QStringLiteral("before=%1").arg(QString::fromUtf8(
            QUrl::toPercentEncoding(before)));
    if (!after.isEmpty())
        parts << QStringLiteral("after=%1").arg(QString::fromUtf8(
            QUrl::toPercentEncoding(after)));
    if (!withUser.isEmpty())
        parts << QStringLiteral("with_user=%1").arg(QString::fromUtf8(
            QUrl::toPercentEncoding(withUser)));
    return parts.isEmpty() ? QString() : QStringLiteral("?") + parts.join('&');
}

} // namespace

QString Client::fetchInbox(QJsonArray* out,
                           int limit,
                           const QString& before,
                           const QString& after,
                           const QString& withUser)
{
    const QString query = buildMessagesQuery(limit, before, after, withUser);
    const QByteArray resp = httpRequest(QStringLiteral("GET"),
                                        QStringLiteral("/api/messages/inbox") + query,
                                        {});
    if (m_lastStatus != 200) {
        if (!m_lastError.isEmpty()) return m_lastError;
        return QStringLiteral("inbox fetch failed (HTTP %1)").arg(m_lastStatus);
    }
    if (out) *out = QJsonDocument::fromJson(resp).array();
    return {};
}

QString Client::fetchSent(QJsonArray* out,
                          int limit,
                          const QString& before,
                          const QString& withUser)
{
    const QString query = buildMessagesQuery(limit, before, QString(), withUser);
    const QByteArray resp = httpRequest(QStringLiteral("GET"),
                                        QStringLiteral("/api/messages/sent") + query,
                                        {});
    if (m_lastStatus != 200) {
        if (!m_lastError.isEmpty()) return m_lastError;
        return QStringLiteral("sent fetch failed (HTTP %1)").arg(m_lastStatus);
    }
    if (out) *out = QJsonDocument::fromJson(resp).array();
    return {};
}
