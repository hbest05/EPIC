/**
 * CryptoDaemonClient.cpp — synchronous transport for the Python daemon.
 *
 * Newline-delimited JSON over a single QTcpSocket connection to
 * 127.0.0.1:DAEMON_PORT (default 47291). All calls are blocking; the daemon is single-threaded
 * and serves one request at a time, so the UI thread layers a 10-second
 * timeout per call on top of Qt's socket I/O and surfaces any failure as
 * a CryptoDaemonError.
 */

#include "CryptoDaemonClient.hpp"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonValue>
#include <QtNetwork/QTcpSocket>

namespace {

constexpr int kCallTimeoutMs = 10'000;

QByteArray b64decode(const QJsonValue& v)
{
    return QByteArray::fromBase64(v.toString().toUtf8(), QByteArray::AbortOnBase64DecodingErrors);
}

QString b64encode(const QByteArray& bytes)
{
    return QString::fromUtf8(bytes.toBase64());
}

} // namespace

CryptoDaemonClient::CryptoDaemonClient(const QString& host,
                                       uint16_t port,
                                       int connectTimeoutMs)
    : m_socket(new QTcpSocket())
{
    m_socket->connectToHost(host, port);
    if (!m_socket->waitForConnected(connectTimeoutMs)) {
        const QString err = m_socket->errorString();
        delete m_socket;
        m_socket = nullptr;
        throw CryptoDaemonError(
            QStringLiteral("transport"),
            QStringLiteral("crypto daemon connect failed: %1").arg(err));
    }
    // Newline-framed JSON is small and latency-sensitive — disable Nagle.
    m_socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);
}

CryptoDaemonClient::~CryptoDaemonClient()
{
    if (m_socket) {
        m_socket->disconnectFromHost();
        delete m_socket;
    }
}

bool CryptoDaemonClient::isConnected() const
{
    return m_socket && m_socket->state() == QAbstractSocket::ConnectedState;
}

QJsonObject CryptoDaemonClient::call(const QString& op, const QJsonObject& params)
{
    if (!isConnected()) {
        throw CryptoDaemonError(
            QStringLiteral("transport"),
            QStringLiteral("crypto daemon not connected"));
    }

    QJsonObject req;
    req.insert(QStringLiteral("op"), op);
    req.insert(QStringLiteral("params"), params);

    QByteArray line = QJsonDocument(req).toJson(QJsonDocument::Compact);
    line.append('\n');

    if (m_socket->write(line) != line.size() ||
        !m_socket->waitForBytesWritten(kCallTimeoutMs)) {
        throw CryptoDaemonError(
            QStringLiteral("transport"),
            QStringLiteral("write to daemon failed: %1").arg(m_socket->errorString()));
    }

    // Read until the recv buffer holds a newline-terminated line.
    while (!m_recvBuf.contains('\n')) {
        if (!m_socket->waitForReadyRead(kCallTimeoutMs)) {
            throw CryptoDaemonError(
                QStringLiteral("transport"),
                QStringLiteral("daemon read timed out"));
        }
        m_recvBuf.append(m_socket->readAll());
    }

    const qsizetype nl = m_recvBuf.indexOf('\n');
    const QByteArray respLine = m_recvBuf.left(nl);
    m_recvBuf.remove(0, nl + 1);

    QJsonParseError parseErr{};
    const QJsonDocument doc = QJsonDocument::fromJson(respLine, &parseErr);
    if (parseErr.error != QJsonParseError::NoError || !doc.isObject()) {
        throw CryptoDaemonError(
            QStringLiteral("transport"),
            QStringLiteral("daemon returned non-JSON: %1").arg(parseErr.errorString()));
    }

    const QJsonObject resp = doc.object();
    const QString status = resp.value(QStringLiteral("status")).toString();
    if (status != QStringLiteral("ok")) {
        throw CryptoDaemonError(
            resp.value(QStringLiteral("code")).toString(QStringLiteral("internal")),
            resp.value(QStringLiteral("message")).toString(QStringLiteral("daemon error")));
    }

    return resp.value(QStringLiteral("data")).toObject();
}

CryptoDaemonClient::Identity CryptoDaemonClient::generateIdentity(const QString& passphrase)
{
    QJsonObject params;
    params.insert(QStringLiteral("passphrase"), passphrase);
    const QJsonObject data = call(QStringLiteral("generate_identity"), params);
    Identity id;
    id.ikPub   = b64decode(data.value(QStringLiteral("ik_pub")));
    id.signPub = b64decode(data.value(QStringLiteral("sign_pub")));
    return id;
}

CryptoDaemonClient::Identity CryptoDaemonClient::loadIdentity(const QString& passphrase)
{
    QJsonObject params;
    params.insert(QStringLiteral("passphrase"), passphrase);
    const QJsonObject data = call(QStringLiteral("load_identity"), params);
    Identity id;
    id.ikPub   = b64decode(data.value(QStringLiteral("ik_pub")));
    id.signPub = b64decode(data.value(QStringLiteral("sign_pub")));
    return id;
}

QList<CryptoDaemonClient::SessionInfo> CryptoDaemonClient::listSessions()
{
    const QJsonObject data = call(QStringLiteral("list_sessions"), QJsonObject{});
    QList<SessionInfo> out;
    const QJsonArray arr = data.value(QStringLiteral("sessions")).toArray();
    out.reserve(arr.size());
    for (const QJsonValue& v : arr) {
        const QJsonObject o = v.toObject();
        SessionInfo info;
        info.sessionId  = o.value(QStringLiteral("session_id")).toString();
        info.peerUserId = o.value(QStringLiteral("peer_user_id")).toString();
        info.role       = o.value(QStringLiteral("role")).toString();
        out.append(info);
    }
    return out;
}

PrekeyBundle CryptoDaemonClient::generatePrekeys(const QByteArray& signPub)
{
    QJsonObject params;
    if (!signPub.isEmpty()) {
        params.insert(QStringLiteral("sign_pub"), b64encode(signPub));
    }
    const QJsonObject data = call(QStringLiteral("generate_prekeys"), params);

    PrekeyBundle out;
    out.spkPub = b64decode(data.value(QStringLiteral("spk_pub")));
    out.spkSig = b64decode(data.value(QStringLiteral("spk_sig")));
    const QJsonArray opks = data.value(QStringLiteral("opks")).toArray();
    out.opks.reserve(opks.size());
    for (const QJsonValue& v : opks) {
        out.opks.append(QByteArray::fromBase64(v.toString().toUtf8()));
    }
    return out;
}

X3dhSendResult CryptoDaemonClient::x3dhSend(const QString& peerUsername,
                                            const QString& plaintext,
                                            const PeerKeyBundle& bobBundle)
{
    QJsonObject bundle;
    bundle.insert(QStringLiteral("ik_pub"),   b64encode(bobBundle.ikPub));
    bundle.insert(QStringLiteral("sign_pub"), b64encode(bobBundle.signPub));
    bundle.insert(QStringLiteral("spk_pub"),  b64encode(bobBundle.spkPub));
    bundle.insert(QStringLiteral("spk_sig"),  b64encode(bobBundle.spkSig));
    if (!bobBundle.opkPub.isEmpty()) {
        bundle.insert(QStringLiteral("opk_pub"), b64encode(bobBundle.opkPub));
    }

    QJsonObject params;
    params.insert(QStringLiteral("peer_user_id"), peerUsername);
    params.insert(QStringLiteral("plaintext"),    plaintext);
    params.insert(QStringLiteral("bundle"),       bundle);

    const QJsonObject data = call(QStringLiteral("x3dh_send"), params);
    const QJsonObject msg  = data.value(QStringLiteral("message")).toObject();

    X3dhSendResult out;
    out.sessionId  = data.value(QStringLiteral("session_id")).toString();
    out.ikPub      = b64decode(data.value(QStringLiteral("ik_pub")));
    out.ekPub      = b64decode(data.value(QStringLiteral("ek_pub")));
    // used_opk_pub is null when no OPK was consumed
    const QJsonValue opkVal = data.value(QStringLiteral("used_opk_pub"));
    if (opkVal.isString()) {
        out.usedOpkPub = b64decode(opkVal);
    }
    out.ciphertext = b64decode(msg.value(QStringLiteral("ciphertext")));
    out.nonce      = b64decode(msg.value(QStringLiteral("nonce")));
    out.ratchetPub = b64decode(msg.value(QStringLiteral("ratchet_pub")));
    out.pn         = msg.value(QStringLiteral("pn")).toInt();
    out.n          = msg.value(QStringLiteral("n")).toInt();
    out.aad        = b64decode(msg.value(QStringLiteral("aad")));
    return out;
}

QString CryptoDaemonClient::x3dhReceive(const QString& peerUsername,
                                         const X3dhInboundHeader& header)
{
    QJsonObject hdr;
    hdr.insert(QStringLiteral("ik_a"), b64encode(header.ikA));
    hdr.insert(QStringLiteral("ek_a"), b64encode(header.ekA));
    if (!header.usedOpkPub.isEmpty()) {
        hdr.insert(QStringLiteral("used_opk_pub"), b64encode(header.usedOpkPub));
    }

    QJsonObject params;
    params.insert(QStringLiteral("peer_user_id"), peerUsername);
    params.insert(QStringLiteral("header"),       hdr);

    const QJsonObject data = call(QStringLiteral("x3dh_receive"), params);
    return data.value(QStringLiteral("session_id")).toString();
}

EncryptedMessage CryptoDaemonClient::encryptMessage(const QString& sessionId,
                                                    const QString& plaintext)
{
    QJsonObject params;
    params.insert(QStringLiteral("session_id"), sessionId);
    params.insert(QStringLiteral("plaintext"),  plaintext);

    const QJsonObject data = call(QStringLiteral("encrypt_message"), params);

    EncryptedMessage out;
    out.ciphertext = b64decode(data.value(QStringLiteral("ciphertext")));
    out.nonce      = b64decode(data.value(QStringLiteral("nonce")));
    out.ratchetPub = b64decode(data.value(QStringLiteral("ratchet_pub")));
    out.pn         = data.value(QStringLiteral("pn")).toInt();
    out.n          = data.value(QStringLiteral("n")).toInt();
    out.aad        = b64decode(data.value(QStringLiteral("aad")));
    return out;
}

QString CryptoDaemonClient::decryptMessage(const QString& sessionId,
                                            const EncryptedMessageFields& f)
{
    QJsonObject params;
    params.insert(QStringLiteral("session_id"),  sessionId);
    params.insert(QStringLiteral("ciphertext"),  b64encode(f.ciphertext));
    params.insert(QStringLiteral("nonce"),       b64encode(f.nonce));
    params.insert(QStringLiteral("ratchet_pub"), b64encode(f.ratchetPub));
    params.insert(QStringLiteral("pn"),          f.pn);
    params.insert(QStringLiteral("n"),           f.n);

    const QJsonObject data = call(QStringLiteral("decrypt_message"), params);
    return data.value(QStringLiteral("plaintext")).toString();
}

