/**
 * MainWindow.cpp — chat UI + inbox polling loop.
 *
 * Outbound: encryptMessage / x3dhSend through the daemon, then POST.
 * Inbound: poll /messages/inbox for ids newer than the last seen one
 * (?after=<id>), run x3dhReceive on any new session, then decryptMessage.
 *
 * History persistence: the Double Ratchet consumes each message key on first
 * decrypt, so server ciphertext cannot be re-decrypted after a restart. We
 * therefore keep a local plaintext history cache per user (m_threads, mirrored
 * to disk) which is the source of truth for the thread view. Sessions are
 * restored from the daemon's persisted session files so newly-arrived (offline)
 * messages still decrypt in order.
 */

#include "MainWindow.hpp"

#include "Client.hpp"
#include "CryptoDaemonClient.hpp"

#include <QtCore/QDateTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>
#include <QtCore/QStandardPaths>
#include <QtCore/QTimer>
#include <QtCore/QUrl>
#include <QtCore/QUrlQuery>
#include <QtCore/QUuid>
#include <QtNetwork/QAbstractSocket>
#include <QtNetwork/QNetworkRequest>
#include <QtWebSockets/QWebSocket>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTextEdit>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QWidget>

namespace {

QByteArray b64dec(const QJsonValue& v)
{
    return QByteArray::fromBase64(v.toString().toUtf8());
}

QString nowIso()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
}

} // namespace

MainWindow::MainWindow(Client* client, bool freshRegistration, QWidget* parent)
    : QMainWindow(parent)
    , m_client(client)
    , m_webSocket(new QWebSocket(QString(), QWebSocketProtocol::VersionLatest, this))
    , m_reconnectTimer(new QTimer(this))
    , m_reconnectDelayMs(kInitialReconnectMs)
    , m_contactList(new QListWidget(this))
    , m_thread(new QTextEdit(this))
    , m_compose(new QLineEdit(this))
    , m_sendButton(new QPushButton(tr("Send"), this))
    , m_addContactButton(new QPushButton(tr("Add contact"), this))
    , m_loadOlderButton(new QPushButton(tr("Load older messages"), this))
    , m_topBar(new QLabel(this))
{
    setWindowTitle(tr("SecureMsg"));
    resize(900, 600);

    m_thread->setReadOnly(true);
    m_compose->setPlaceholderText(tr("Type a message…"));
    m_loadOlderButton->setVisible(false);

    auto* left = new QWidget(this);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->addWidget(m_addContactButton);
    leftLayout->addWidget(m_contactList);

    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);
    auto* composeRow = new QHBoxLayout;
    composeRow->addWidget(m_compose);
    composeRow->addWidget(m_sendButton);
    rightLayout->addWidget(m_loadOlderButton);
    rightLayout->addWidget(m_thread);
    rightLayout->addLayout(composeRow);

    auto* split = new QSplitter(this);
    split->addWidget(left);
    split->addWidget(right);
    split->setStretchFactor(0, 1);
    split->setStretchFactor(1, 3);

    auto* central = new QWidget(this);
    auto* mainLayout = new QVBoxLayout(central);
    mainLayout->addWidget(m_topBar);
    mainLayout->addWidget(split, 1);
    setCentralWidget(central);

    m_topBar->setText(tr("\xF0\x9F\x94\x92 %1  —  signed in as %2")
                      .arg(m_client->baseHostname(), m_client->username()));
    m_topBar->setStyleSheet(QStringLiteral("padding: 6px; background: #f0f4f8;"));

    connect(m_sendButton,       &QPushButton::clicked,         this, &MainWindow::onSendClicked);
    connect(m_compose,          &QLineEdit::returnPressed,     this, &MainWindow::onSendClicked);
    connect(m_addContactButton, &QPushButton::clicked,         this, &MainWindow::onAddContactClicked);
    connect(m_loadOlderButton,  &QPushButton::clicked,         this, &MainWindow::onLoadOlderClicked);
    connect(m_contactList,      &QListWidget::itemClicked,     this, &MainWindow::onContactSelected);

    // Real-time delivery socket wiring.
    m_reconnectTimer->setSingleShot(true);
    connect(m_reconnectTimer, &QTimer::timeout,            this, &MainWindow::connectWebSocket);
    connect(m_webSocket, &QWebSocket::connected,           this, &MainWindow::onWsConnected);
    connect(m_webSocket, &QWebSocket::disconnected,        this, &MainWindow::onWsDisconnected);
    connect(m_webSocket, &QWebSocket::textMessageReceived, this, &MainWindow::onWsTextMessage);
    connect(m_webSocket, &QWebSocket::errorOccurred,
            this, [this](QAbstractSocket::SocketError) { scheduleReconnect(); });

    // Rebuild local thread history and the username -> session map before we
    // open the socket, so restored conversations show immediately on login.
    loadHistory();
    restoreSessions();

    // Pull anything that arrived while we were offline straight away — this is
    // the one-shot fallback that the real-time socket complements.
    QTimer::singleShot(0, this, &MainWindow::pollInbox);
    connectWebSocket();

    // Replenish OPK pool on startup — Bobs who run out can't receive new
    // sessions. Skip right after registration: that flow already uploaded a
    // full batch, and a second upload here would seed server OPKs from a batch
    // the daemon only partially holds in memory.
    if (!freshRegistration) {
        try {
            const PrekeyBundle pre = m_client->daemon()->generatePrekeys();
            const QString err = m_client->uploadPrekeys(pre.spkPub, pre.spkSig, pre.opks);
            if (!err.isEmpty()) {
                QMessageBox::warning(this, tr("Prekey refresh failed"), err);
            }
        } catch (const CryptoDaemonError& e) {
            QMessageBox::warning(this, tr("Prekey refresh failed"),
                                 tr("Daemon error: %1").arg(e.message()));
        }
    }
}

// ---------------------------------------------------------------------------
// Local history cache
// ---------------------------------------------------------------------------

QString MainWindow::historyFilePath() const
{
    const QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation)
                        + QStringLiteral("/history");
    QDir().mkpath(dir);
    // One file per user so multiple accounts on one host don't collide.
    const QString safeUser = QString::fromUtf8(
        m_client->username().toUtf8().toBase64(QByteArray::Base64UrlEncoding
                                               | QByteArray::OmitTrailingEquals));
    return dir + QStringLiteral("/") + safeUser + QStringLiteral(".json");
}

void MainWindow::loadHistory()
{
    QFile f(historyFilePath());
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text)) return;
    const QJsonObject root = QJsonDocument::fromJson(f.readAll()).object();
    f.close();

    m_lastInboxId = root.value(QStringLiteral("last_inbox_id")).toString();

    const QJsonArray msgs = root.value(QStringLiteral("messages")).toArray();
    for (const QJsonValue& v : msgs) {
        const QJsonObject o = v.toObject();
        ThreadMessage m;
        m.id     = o.value(QStringLiteral("id")).toString();
        m.fromMe = o.value(QStringLiteral("from_me")).toBool();
        m.sender = o.value(QStringLiteral("sender")).toString();
        m.text   = o.value(QStringLiteral("text")).toString();
        m.ts     = o.value(QStringLiteral("ts")).toString();
        const QString contact = o.value(QStringLiteral("contact")).toString();
        if (contact.isEmpty()) continue;

        m_threads[contact].append(m);
        if (!m.id.isEmpty()) m_seenMessageIds.insert(m.id);
        ensureContact(contact);
    }
}

void MainWindow::saveHistory() const
{
    QJsonArray msgs;
    for (auto it = m_threads.constBegin(); it != m_threads.constEnd(); ++it) {
        for (const ThreadMessage& m : it.value()) {
            QJsonObject o;
            o.insert(QStringLiteral("contact"), it.key());
            o.insert(QStringLiteral("id"),      m.id);
            o.insert(QStringLiteral("from_me"), m.fromMe);
            o.insert(QStringLiteral("sender"),  m.sender);
            o.insert(QStringLiteral("text"),    m.text);
            o.insert(QStringLiteral("ts"),      m.ts);
            msgs.append(o);
        }
    }

    QJsonObject root;
    root.insert(QStringLiteral("last_inbox_id"), m_lastInboxId);
    root.insert(QStringLiteral("messages"), msgs);

    QFile f(historyFilePath());
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) return;
    f.write(QJsonDocument(root).toJson(QJsonDocument::Compact));
    f.close();
}

void MainWindow::restoreSessions()
{
    QList<CryptoDaemonClient::SessionInfo> sessions;
    try {
        sessions = m_client->daemon()->listSessions();
    } catch (const CryptoDaemonError&) {
        // Non-fatal: without restored sessions we simply can't decrypt new
        // messages from existing conversations until a fresh handshake.
        return;
    }
    for (const auto& s : sessions) {
        if (s.peerUserId.isEmpty() || s.sessionId.isEmpty()) continue;
        // Last one wins if a peer somehow has multiple sessions.
        m_sessions.insert(s.peerUserId, s.sessionId);
        m_sentFirstMessage.insert(s.peerUserId, true);
        ensureContact(s.peerUserId);
    }
}

// ---------------------------------------------------------------------------
// Thread rendering
// ---------------------------------------------------------------------------

void MainWindow::ensureContact(const QString& username)
{
    if (m_contactList->findItems(username, Qt::MatchExactly).isEmpty()) {
        m_contactList->addItem(username);
    }
}

void MainWindow::appendMessage(const QString& contact, const ThreadMessage& msg, bool persist)
{
    m_threads[contact].append(msg);
    if (!msg.id.isEmpty()) m_seenMessageIds.insert(msg.id);
    ensureContact(contact);
    if (persist) saveHistory();
    if (contact == m_activeContact) renderActiveThread();
}

void MainWindow::renderActiveThread()
{
    m_thread->clear();
    if (m_activeContact.isEmpty()) return;

    m_thread->append(tr("— conversation with %1 —").arg(m_activeContact));

    const QList<ThreadMessage>& all = m_threads.value(m_activeContact);
    const int limit = m_renderLimit.value(m_activeContact, kPageSize);
    const int start = qMax(0, all.size() - limit);

    for (int i = start; i < all.size(); ++i) {
        const ThreadMessage& m = all[i];
        if (m.fromMe) {
            m_thread->append(QStringLiteral("me: ") + m.text);
        } else {
            m_thread->append(QStringLiteral("%1: %2").arg(m.sender, m.text));
        }
    }

    m_loadOlderButton->setVisible(start > 0);
}

void MainWindow::selectContact(const QString& username)
{
    m_activeContact = username;
    m_renderLimit.insert(username, kPageSize);
    renderActiveThread();
}

void MainWindow::onContactSelected(QListWidgetItem* item)
{
    if (!item) return;
    selectContact(item->text());
}

void MainWindow::onLoadOlderClicked()
{
    if (m_activeContact.isEmpty()) return;
    const int current = m_renderLimit.value(m_activeContact, kPageSize);
    m_renderLimit.insert(m_activeContact, current + kPageSize);
    renderActiveThread();
}

// ---------------------------------------------------------------------------
// Contacts / sessions
// ---------------------------------------------------------------------------

bool MainWindow::startSessionWith(const QString& username, QString* err)
{
    QJsonObject bundle;
    const QString fetchErr = m_client->fetchKeybundle(username, &bundle);
    if (!fetchErr.isEmpty()) {
        if (err) *err = fetchErr;
        return false;
    }

    PeerKeyBundle peer;
    peer.ikPub   = b64dec(bundle.value(QStringLiteral("ik_x25519")));
    peer.signPub = b64dec(bundle.value(QStringLiteral("ik_ed25519")));
    const QJsonObject spk = bundle.value(QStringLiteral("spk")).toObject();
    peer.spkPub = b64dec(spk.value(QStringLiteral("public_key")));
    peer.spkSig = b64dec(spk.value(QStringLiteral("signature")));
    const QJsonValue opkVal = bundle.value(QStringLiteral("opk"));
    if (opkVal.isObject()) {
        peer.opkPub = b64dec(opkVal.toObject().value(QStringLiteral("public_key")));
    }

    // Defer the actual x3dh_send until the user types something — we don't
    // want to burn an OPK and a session just to "add" a contact. Store the
    // peer bundle by enqueueing a pending session marker.
    m_sessions.insert(username, QString{});       // empty == not-yet-initialised
    m_sentFirstMessage.insert(username, false);
    Q_UNUSED(peer);
    return true;
}

void MainWindow::onAddContactClicked()
{
    bool ok = false;
    const QString name = QInputDialog::getText(this, tr("Add contact"),
                                               tr("Username:"), QLineEdit::Normal,
                                               QString{}, &ok).trimmed();
    if (!ok || name.isEmpty()) return;

    if (name == m_client->username()) {
        QMessageBox::warning(this, tr("Couldn't add contact"),
                             tr("You cannot add yourself as a contact"));
        return;
    }

    // Adding a contact we already have history with shouldn't wipe the session.
    if (!m_sessions.contains(name)) {
        QString err;
        if (!startSessionWith(name, &err)) {
            QMessageBox::warning(this, tr("Couldn't add contact"), err);
            return;
        }
    }

    ensureContact(name);
    selectContact(name);
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

void MainWindow::onSendClicked()
{
    if (m_activeContact.isEmpty()) {
        QMessageBox::information(this, tr("No contact selected"),
                                 tr("Pick a contact on the left first."));
        return;
    }
    const QString text = m_compose->text();
    if (text.isEmpty()) return;
    m_compose->clear();

    const QString contact = m_activeContact;
    QString sessionId = m_sessions.value(contact);

    try {
        if (sessionId.isEmpty()) {
            // First message — fetch bundle (again, fresh OPK) and run x3dh_send.
            QJsonObject bundle;
            const QString fetchErr = m_client->fetchKeybundle(contact, &bundle);
            if (!fetchErr.isEmpty()) {
                QMessageBox::warning(this, tr("Couldn't reach %1").arg(contact), fetchErr);
                return;
            }
            PeerKeyBundle peer;
            peer.ikPub   = b64dec(bundle.value(QStringLiteral("ik_x25519")));
            peer.signPub = b64dec(bundle.value(QStringLiteral("ik_ed25519")));
            const QJsonObject spk = bundle.value(QStringLiteral("spk")).toObject();
            peer.spkPub = b64dec(spk.value(QStringLiteral("public_key")));
            peer.spkSig = b64dec(spk.value(QStringLiteral("signature")));
            const QJsonValue opkVal = bundle.value(QStringLiteral("opk"));
            if (opkVal.isObject()) {
                peer.opkPub = b64dec(opkVal.toObject().value(QStringLiteral("public_key")));
            }

            const X3dhSendResult r = m_client->daemon()->x3dhSend(contact, text, peer);

            QJsonObject hdr;
            hdr.insert(QStringLiteral("ik_a"), QString::fromUtf8(r.ikPub.toBase64()));
            hdr.insert(QStringLiteral("ek_a"), QString::fromUtf8(r.ekPub.toBase64()));
            if (!r.usedOpkPub.isEmpty()) {
                hdr.insert(QStringLiteral("used_opk_pub"),
                           QString::fromUtf8(r.usedOpkPub.toBase64()));
            }

            const QString err = m_client->sendMessage(contact,
                                                      r.ciphertext, r.nonce,
                                                      r.ratchetPub, r.pn, r.n,
                                                      &hdr);
            if (!err.isEmpty()) {
                QMessageBox::warning(this, tr("Send failed"), err);
                return;
            }

            m_sessions.insert(contact, r.sessionId);
            m_sentFirstMessage.insert(contact, true);
        } else {
            const EncryptedMessage enc =
                m_client->daemon()->encryptMessage(sessionId, text);
            const QString err = m_client->sendMessage(contact,
                                                      enc.ciphertext, enc.nonce,
                                                      enc.ratchetPub, enc.pn, enc.n,
                                                      nullptr);
            if (!err.isEmpty()) {
                QMessageBox::warning(this, tr("Send failed"), err);
                return;
            }
        }
    } catch (const CryptoDaemonError& e) {
        QMessageBox::warning(this, tr("Encrypt failed"), e.message());
        return;
    }

    // Cache the plaintext locally — we can never recover it from the server
    // (we don't keep our own send-side message keys).
    ThreadMessage mine;
    mine.id     = QUuid::createUuid().toString(QUuid::WithoutBraces);
    mine.fromMe = true;
    mine.sender = m_client->username();
    mine.text   = text;
    mine.ts     = nowIso();
    appendMessage(contact, mine);
}

// ---------------------------------------------------------------------------
// Inbox polling (incremental)
// ---------------------------------------------------------------------------

void MainWindow::pollInbox()
{
    QJsonArray inbox;
    // Only fetch messages newer than the last one we processed. On the very
    // first run (empty cursor) this pulls the most recent page to bootstrap.
    const QString err = m_client->fetchInbox(&inbox, kPageSize, QString(),
                                             m_lastInboxId, QString());
    if (!err.isEmpty()) {
        // Quiet: poll failures shouldn't spam dialogs.
        return;
    }
    if (inbox.isEmpty()) return;

    // The server returns newest-first; decrypt oldest-first so the Double
    // Ratchet receive chain advances in order.
    QList<QJsonObject> ordered;
    ordered.reserve(inbox.size());
    for (const QJsonValue& v : inbox) ordered.prepend(v.toObject());

    // The newest id in this batch becomes the next poll cursor regardless of
    // per-message decrypt success — failed messages are unrecoverable anyway.
    const QString newestId = inbox.first().toObject()
                                 .value(QStringLiteral("id")).toString();

    bool changed = false;
    for (const QJsonObject& m : ordered) {
        // Persist once at the end of the batch instead of per message.
        if (processInboundMessage(m, /*persist=*/false)) changed = true;
    }

    if (!newestId.isEmpty()) m_lastInboxId = newestId;
    saveHistory();
    if (changed) renderActiveThread();
}

bool MainWindow::processInboundMessage(const QJsonObject& m, bool persist)
{
    const QString id = m.value(QStringLiteral("id")).toString();
    if (id.isEmpty() || m_seenMessageIds.contains(id)) return false;
    m_seenMessageIds.insert(id);

    const QString sender = m.value(QStringLiteral("sender_username")).toString();

    QString sessionId = m_sessions.value(sender);
    try {
        const QJsonValue hdrVal = m.value(QStringLiteral("x3dh_header"));
        if (hdrVal.isObject() && sessionId.isEmpty()) {
            const QJsonObject h = hdrVal.toObject();
            X3dhInboundHeader hdr;
            hdr.ikA = b64dec(h.value(QStringLiteral("ik_a")));
            hdr.ekA = b64dec(h.value(QStringLiteral("ek_a")));
            const QJsonValue opk = h.value(QStringLiteral("used_opk_pub"));
            if (opk.isString()) hdr.usedOpkPub = b64dec(opk);
            sessionId = m_client->daemon()->x3dhReceive(sender, hdr);
            m_sessions.insert(sender, sessionId);
            ensureContact(sender);
        }
        if (sessionId.isEmpty()) {
            // Subsequent message but we have no session — skip quietly.
            return false;
        }

        EncryptedMessageFields f;
        f.ciphertext = b64dec(m.value(QStringLiteral("ciphertext")));
        f.nonce      = b64dec(m.value(QStringLiteral("nonce")));
        f.ratchetPub = b64dec(m.value(QStringLiteral("ratchet_pub")));
        f.pn         = m.value(QStringLiteral("pn")).toInt();
        f.n          = m.value(QStringLiteral("n")).toInt();

        const QString plaintext = m_client->daemon()->decryptMessage(sessionId, f);

        ThreadMessage tm;
        tm.id     = id;
        tm.fromMe = false;
        tm.sender = sender;
        tm.text   = plaintext;
        tm.ts     = m.value(QStringLiteral("created_at")).toString(nowIso());
        appendMessage(sender, tm, persist);
        return true;
    } catch (const CryptoDaemonError& e) {
        if (sender == m_activeContact) {
            m_thread->append(tr("[%1] decrypt failed: %2").arg(sender, e.message()));
        }
        return false;
    }
}

// ---------------------------------------------------------------------------
// Real-time delivery socket (QWebSocket → /ws)
// ---------------------------------------------------------------------------

void MainWindow::connectWebSocket()
{
    // Don't stack connections if we're already up or mid-handshake.
    if (m_webSocket->state() != QAbstractSocket::UnconnectedState) return;

    const QString token = m_client->accessTokenCookie();

    // Authenticate the handshake two ways for robustness: the access_token
    // cookie (mirrors the REST auth) and a ?token= query param fallback for
    // when the upgrade request can't carry the cookie. The backend prefers the
    // cookie and falls back to the query param.
    QUrl url(m_client->websocketUrl());
    if (!token.isEmpty()) {
        QUrlQuery q;
        q.addQueryItem(QStringLiteral("token"), token);
        url.setQuery(q);
    }

    QNetworkRequest req(url);
    if (!token.isEmpty()) {
        req.setRawHeader("Cookie", "access_token=" + token.toUtf8());
    }
    m_webSocket->open(req);
}

void MainWindow::onWsConnected()
{
    // Successful connect resets the backoff and cancels any pending retry.
    m_reconnectDelayMs = kInitialReconnectMs;
    m_reconnectTimer->stop();

    // Catch up on anything that landed while the socket was down — the push
    // path only covers messages sent while we were connected.
    pollInbox();
}

void MainWindow::onWsDisconnected()
{
    scheduleReconnect();
}

void MainWindow::scheduleReconnect()
{
    // A single pending retry is enough — both disconnected and errorOccurred
    // can fire for one drop.
    if (m_reconnectTimer->isActive()) return;
    m_reconnectTimer->start(m_reconnectDelayMs);
    m_reconnectDelayMs = qMin(m_reconnectDelayMs * 2, kMaxReconnectMs);
}

void MainWindow::onWsTextMessage(const QString& text)
{
    const QJsonObject obj = QJsonDocument::fromJson(text.toUtf8()).object();
    if (obj.value(QStringLiteral("type")).toString() != QStringLiteral("new_message")) return;

    const QJsonObject m = obj.value(QStringLiteral("message")).toObject();
    if (processInboundMessage(m, /*persist=*/false)) {
        // Advance the poll cursor so the fallback poll won't refetch this one.
        const QString id = m.value(QStringLiteral("id")).toString();
        if (!id.isEmpty()) m_lastInboxId = id;
        saveHistory();
    }
}
