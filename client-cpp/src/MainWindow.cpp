/**
 * MainWindow.cpp — chat UI + inbox polling loop.
 *
 * Outbound: encryptMessage / x3dhSend through the daemon, then POST.
 * Inbound: poll /messages/inbox for ids newer than the last seen one
 * (?after=<id>), run x3dhReceive on any new session, then decryptMessage.
 *
 * History persistence: the Double Ratchet consumes each message key on first
 * decrypt, so server ciphertext cannot be re-decrypted after a restart. We
 * therefore keep a local plaintext history cache per user (m_store, mirrored
 * to disk) which is the source of truth for the thread view. Sessions are
 * restored from the daemon's persisted session files so newly-arrived (offline)
 * messages still decrypt in order.
 */

#include "MainWindow.hpp"

#include "Client.hpp"
#include "CryptoDaemonClient.hpp"
#include "MessageItemDelegate.hpp"

#include <QtCore/QDateTime>
#include <QtCore/QDebug>
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
#include <algorithm>
#include <QtWidgets/QFileDialog>
#include <QtWidgets/QInputDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QListWidget>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QMenu>
#include <QtWidgets/QStyledItemDelegate>
#include <QtWidgets/QVBoxLayout>
#include <QtGui/QMouseEvent>
#include <QtGui/QPainter>
#include <QtWidgets/QWidget>

namespace {

static constexpr int kDotsZoneWidth   = 28; // px on the right for the ⋮ hit target
static constexpr int kCircleZoneWidth = 28; // px on the left for the selection circle hit target
static constexpr int kCircleRadius    =  7; // outer circle radius (scales with typical row height)
static constexpr int kDotRadius       =  3; // inner dot radius when selected

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
    , m_thread(new QListWidget(this))
    , m_compose(new QLineEdit(this))
    , m_sendButton(new QPushButton(tr("Send"), this))
    , m_addContactButton(new QPushButton(tr("Add contact"), this))
    , m_loadOlderButton(new QPushButton(tr("Load older messages"), this))
    , m_topBar(new QLabel(this))
    , m_composeWidget(new QWidget(this))
    , m_selectionBar(new QWidget(this))
    , m_selectionCountLabel(new QLabel(this))
    , m_selectionDeleteButton(new QPushButton(tr("Delete"), this))
    , m_selectionForwardButton(new QPushButton(tr("Forward"), this))
    , m_selectionDownloadButton(new QPushButton(tr("Download"), this))
{
    setWindowTitle(tr("SecureMsg"));
    resize(900, 600);

    m_compose->setPlaceholderText(tr("Type a message…"));
    m_loadOlderButton->setVisible(false);
    m_thread->setItemDelegate(new MessageItemDelegate(&m_selectionMode, m_thread));
    m_thread->setMouseTracking(true);
    m_thread->viewport()->setMouseTracking(true);
    m_thread->viewport()->installEventFilter(this);

    // Compose row (normal mode)
    auto* composeLayout = new QHBoxLayout(m_composeWidget);
    composeLayout->setContentsMargins(0, 0, 0, 0);
    composeLayout->addWidget(m_compose);
    composeLayout->addWidget(m_sendButton);

    // Selection bar (selection mode) — hidden until user enters selection mode
    auto* selBarLayout = new QHBoxLayout(m_selectionBar);
    selBarLayout->setContentsMargins(4, 4, 4, 4);
    m_selectionDeleteButton->setEnabled(false);
    m_selectionForwardButton->setEnabled(false);
    m_selectionDownloadButton->setEnabled(false);
    auto* cancelSelButton = new QPushButton(tr("Cancel"), this);
    selBarLayout->addWidget(m_selectionCountLabel, 1);
    selBarLayout->addWidget(m_selectionForwardButton);
    selBarLayout->addWidget(m_selectionDownloadButton);
    selBarLayout->addWidget(m_selectionDeleteButton);
    selBarLayout->addWidget(cancelSelButton);
    m_selectionBar->setVisible(false);

    auto* left = new QWidget(this);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->addWidget(m_addContactButton);
    leftLayout->addWidget(m_contactList);

    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);
    rightLayout->addWidget(m_loadOlderButton);
    rightLayout->addWidget(m_thread);
    rightLayout->addWidget(m_composeWidget);
    rightLayout->addWidget(m_selectionBar);

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

    // currentUser() also available: m_client->currentUser().username(), .x25519PublicKey(), etc.
    m_topBar->setText(tr("\xF0\x9F\x90\xBF %1  —  signed in as %2")
                      .arg(m_client->baseHostname(), m_client->username()));
    m_topBar->setStyleSheet(QStringLiteral("padding: 6px; background: #f0f4f8;"));

    connect(m_sendButton,            &QPushButton::clicked,         this, &MainWindow::onSendClicked);
    connect(m_compose,               &QLineEdit::returnPressed,     this, &MainWindow::onSendClicked);
    m_thread->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_thread, &QListWidget::customContextMenuRequested,
            this, &MainWindow::onThreadContextMenu);
    connect(m_thread,                &QListWidget::itemSelectionChanged, this, &MainWindow::onSelectionChanged);
    connect(m_selectionDeleteButton,   &QPushButton::clicked, this, &MainWindow::onSelectionDeleteClicked);
    connect(m_selectionForwardButton,  &QPushButton::clicked, this, &MainWindow::onSelectionForwardClicked);
    connect(m_selectionDownloadButton, &QPushButton::clicked, this, &MainWindow::onSelectionDownloadClicked);
    connect(cancelSelButton,         &QPushButton::clicked,         this, &MainWindow::exitSelectionMode);
    connect(m_addContactButton,      &QPushButton::clicked,         this, &MainWindow::onAddContactClicked);
    connect(m_loadOlderButton,       &QPushButton::clicked,         this, &MainWindow::onLoadOlderClicked);
    connect(m_contactList,           &QListWidget::itemClicked,     this, &MainWindow::onContactSelected);

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

    m_store.setLastInboxId(root.value(QStringLiteral("last_inbox_id")).toString().toStdString());

    const QJsonArray msgs = root.value(QStringLiteral("messages")).toArray();

    // std::find used via QSet::contains for O(1) duplicate detection —
    // the seen-id set already uses QSet which is a hash set.
    const auto missingContact = std::find_if(msgs.constBegin(), msgs.constEnd(),
        [](const QJsonValue& v) {
            return v.toObject().value(QStringLiteral("contact")).toString().isEmpty();
        });
    if (missingContact != msgs.constEnd()) {
        qWarning() << "MainWindow::loadHistory: history contains message(s) with an empty contact field";
    }

    for (const QJsonValue& v : msgs) {
        const QJsonObject o = v.toObject();
        const QString contact = o.value(QStringLiteral("contact")).toString();
        if (contact.isEmpty()) continue;

        Message m;
        m.setId(o.value(QStringLiteral("id")).toString());
        m.setDirection(o.value(QStringLiteral("from_me")).toBool()
                           ? Message::Direction::Sent
                           : Message::Direction::Received);
        m.setSenderUsername(o.value(QStringLiteral("sender")).toString());
        m.setPlaintext(o.value(QStringLiteral("text")).toString());
        m.setCreatedAt(QDateTime::fromString(
            o.value(QStringLiteral("ts")).toString(), Qt::ISODate));

        m_store.conversation(contact.toStdString()).messages.push_back(m);
        m_store.markIdSeen(m.id().toStdString());
        ensureContact(contact);
    }
}

void MainWindow::saveHistory() const
{
    QJsonArray msgs;
    for (const std::string& contact : m_store.contactUsernames()) {
        const MessageStore::Conversation* conv = m_store.conversationPtr(contact);
        if (!conv) continue;
        const QString contactName = QString::fromStdString(contact);
        std::for_each(conv->messages.cbegin(), conv->messages.cend(),
            [&msgs, &contactName](const Message& m) {
                QJsonObject o;
                o.insert(QStringLiteral("contact"), contactName);
                o.insert(QStringLiteral("id"),      m.id());
                o.insert(QStringLiteral("from_me"), m.direction() == Message::Direction::Sent);
                o.insert(QStringLiteral("sender"),  m.senderUsername());
                o.insert(QStringLiteral("text"),    m.plaintext());
                o.insert(QStringLiteral("ts"),      m.createdAt().toString(Qt::ISODate));
                msgs.append(o);
            });
    }

    QJsonObject root;
    root.insert(QStringLiteral("last_inbox_id"), QString::fromStdString(m_store.lastInboxId()));
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
        MessageStore::Conversation& conv = m_store.conversation(s.peerUserId.toStdString());
        conv.sessionId = s.sessionId.toStdString();
        conv.sentFirstMessage = true;
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

void MainWindow::appendMessage(const QString& contact, const Message& msg, bool persist)
{
    m_store.addMessage(contact.toStdString(), msg);
    m_store.markIdSeen(msg.id().toStdString());
    ensureContact(contact);
    if (persist) saveHistory();
    if (contact == m_activeContact) renderActiveThread();
}

void MainWindow::renderActiveThread()
{
    m_thread->clear();
    if (m_activeContact.isEmpty()) return;

    const std::vector<Message>& all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);

    for (int i = start; i < static_cast<int>(all.size()); ++i) {
        const Message& m = all[i];
        const QString label = (m.direction() == Message::Direction::Sent)
            ? QStringLiteral("me: ") + m.plaintext()
            : QStringLiteral("%1: %2").arg(m.senderUsername(), m.plaintext());
        m_thread->addItem(label);
    }

    m_loadOlderButton->setVisible(start > 0);
}

void MainWindow::selectContact(const QString& username)
{
    if (m_selectionMode) exitSelectionMode();
    m_activeContact = username;
    m_store.conversation(username.toStdString()).renderLimit = kPageSize;
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
    const std::string activeKey = m_activeContact.toStdString();
    const int current = m_store.conversation(activeKey).renderLimit;
    const int total   = m_store.countMessagesFor(activeKey);
    // Don't grow the render window past the number of messages we actually have.
    m_store.conversation(activeKey).renderLimit = qMin(current + kPageSize, total);
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
    MessageStore::Conversation& conv = m_store.conversation(username.toStdString());
    conv.sessionId = std::string{};  // empty == not-yet-initialised
    conv.sentFirstMessage = false;
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
    if (!m_store.hasConversation(name.toStdString())) {
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

bool MainWindow::sendTextToContact(const QString& contact, const QString& text)
{
    QString sessionId = QString::fromStdString(m_store.conversation(contact.toStdString()).sessionId);
    QString msgId;

    try {
        if (sessionId.isEmpty()) {
            // First message to this contact — fetch keybundle, run x3dh_send.
            QJsonObject bundle;
            const QString fetchErr = m_client->fetchKeybundle(contact, &bundle);
            if (!fetchErr.isEmpty()) {
                QMessageBox::warning(this, tr("Couldn't reach %1").arg(contact), fetchErr);
                return false;
            }
            PeerKeyBundle peer;
            peer.ikPub   = b64dec(bundle.value(QStringLiteral("ik_x25519")));
            peer.signPub = b64dec(bundle.value(QStringLiteral("ik_ed25519")));
            const QJsonObject spk = bundle.value(QStringLiteral("spk")).toObject();
            peer.spkPub = b64dec(spk.value(QStringLiteral("public_key")));
            peer.spkSig = b64dec(spk.value(QStringLiteral("signature")));
            const QJsonValue opkVal = bundle.value(QStringLiteral("opk"));
            if (opkVal.isObject())
                peer.opkPub = b64dec(opkVal.toObject().value(QStringLiteral("public_key")));

            const X3dhSendResult r = m_client->daemon()->x3dhSend(contact, text, peer);

            QJsonObject hdr;
            hdr.insert(QStringLiteral("ik_a"), QString::fromUtf8(r.ikPub.toBase64()));
            hdr.insert(QStringLiteral("ek_a"), QString::fromUtf8(r.ekPub.toBase64()));
            if (!r.usedOpkPub.isEmpty())
                hdr.insert(QStringLiteral("used_opk_pub"),
                           QString::fromUtf8(r.usedOpkPub.toBase64()));

            const QString err = m_client->sendMessage(contact,
                                                      r.ciphertext, r.nonce,
                                                      r.ratchetPub, r.pn, r.n,
                                                      &hdr, &msgId);
            if (!err.isEmpty()) {
                QMessageBox::warning(this, tr("Send failed"), err);
                return false;
            }
            MessageStore::Conversation& conv = m_store.conversation(contact.toStdString());
            conv.sessionId = r.sessionId.toStdString();
            conv.sentFirstMessage = true;
        } else {
            const EncryptedMessage enc =
                m_client->daemon()->encryptMessage(sessionId, text);
            const QString err = m_client->sendMessage(contact,
                                                      enc.ciphertext, enc.nonce,
                                                      enc.ratchetPub, enc.pn, enc.n,
                                                      nullptr, &msgId);
            if (!err.isEmpty()) {
                QMessageBox::warning(this, tr("Send failed"), err);
                return false;
            }
        }
    } catch (const CryptoDaemonError& e) {
        QMessageBox::warning(this, tr("Encrypt failed"), e.message());
        return false;
    }

    Message mine;
    mine.setId(msgId);
    mine.setDirection(Message::Direction::Sent);
    mine.setSenderUsername(m_client->username());
    mine.setPlaintext(text);
    mine.setCreatedAt(QDateTime::fromString(nowIso(), Qt::ISODate));
    appendMessage(contact, mine);
    return true;
}

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
    sendTextToContact(m_activeContact, text);
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
                                             QString::fromStdString(m_store.lastInboxId()), QString());
    if (!err.isEmpty()) {
        // Quiet: poll failures shouldn't spam dialogs.
        return;
    }
    if (inbox.isEmpty()) return;

    // The server returns newest-first; decrypt oldest-first so the Double
    // Ratchet receive chain advances in order.
    QList<QJsonObject> ordered;
    ordered.reserve(inbox.size());
    std::transform(inbox.begin(), inbox.end(), std::back_inserter(ordered),
        [](const QJsonValue& v) { return v.toObject(); });
    // reverse so Double Ratchet receive chain advances oldest-first
    std::reverse(ordered.begin(), ordered.end()); // server returns newest-first

    // The newest id in this batch becomes the next poll cursor regardless of
    // per-message decrypt success — failed messages are unrecoverable anyway.
    const QString newestId = inbox.first().toObject()
                                 .value(QStringLiteral("id")).toString();

    bool changed = false;
    for (const QJsonObject& m : ordered) {
        // Persist once at the end of the batch instead of per message.
        if (processInboundMessage(m, /*persist=*/false)) changed = true;
    }

    if (!newestId.isEmpty()) m_store.setLastInboxId(newestId.toStdString());
    saveHistory();
    if (changed) renderActiveThread();
}

bool MainWindow::processInboundMessage(const QJsonObject& m, bool persist)
{
    const QString id = m.value(QStringLiteral("id")).toString();
    if (id.isEmpty() || m_store.isIdSeen(id.toStdString())) return false;
    m_store.markIdSeen(id.toStdString());

    const QString sender = m.value(QStringLiteral("sender_username")).toString();

    QString sessionId = QString::fromStdString(m_store.conversation(sender.toStdString()).sessionId);
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
            m_store.conversation(sender.toStdString()).sessionId = sessionId.toStdString();
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

        Message tm;
        tm.setId(id);
        tm.setDirection(Message::Direction::Received);
        tm.setSenderUsername(sender);
        tm.setPlaintext(plaintext);
        tm.setCreatedAt(QDateTime::fromString(
            m.value(QStringLiteral("created_at")).toString(nowIso()), Qt::ISODate));
        appendMessage(sender, tm, persist);
        return true;
    } catch (const CryptoDaemonError& e) {
        if (sender == m_activeContact) {
            m_thread->addItem(tr("[%1] decrypt failed: %2").arg(sender, e.message()));
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
    const QString type = obj.value(QStringLiteral("type")).toString();

    if (type == QStringLiteral("new_message")) {
        const QJsonObject m = obj.value(QStringLiteral("message")).toObject();
        if (processInboundMessage(m, /*persist=*/false)) {
            const QString id = m.value(QStringLiteral("id")).toString();
            if (!id.isEmpty()) m_store.setLastInboxId(id.toStdString());
            saveHistory();
        }
        return;
    }

    if (type == QStringLiteral("message_deleted")) {
        const QString msgId = obj.value(QStringLiteral("message_id")).toString();
        if (msgId.isEmpty()) return;

        // Remove the message from the local cache (find_if + erase, inside the store).
        if (m_store.hasMessageId(msgId.toStdString())) {
            m_store.removeMessageById(msgId.toStdString());
            saveHistory();
            renderActiveThread();
        }
    }
}

// ---------------------------------------------------------------------------
// Selection mode
// ---------------------------------------------------------------------------

void MainWindow::enterSelectionMode(int initialRow)
{
    m_selectionMode = true;
    m_thread->setSelectionMode(QAbstractItemView::MultiSelection);
    m_thread->clearSelection();
    if (initialRow >= 0 && initialRow < m_thread->count())
        m_thread->item(initialRow)->setSelected(true);
    // indent items right to make room for the circles
    m_thread->setStyleSheet(QStringLiteral("QListWidget::item { padding-left: 30px; }"));
    m_composeWidget->setVisible(false);
    m_selectionBar->setVisible(true);
    onSelectionChanged();
    m_thread->viewport()->update();
}

void MainWindow::exitSelectionMode()
{
    m_selectionMode = false;
    m_thread->setSelectionMode(QAbstractItemView::SingleSelection);
    m_thread->clearSelection();
    m_thread->setStyleSheet(QString());
    m_selectionBar->setVisible(false);
    m_composeWidget->setVisible(true);
    m_thread->viewport()->update();
}

void MainWindow::onSelectionChanged()
{
    if (!m_selectionMode) return;
    const int n = m_thread->selectedItems().count();
    m_selectionCountLabel->setText(
        n == 1 ? tr("1 message selected")
               : tr("%1 messages selected").arg(n));
    m_selectionDeleteButton->setEnabled(n > 0);
    m_selectionForwardButton->setEnabled(n > 0);
    m_selectionDownloadButton->setEnabled(n > 0);
}

void MainWindow::onSelectionDeleteClicked()
{
    if (m_activeContact.isEmpty()) return;
    const QList<QListWidgetItem*> selected = m_thread->selectedItems();
    if (selected.isEmpty()) return;

    const std::vector<Message>& all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);

    // Validate — all selected messages must have a server UUID
    QStringList ids;
    for (const QListWidgetItem* item : selected) {
        const int idx = start + m_thread->row(item);
        if (idx < 0 || idx >= static_cast<int>(all.size())) continue;
        if (all.at(idx).id().isEmpty()) {
            QMessageBox::warning(this, tr("Cannot delete"),
                                 tr("One or more selected messages have no server ID."));
            return;
        }
        ids << all.at(idx).id();
    }
    if (ids.isEmpty()) return;

    // Delete from server and local cache one at a time. Use ID-based lookup so
    // earlier removals don't shift the indices of later ones.
    for (const QString& id : ids) {
        const QString err = m_client->deleteMessage(id);
        if (!err.isEmpty()) {
            QMessageBox::warning(this, tr("Delete failed"), err);
            break; // leave any remaining messages in place — user can retry
        }
        m_store.removeMessageById(id.toStdString());
    }

    saveHistory();
    exitSelectionMode();
    renderActiveThread();
}

// ---------------------------------------------------------------------------
// Event filter — left-click on the ⋮ zone triggers the context menu
// ---------------------------------------------------------------------------

bool MainWindow::eventFilter(QObject* obj, QEvent* event)
{
    if (obj == m_thread->viewport() && event->type() == QEvent::MouseButtonPress) {
        const auto* me = static_cast<QMouseEvent*>(event);
        if (me->button() == Qt::LeftButton) {
            if (m_selectionMode) {
                QListWidgetItem* item = m_thread->itemAt(me->pos());
                if (item) {
                    const QRect rect = m_thread->visualItemRect(item);
                    const QRect circleZone(rect.left(), rect.top(),
                                           kCircleZoneWidth, rect.height());
                    if (circleZone.contains(me->pos())) {
                        // Circle hit — let MultiSelection toggle it natively.
                        return false;
                    }
                }
                // Anywhere outside a circle: clear all and consume.
                m_thread->clearSelection();
                return true;
            } else {
                // Normal mode: left-click on the ⋮ zone shows the context menu.
                const QListWidgetItem* item = m_thread->itemAt(me->pos());
                if (item) {
                    const QRect rect = m_thread->visualItemRect(item);
                    const QRect dotsZone(rect.right() - kDotsZoneWidth, rect.top(),
                                         kDotsZoneWidth, rect.height());
                    if (dotsZone.contains(me->pos())) {
                        onThreadContextMenu(me->pos());
                        return true;
                    }
                }
            }
        }
    }
    return QMainWindow::eventFilter(obj, event);
}

// ---------------------------------------------------------------------------
// Delete (right-click anywhere on row, or left-click ⋮)
// ---------------------------------------------------------------------------

void MainWindow::onThreadContextMenu(const QPoint& pos)
{
    if (m_selectionMode) return; // selection bar owns actions in selection mode
    const QListWidgetItem* item = m_thread->itemAt(pos);
    if (!item) return;
    const int row = m_thread->row(item);

    QMenu menu(this);
    QAction* deleteAction       = menu.addAction(tr("Delete message"));
    QAction* forwardAction      = menu.addAction(tr("Forward message…"));
    QAction* saveMessageAction  = menu.addAction(tr("Download message"));
    QAction* saveConvoAction    = menu.addAction(tr("Download conversation"));
    menu.addSeparator();
    QAction* selectAction       = menu.addAction(tr("Select messages…"));

    // "Revoke access…" only applies to a message we forwarded to this contact,
    // identified by the leading forward-arrow marker (↪) on its text.
    const std::vector<Message>& menuMsgs = m_store.conversation(m_activeContact.toStdString()).messages;
    const int menuLimit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int menuStart = qMax(0, static_cast<int>(menuMsgs.size()) - menuLimit);
    const int menuIdx   = menuStart + row;
    const bool isForwarded = menuIdx >= 0 && menuIdx < static_cast<int>(menuMsgs.size())
                             && menuMsgs.at(menuIdx).plaintext().startsWith(QChar(0x21AA));
    QAction* revokeAction       = isForwarded ? menu.addAction(tr("Revoke access…")) : nullptr;

    const QAction* chosen       = menu.exec(m_thread->mapToGlobal(pos));
    if (!chosen) return;

    if (chosen == revokeAction)      { onRevokeAccess(row);     return; }
    if (chosen == selectAction)      { enterSelectionMode(row); return; }
    if (chosen == forwardAction)     { onForwardSingle(row);    return; }
    if (chosen == saveMessageAction) { onDownloadSingle(row);   return; }
    if (chosen == saveConvoAction) {
        saveMessagesToFile(m_store.messagesFor(m_activeContact.toStdString()),
                           QStringLiteral("conversation_with_%1.txt").arg(m_activeContact));
        return;
    }
    if (chosen != deleteAction)  { return; }

    // --- Delete single message ---
    const std::vector<Message>& all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);
    const int idx   = start + row;
    if (idx < 0 || idx >= static_cast<int>(all.size())) return;

    const QString msgId = all.at(idx).id();
    if (msgId.isEmpty()) {
        QMessageBox::warning(this, tr("Cannot delete"),
                             tr("This message has no server ID and cannot be deleted remotely."));
        return;
    }

    const QString err = m_client->deleteMessage(msgId);
    if (!err.isEmpty()) {
        QMessageBox::warning(this, tr("Delete failed"), err);
        return;
    }

    m_store.removeMessageById(msgId.toStdString());
    saveHistory();
    renderActiveThread();
}

void MainWindow::onRevokeAccess(int row)
{
    const std::vector<Message>& all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);
    const int idx   = start + row;
    if (idx < 0 || idx >= static_cast<int>(all.size())) return;

    const QString msgId = all.at(idx).id();
    if (msgId.isEmpty()) {
        QMessageBox::warning(this, tr("Cannot revoke"),
                             tr("This message has no server ID and cannot be revoked."));
        return;
    }

    const auto confirm = QMessageBox::question(
        this, tr("Revoke access"),
        tr("Revoke the recipient's access to this forwarded message? "
           "They will no longer be able to view it."),
        QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
    if (confirm != QMessageBox::Yes) return;

    const QString err = m_client->revokeAccess(msgId);
    if (!err.isEmpty()) {
        QMessageBox::warning(this, tr("Revoke failed"), err);
        return;
    }

    // The message stays visible on our (sender) side; only the recipient's
    // client removes it, via the message_deleted WebSocket push.
    QMessageBox::information(this, tr("Access revoked"),
                             tr("Access revoked. The recipient can no longer see this message."));
}

// ---------------------------------------------------------------------------
// Forward
// ---------------------------------------------------------------------------

QString MainWindow::pickForwardTarget(const QString& excludeUsername)
{
    // Build contact list from everyone we have a thread with, minus current contact.
    // contactUsernames() returns std::vector<std::string>, already sorted.
    QStringList contacts;
    for (const std::string& c : m_store.contactUsernames()) {
        const QString cu = QString::fromStdString(c);
        if (cu != excludeUsername) contacts << cu;
    }

    bool ok = false;
    QString target;
    if (contacts.isEmpty()) {
        target = QInputDialog::getText(this, tr("Forward to"),
                                       tr("Username:"), QLineEdit::Normal,
                                       QString{}, &ok).trimmed();
    } else {
        // Editable so the user can also type someone not yet in their contacts.
        target = QInputDialog::getItem(this, tr("Forward to"),
                                       tr("Select or type a contact:"),
                                       contacts, 0, /*editable=*/true, &ok).trimmed();
    }
    return ok ? target : QString{};
}

void MainWindow::onForwardSingle(int row)
{
    const QString target = pickForwardTarget(m_activeContact);
    if (target.isEmpty()) return;
    if (target == m_client->username()) {
        QMessageBox::warning(this, tr("Cannot forward"),
                             tr("You cannot forward a message to yourself."));
        return;
    }

    const std::vector<Message>& all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);
    const int idx   = start + row;
    if (idx < 0 || idx >= static_cast<int>(all.size())) return;

    // Client-side re-encryption — decrypt already cached, re-encrypt fresh.
    const Message& msg = all.at(idx);
    const QString origSender = (msg.direction() == Message::Direction::Sent)
                                   ? m_client->username() : msg.senderUsername();
    const QString fwdText = QChar(0x21AA) + QStringLiteral(" from ")
                            + origSender + QStringLiteral(": ") + msg.plaintext();
    if (sendTextToContact(target, fwdText))
        QMessageBox::information(this, tr("Forwarded"),
                                 tr("Message forwarded to %1.").arg(target));
}

void MainWindow::onSelectionForwardClicked()
{
    if (m_activeContact.isEmpty()) return;
    const QList<QListWidgetItem*> selected = m_thread->selectedItems();
    if (selected.isEmpty()) return;

    const QString target = pickForwardTarget(m_activeContact);
    if (target.isEmpty()) return;
    if (target == m_client->username()) {
        QMessageBox::warning(this, tr("Cannot forward"),
                             tr("You cannot forward messages to yourself."));
        return;
    }

    // Snapshot copy: sendTextToContact() below may insert a new conversation
    // into the store and rehash it, which would invalidate a live reference.
    const std::vector<Message> all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);

    // The first call may do X3DH (establishing a session); subsequent calls in
    // this loop use the ratchet session created by the first.
    int successCount = 0;
    for (const QListWidgetItem* item : selected) {
        const int idx = start + m_thread->row(item);
        if (idx < 0 || idx >= static_cast<int>(all.size())) continue;
        const Message& msg = all.at(idx);
        const QString origSender = (msg.direction() == Message::Direction::Sent)
                                       ? m_client->username() : msg.senderUsername();
        const QString fwdText = QChar(0x21AA) + QStringLiteral(" from ")
                                + origSender + QStringLiteral(": ") + msg.plaintext();
        if (!sendTextToContact(target, fwdText)) {
            exitSelectionMode();
            return;
        }
        ++successCount;
    }

    QMessageBox::information(this, tr("Forwarded"),
                             tr("%1 message(s) forwarded to %2.").arg(successCount).arg(target));
    exitSelectionMode();
}

// ---------------------------------------------------------------------------
// Download / save to .txt
// ---------------------------------------------------------------------------

void MainWindow::saveMessagesToFile(const std::vector<Message>& messages,
                                    const QString& defaultName)
{
    if (messages.empty()) return;

    const QString path = QFileDialog::getSaveFileName(
        this, tr("Save messages"), defaultName,
        tr("Text files (*.txt);;All files (*)"));
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Save failed"),
                             tr("Could not open file for writing: %1").arg(path));
        return;
    }

    QTextStream out(&f);
    out.setEncoding(QStringConverter::Utf8);
    for (const Message& m : messages) {
        // Render the stored timestamp into a readable local time string.
        const QDateTime dt = m.createdAt();
        const QString ts = dt.isValid()
            ? dt.toLocalTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
            : dt.toString(Qt::ISODate);
        const QString sender = (m.direction() == Message::Direction::Sent)
                                   ? m_client->username() : m.senderUsername();
        out << QStringLiteral("[%1] %2: %3\n").arg(ts, sender, m.plaintext());
    }
    f.close();
}

void MainWindow::onDownloadSingle(int row)
{
    if (m_activeContact.isEmpty()) return;
    const std::vector<Message>& all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);
    const int idx   = start + row;
    if (idx < 0 || idx >= static_cast<int>(all.size())) return;

    std::vector<Message> single;
    single.push_back(all.at(idx));
    saveMessagesToFile(single,
        QStringLiteral("message_%1.txt").arg(
            QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))));
}

void MainWindow::onSelectionDownloadClicked()
{
    if (m_activeContact.isEmpty()) return;
    const QList<QListWidgetItem*> selected = m_thread->selectedItems();
    if (selected.isEmpty()) return;

    const std::vector<Message>& all = m_store.conversation(m_activeContact.toStdString()).messages;
    const int limit = m_store.conversation(m_activeContact.toStdString()).renderLimit;
    const int start = qMax(0, static_cast<int>(all.size()) - limit);

    QList<int> indices;
    for (const QListWidgetItem* item : selected) {
        const int idx = start + m_thread->row(item);
        if (idx >= 0 && idx < static_cast<int>(all.size()))
            indices.append(idx);
    }
    std::sort(indices.begin(), indices.end());

    std::vector<Message> toSave;
    for (int idx : indices)
        toSave.push_back(all.at(idx));

    saveMessagesToFile(toSave,
        QStringLiteral("selected_messages_%1_%2.txt")
            .arg(m_activeContact,
                 QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))));
    exitSelectionMode();
}
