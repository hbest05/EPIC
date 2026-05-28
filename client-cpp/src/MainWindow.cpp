/**
 * MainWindow.cpp — chat UI + inbox polling loop.
 *
 * Outbound: encryptMessage / x3dhSend through the daemon, then POST.
 * Inbound: poll /messages/inbox every 5 s, run x3dhReceive on any new
 * session, then decryptMessage to obtain plaintext for display. Session
 * ids are kept in m_sessions keyed by contact username.
 */

#include "MainWindow.hpp"

#include "Client.hpp"
#include "CryptoDaemonClient.hpp"

#include <QtCore/QJsonArray>
#include <QtCore/QJsonObject>
#include <QtCore/QTimer>
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

} // namespace

MainWindow::MainWindow(Client* client, bool freshRegistration, QWidget* parent)
    : QMainWindow(parent)
    , m_client(client)
    , m_pollTimer(new QTimer(this))
    , m_contactList(new QListWidget(this))
    , m_thread(new QTextEdit(this))
    , m_compose(new QLineEdit(this))
    , m_sendButton(new QPushButton(tr("Send"), this))
    , m_addContactButton(new QPushButton(tr("Add contact"), this))
    , m_topBar(new QLabel(this))
{
    setWindowTitle(tr("SecureMsg"));
    resize(900, 600);

    m_thread->setReadOnly(true);
    m_compose->setPlaceholderText(tr("Type a message…"));

    auto* left = new QWidget(this);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->addWidget(m_addContactButton);
    leftLayout->addWidget(m_contactList);

    auto* right = new QWidget(this);
    auto* rightLayout = new QVBoxLayout(right);
    auto* composeRow = new QHBoxLayout;
    composeRow->addWidget(m_compose);
    composeRow->addWidget(m_sendButton);
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
    connect(m_contactList,      &QListWidget::itemClicked,     this, &MainWindow::onContactSelected);
    connect(m_pollTimer,        &QTimer::timeout,              this, &MainWindow::pollInbox);

    m_pollTimer->start(5000);

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

void MainWindow::selectContact(const QString& username)
{
    m_activeContact = username;
    m_thread->clear();
    m_thread->append(tr("— conversation with %1 —").arg(username));
}

void MainWindow::onContactSelected(QListWidgetItem* item)
{
    if (!item) return;
    selectContact(item->text());
}

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

    QString err;
    if (!startSessionWith(name, &err)) {
        QMessageBox::warning(this, tr("Couldn't add contact"), err);
        return;
    }

    if (m_contactList->findItems(name, Qt::MatchExactly).isEmpty()) {
        m_contactList->addItem(name);
    }
    selectContact(name);
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

    m_thread->append(QStringLiteral("me: ") + text);
}

void MainWindow::pollInbox()
{
    QJsonArray inbox;
    const QString err = m_client->fetchInbox(&inbox);
    if (!err.isEmpty()) {
        // Quiet: poll failures shouldn't spam dialogs.
        return;
    }

    for (const QJsonValue& v : inbox) {
        const QJsonObject m = v.toObject();
        const QString id = m.value(QStringLiteral("id")).toString();
        if (m_seenMessageIds.contains(id)) continue;
        m_seenMessageIds.insert(id);

        const QString sender = m.value(QStringLiteral("sender_username")).toString();

        // First message of a session carries the X3DH header — run receive.
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

                if (m_contactList->findItems(sender, Qt::MatchExactly).isEmpty()) {
                    m_contactList->addItem(sender);
                }
            }
            if (sessionId.isEmpty()) {
                // Subsequent message but we have no session — surface and skip.
                m_thread->append(tr("[%1] (no session — dropping)").arg(sender));
                continue;
            }

            EncryptedMessageFields f;
            f.ciphertext = b64dec(m.value(QStringLiteral("ciphertext")));
            f.nonce      = b64dec(m.value(QStringLiteral("nonce")));
            f.ratchetPub = b64dec(m.value(QStringLiteral("ratchet_pub")));
            f.pn         = m.value(QStringLiteral("pn")).toInt();
            f.n          = m.value(QStringLiteral("n")).toInt();

            const QString plaintext = m_client->daemon()->decryptMessage(sessionId, f);

            if (sender == m_activeContact) {
                m_thread->append(QStringLiteral("%1: %2").arg(sender, plaintext));
            }
        } catch (const CryptoDaemonError& e) {
            m_thread->append(tr("[%1] decrypt failed: %2").arg(sender, e.message()));
        }
    }
}
