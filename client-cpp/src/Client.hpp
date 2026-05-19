#pragma once

/**
 * Client.hpp — Main application controller and top-level window.
 *
 * The Client class is the central coordinator. It owns:
 *   - The local User (identity + keypair)
 *   - The MessageStore (crypto + cache)
 *   - A map of known contacts (remote Users, public-key-only)
 *   - The HTTP session (libcurl) for talking to the FastAPI backend
 *   - The Qt main window UI
 *
 * Qt signals emitted by the HTTP layer (or a polling timer) drive UI updates
 * without blocking the event loop.
 */

#include <QMainWindow>
#include <QTimer>
#include <QMap>
#include <memory>

#include "User.hpp"
#include "MessageStore.hpp"

class Client : public QMainWindow
{
    Q_OBJECT

public:
    explicit Client(QWidget* parent = nullptr);
    ~Client() override;

    // --- Auth ---
    /**
     * POST /api/auth/register — generate keypair, send registration request.
     * TODO: Implement using libcurl (see httpPost helper).
     */
    void registerUser(const QString& username, const QString& email, const QString& password);

    /**
     * POST /api/auth/login — verify credentials, receive JWT, store in memory.
     * TODO: Implement.
     */
    void login(const QString& username, const QString& password);

    void logout();

    // --- Contacts ---
    /**
     * GET /api/auth/user/{username}/pubkeys — fetch a contact's public keys.
     * TODO: Implement and cache in m_contacts.
     */
    void fetchContactKeys(const QString& username);

    // --- Messaging ---
    /**
     * Encrypt and POST a message to /api/messages/send.
     * TODO: Implement.
     */
    void sendMessage(const QString& recipientUsername, const QString& plaintext);

    /**
     * GET /api/messages/inbox — fetch new messages, decrypt, update UI.
     * Called by m_pollTimer every N seconds.
     * TODO: Implement.
     */
    void pollInbox();

private slots:
    void onSendClicked();
    void onLoginClicked();
    void onRegisterClicked();

private:
    // --- HTTP helpers using libcurl ---
    /**
     * Perform a blocking HTTP POST with JSON body.
     * TODO: Move to async (QThread or libcurl multi-handle) to avoid blocking UI.
     */
    QByteArray httpPost(const QString& endpoint, const QByteArray& jsonBody);
    QByteArray httpGet(const QString& endpoint);

    void setupUi();
    void showAuthView();
    void showChatView();

    // --- State ---
    std::unique_ptr<User> m_localUser;
    QMap<QString, std::shared_ptr<User>> m_contacts;
    MessageStore* m_store;
    QTimer* m_pollTimer;

    QString m_jwtToken;
    QString m_activeRecipient;

    // TODO: Add Qt widget members (QListWidget, QTextEdit, etc.)
    static constexpr const char* API_BASE = "http://localhost:8000/api";
};
