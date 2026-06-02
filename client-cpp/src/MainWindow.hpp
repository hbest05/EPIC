#pragma once

/**
 * MainWindow.hpp — post-auth chat window.
 *
 * Layout: contact list on the left, message thread on the right with a
 * compose box at the bottom, top bar showing server hostname / username
 * / TLS indicator. Inbound messages arrive in real time over a QWebSocket
 * to /ws; each is pushed through the crypto daemon's decrypt path before
 * display. pollInbox() runs once on login (and on each reconnect) as a
 * fallback to catch messages that arrived while offline.
 */

#include <QtCore/QString>
#include <QtWidgets/QMainWindow>

#include <vector>

#include "Message.hpp"
#include "MessageStore.hpp"
#include "TofuStore.hpp"

class Client;
class QJsonObject;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPushButton;
class QTimer;
class QWebSocket;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    /** @param freshRegistration when true, skip the startup OPK replenish —
     *  registration has already uploaded a full prekey batch, so replenishing
     *  again would push a second batch the daemon hasn't tracked in memory. */
    explicit MainWindow(Client* client, bool freshRegistration = false,
                        QWidget* parent = nullptr);

    bool eventFilter(QObject* obj, QEvent* event) override;

private slots:
    void onSendClicked();
    void onAddContactClicked();
    void onChangePasswordClicked();
    void onThreadContextMenu(const QPoint& pos);
    void onRevokeAccess(int row);
    void onContactSelected(QListWidgetItem* item);
    void onLoadOlderClicked();
    void pollInbox();

    void onSelectionChanged();
    void onSelectionDeleteClicked();
    void onSelectionForwardClicked();
    void onSelectionDownloadClicked();
    void onForwardSingle(int row);
    void onDownloadSingle(int row);
    void enterSelectionMode(int initialRow = -1);
    void exitSelectionMode();

    // --- Real-time delivery socket ---
    void onWsConnected();
    void onWsDisconnected();
    void onWsTextMessage(const QString& text);

private:
    /** Bind the active contact and refresh the thread view. */
    void selectContact(const QString& username);

    /** Establish a Double Ratchet session with a new contact by fetching
     *  their key bundle and running x3dh_send for the opening message. */
    bool startSessionWith(const QString& username, QString* err);

    /** Encrypt and send text to contact (handles X3DH vs ratchet, appends to
     *  local thread). Used by onSendClicked and the forward paths. */
    bool sendTextToContact(const QString& contact, const QString& text);

    /** Add a contact to the list widget if it isn't already present. */
    void ensureContact(const QString& username);

    /** Record a message in the in-memory thread map and (optionally) persist. */
    void appendMessage(const QString& contact, const Message& msg, bool persist = true);

    /** Repaint the thread view for the active contact, honouring the
     *  per-contact render window used by "Load older messages". */
    void renderActiveThread();

    /** Restore the peer-username -> session-id map from the daemon's
     *  persisted sessions after login. */
    void restoreSessions();

    /** Decrypt and append a single inbound message object (the shape returned
     *  by /messages/inbox and pushed over the WebSocket). Handles dedupe,
     *  x3dh_receive on a new session, and Double Ratchet decrypt.
     *  @returns true if a new message was appended. */
    bool processInboundMessage(const QJsonObject& m, bool persist);

    /** Open (or reopen) the QWebSocket to /ws, authenticating with the
     *  access_token cookie. */
    void connectWebSocket();

    /** Arm the reconnect timer using the current exponential backoff delay,
     *  then double the delay up to the 30s ceiling. */
    void scheduleReconnect();

    /** Local plaintext history cache (per logged-in user). */
    QString historyFilePath() const;
    void    loadHistory();
    void    saveHistory() const;

    Client*  m_client;                 // not owned

    QWebSocket* m_webSocket;
    QTimer*     m_reconnectTimer;       // single-shot; fires connectWebSocket()
    int         m_reconnectDelayMs;     // current backoff delay, capped at kMaxReconnectMs

    QListWidget* m_contactList;
    QListWidget* m_thread;
    QLineEdit*   m_compose;
    QPushButton* m_sendButton;
    QPushButton* m_addContactButton;
    QPushButton* m_changePasswordButton;
    QPushButton* m_loadOlderButton;
    QLabel*      m_topBar;

    bool         m_selectionMode = false;
    QWidget*     m_composeWidget;
    QWidget*     m_selectionBar;
    QLabel*      m_selectionCountLabel;
    QPushButton* m_selectionDeleteButton;
    QPushButton* m_selectionForwardButton;
    QPushButton* m_selectionDownloadButton;

    /** Show a contact-picker dialog; returns chosen username or empty on cancel.
     *  Excludes excludeUsername (the active contact) from the suggestion list. */
    QString pickForwardTarget(const QString& excludeUsername = QString());

    /** Write messages to a .txt file chosen via a save dialog.
     *  defaultName is suggested in the file chooser. */
    void saveMessagesToFile(const std::vector<Message>& messages,
                            const QString& defaultName);

    QString m_activeContact;

    /** Owns all per-contact conversation state (session id, first-message
     *  flag, render window, decrypted history), the seen-id set, and the
     *  incremental-poll cursor. */
    MessageStore m_store;

    /** Trust-On-First-Use identity-key pins, checked before every X3DH session
     *  setup to catch a peer's identity key changing under us (MITM signal). */
    TofuStore m_tofuStore;

    static constexpr int kPageSize = 30;

    /** WebSocket reconnect backoff bounds: start at 1s, double each failed
     *  attempt, cap at 30s. */
    static constexpr int kInitialReconnectMs = 1000;
    static constexpr int kMaxReconnectMs     = 30000;
};
