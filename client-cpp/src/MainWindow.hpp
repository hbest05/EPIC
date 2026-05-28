#pragma once

/**
 * MainWindow.hpp — post-auth chat window.
 *
 * Layout: contact list on the left, message thread on the right with a
 * compose box at the bottom, top bar showing server hostname / username
 * / TLS indicator. A 5-second QTimer polls /messages/inbox; new messages
 * are pushed through the crypto daemon's decrypt path before display.
 */

#include <QtCore/QHash>
#include <QtCore/QSet>
#include <QtCore/QString>
#include <QtWidgets/QMainWindow>

class Client;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPushButton;
class QTextEdit;
class QTimer;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    /** @param freshRegistration when true, skip the startup OPK replenish —
     *  registration has already uploaded a full prekey batch, so replenishing
     *  again would push a second batch the daemon hasn't tracked in memory. */
    explicit MainWindow(Client* client, bool freshRegistration = false,
                        QWidget* parent = nullptr);

private slots:
    void onSendClicked();
    void onAddContactClicked();
    void onContactSelected(QListWidgetItem* item);
    void onLoadOlderClicked();
    void pollInbox();

private:
    /** One displayed message in a conversation thread. Persisted to the local
     *  plaintext history cache so threads survive a client restart — the
     *  Double Ratchet consumes message keys on first decrypt, so server
     *  ciphertext cannot be re-decrypted later. */
    struct ThreadMessage
    {
        QString id;
        bool    fromMe = false;
        QString sender;     ///< username of the sender (us, or the contact)
        QString text;
        QString ts;         ///< ISO-8601 timestamp for ordering
    };

    /** Bind the active contact and refresh the thread view. */
    void selectContact(const QString& username);

    /** Establish a Double Ratchet session with a new contact by fetching
     *  their key bundle and running x3dh_send for the opening message. */
    bool startSessionWith(const QString& username, QString* err);

    /** Add a contact to the list widget if it isn't already present. */
    void ensureContact(const QString& username);

    /** Record a message in the in-memory thread map and (optionally) persist. */
    void appendMessage(const QString& contact, const ThreadMessage& msg, bool persist = true);

    /** Repaint the thread view for the active contact, honouring the
     *  per-contact render window used by "Load older messages". */
    void renderActiveThread();

    /** Restore the peer-username -> session-id map from the daemon's
     *  persisted sessions after login. */
    void restoreSessions();

    /** Local plaintext history cache (per logged-in user). */
    QString historyFilePath() const;
    void    loadHistory();
    void    saveHistory() const;

    Client*  m_client;                 // not owned
    QTimer*  m_pollTimer;

    QListWidget* m_contactList;
    QTextEdit*   m_thread;
    QLineEdit*   m_compose;
    QPushButton* m_sendButton;
    QPushButton* m_addContactButton;
    QPushButton* m_loadOlderButton;
    QLabel*      m_topBar;

    QString m_activeContact;

    /** Per-contact Double Ratchet session id, returned by the daemon. */
    QHash<QString, QString> m_sessions;
    /** Inbox ids we've already rendered, to keep polling idempotent. */
    QSet<QString> m_seenMessageIds;
    /** True once the first outgoing message of a session has been sent;
     *  controls whether to ship the X3DH initiator header. */
    QHash<QString, bool> m_sentFirstMessage;

    /** Full decrypted history per contact, oldest first. */
    QHash<QString, QList<ThreadMessage>> m_threads;
    /** How many trailing messages to show per contact; grows on "Load older". */
    QHash<QString, int> m_renderLimit;
    /** Server id of the newest inbox message we've processed — the cursor for
     *  incremental polling (?after=<id>). */
    QString m_lastInboxId;

    static constexpr int kPageSize = 30;
};
