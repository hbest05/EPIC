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
    explicit MainWindow(Client* client, QWidget* parent = nullptr);

private slots:
    void onSendClicked();
    void onAddContactClicked();
    void onContactSelected(QListWidgetItem* item);
    void pollInbox();

private:
    /** Bind the active contact and refresh the thread view. */
    void selectContact(const QString& username);

    /** Establish a Double Ratchet session with a new contact by fetching
     *  their key bundle and running x3dh_send for the opening message. */
    bool startSessionWith(const QString& username, QString* err);

    Client*  m_client;                 // not owned
    QTimer*  m_pollTimer;

    QListWidget* m_contactList;
    QTextEdit*   m_thread;
    QLineEdit*   m_compose;
    QPushButton* m_sendButton;
    QPushButton* m_addContactButton;
    QLabel*      m_topBar;

    QString m_activeContact;

    /** Per-contact Double Ratchet session id, returned by the daemon. */
    QHash<QString, QString> m_sessions;
    /** Inbox ids we've already rendered, to keep polling idempotent. */
    QSet<QString> m_seenMessageIds;
    /** True once the first outgoing message of a session has been sent;
     *  controls whether to ship the X3DH initiator header. */
    QHash<QString, bool> m_sentFirstMessage;
};
