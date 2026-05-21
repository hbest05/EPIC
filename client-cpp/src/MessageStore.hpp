#pragma once

/**
 * MessageStore.hpp — Local message cache.
 *
 * Responsibilities:
 *   1. Cache messages in memory for the UI
 *   2. Delegate encrypt/decrypt to the Python crypto daemon via Unix socket
 *   3. Optionally persist the cache to a local SQLite DB (future work)
 *
 * Crypto operations are NOT performed here — they are delegated to the
 * Python crypto daemon over a Unix domain socket (IPC).
 */

#include <QObject>
#include <QList>
#include <QByteArray>

#include "Message.hpp"
#include "User.hpp"

class MessageStore : public QObject
{
    Q_OBJECT

public:
    explicit MessageStore(QObject* parent = nullptr);

    /**
     * Request encryption of `plaintext` for `recipient` via the Python crypto
     * daemon and return a Message ready for transmission.
     *
     * TODO: delegate to Python crypto daemon via Unix socket
     *
     * @param plaintext UTF-8 message text
     * @param recipient Must have x25519PublicKey populated
     * @param sender    Local user (daemon holds the private key)
     */
    Message encryptMessage(const QString& plaintext, const User& recipient, const User& sender);

    /**
     * Request decryption of an incoming Message via the Python crypto daemon.
     * Returns false if the daemon reports a failure.
     *
     * TODO: delegate to Python crypto daemon via Unix socket
     *
     * @param message   Message with ciphertext and ratchet header
     * @param sender    Remote user with ed25519PublicKey and x25519PublicKey
     * @param localUser Local user (daemon holds the private key)
     * @returns true on success, false on decryption failure
     */
    bool decryptMessage(Message& message, const User& sender, const User& localUser);

    // --- Cache access ---
    QList<Message> messagesFor(const QString& contactUsername) const;
    void addMessage(const Message& msg);
    void clearCache();

signals:
    void newMessageReceived(const Message& msg);

private:
    QList<Message> m_cache;
};
