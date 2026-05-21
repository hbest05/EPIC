/**
 * MessageStore.cpp — Message cache implementation.
 */

#include "MessageStore.hpp"
#include <QDebug>

MessageStore::MessageStore(QObject* parent)
    : QObject(parent)
{
}

Message MessageStore::encryptMessage(
    const QString& plaintext,
    const User& recipient,
    const User& sender)
{
    Message msg;

    // TODO: delegate to Python crypto daemon via Unix socket
    // Send plaintext + recipient public key to daemon, receive ciphertext + header

    qWarning() << "MessageStore::encryptMessage: not implemented yet";
    return msg;
}

bool MessageStore::decryptMessage(
    Message& message,
    const User& sender,
    const User& localUser)
{
    // TODO: delegate to Python crypto daemon via Unix socket
    // Send ciphertext + ratchet header to daemon, receive plaintext

    qWarning() << "MessageStore::decryptMessage: not implemented yet";
    return false;
}

QList<Message> MessageStore::messagesFor(const QString& contactUsername) const
{
    QList<Message> result;
    for (const Message& msg : m_cache) {
        if (msg.senderUsername() == contactUsername ||
            msg.recipientUsername() == contactUsername) {
            result.append(msg);
        }
    }
    return result;
}

void MessageStore::addMessage(const Message& msg)
{
    m_cache.append(msg);
    emit newMessageReceived(msg);
}

void MessageStore::clearCache()
{
    m_cache.clear();
}
