#pragma once

/**
 * MessageStore.hpp — Structured local cache + conversation state manager.
 *
 * Holds one Conversation per contact: the Double Ratchet session id, the
 * "first message sent" flag, the per-contact render window, and the full
 * decrypted message history (oldest first). This is the source of truth for
 * the thread view, since the Double Ratchet consumes each message key on
 * first decrypt and server ciphertext cannot be re-decrypted after a restart.
 *
 * Encryption/decryption is handled by MainWindow via CryptoDaemonClient —
 * MessageStore is a structured local cache and conversation state manager.
 *
 * As the core data layer (not a GUI class), MessageStore uses STL containers
 * (std::string / std::vector / std::unordered_map / std::unordered_set)
 * internally; Qt types are confined to the QObject signal boundary.
 */

#include <QObject>
#include <QString>

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "Message.hpp"

class MessageStore : public QObject
{
    Q_OBJECT

public:
    explicit MessageStore(QObject* parent = nullptr);

    /** All per-contact conversation state: session, flags, render window,
     *  and decrypted message history. */
    struct Conversation
    {
        std::string sessionId;
        bool sentFirstMessage = false;
        int renderLimit = 30;
        std::vector<Message> messages;
    };

    // Store/retrieve conversations
    Conversation& conversation(const std::string& contactUsername);
    const Conversation* conversationPtr(const std::string& contactUsername) const;
    bool hasConversation(const std::string& contactUsername) const;
    std::vector<std::string> contactUsernames() const;  // returns all keys, sorted

    // Message operations (kept for backward compat + STL demo)
    void addMessage(const std::string& contactUsername, const Message& msg);
    bool hasMessageId(const std::string& id) const;        // uses std::any_of
    void markIdSeen(const std::string& id);
    bool isIdSeen(const std::string& id) const;
    void removeMessageById(const std::string& msgId);      // uses std::find_if + erase
    std::vector<Message> messagesFor(const std::string& contactUsername) const; // uses std::copy_if
    std::vector<Message> receivedMessagesFor(const std::string& contactUsername) const; // uses std::copy_if
    int countMessagesFor(const std::string& contactUsername) const;             // uses std::count_if

    // Persistence cursor
    const std::string& lastInboxId() const { return m_lastInboxId; }
    void setLastInboxId(const std::string& id) { m_lastInboxId = id; }

    void clear();

signals:
    void messageAdded(const QString& contactUsername, const Message& msg);

private:
    std::unordered_map<std::string, Conversation> m_conversations;
    std::unordered_set<std::string> m_seenIds;
    std::string m_lastInboxId;
};
