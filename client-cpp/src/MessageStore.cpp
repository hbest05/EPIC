/**
 * MessageStore.cpp — structured local cache + conversation state manager.
 *
 * Encryption/decryption is handled by MainWindow via CryptoDaemonClient —
 * MessageStore only stores conversation state and decrypted history.
 *
 * Core storage uses STL containers; Qt appears only at the signal boundary.
 */

#include "MessageStore.hpp"

#include <algorithm>
#include <cctype>

MessageStore::MessageStore(QObject* parent)
    : QObject(parent)
{
}

MessageStore::Conversation& MessageStore::conversation(const std::string& contactUsername)
{
    // operator[] default-constructs a Conversation on first access.
    return m_conversations[contactUsername];
}

const MessageStore::Conversation* MessageStore::conversationPtr(const std::string& contactUsername) const
{
    const auto it = m_conversations.find(contactUsername);
    return it == m_conversations.end() ? nullptr : &it->second;
}

bool MessageStore::hasConversation(const std::string& contactUsername) const
{
    return m_conversations.count(contactUsername) > 0;
}

std::vector<std::string> MessageStore::contactUsernames() const
{
    std::vector<std::string> keys;
    keys.reserve(m_conversations.size());
    for (const auto& entry : m_conversations) {
        keys.push_back(entry.first);
    }
    // Case-insensitive (ASCII) ordering so the picker list reads naturally.
    std::sort(keys.begin(), keys.end(),
              [](const std::string& a, const std::string& b) {
                  return std::lexicographical_compare(
                      a.begin(), a.end(), b.begin(), b.end(),
                      [](unsigned char c1, unsigned char c2) {
                          return std::tolower(c1) < std::tolower(c2);
                      });
              });
    return keys;
}

void MessageStore::addMessage(const std::string& contactUsername, const Message& msg)
{
    m_conversations[contactUsername].messages.push_back(msg);
    emit messageAdded(QString::fromStdString(contactUsername), msg);
}

bool MessageStore::hasMessageId(const std::string& id) const
{
    return std::any_of(m_conversations.cbegin(), m_conversations.cend(),
        [&id](const auto& entry) {
            const Conversation& conv = entry.second;
            return std::any_of(conv.messages.cbegin(), conv.messages.cend(),
                [&id](const Message& msg) { return msg.id().toStdString() == id; });
        });
}

void MessageStore::markIdSeen(const std::string& id)
{
    if (!id.empty()) m_seenIds.insert(id);
}

bool MessageStore::isIdSeen(const std::string& id) const
{
    return m_seenIds.count(id) > 0;
}

void MessageStore::removeMessageById(const std::string& msgId)
{
    for (auto& entry : m_conversations) {
        std::vector<Message>& messages = entry.second.messages;
        const auto found = std::find_if(messages.begin(), messages.end(),
            [&msgId](const Message& msg) { return msg.id().toStdString() == msgId; });
        if (found != messages.end()) {
            messages.erase(found);
            m_seenIds.erase(msgId);
            return;
        }
    }
}

std::vector<Message> MessageStore::messagesFor(const std::string& contactUsername) const
{
    std::vector<Message> result;
    const Conversation* conv = conversationPtr(contactUsername);
    if (!conv) return result;
    std::copy_if(conv->messages.cbegin(), conv->messages.cend(),
                 std::back_inserter(result),
                 [](const Message&) { return true; });
    return result;
}

int MessageStore::countMessagesFor(const std::string& contactUsername) const
{
    const Conversation* conv = conversationPtr(contactUsername);
    if (!conv) return 0;
    return static_cast<int>(std::count_if(conv->messages.cbegin(), conv->messages.cend(),
        [](const Message&) { return true; }));
}

void MessageStore::clear()
{
    m_conversations.clear();
    m_seenIds.clear();
    m_lastInboxId.clear();
}
