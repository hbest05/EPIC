#pragma once

/**
 * MessageStore.hpp — Local encrypted message cache and crypto orchestrator.
 *
 * Responsibilities:
 *   1. Encrypt outgoing messages (ECDH + XSalsa20-Poly1305 via libsodium)
 *   2. Decrypt incoming messages
 *   3. Verify Ed25519 signatures on received messages
 *   4. Cache decrypted messages in memory for the UI
 *   5. Optionally persist the cache to a local SQLite DB (future work)
 *
 * Crypto operations use libsodium's combined-mode box:
 *   crypto_box_easy()      — encrypt with ephemeral keypair + recipient pubkey
 *   crypto_box_open_easy() — decrypt with own private key + ephemeral pubkey
 *   crypto_sign_detached() — sign ciphertext with sender's Ed25519 key
 *   crypto_sign_verify_detached() — verify signature against sender's pubkey
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
     * Encrypt `plaintext` for `recipient` and populate a Message object
     * ready for transmission.
     *
     * Steps (TODO):
     *   1. crypto_kx_client_session_keys() or generate ephemeral keypair
     *   2. crypto_box_easy(ciphertext, plaintext, nonce, recipient_pk, ephemeral_sk)
     *   3. crypto_sign_detached(signature, ciphertext, sender_signing_sk)
     *   4. Return Message with ciphertext, ephemeralPublicKey, signature set
     *
     * @param plaintext UTF-8 message text
     * @param recipient Must have x25519PublicKey populated
     * @param sender    Must have x25519PrivateKey and ed25519PrivateKey populated
     */
    Message encryptMessage(const QString& plaintext, const User& recipient, const User& sender);

    /**
     * Decrypt an incoming Message. Verifies the sender's signature before
     * attempting decryption — returns false if signature is invalid.
     *
     * TODO: Implement using crypto_sign_verify_detached + crypto_box_open_easy.
     *
     * @param message   Message with ciphertext, ephemeralPublicKey, signature
     * @param sender    Remote user with ed25519PublicKey and x25519PublicKey
     * @param localUser Must have x25519PrivateKey populated
     * @returns true on success, false on signature or decryption failure
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
