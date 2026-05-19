/**
 * MessageStore.cpp — Crypto and cache implementation.
 */

#include "MessageStore.hpp"
#include <QDebug>
#include <sodium.h>

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

    // TODO: Step 1 — Generate ephemeral X25519 keypair
    // unsigned char eph_pk[crypto_kx_PUBLICKEYBYTES];
    // unsigned char eph_sk[crypto_kx_SECRETKEYBYTES]; // stack-alloc, zero after use

    // TODO: Step 2 — Generate random nonce
    // unsigned char nonce[crypto_box_NONCEBYTES];
    // randombytes_buf(nonce, sizeof(nonce));

    // TODO: Step 3 — Encrypt with crypto_box_easy
    // (recipient's x25519 public key + ephemeral secret key)

    // TODO: Step 4 — Sign ciphertext with sender's ed25519 private key

    // TODO: Step 5 — Populate msg fields (ciphertext, ephemeralPublicKey, signature)

    // TODO: Step 6 — sodium_memzero(eph_sk, sizeof(eph_sk)) — wipe ephemeral sk

    qWarning() << "MessageStore::encryptMessage: not implemented yet";
    return msg;
}

bool MessageStore::decryptMessage(
    Message& message,
    const User& sender,
    const User& localUser)
{
    // TODO: Step 1 — Verify Ed25519 signature
    // crypto_sign_verify_detached(sig_bytes, ciphertext_bytes, ciphertext_len, sender_ed25519_pk)
    // Return false if verification fails — do not attempt decryption

    // TODO: Step 2 — Decrypt with crypto_box_open_easy
    // (ephemeral public key from message + local user's x25519 private key)

    // TODO: Step 3 — Set message.setPlaintext(decrypted_utf8)

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
