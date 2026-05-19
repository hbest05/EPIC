#pragma once

/**
 * Message.hpp — Represents a single encrypted message.
 *
 * A Message object can be in one of two states:
 *   - Plaintext (before send / after successful decrypt): m_plaintext populated
 *   - Ciphertext (in transit / stored locally): m_ciphertext populated
 *
 * Encryption is performed by MessageStore before sending and decryption is
 * performed by MessageStore after receiving, so Message itself is a dumb
 * data holder. This makes unit testing of the crypto layer straightforward.
 */

#include <QString>
#include <QByteArray>
#include <QDateTime>

class Message
{
public:
    enum class Direction { Sent, Received };

    Message() = default;

    // --- Identity ---
    QString id() const { return m_id; }
    void setId(const QString& id) { m_id = id; }

    // --- Participants ---
    QString senderUsername() const { return m_senderUsername; }
    QString recipientUsername() const { return m_recipientUsername; }
    void setSenderUsername(const QString& u) { m_senderUsername = u; }
    void setRecipientUsername(const QString& u) { m_recipientUsername = u; }

    Direction direction() const { return m_direction; }
    void setDirection(Direction d) { m_direction = d; }

    // --- Content ---
    QString plaintext() const { return m_plaintext; }
    void setPlaintext(const QString& text) { m_plaintext = text; }

    QByteArray ciphertext() const { return m_ciphertext; }
    void setCiphertext(const QByteArray& ct) { m_ciphertext = ct; }

    // Ephemeral X25519 public key used for ECDH — included with ciphertext
    QByteArray ephemeralPublicKey() const { return m_ephemeralPublicKey; }
    void setEphemeralPublicKey(const QByteArray& key) { m_ephemeralPublicKey = key; }

    // Ed25519 signature of the ciphertext by sender
    QByteArray signature() const { return m_signature; }
    void setSignature(const QByteArray& sig) { m_signature = sig; }

    // --- Blockchain audit ---
    QString keccak256Hash() const { return m_keccak256Hash; }
    void setKeccak256Hash(const QString& h) { m_keccak256Hash = h; }

    bool blockchainConfirmed() const { return m_blockchainConfirmed; }
    void setBlockchainConfirmed(bool v) { m_blockchainConfirmed = v; }

    QString txHash() const { return m_txHash; }
    void setTxHash(const QString& h) { m_txHash = h; }

    // --- Timestamps ---
    QDateTime createdAt() const { return m_createdAt; }
    void setCreatedAt(const QDateTime& dt) { m_createdAt = dt; }

private:
    QString    m_id;
    QString    m_senderUsername;
    QString    m_recipientUsername;
    Direction  m_direction = Direction::Received;

    QString    m_plaintext;
    QByteArray m_ciphertext;
    QByteArray m_ephemeralPublicKey;
    QByteArray m_signature;

    QString    m_keccak256Hash;
    bool       m_blockchainConfirmed = false;
    QString    m_txHash;

    QDateTime  m_createdAt;
};
