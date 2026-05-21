#pragma once

/**
 * User.hpp — Represents a user account (local or remote).
 *
 * Holds the username and public keys received from the server.
 * Private key material and all crypto operations are handled by
 * the Python crypto daemon via Unix socket IPC; this class stores
 * no private keys.
 */

#include <QString>
#include <QByteArray>

class User
{
public:
    User() = default;
    explicit User(const QString& username);

    // Disable copy to prevent accidental duplication
    User(const User&) = delete;
    User& operator=(const User&) = delete;
    User(User&&) = default;
    User& operator=(User&&) = default;

    // --- Identity ---
    QString username() const { return m_username; }
    QString userId() const { return m_userId; }
    void setUserId(const QString& id) { m_userId = id; }

    // --- Public keys (received from server) ---
    QByteArray x25519PublicKey() const { return m_x25519PublicKey; }
    QByteArray ed25519PublicKey() const { return m_ed25519PublicKey; }

    void setX25519PublicKey(const QByteArray& key) { m_x25519PublicKey = key; }
    void setEd25519PublicKey(const QByteArray& key) { m_ed25519PublicKey = key; }

private:
    QString m_username;
    QString m_userId;

    QByteArray m_x25519PublicKey;
    QByteArray m_ed25519PublicKey;
};
