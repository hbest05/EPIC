#pragma once

/**
 * User.hpp — Represents a local user account.
 *
 * Holds identity, public keys, and (in sodium_malloc'd locked memory)
 * private key material. freePrivateKeys() zeroes and releases private
 * keys on destruction so they are not left in swappable memory.
 */

#include <QString>
#include <QByteArray>
#include <sodium.h>

class User
{
public:
    User() = default;
    explicit User(const QString& username);
    ~User();

    // Disable copy to prevent accidental duplication of key material
    User(const User&) = delete;
    User& operator=(const User&) = delete;
    User(User&&) = default;
    User& operator=(User&&) = default;

    // --- Identity ---
    QString username() const { return m_username; }
    QString userId() const { return m_userId; }
    void setUserId(const QString& id) { m_userId = id; }

    // --- Public keys (received from server or generated locally) ---
    QByteArray x25519PublicKey() const { return m_x25519PublicKey; }
    QByteArray ed25519PublicKey() const { return m_ed25519PublicKey; }

    void setX25519PublicKey(const QByteArray& key) { m_x25519PublicKey = key; }
    void setEd25519PublicKey(const QByteArray& key) { m_ed25519PublicKey = key; }

    // --- Key management ---
    bool generateKeyPairs();
    bool saveKeyFile(const QString& path, const QString& password);
    bool loadKeyFile(const QString& path, const QString& password);

private:
    void freePrivateKeys();

    QString m_username;
    QString m_userId;

    QByteArray m_x25519PublicKey;
    QByteArray m_ed25519PublicKey;

    // sodium_malloc'd — locked, excluded from core dumps and swap
    unsigned char* m_x25519PrivateKey  = nullptr;
    unsigned char* m_ed25519PrivateKey = nullptr;
};
