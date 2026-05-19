#pragma once

/**
 * User.hpp — Represents a user account (local or remote).
 *
 * For the local user: holds the full keypair (private key in locked memory).
 * For remote contacts: holds only public keys fetched from /api/auth/user/{username}/pubkeys.
 *
 * libsodium memory security:
 *   Private key bytes are stored in a sodium_malloc'd buffer with sodium_mlock()
 *   so they are excluded from core dumps and swap. Call lockMemory() after
 *   setting private key bytes and unlockMemory() only during crypto operations.
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

    // Disable copy to prevent accidental private key duplication
    User(const User&) = delete;
    User& operator=(const User&) = delete;
    User(User&&) = default;
    User& operator=(User&&) = default;

    // --- Identity ---
    QString username() const { return m_username; }
    QString userId() const { return m_userId; }
    void setUserId(const QString& id) { m_userId = id; }

    // --- Public keys (safe to share with server) ---
    QByteArray x25519PublicKey() const { return m_x25519PublicKey; }
    QByteArray ed25519PublicKey() const { return m_ed25519PublicKey; }

    void setX25519PublicKey(const QByteArray& key) { m_x25519PublicKey = key; }
    void setEd25519PublicKey(const QByteArray& key) { m_ed25519PublicKey = key; }

    // --- Keypair generation (local user only) ---
    /**
     * Generate a new X25519 keypair and an Ed25519 keypair using libsodium.
     * Private key bytes are written into sodium_malloc'd memory.
     * TODO: Implement using crypto_kx_keypair() and crypto_sign_keypair().
     */
    bool generateKeyPairs();

    /**
     * Persist the keypair to an encrypted keyfile on disk.
     * The file is encrypted with the user's password (Argon2id KDF).
     * TODO: Implement using crypto_secretstream or crypto_secretbox.
     */
    bool saveKeyFile(const QString& path, const QString& password);

    /**
     * Load keypair from an encrypted keyfile.
     * TODO: Implement.
     */
    bool loadKeyFile(const QString& path, const QString& password);

    // --- Private key access (local user only — use with care) ---
    const unsigned char* x25519PrivateKey() const { return m_x25519PrivateKey; }
    const unsigned char* ed25519PrivateKey() const { return m_ed25519PrivateKey; }

private:
    QString m_username;
    QString m_userId;

    QByteArray m_x25519PublicKey;   // crypto_kx_PUBLICKEYBYTES
    QByteArray m_ed25519PublicKey;  // crypto_sign_PUBLICKEYBYTES

    // Private keys — stored in sodium_malloc'd, mlock'd memory
    unsigned char* m_x25519PrivateKey = nullptr;  // crypto_kx_SECRETKEYBYTES
    unsigned char* m_ed25519PrivateKey = nullptr; // crypto_sign_SECRETKEYBYTES

    void freePrivateKeys();
};
