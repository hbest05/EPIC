/**
 * User.cpp — Implementation of the User class.
 *
 * All private key operations use libsodium's secure memory allocation
 * (sodium_malloc / sodium_free) to minimise exposure of key material.
 */

#include "User.hpp"
#include <QDebug>

User::User(const QString& username)
    : m_username(username)
{
}

User::~User()
{
    freePrivateKeys();
}

void User::freePrivateKeys()
{
    if (m_x25519PrivateKey) {
        sodium_memzero(m_x25519PrivateKey, crypto_kx_SECRETKEYBYTES);
        sodium_free(m_x25519PrivateKey);
        m_x25519PrivateKey = nullptr;
    }
    if (m_ed25519PrivateKey) {
        sodium_memzero(m_ed25519PrivateKey, crypto_sign_SECRETKEYBYTES);
        sodium_free(m_ed25519PrivateKey);
        m_ed25519PrivateKey = nullptr;
    }
}

bool User::generateKeyPairs()
{
    // TODO: Allocate secure memory for private keys
    // m_x25519PrivateKey = static_cast<unsigned char*>(sodium_malloc(crypto_kx_SECRETKEYBYTES));
    // m_ed25519PrivateKey = static_cast<unsigned char*>(sodium_malloc(crypto_sign_SECRETKEYBYTES));

    // TODO: Generate X25519 keypair
    // unsigned char pk_x[crypto_kx_PUBLICKEYBYTES];
    // crypto_kx_keypair(pk_x, m_x25519PrivateKey);
    // m_x25519PublicKey = QByteArray(reinterpret_cast<char*>(pk_x), crypto_kx_PUBLICKEYBYTES);

    // TODO: Generate Ed25519 keypair
    // unsigned char pk_ed[crypto_sign_PUBLICKEYBYTES];
    // crypto_sign_keypair(pk_ed, m_ed25519PrivateKey);
    // m_ed25519PublicKey = QByteArray(reinterpret_cast<char*>(pk_ed), crypto_sign_PUBLICKEYBYTES);

    qWarning() << "User::generateKeyPairs: not implemented yet";
    return false;
}

bool User::saveKeyFile(const QString& path, const QString& password)
{
    // TODO:
    // 1. Derive an encryption key from password using crypto_pwhash (Argon2id)
    // 2. Encrypt private key bytes using crypto_secretbox_easy
    // 3. Write nonce + ciphertext to file at `path`
    Q_UNUSED(path)
    Q_UNUSED(password)
    qWarning() << "User::saveKeyFile: not implemented yet";
    return false;
}

bool User::loadKeyFile(const QString& path, const QString& password)
{
    // TODO:
    // 1. Read nonce + ciphertext from file
    // 2. Derive decryption key from password (same Argon2id params as saveKeyFile)
    // 3. Decrypt with crypto_secretbox_open_easy
    // 4. Write plaintext bytes into sodium_malloc'd m_*PrivateKey buffers
    Q_UNUSED(path)
    Q_UNUSED(password)
    qWarning() << "User::loadKeyFile: not implemented yet";
    return false;
}
