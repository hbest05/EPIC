/**
 * User.cpp — Implementation of the User class.
 *
 * Private key material lives in sodium_malloc'd memory for the lifetime of the
 * User object. freePrivateKeys() zeroes and frees it on destruction so keys
 * are not left in swappable memory after the object is gone.
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
    // Allocate locked memory — excluded from core dumps and swap
    m_x25519PrivateKey = static_cast<unsigned char*>(sodium_malloc(crypto_kx_SECRETKEYBYTES));
    m_ed25519PrivateKey = static_cast<unsigned char*>(sodium_malloc(crypto_sign_SECRETKEYBYTES));

    if (!m_x25519PrivateKey || !m_ed25519PrivateKey) {
        qWarning() << "User::generateKeyPairs: sodium_malloc failed";
        freePrivateKeys();
        return false;
    }

    // X25519 identity key — used in X3DH DH operations
    unsigned char pk_x[crypto_kx_PUBLICKEYBYTES];
    if (crypto_kx_keypair(pk_x, m_x25519PrivateKey) != 0) {
        qWarning() << "User::generateKeyPairs: crypto_kx_keypair failed";
        freePrivateKeys();
        return false;
    }
    // Raw 32-byte format — matches Web Crypto exportKey("raw") on the JS client
    m_x25519PublicKey = QByteArray(reinterpret_cast<char*>(pk_x), crypto_kx_PUBLICKEYBYTES);

    // Ed25519 signing key — used to sign the Signed Prekey (SPK)
    unsigned char pk_ed[crypto_sign_PUBLICKEYBYTES];
    if (crypto_sign_keypair(pk_ed, m_ed25519PrivateKey) != 0) {
        qWarning() << "User::generateKeyPairs: crypto_sign_keypair failed";
        freePrivateKeys();
        return false;
    }
    m_ed25519PublicKey = QByteArray(reinterpret_cast<char*>(pk_ed), crypto_sign_PUBLICKEYBYTES);

    return true;
}

bool User::saveKeyFile(const QString& path, const QString& password)
{
    // TODO: Encrypt private key at rest — separate task.
    // Plan: Argon2id(password, salt_local, m=65536, t=3, p=4) → wrap_key
    //       crypto_secretbox_easy(wrap_key, private_key_bytes) → ciphertext
    //       Write: salt || nonce || ciphertext to file at path
    Q_UNUSED(path)
    Q_UNUSED(password)
    qWarning() << "User::saveKeyFile: not yet implemented";
    return false;
}

bool User::loadKeyFile(const QString& path, const QString& password)
{
    // TODO: Decrypt key file — separate task.
    // Plan: Read salt || nonce || ciphertext from file
    //       Argon2id(password, salt) → wrap_key
    //       crypto_secretbox_open_easy → private key bytes into sodium_malloc'd buffers
    Q_UNUSED(path)
    Q_UNUSED(password)
    qWarning() << "User::loadKeyFile: not yet implemented";
    return false;
}
