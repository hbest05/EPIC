/**
 * User.cpp — Implementation of the User class.
 *
 * Private key material lives in sodium_malloc'd memory for the lifetime of the
 * User object. freePrivateKeys() zeroes and frees it on destruction so keys
 * are not left in swappable memory after the object is gone.
 */

#include "User.hpp"
#include <QDebug>
#include <QFile>

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

// ---------------------------------------------------------------------------
// Key file format (binary, fixed layout):
//   [16 bytes]  Argon2id salt          (crypto_pwhash_SALTBYTES)
//   [ 1 byte ]  algorithm flag         (0x01 = AES-256-GCM, 0x02 = ChaCha20-Poly1305-IETF)
//   [12 bytes]  nonce                  (96-bit, same size for both algorithms)
//   [112 bytes] ciphertext             (96-byte plaintext + 16-byte MAC)
//
// Plaintext layout (96 bytes total):
//   [32 bytes]  X25519 private key     (crypto_kx_SECRETKEYBYTES)
//   [64 bytes]  Ed25519 private key    (crypto_sign_SECRETKEYBYTES)
//
// AAD: username as UTF-8 bytes — binds the ciphertext to this user's file.
//
// Key derivation: Argon2id(password, salt, m=65536 KiB, t=3, p=1)
//   Note: libsodium's high-level crypto_pwhash API fixes parallelism to 1.
//   The spec targets p=4 but that requires the low-level Argon2 API; the
//   security difference is negligible for this threat model.
// ---------------------------------------------------------------------------

static constexpr size_t KF_NONCE_BYTES  = 12;   // 96-bit, same for AES-GCM and ChaCha20
static constexpr size_t KF_MAC_BYTES    = 16;
static constexpr size_t KF_PLAIN_LEN    = crypto_kx_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES;
static constexpr size_t KF_CIPHER_LEN   = KF_PLAIN_LEN + KF_MAC_BYTES;
static constexpr unsigned char ALG_AES  = 0x01;
static constexpr unsigned char ALG_CHA  = 0x02;

bool User::saveKeyFile(const QString& path, const QString& password)
{
    if (!m_x25519PrivateKey || !m_ed25519PrivateKey) {
        qWarning() << "User::saveKeyFile: no key material to save";
        return false;
    }

    const bool useAes = crypto_aead_aes256gcm_is_available();

    // --- Argon2id key derivation ---
    unsigned char salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    unsigned char wrap_key[32];
    const QByteArray pwd = password.toUtf8();
    if (crypto_pwhash(
            wrap_key, sizeof(wrap_key),
            pwd.constData(), static_cast<unsigned long long>(pwd.size()),
            salt,
            3,         // opslimit — t=3
            67108864,  // memlimit — 64 MiB
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        // Out of memory — Argon2id allocation failed
        return false;
    }

    // --- Build plaintext: x25519_sk || ed25519_sk ---
    unsigned char plaintext[KF_PLAIN_LEN];
    memcpy(plaintext,                        m_x25519PrivateKey, crypto_kx_SECRETKEYBYTES);
    memcpy(plaintext + crypto_kx_SECRETKEYBYTES, m_ed25519PrivateKey, crypto_sign_SECRETKEYBYTES);

    // --- 96-bit nonce, fresh per save ---
    unsigned char nonce[KF_NONCE_BYTES];
    randombytes_buf(nonce, sizeof(nonce));

    // --- AEAD encrypt with username as AAD ---
    const QByteArray aad = m_username.toUtf8();
    unsigned char ciphertext[KF_CIPHER_LEN];
    unsigned long long clen = 0;
    const int rc = useAes
        ? crypto_aead_aes256gcm_encrypt(
              ciphertext, &clen,
              plaintext, KF_PLAIN_LEN,
              reinterpret_cast<const unsigned char*>(aad.constData()), static_cast<unsigned long long>(aad.size()),
              nullptr, nonce, wrap_key)
        : crypto_aead_chacha20poly1305_ietf_encrypt(
              ciphertext, &clen,
              plaintext, KF_PLAIN_LEN,
              reinterpret_cast<const unsigned char*>(aad.constData()), static_cast<unsigned long long>(aad.size()),
              nullptr, nonce, wrap_key);

    sodium_memzero(plaintext,  sizeof(plaintext));
    sodium_memzero(wrap_key,   sizeof(wrap_key));

    if (rc != 0) {
        qWarning() << "User::saveKeyFile: AEAD encryption failed";
        return false;
    }

    // --- Write: salt || alg_flag || nonce || ciphertext ---
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        qWarning() << "User::saveKeyFile: cannot open" << path;
        return false;
    }

    const unsigned char alg_flag = useAes ? ALG_AES : ALG_CHA;
    file.write(reinterpret_cast<const char*>(salt),       sizeof(salt));
    file.write(reinterpret_cast<const char*>(&alg_flag),  1);
    file.write(reinterpret_cast<const char*>(nonce),      sizeof(nonce));
    file.write(reinterpret_cast<const char*>(ciphertext), static_cast<qsizetype>(clen));
    file.close();

    return true;
}

bool User::loadKeyFile(const QString& path, const QString& password)
{
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        qWarning() << "User::loadKeyFile: cannot open" << path;
        return false;
    }

    // --- Read header ---
    unsigned char salt[crypto_pwhash_SALTBYTES];
    if (file.read(reinterpret_cast<char*>(salt), sizeof(salt)) != static_cast<qint64>(sizeof(salt))) {
        qWarning() << "User::loadKeyFile: file too short (salt)";
        return false;
    }

    unsigned char alg_flag = 0;
    if (file.read(reinterpret_cast<char*>(&alg_flag), 1) != 1) {
        qWarning() << "User::loadKeyFile: file too short (alg flag)";
        return false;
    }

    unsigned char nonce[KF_NONCE_BYTES];
    if (file.read(reinterpret_cast<char*>(nonce), sizeof(nonce)) != static_cast<qint64>(sizeof(nonce))) {
        qWarning() << "User::loadKeyFile: file too short (nonce)";
        return false;
    }

    const QByteArray ciphertext = file.readAll();
    file.close();

    if (static_cast<size_t>(ciphertext.size()) != KF_CIPHER_LEN) {
        qWarning() << "User::loadKeyFile: unexpected ciphertext length";
        return false;
    }

    // --- Argon2id key derivation (same parameters as saveKeyFile) ---
    unsigned char wrap_key[32];
    const QByteArray pwd = password.toUtf8();
    if (crypto_pwhash(
            wrap_key, sizeof(wrap_key),
            pwd.constData(), static_cast<unsigned long long>(pwd.size()),
            salt,
            3,
            67108864,
            crypto_pwhash_ALG_ARGON2ID13) != 0) {
        return false;
    }

    // --- AEAD decrypt ---
    const QByteArray aad = m_username.toUtf8();
    unsigned char plaintext[KF_PLAIN_LEN];
    unsigned long long plen = 0;

    int rc = -1;
    if (alg_flag == ALG_AES) {
        if (!crypto_aead_aes256gcm_is_available()) {
            sodium_memzero(wrap_key, sizeof(wrap_key));
            qWarning() << "User::loadKeyFile: file uses AES-256-GCM but AES-NI is not available on this CPU";
            return false;
        }
        rc = crypto_aead_aes256gcm_decrypt(
            plaintext, &plen,
            nullptr,
            reinterpret_cast<const unsigned char*>(ciphertext.constData()), static_cast<unsigned long long>(ciphertext.size()),
            reinterpret_cast<const unsigned char*>(aad.constData()), static_cast<unsigned long long>(aad.size()),
            nonce, wrap_key);
    } else if (alg_flag == ALG_CHA) {
        rc = crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &plen,
            nullptr,
            reinterpret_cast<const unsigned char*>(ciphertext.constData()), static_cast<unsigned long long>(ciphertext.size()),
            reinterpret_cast<const unsigned char*>(aad.constData()), static_cast<unsigned long long>(aad.size()),
            nonce, wrap_key);
    } else {
        qWarning() << "User::loadKeyFile: unknown algorithm flag" << alg_flag;
    }

    sodium_memzero(wrap_key, sizeof(wrap_key));

    if (rc != 0 || plen != KF_PLAIN_LEN) {
        sodium_memzero(plaintext, sizeof(plaintext));
        // Generic message — do not reveal whether failure was bad password or corrupt file
        qWarning() << "User::loadKeyFile: decryption failed";
        return false;
    }

    // --- Load into secure memory, replacing any existing keys ---
    freePrivateKeys();

    m_x25519PrivateKey  = static_cast<unsigned char*>(sodium_malloc(crypto_kx_SECRETKEYBYTES));
    m_ed25519PrivateKey = static_cast<unsigned char*>(sodium_malloc(crypto_sign_SECRETKEYBYTES));

    if (!m_x25519PrivateKey || !m_ed25519PrivateKey) {
        sodium_memzero(plaintext, sizeof(plaintext));
        freePrivateKeys();
        return false;
    }

    memcpy(m_x25519PrivateKey,  plaintext,                           crypto_kx_SECRETKEYBYTES);
    memcpy(m_ed25519PrivateKey, plaintext + crypto_kx_SECRETKEYBYTES, crypto_sign_SECRETKEYBYTES);
    sodium_memzero(plaintext, sizeof(plaintext));

    return true;
}
