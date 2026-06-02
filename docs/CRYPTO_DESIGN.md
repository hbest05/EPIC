# Cryptographic Design Document — SecureMsg
## CS4455 Epic Project 2026 | Team Cryptmunks

**Version:** 1.0  
**Date:** 2026-06-02  
**Authors:** Holly Best, Matthew Burke, Julia Hooper  

---

## 1. Threat Model

SecureMsg must protect messages against four attacker classes:

### 1.1 Passive Network Attacker
An observer who can read all IP traffic between clients and the server.

**Properties held:**
- Message confidentiality: all payloads are AES-256-GCM ciphertext; the plaintext is never on the wire after TLS.
- Message authenticity: Ed25519 signatures on prekey bundles and AEAD tags on every message prevent undetected forgery.
- Forward secrecy: per-message AES-256-GCM keys are derived via the Double Ratchet and erased after use; capturing future traffic does not compromise past messages.

**Properties not held:**
- Metadata (sender, recipient, timing, message volume) is visible after TLS is stripped — TLS protects the wire but the server sees and stores metadata.

### 1.2 Active Network Attacker
An attacker who can additionally modify, drop, replay, or inject traffic.

**Properties held:**
- Ciphertext modification: AES-256-GCM authentication tags detect any byte-level tampering; the receiving client rejects tampered messages.
- Replay: Double Ratchet message indices (N) and previous-chain lengths (PN) are bound into AEAD associated data; a replayed message either fails the AEAD tag or is rejected as an out-of-order duplicate.
- Injection: the attacker cannot forge a valid AEAD ciphertext without the per-message key.

**Properties not held:**
- An active attacker who can intercept the initial key bundle fetch (before TOFU pinning) can perform a man-in-the-middle attack by substituting their own public keys. After the first successful exchange, the public key fingerprint is pinned locally; subsequent substitutions are detected.

### 1.3 Honest-but-Curious Server
The server faithfully executes the protocol but logs everything it sees.

**Properties held:**
- Message confidentiality: the server stores `ciphertext` (BYTEA), `nonce` (BYTEA), and `hpke_enc_blob` (BYTEA) — opaque byte sequences it cannot decrypt without the recipient's private key.
- Password confidentiality: the server stores only Argon2id hashes; it cannot recover plaintext passwords.

**Properties not held:**
- Traffic analysis: the server sees sender UUID, recipient UUID, message count, and timestamps. It can infer social graphs and communication patterns.
- Metadata: message sizes (even padded to 256-byte blocks) may leak coarse-grained content type.

### 1.4 Fully Compromised Server
An attacker with full read/write access to the database and the ability to send arbitrary API responses.

**Properties held:**
- Message confidentiality: the database contains only ciphertext; without the recipient's X25519 private key (stored only in the crypto daemon on the client machine) the attacker cannot decrypt messages.
- Ciphertext integrity: AEAD tags detect modification of stored ciphertext; the recipient's client will reject tampered messages.
- Password cracking resistance: Argon2id with m=65536, t=3, p=4 makes offline dictionary attacks expensive.

**Properties NOT held (must be stated explicitly per spec):**
- **Key distribution integrity**: a compromised server can serve malicious public key bundles to new users or users who have not yet pinned a peer's key. The first message to a new contact could be encrypted to the attacker's key (TOFU is vulnerable to active attack before first contact).
- **Message delivery guarantees**: the server can silently drop or delay messages; clients have no out-of-band channel to detect this.
- **Session unlinkability**: the compromised database exposes which users have active ratchet sessions with each other.
- **One-time prekey exhaustion**: the server can withhold one-time prekeys, forcing all new sessions to use the signed prekey only (still secure, but reduces forward secrecy at session establishment).

---

## 2. Construction Walkthrough

### 2.1 Registration and Key Publication

```
Client (crypto-daemon)                       Server (PostgreSQL)
──────────────────────                       ──────────────────
1. Generate IK_priv (X25519)
   Generate IK_sign_priv (Ed25519)
   Derive IK_pub, IK_sign_pub

2. Generate SPK_priv (X25519)
   Sign SPK_pub with IK_sign_priv → SPK_sig
   Generate OPK_1..N (X25519, one-time prekeys)

3. Argon2id(password) → password_hash

4. POST /api/auth/register {
     username, email, password_hash,
     identity_key: base64(IK_pub),
     ed25519_public_key: base64(IK_sign_pub)
   }
                                             Store: users row
                                             (password_hash, IK_pub, IK_sign_pub)

5. POST /api/auth/upload-prekeys {
     spk: { public_key, signature },
     opks: [ { public_key } × N ]
   }
                                             Store: signed_prekeys, one_time_prekeys
```

**Key storage at rest (client side):**  
The identity private key (`IK_priv`) and signing key (`IK_sign_priv`) are persisted in `~/.config/SecureMsg/identity.json`. They are encrypted under AES-256-GCM with a key derived as:

```
wrap_key = HKDF-SHA256(
    ikm  = PBKDF2-HMAC-SHA256(passphrase, salt, iterations=600000),
    salt = random_16_bytes,
    info = b"SecureMsg_IdentityKeyWrap_v1"
)
```

The PBKDF2 iteration count (600000) follows the 2023 OWASP recommendation for PBKDF2-HMAC-SHA256. The KDF parameters (PBKDF2 salt, HKDF salt, HKDF info string) are stored alongside the ciphertext in `identity.json`; the wrap key itself is never persisted.

The web client (`frontend/crypto.js`) uses a parallel construction with the Web Crypto API:  
`PBKDF2(passphrase, salt, 600000 iterations, SHA-256)` → `AES-KW` to wrap the X25519 private key in a JWK envelope.

### 2.2 Session Establishment — X3DH

When Alice sends the first message to Bob, the crypto daemon performs X3DH (Signal Protocol §3):

```
Alice fetches Bob's prekey bundle from server:
  IK_B_pub, IK_B_sign_pub, SPK_B_pub, SPK_B_sig, OPK_B_pub (if available)

1. Verify Ed25519 signature: Verify(IK_B_sign_pub, SPK_B_pub, SPK_B_sig)
   → abort if invalid (server cannot forge a valid SPK signature without IK_B_sign_priv)

2. Generate ephemeral EK_A (X25519)

3. Compute DHs:
   DH1 = X25519(IK_A_priv, SPK_B_pub)      # mutual auth
   DH2 = X25519(EK_A_priv, IK_B_pub)       # forward secrecy
   DH3 = X25519(EK_A_priv, SPK_B_pub)      # forward secrecy
   DH4 = X25519(EK_A_priv, OPK_B_pub)      # one-time, deniability

4. SK = HKDF-SHA256(
       ikm  = DH1 || DH2 || DH3 || DH4,
       salt = 0x00 × 32,
       info = b"SecureMsg_X3DH_v1"
   ) → 32 bytes

5. Initialise Double Ratchet with SK as root key.
   Alice's initial ratchet public key is sent to Bob in the message header.
```

The HKDF info string `SecureMsg_X3DH_v1` provides domain separation so the output cannot be confused with keys derived for other purposes.  
Reference: Signal X3DH specification, §2–§3 (Marlinspike & Perrin, 2016).

### 2.3 Sending a Message — Double Ratchet

Reference: Signal Double Ratchet specification (Marlinspike & Perrin, 2016), §2–§5.

```
Per-message symmetric ratchet step:
  (CK_next, MK) = HKDF-SHA256(CK, salt=None, info=b"SecureMsg_MsgKey_v1") → 64 bytes
  CK_next → replaces current chain key (erased immediately after split)
  MK      → 32-byte AES-256-GCM message key (erased after encryption)

DH ratchet step (on new peer ratchet public key):
  (RK_next, CK_new) = HKDF-SHA256(
      ikm  = X25519(our_ratchet_priv, their_ratchet_pub),
      salt = RK,
      info = b"SecureMsg_Ratchet_v1"
  )

Encryption:
  nonce   = os.urandom(12)           # 96-bit random nonce, never reused under MK
  plaintext_padded = PKCS7-pad(plaintext, block=256)   # hide message length
  aad     = SHA-256(IK_A_pub) || SHA-256(IK_B_pub)
          || ratchet_pub_bytes || PN.to_bytes(4) || N.to_bytes(4)
  ct      = AES-256-GCM.Encrypt(MK, nonce, plaintext_padded, aad)

Message stored on server: { ciphertext: ct, nonce: nonce, ratchet_pub, PN, N }
```

**Nonce strategy:** Each nonce is independently drawn from `os.urandom(12)` (Python's interface to `/dev/urandom`, a CSPRNG). Because nonces are random 96-bit values and are used at most once per message key (message keys are ephemeral and erased), the collision probability is negligible (birthday bound: 2^48 messages before a 50% collision probability under a single key — impossible in practice since the key is never reused).

**Associated data (AAD):** AAD binds both parties' long-term key fingerprints, the sender's current ratchet public key, and the message sequence numbers (PN, N). Any substitution of a message between different conversations, or tampering with the ratchet header, causes AEAD authentication to fail.

**Forward secrecy:** Chain keys and message keys are derived and then immediately overwritten in memory after use (`del ck, mk` in `double_ratchet.py`). Compromise of the current state does not reveal keys for already-delivered messages.

**DoS protection:** The Double Ratchet allows buffering skipped messages. SecureMsg limits `MAX_SKIP = 1000` (Signal Protocol §5 — this is a DoS protection limit, not an optimisation).

### 2.4 Receiving a Message

```
Bob's crypto daemon:
1. Looks up ratchet session by session_id from the database record.
2. If ratchet_pub differs from Bob's current ratchet state → perform DH ratchet step.
3. Advance symmetric chain to message index N, buffering any skipped message keys.
4. Derive MK from chain key (same HKDF step as sender).
5. ct = AES-256-GCM.Decrypt(MK, nonce, ciphertext, aad)
   → Raises InvalidTag if tampered or replayed → client shows error, does not display.
6. Strip PKCS7 padding → recover plaintext.
7. Erase MK.
```

### 2.5 Storage at Rest

| Data | Location | Protection |
|---|---|---|
| Message ciphertext | PostgreSQL `messages.ciphertext` | AES-256-GCM — server cannot decrypt |
| Nonce | PostgreSQL `messages.nonce` | Not secret; required for decryption |
| HPKE enc blob | PostgreSQL `messages.hpke_enc_blob` | Opaque to server |
| Identity private key | `~/.config/SecureMsg/identity.json` | AES-256-GCM, key derived from passphrase |
| Ratchet session state | PostgreSQL `ratchet_sessions` | Encrypted by daemon before upload (session state blob) |
| Password | PostgreSQL `users.password_hash` | Argon2id hash only — plaintext never stored |

---

## 3. Primitive Justifications

### 3.1 AES-256-GCM (AEAD)

- **Algorithm:** AES in Galois/Counter Mode with 256-bit key.
- **Parameters:** 96-bit (12-byte) random nonce; 128-bit authentication tag (GCM default).
- **Security property:** Authenticated encryption with associated data (AEAD) — provides IND-CCA2 confidentiality and INT-CTXT integrity simultaneously. A single primitive replaces the need for a separate MAC. An attacker who modifies even one bit of ciphertext causes the AEAD tag verification to fail with overwhelming probability (2^{-128}).
- **Why 256-bit key:** Provides 128-bit security against Grover's algorithm (quantum adversary). The marginal cost over AES-128 is negligible in software.
- **Why 96-bit nonce:** NIST SP 800-38D §8.2.1 recommends 96-bit nonces for GCM when nonces are random; the full 128-bit counter is then available for the GHASH function without truncation, maximising security.
- **Nonce uniqueness:** Each nonce is independently generated by `os.urandom(12)` and used under a unique per-message key (the message key is derived from the chain key and erased after a single use). Even if two random nonces collide, they encrypt under different keys, so there is no security degradation.
- **Reference:** NIST SP 800-38D (November 2007), §5.2; NIST FIPS 197 (AES).
- **Forbidden patterns avoided:** No ECB mode, no fixed nonce, no nonce reuse, no hand-rolled construction.

### 3.2 X25519 (ECDH)

- **Algorithm:** Diffie-Hellman over Curve25519.
- **Security property:** Computational Diffie-Hellman hardness on the Ristretto / Curve25519 group (128-bit classical security). Provides perfect forward secrecy when combined with the Double Ratchet (each DH step produces a fresh root for a new chain).
- **Why not P-256:** Curve25519 has a simpler, constant-time implementation in libsodium/`cryptography`, with no known implementation pitfalls (no requirement to validate curve points, cofactor is handled correctly by the library).
- **Reference:** RFC 7748 §5 (Langley, Hamburg, Turner, 2016).

### 3.3 Ed25519 (Digital Signatures)

- **Algorithm:** EdDSA over Curve25519 with SHA-512.
- **Security property:** EUF-CMA (existential unforgeability under chosen-message attack). Used to sign the SignedPreKey bundle so recipients can verify the bundle came from the claimed sender's identity key.
- **Why Ed25519 over ECDSA-P256:** Deterministic (no random per-signature nonce; eliminates nonce-reuse vulnerability), constant-time, smaller signatures (64 bytes).
- **Reference:** RFC 8032 §5.1 (Josefsson & Liusvaara, 2017).

### 3.4 HKDF-SHA256 (Key Derivation)

- **Algorithm:** HMAC-based Extract-and-Expand Key Derivation Function, SHA-256 hash.
- **Parameters:** Explicit `info` strings (`SecureMsg_X3DH_v1`, `SecureMsg_Ratchet_v1`, `SecureMsg_MsgKey_v1`, `SecureMsg_IdentityKeyWrap_v1`) provide domain separation — keys derived for different purposes cannot be confused even if the same IKM is reused.
- **Security property:** PRF security under the assumption that HMAC-SHA256 is a PRF. Outputs are computationally indistinguishable from random.
- **Reference:** RFC 5869 §2 (Krawczyk & Eronen, 2010).

### 3.5 Argon2id (Password Hashing)

- **Algorithm:** Argon2id (hybrid of Argon2i and Argon2d) via `passlib`.
- **Parameters:** `m=65536` (64 MiB memory), `t=3` (3 time passes), `p=4` (4 parallel lanes).
- **Security property:** Memory-hard — an attacker attempting an offline dictionary attack against a stolen `password_hash` must allocate 64 MiB per hash evaluation, making GPU-parallel attacks expensive. Argon2id is resistant to both side-channel timing attacks (from Argon2i) and GPU optimisation attacks (from Argon2d).
- **Why these parameters:** OWASP Password Storage Cheat Sheet (2024) recommends Argon2id with m≥19456 for minimum deployment; m=65536, t=3 is the OWASP "recommended" profile. A single hash takes ~200 ms on a 2024 server CPU, acceptable for login latency.
- **Reference:** RFC 9106 §4 (Biryukov, Dinu, Khovratovich, Josefsson, 2021); OWASP Password Storage Cheat Sheet (2024).

### 3.6 Trust Model (TOFU with Pinning)

New users' public keys are fetched from the server at first contact and their Ed25519 fingerprint is pinned locally in the client's SQLite message store. Subsequent fetches that return a different key trigger a warning and require explicit user re-confirmation. This is Trust-On-First-Use (TOFU).

**Limitation (stated explicitly):** TOFU is vulnerable to an active or compromised server substituting a malicious key *before* the first message. We do not implement a PKI or a web-of-trust; out-of-band fingerprint verification (e.g. QR code, safety numbers) is available in the UI as a manual step but is not enforced.

---

## 4. Known Limitations

1. **Server timestamp trust:** Message `created_at` is set server-side on receipt. The `plaintext_timestamp` inside the encrypted payload is client-supplied and trusted by the recipient's display layer; a malicious client could lie about when a message was composed.

2. **No key rotation:** Long-term identity keys (`IK`) are not rotated. If a client device is compromised and the identity key is extracted (e.g., passphrase brute-forced from a stolen `identity.json`), all future sessions established with that key could be compromised. The Double Ratchet provides per-message forward secrecy for past messages but not post-compromise security for future messages established via a stolen IK.

3. **message_id excluded from AAD:** The AEAD associated data does not include the message UUID. A compromised server could swap two ciphertexts between the same sender/recipient pair without the AEAD tag failing (the ratchet indices PN and N are included, so this is constrained to messages at the same ratchet step in the same conversation — in practice this is very limited).

4. **OPK replenishment:** The C++ client does not automatically replenish one-time prekeys when the server's supply is low. If OPKs are exhausted, new sessions fall back to using the signed prekey only, losing the one-time-prekey contribution to X3DH (still secure but with reduced deniability and one fewer DH in the key material).

5. **No post-quantum cryptography:** All primitives are based on classical elliptic-curve cryptography. A sufficiently large quantum computer running Shor's algorithm could break X25519 and Ed25519. This is considered out of scope for a 2026 student project.

6. **TOFU first-contact vulnerability:** Described in §3.6 above.

---

## 5. Library and Implementation Compliance

| Primitive | Library | Version | Notes |
|---|---|---|---|
| AES-256-GCM | `cryptography` (Python), OpenSSL EVP (C++) | ≥42.0 | Hardware AES-NI used where available |
| X25519 | `cryptography` (Python), libsodium (C++) | RFC 7748 | |
| Ed25519 | `cryptography` (Python) | RFC 8032 | |
| HKDF-SHA256 | `cryptography` (Python) | RFC 5869 | |
| Argon2id | `passlib[argon2]` (Python) | RFC 9106 | |
| CSPRNG | `os.urandom` / `secrets` (Python), `RAND_bytes` via OpenSSL (C++) | | All randomness from OS CSPRNG |
| Web client | Web Crypto API (browser-native) | W3C spec | `crypto.subtle.generateKey`, `crypto.subtle.encrypt` |

**Forbidden primitives not used:** MD5, SHA-1 in security-relevant roles, DES, 3DES, RC4, ECB mode, Dual_EC_DRBG, textbook RSA, hardcoded keys, hardcoded IVs. These have been explicitly checked in code review and the automated pentest suite (`pentest/tests/test_components.py`).
