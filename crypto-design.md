# SecureMsg (EPIC) — Cryptographic Design Document

**Project:** EPIC / SecureMsg — end-to-end encrypted group messaging
**Scope of this document:** the cryptographic core — key establishment, message protection, key hierarchy, and trust model.

SecureMsg is a hand-rolled implementation of the Signal protocol family (X3DH + Double Ratchet) over modern primitives. All cryptographic operations are performed by a **Python crypto daemon** (using the PyCA `cryptography` library, with `argon2-cffi`'s `hash_secret_raw` for password-based key wrapping). The **C++ Qt client** never touches private key material: it exchanges opaque ciphertext with the daemon over local IPC and forwards it to the server. A **browser frontend** implements the identical wire protocol using the Web Crypto API and is fully interoperable. Two key-algebra rules are enforced throughout and never violated: **X25519 is used for every Diffie–Hellman operation; Ed25519 is signing-only** (it signs the SPK and nothing else). The two are distinct keypairs and are never conflated or derived from one another. **SHA-256 appears only in human-readable fingerprints and diagnostics — never in a security-relevant role** (it never derives a key, authenticates a ciphertext, or gates a protocol decision).

---

## 1. Threat Model

We analyse four attacker classes of increasing capability and state explicitly what survives each.

**(a) Passive network attacker.** Reads all traffic between clients and the server. SecureMsg defends message confidentiality and integrity end-to-end: every payload is AES-256-GCM ciphertext under a message key the attacker never sees, carried inside TLS as a second layer. This attacker learns nothing about plaintext contents. What it *can* still observe is traffic-analysis metadata — message timing, frequency, and ciphertext sizes. We bound the size channel by PKCS#7-padding every plaintext to a 256-byte boundary before encryption, but we acknowledge that timing and volume are not fully concealed and this attacker can perform coarse traffic analysis.

**(b) Active network attacker.** Can modify, drop, replay, or inject traffic in addition to reading it. Ciphertext tampering is detected and rejected: AES-256-GCM is an AEAD, so any bit-flip in the ciphertext, tag, or associated data fails the 128-bit authentication tag and the message is discarded. Replay and reordering are caught by the Double Ratchet's per-message counters (`PN`, `N`), which are bound into the AEAD associated data and into key derivation, so a replayed message either fails authentication or maps to an already-consumed message key. Injection of forged messages fails because the attacker cannot produce a valid tag without the message key. This attacker cannot, however, be stopped from **denying service** (dropping or delaying delivery) — availability is explicitly out of scope.

**(c) Honest-but-curious server.** Executes the protocol faithfully but logs everything it stores and routes. It holds only public key bundles, Argon2id password hashes, and opaque ciphertext with routing headers. It cannot read plaintext (message keys never leave the endpoints), cannot recover login passwords (Argon2id is one-way and memory-hard), and cannot read at-rest private keys (they never leave the device). What it *does* see, unavoidably, is **metadata**: which account talks to which, and when. End-to-end encryption does not hide the social graph, and we do not claim it does.

**(d) Fully compromised server.** Has full database and code access and can return arbitrary, malicious responses to clients — including forged key bundles. **What still holds:** the server still cannot read past or future message plaintext, because confidentiality depends on private keys and ratchet state that exist only on endpoints; and it cannot forge a message that an established session will accept, because it lacks the chain/message keys and cannot produce valid AEAD tags or valid Ed25519 SPK signatures. **What breaks under (d):** a compromised server controls the *introduction* step. Before two parties have pinned each other's identity key (Trust-On-First-Use), the server can substitute a key bundle it controls and mount a man-in-the-middle on the *first* contact, reading and relaying that conversation. It can also drop or delay messages at will (a stronger form of the (b) availability gap), and it retains full metadata/linkability. In short: **server compromise breaks first-contact authenticity and availability; it does not break the confidentiality or integrity of already-established sessions.**

| Attacker | Defended | Not defended (acknowledged) |
|---|---|---|
| (a) Passive network | Confidentiality, integrity (AEAD + TLS) | Traffic analysis (timing, volume) |
| (b) Active network | Tamper detection, replay, injection | Availability / DoS |
| (c) Honest-but-curious server | Plaintext, password, at-rest key secrecy | Metadata (who ↔ whom, when) |
| (d) Fully compromised server | Plaintext & integrity of established sessions, message forgery | First-contact MITM (pre-pinning), availability, linkability |

---

## 2. Key Material Overview

All asymmetric keys are generated from a cryptographically secure RNG (`os.urandom` / libsodium `randombytes`). On the daemon, private keys live inside an Argon2id+AES-256-GCM-encrypted file on disk and are decrypted into process memory only while the session is unlocked. In the browser, private keys are created as **non-extractable `CryptoKey` objects** in IndexedDB — the browser keystore never exposes the raw bytes to JavaScript, so there is nothing to wrap.

| Key | Algorithm | How generated | Where it lives | When erased |
|---|---|---|---|---|
| **IK** (identity) | X25519 | CSPRNG at registration | Public on server; private at rest (wrapped file / non-extractable CryptoKey) | Account deletion (long-term; not rotated) |
| **IK signing key** | Ed25519 | CSPRNG at registration | Public on server; private at rest | Account deletion |
| **SPK** (signed prekey) | X25519 | CSPRNG at registration, rotated periodically | Public + Ed25519 signature on server; private at rest | On rotation (previous SPK immediately overwritten; only the most-recent SPK is kept — in-flight handshakes against a rotated SPK will fail) |
| **OPKs** (one-time prekeys) | X25519 | CSPRNG in a batch at registration / top-up | Public batch on server; privates at rest | Each private erased immediately on consumption (one use only) |
| **EK** (ephemeral) | X25519 | CSPRNG by sender, per new session | Sender memory only; public sent in message header | Immediately after the shared secret `SK` is derived |
| **Ratchet keypairs** | X25519 | CSPRNG on each DH-ratchet step | Ratchet state in memory | When the ratchet advances past them (retained only while needed for skipped-key decryption) |
| **Root key (RK)** | 256-bit secret | HKDF output of each DH-ratchet step | Ratchet state in memory | Overwritten on the next DH-ratchet step |
| **Chain keys (CK)** | 256-bit secret | Seeded from RK; advanced by symmetric ratchet | Ratchet state in memory | Overwritten on each chain step (one-way) |
| **Message keys (MK)** | AES-256 key | HKDF of the chain key, once per message | Transient in memory | Immediately after a single encrypt/decrypt (except skipped keys, see §7) |
| **Session wrap key** | AES-256 key | Argon2id over the user passphrase + salt | Derived in memory at unlock | On logout/lock (resident for the session lifetime — see §7) |

The strict one-message-per-MK lifecycle is the foundation of forward secrecy: a message key is derived, used exactly once, and destroyed, so compromising current ratchet state does not expose previously sent messages.

---

## 3. Registration & Key Publication Flow

```
Client (daemon / browser)                                Server
  |                                                         |
  | 1. Generate IK (X25519), IK_sig (Ed25519)               |
  | 2. Generate SPK (X25519)                                |
  |    sig = Ed25519_Sign(IK_sig.priv, Encode(SPK.pub))     |
  | 3. Generate OPK batch { OPK_1 .. OPK_n } (X25519)       |
  | 4. Wrap private keys at rest (daemon):                  |
  |      wrapK = Argon2id(pass, salt, m=64MiB, t=3, p=1)    |
  |      blob  = AES-256-GCM(wrapK, nonce96, priv_material) |
  |    (browser: keys are non-extractable CryptoKeys —      |
  |     no wrap needed)                                     |
  |                                                         |
  | 5. POST /register  ----------------------------------->  |
  |    { IK.pub, IK_sig.pub, SPK.pub, sig,                  |
  |      [OPK_1.pub .. OPK_n.pub],                          |
  |      auth_hash = Argon2id(login_password, m=64MiB,      |
  |                           t=3, p=4) }                   |
  |                                                         | 6. Verify sig:
  |                                                         |    Ed25519_Verify(IK_sig.pub, SPK.pub, sig)
  |                                                         |    -> reject registration if invalid
  |                                                         | 7. Store public bundle + auth_hash
  |   <-------------------------------------- 200 OK         |
```

**Identity generation.** At first run the client generates two long-term keypairs: an **X25519 identity key (IK)** for all future Diffie–Hellman operations, and a separate **Ed25519 identity-signing key (IK_sig)** used only to sign prekeys. These are independent keys; we deliberately do *not* reuse a single Curve25519 key across both algorithms (no XEdDSA-style birational conversion), which removes the subtle requirements and cross-protocol attack surface of using one key in two algebraic settings.

**Argon2id wrap at rest (daemon).** Private key material is serialised and sealed in a single file: a wrap key is derived from the user's passphrase with Argon2id (`m=65536 KiB`, `t=3`, `p=1`; see §5), and the serialised privates are encrypted with AES-256-GCM under that wrap key with a fresh random 96-bit nonce. A stolen disk image therefore yields only an Argon2id-hardened ciphertext. The browser achieves the equivalent at-rest property differently: keys are stored as non-extractable `CryptoKey` objects, so their raw bytes are never accessible to script and require no application-level wrapping.

**SPK signing with Ed25519.** The signed prekey's public value is signed with `IK_sig` (RFC 8032 §5.1). This signature is what lets a recipient — and the server at publication time — confirm that the SPK genuinely belongs to the advertised identity rather than being a value injected by a network or server attacker.

**OPK batch upload.** A batch of one-time prekey public values is uploaded so that incoming initial messages can consume a fresh OPK each, giving the X3DH handshake one-time entropy and replay resistance (§4, §7).

**Server-side SPK signature verification.** The server verifies the Ed25519 signature over the SPK before accepting the bundle and rejects publication on failure. This is a defence-in-depth check: it is not a substitute for client-side verification (a compromised server could skip it), but it blocks a class of malformed or mismatched bundles at the door and is re-verified by every sender at send time.

---

## 4. Send & Receive Flow

```
Sender (Alice)                                        Recipient (Bob)
  | fetch Bob's bundle: IK_B, IK_sig_B, SPK_B, sig_B, OPK_B |
  | verify: Ed25519_Verify(IK_sig_B, SPK_B, sig_B)          |
  |         -- abort send if invalid                        |
  | generate EK (X25519)                                    |
  |                                                          |
  |  X3DH (4 DH; drop DH4 if no OPK available):             |
  |    DH1 = X25519(IK_A.priv,  SPK_B.pub)                  |
  |    DH2 = X25519(EK_A.priv,  IK_B.pub)                   |
  |    DH3 = X25519(EK_A.priv,  SPK_B.pub)                  |
  |    DH4 = X25519(EK_A.priv,  OPK_B.pub)                  |
  |    SK  = HKDF-SHA256( IKM  = DH1 ‖ DH2 ‖ DH3 ‖ DH4,     |
  |                       salt = 0x00 * 32,                 |
  |                       info = "SecureMsg_X3DH_v1" )      |
  |                                                          |
  |  Double Ratchet initialised with RK = SK               |
  |   per message:                                          |
  |    (CK', MK) = HKDF-SHA256(CK,                          |
  |                  info="SecureMsg_MsgKey_v1")            |
  |    nonce = random 96-bit                                |
  |    pt'   = PKCS7_pad(plaintext, 256)                    |
  |    AAD   = IK_A ‖ IK_B ‖ ratchet_pub ‖ PN ‖ N           |
  |    ct    = AES-256-GCM(MK, nonce, pt', AAD)             |
  |    header = { EK.pub, IK_A.pub, ratchet_pub, PN, N }    |
  |                                                          |
  | POST /messages { header, nonce, ct } --------------->   |
  |                                                          | mirror X3DH from header
  |                                                          | -> derive SK -> RK
  |                                                          | (RK', CK) = HKDF(ikm=DH_out, salt=RK,
  |                                                          |        info="SecureMsg_Ratchet_v1")
  |                                                          | (CK', MK) = HKDF(CK,
  |                                                          |        info="SecureMsg_MsgKey_v1")
  |                                                          | verify tag over AAD; reject on fail
  |                                                          | plaintext = PKCS7_unpad(decrypt)
```

**Why X3DH + Double Ratchet rather than HPKE Mode_Auth.** The natural single-primitive choice for authenticated key establishment is HPKE in authenticated mode (`mode_auth`, RFC 9180 §5.1.1), whose AuthEncap/AuthDecap (RFC 9180 §4.1) fold the sender's static key into the KEM so the recipient cryptographically confirms the message originated from the holder of that key. X3DH provides the same sender-authentication guarantee — `DH1 = X25519(IK_A, SPK_B)` binds the sender's long-term identity into the shared secret, so a recipient who derives the same SK knows it was produced by the holder of IK_A — making X3DH a justified equivalent of Mode_Auth for the introduction step. We choose it over bare HPKE because the conversation, not the single message, is the unit we must protect: X3DH seeds a Double Ratchet that gives forward secrecy across the whole session (each message key is derived once and destroyed, so a later compromise cannot recover earlier messages) and post-compromise security (the DH ratchet injects fresh X25519 entropy each round-trip, locking out an attacker who captured prior state) — properties a single-shot HPKE seal does not provide. X3DH also keeps the asynchronous, offline-friendly publication model (the recipient need only have prekeys on the server; they need not be online), and it preserves deniability by authenticating via shared-secret DH rather than a transferable signature over the message. These gains are not free: the construction is stateful (per-session mutable ratchet state that must be persisted, re-keyed on password change, and reconciled across out-of-order and skipped messages) and more complex than a stateless HPKE call, which enlarges the implementation and its failure surface — a cost we accept and contain with the bounds described in §7 (MAX_SKIPPED, one-key-per-message nonce discipline).

**X3DH handshake.** To start a session, the sender fetches the recipient's bundle, **verifies the Ed25519 signature over the SPK first**, then performs four Diffie–Hellman operations and feeds their ordered concatenation into HKDF (Signal X3DH spec §3, with KDF input encoding per §2.2). Each DH plays a distinct role: `DH1 = X25519(IK_A, SPK_B)` binds the sender's long-term identity (authentication); `DH2 = X25519(EK_A, IK_B)` and `DH3 = X25519(EK_A, SPK_B)` bind the sender's ephemeral to the recipient's identity and signed prekey (forward secrecy); `DH4 = X25519(EK_A, OPK_B)` mixes in one-time entropy that defeats replay of the initial message. The shared secret is `SK = HKDF-SHA256(IKM = DH1‖DH2‖DH3‖DH4, salt = 32 zero bytes, info = "SecureMsg_X3DH_v1")`. An all-zero salt is explicitly permitted by HKDF (RFC 5869 §3.1); the `info` string provides domain separation so this secret can never collide with a key derived in another context. If the recipient has no OPK left, the handshake gracefully drops to **3-DH** (DH1‖DH2‖DH3); authentication and forward secrecy are retained, replay protection of the very first message is weakened until OPKs are replenished (§7).

**Double Ratchet — symmetric chain step.** Within a chain, each message key is produced by a one-way symmetric ratchet: `(CK_next, MK) = HKDF-SHA256(CK, info = "SecureMsg_MsgKey_v1")`. The old chain key is overwritten, so a compromise of current state cannot reconstruct earlier message keys — this is the forward-secrecy property (Signal Double Ratchet spec §3).

**Double Ratchet — DH ratchet step.** Whenever a new ratchet public key is observed, the parties run a DH ratchet: a fresh X25519 DH output is fed through HKDF with the current root key as the salt, `(RK_next, CK) = HKDF-SHA256(IKM = DH_out, salt = RK, info = "SecureMsg_Ratchet_v1")`, producing 64 bytes split into the next root key (first 32) and the new chain key (last 32), seeding a new chain. Using `RK` as the salt rather than concatenating it into the input material follows the Signal Double Ratchet convention (DR spec §3.3), where the prior root key keys the extract step and the DH output is the fresh keying material. This injects new entropy on every conversational round-trip and gives **post-compromise security** (break-in recovery): an attacker who learns the state at one moment is locked out again after the next ratchet (Signal DR spec §3). The three info strings — `SecureMsg_X3DH_v1`, `SecureMsg_MsgKey_v1`, `SecureMsg_Ratchet_v1` — are pairwise distinct, giving each derivation context its own key space (RFC 5869 §3.2).

**AAD construction.** Each AEAD encryption authenticates, but does not encrypt, the associated data `AAD = IK_A ‖ IK_B ‖ ratchet_pub ‖ PN ‖ N`. This cryptographically binds every ciphertext to the sender identity, recipient identity, the current ratchet public key, the previous chain length (`PN`), and the message number (`N`). An attacker cannot splice a ciphertext into a different session, re-attribute it to another sender, or reorder it without invalidating the 128-bit tag.

**Nonce strategy.** A fresh **random 96-bit nonce** is drawn per message. GCM's security requires that a `(key, nonce)` pair is never reused. Here that requirement is satisfied *structurally* rather than by hoping randomness avoids collisions: **each message key `MK` is derived once and used for exactly one encryption**, so every encryption occurs under a unique key. Reuse of a `(key, nonce)` pair is therefore impossible regardless of nonce-collision probability, because the key never repeats. The random nonce is carried alongside the ciphertext.

**PKCS#7 padding.** Plaintext is padded with PKCS#7 to a 256-byte boundary *before* encryption, so the padding is inside the AEAD and is itself integrity-protected (a tampered pad length fails the tag). This quantises ciphertext lengths and blunts the length side-channel available to network and server observers (§1a, §1c); it does not eliminate volume/timing analysis.

---

## 5. Primitive Justification Table

| Primitive | Algorithm + Params | Security Property | Why These Params | RFC / Citation |
|---|---|---|---|---|
| Message encryption | **AES-256-GCM** — key 256-bit, nonce 96-bit, tag 128-bit | IND-CCA2 AEAD: confidentiality + integrity | 256-bit key gives a 128-bit security margin against Grover (harvest-now-decrypt-later). 96-bit is the native GCM nonce length, used directly as the GCM `J0` initial counter without GHASH re-derivation. 128-bit tag is full strength — maximum forgery resistance. | NIST SP 800-38D §5.2.1.1, §8.2; RFC 5116 §5.3 |
| DH / key agreement | **X25519** — Curve25519 ECDH, 256-bit keys, clamped scalars, cofactor 8 | Computational-DH hardness; ~128-bit classical security | Montgomery-ladder X25519 is constant-time and free of the invalid-curve / point-validation pitfalls of NIST P-curves; clamping fixes the cofactor and high bit. It is also the DH that underlies DHKEM(X25519, HKDF-SHA256) in HPKE (RFC 9180 §7.1), but here we use raw X25519 inside X3DH. | RFC 7748 §5, §6.1 |
| Signatures | **Ed25519** — EdDSA over edwards25519, deterministic nonce, SHA-512 internal | EUF-CMA signatures | Deterministic per-message nonce derivation eliminates the catastrophic nonce-reuse private-key recovery that afflicts ECDSA. ~128-bit security. Used solely to sign the SPK — never for DH. | RFC 8032 §5.1 |
| Key derivation | **HKDF-SHA256** — extract-then-expand, 256-bit output, explicit salt + info | PRF; cryptographic domain separation | SHA-256 as the underlying PRF. Distinct `info` strings (`SecureMsg_X3DH_v1`, `SecureMsg_MsgKey_v1`, `SecureMsg_Ratchet_v1`) strip algebraic structure from DH outputs and guarantee that a key in one context cannot collide with another. All-zero salt in X3DH is permitted with no loss of security. | RFC 5869 §2.2, §2.3, §3.1, §3.2 |
| Password hashing (server) | **Argon2id** — m=65536 KiB (64 MiB), t=3, p=4 | Memory-hard; resists GPU/ASIC parallelism and side-channels (hybrid) | Exceeds the OWASP minimum (19 MiB, t=2). 64 MiB at t=3 closes the data-independent TMTO gap discussed for Argon2 tuning; p=4 exploits server cores to keep wall-clock low while multiplying attacker cost. | RFC 9106 §4, §7.4; OWASP Password Storage Cheat Sheet |
| Key wrap (client, at rest) | **Argon2id** — m=65536 KiB (64 MiB), t=3, **p=1** | Memory-hard at-rest protection of private keys | Same 64 MiB memory hardness. **p differs from the server's p=4** because the daemon uses `argon2-cffi` (`argon2.low_level.hash_secret_raw`) with `parallelism` explicitly set to 1 (`ARGON_PAR = 1`), matching libsodium's fixed default and keeping the at-rest wrap single-threaded. The deviation is acknowledged and its impact is negligible for this threat model: the wrap defends a *stolen device* (offline, single-target) rather than an online guessing oracle, memory hardness dominates attacker cost, and `p` scales throughput, not memory. | RFC 9106 §3.1, §4 (parallelism parameter) |
| Initial key agreement | **X3DH** — 4 DH (3-DH fallback), HKDF over concatenation | Mutually-authenticated key agreement, forward secrecy, cryptographic deniability | DH1 binds identities (auth); DH2/DH3 bind ephemeral to identity + SPK (forward secrecy); DH4 over a one-time OPK gives replay resistance for the initial message. Fallback to 3-DH on OPK depletion preserves auth + FS. | Signal X3DH spec §3 (protocol), §2.2 (KDF/encoding), §4.6 (security considerations) |
| Ratcheting | **Double Ratchet** — symmetric chain + DH ratchet, skipped-key store bounded at MAX_SKIPPED=100 | Forward secrecy + post-compromise security | One-way symmetric chain (each MK derived once, then deleted) gives FS; DH ratchet injecting fresh X25519 entropy per round-trip gives break-in recovery. Skipped keys bounded at 100 to cap memory and prevent a skip-count DoS. | Signal Double Ratchet spec §3 (ratchet), §4.2 (skipped message keys) |

---

## 6. Trust Model

SecureMsg uses **Trust-On-First-Use (TOFU)**, the standard authenticity model for Signal/WhatsApp-class messengers that operate without a public-key infrastructure.

**First-contact key pinning.** The first time a user starts a conversation, the client fetches the peer's public bundle from the server and **pins the peer's identity key (IK) locally**. From that moment on, the pinned key is the authority for that contact: if the server later serves a different IK for the same contact, the client detects the mismatch and surfaces a key-change warning rather than silently re-keying. Pinning is implemented in both clients: the C++ client stores pins in `tofu_pins.json` under `QStandardPaths::AppDataLocation` (SHA-256 of the raw X25519 IK bytes, lowercase hex, saved atomically via `QSaveFile`); the browser client stores pins in IndexedDB under the `"pins"` object store using the same fingerprint format. A key-change triggers a `QMessageBox::critical` warning and hard blocks the message in the C++ client, and a visible banner with contact block in the browser client. The check fires on session establishment only — once a session exists the shared secret is already derived from the pinned key and a server key-swap cannot affect it.

**Ed25519 SPK verification on every send.** Independently of pinning, the client verifies the Ed25519 signature over the recipient's SPK *every time* it builds a new session (§4). A bundle whose SPK signature does not verify under the pinned identity-signing key is rejected before any DH is computed. This means that even a fully compromised server cannot get a victim to run X3DH against an unsigned or mismatched prekey for an already-known contact.

**Out-of-band fingerprints.** For users who want to close the TOFU gap manually, the client can display a **SHA-256 fingerprint** of the identity keys for out-of-band comparison (e.g. read aloud or scanned). This fingerprint is purely a human-verification aid and a diagnostic — it is never fed into key derivation, never authenticates a ciphertext, and never gates a protocol decision. It is the *only* place SHA-256 is used.

**Known limitation of the model.** TOFU trusts the *first* key it sees. A server that is malicious at the moment of first contact (attacker class (d)) can substitute a bundle and MITM that initial exchange; the substitution becomes detectable only after a legitimate key is later pinned, or immediately if users compare fingerprints out of band. This is the inherent first-contact window of any TOFU system.

**Why not PKI.** A certificate-authority PKI would, in principle, authenticate keys at first contact, but it introduces a trusted third party, certificate issuance and revocation machinery, and trust-root management — operational complexity that is disproportionate for a project of this scope and that simply shifts trust from the server to a CA. For the stated threat model, TOFU with key pinning and signed prekeys is the established, appropriate choice (this is exactly the model Signal deploys), and we accept its first-contact window as a documented limitation rather than mask it with infrastructure we cannot operate correctly.

---

## 7. Known Limitations

We list these openly; each is a deliberate trade-off rather than an oversight.

- **TOFU first-contact MITM window.** Authenticity of a contact's identity key is only guaranteed *after* first-use pinning. A server malicious at first contact can MITM that initial conversation until a legitimate key is pinned or users verify fingerprints out of band (§6).
- **Metadata is visible to the server.** End-to-end encryption hides message *contents*, not the *fact* of communication. The server necessarily learns who messages whom and when. PKCS#7 padding to 256 bytes reduces the ciphertext-size channel but does not conceal timing, frequency, or the social graph.
- **Skipped message keys cached in memory.** To handle out-of-order delivery, undecrypted-chain message keys are retained, bounded at **MAX_SKIPPED = 100** per chain. While cached these are live plaintext keys in memory and represent a small, bounded reduction in forward secrecy (an endpoint compromise during the window could decrypt those specific skipped messages). The cap also exists to defeat a denial-of-service via a crafted large skip count, which would otherwise force unbounded key derivation.
- **Identity wrap key resident in memory for the session.** Once the user unlocks, the Argon2id-derived session wrap key (and the decrypted private keys) live in process memory for the session lifetime. An attacker with live memory-scrape or cold-boot access to an *already-unlocked* endpoint can extract them. This is the standard limit of any at-rest scheme: encryption protects keys at rest, not against a compromised running host.
- **No cross-device account portability — by design.** Private keys are device-local and non-extractable (non-extractable `CryptoKey` in the browser; never-exported wrapped files on the daemon). An account cannot be cloned to a second device by copying key material. We classify this as a **trust-model strength, not a weakness**: there is no key-export path for malware or a coerced backup to abuse, and the attack surface for key exfiltration is minimised. The cost is convenience (re-enrolment per device), which we accept.
- **OPK depletion fallback to 3-DH.** When a recipient's one-time prekeys are exhausted, X3DH falls back to a 3-DH handshake (§4). Mutual authentication and forward secrecy are preserved, but the one-time replay protection on the *initial* message is lost until the OPK pool is replenished.
- **AEAD is not key-committing.** Standard AES-256-GCM does not commit to its key, which is relevant because message *forwarding* is a product feature: in principle a malicious server could craft a ciphertext that decrypts validly under two different keys. We are aware of the mitigations (a key-committing AEAD construction, or AES-GCM-SIV per RFC 8452 for nonce-misuse resistance) and treat adopting one as future work; our current nonce discipline (one key per message) already removes the nonce-reuse failure mode.
- **Post-quantum exposure.** X25519 is not quantum-resistant — a "harvest-now, decrypt-later" adversary could record today's ciphertexts and break the key agreement once large quantum computers exist. AES-256 retains a 128-bit effective margin under Grover and remains adequate. A hybrid X25519 + ML-KEM (Kyber) key agreement is the natural future-work path.
- **Availability is out of scope.** A network or server adversary can drop or delay messages. SecureMsg guarantees that delivered messages are confidential and authentic; it does not guarantee that messages are delivered.
