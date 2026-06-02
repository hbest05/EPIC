# CS4455 Epic Project — Cover Document
## SecureMsg — Team Cryptmunks

| Field | Value |
|---|---|
| Group Name | Cryptmunks |
| Project Name | SecureMsg |
| GitHub Repository | https://github.com/hbest05/EPIC |
| Deployment URL | https://alpha-and-the-cryptmunks.theburkenator.com |
| Presentation Slot | Thursday 4th June 2026, 10:40 |

---

## Team Members

| Full Name | Student ID |
|---|---|
| Holly Best | [INSERT STUDENT ID] |
| Matthew Burke | [INSERT STUDENT ID] |
| Julia Hooper | [INSERT STUDENT ID] |

---

## Contribution Breakdown

### Holly Best — ~35%

**Primary role:** Dev B — Cryptography & Backend

- **Crypto daemon** (`crypto-daemon/`): Designed and implemented the full Signal Protocol stack — X3DH key agreement (`x3dh.py`), Double Ratchet session state machine (`double_ratchet.py`), identity key generation and persistence (`identity.py`), session store (`session_store.py`), IPC transport layer (`transport.py`), and daemon entry point (`main.py`).
- **Backend database schema** (`backend/app/models/`): Designed the `users`, `messages`, `message_access`, `user_keys`, `ratchet_sessions`, `signed_prekeys`, and `one_time_prekeys` tables; drove decisions on separate nonce column, UUID server-side generation, and soft-delete via `revoked_at`.
- **Authentication service** (`backend/app/services/auth_service.py`): Argon2id password hashing (m=65536, t=3, p=4), JWT lifecycle, CSRF double-submit cookie pattern, rate-limiting integration.
- **Security hardening**: Applied fixes after automated pentest — MAX_SKIP DoS protection on Double Ratchet skipped-message windows, change-password endpoint with re-encryption of identity key under new passphrase (`feat/password-change` branch).
- **C++ STL refactor** (`feat/cpp-stl-refactor`): Wired live `User`, `Message`, and `MessageStore` classes into the running Qt client; replaced ad-hoc containers with `std::vector`, `std::unordered_map`, and STL algorithms throughout.
- **Pentest suite** (`pentest/`): Co-authored automated security tests and applied post-pentest fixes; wrote `pentest/report/pentest_report.md`.
- **Documentation**: `NETWORK_REPORT.md`, this cover document, `docs/CRYPTO_DESIGN.md`.

---

### Matthew Burke — ~40%

**Primary role:** Dev A — C++ Client & Networking

- **Qt C++ desktop client** (`client-cpp/src/`): Full implementation of `Client`, `Message`, `MessageStore`, `User`, `CryptoDaemonClient`, `NetworkUtils`, `TLSVerifier`, `LoginWindow`, `MainWindow`, and `MessageItemDelegate` classes.
- **TLS connectivity**: `TLSVerifier.cpp` performs peer-certificate verification using OpenSSL EVP; `NetworkUtils.cpp` wraps libcurl for HTTPS REST calls and manages cookie jar for httpOnly session tokens.
- **IPC to crypto daemon**: `CryptoDaemonClient.cpp` — TCP socket client on port 47291 that sends JSON-framed encrypt/decrypt requests to the Python daemon process.
- **CMake build system** (`client-cpp/CMakeLists.txt`): Qt6, OpenSSL, libcurl, libsodium integration; vcpkg toolchain; daemon port override via `-DDAEMON_PORT`.
- **WebSocket messaging**: Real-time message delivery via Qt6 WebSockets connected to the FastAPI `/ws` endpoint.
- **Backend routers** (`backend/app/routers/messages.py`, `ws.py`): Message send/receive/delete/forward endpoints; WebSocket hub with per-user room management.
- **Revocation flow**: Per-message delete-for-recipient logic, WebSocket push notification to recipient on revocation, sender-only enforcement.

---

### Julia Hooper — ~25%

**Primary role:** Dev C — Web Frontend & Blockchain Verification

- **Web frontend** (`frontend/`): Full JavaScript client — `index.html` (auth + messaging UI), `app.js` (session management, send/receive, forwarding), `crypto.js` (Web Crypto API: X25519 ECDH, AES-256-GCM, key wrapping under user passphrase), `styles.css`.
- **Key wrapping**: Client-side private key encrypted at rest under AES-256-GCM with a key derived from the user's passphrase via PBKDF2-HMAC-SHA256 (`crypto.js`).
- **Blockchain verification page** (`frontend/verify.html`, `frontend/verify.js`): Standalone page that accepts a transaction hash or message UUID, fetches the on-chain keccak256 hash via a public `/api/blockchain/verify` endpoint, recomputes the hash of pasted ciphertext, and displays a clear pass/fail result with block timestamp.
- **Content Security Policy**: `backend/app/middleware/` — CSP header middleware; static file serving configuration.
- **Alembic migrations** (`backend/alembic/versions/`): Initial schema migration and incremental migrations for Signal Protocol tables, blockchain fields, and forwarding/revocation columns.
- **Smart contract deployment**: Assisted with `blockchain/contracts/MessageDigest.sol` deployment to Sepolia; contributed to `digestRecorder.js` integration tests.

---

## Additional Design Documents

The following documents are included in this repository and form part of the submission:

| Document | Location | Required by |
|---|---|---|
| Cryptographic Design Document | `docs/CRYPTO_DESIGN.md` | Cryptography (O'Brien) |
| Network Architecture Documentation | `NETWORK_REPORT.md` | Networks (Burkley) |
| Penetration Testing Report | `pentest/report/pentest_report.md` | Networks (Burkley) |
| AI Prompt Artefacts | `docs/AI_ARTEFACTS.md` | All minors (2026 requirement) |
| Blockchain contract address + ABI | `blockchain/deployedAddress.json`, `blockchain/MessageDigestRegistryABI.json` | Blockchain (Le Gear) |

---

## Known Limitations

- The reverse proxy (TLS termination in front of Uvicorn) is an operational deployment concern and is not included in the repository.
- The server trusts the client-supplied timestamp on messages; a malicious client could backdate messages.
- `message_id` is excluded from the AEAD associated data — a server could swap two ciphertexts between the same sender/recipient pair without triggering an authentication failure at the AEAD layer (mitigated by Double Ratchet sequence numbers in the AAD).
- No key rotation: if a long-term identity key is compromised, all past sessions established with that key are at risk. The Double Ratchet provides forward secrecy per-message but not post-compromise security beyond the ratchet window.
- One-time prekeys are not currently replenished automatically by the C++ client; the client logs a warning when the server's OPK supply falls below a threshold.
