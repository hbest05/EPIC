# Network Architecture Documentation
**Team:** Cryptmunks — CS4455 Epic Project 2026  
**Subject:** Computer Networks & Cybersecurity (Mark Burkley)

---

## Overview

SecureMsg is a multi-client, end-to-end encrypted messaging application. The system spans three deployment environments: the end-user's local machine (C++ Qt desktop client + crypto daemon), a cloud VM (`cryptmunks.theburkenator.com`), and the Ethereum Sepolia testnet for tamper-evident audit trails.

The PlantUML diagram in [`network_architecture.puml`](network_architecture.puml) provides the canonical visual reference.

---

## Component Inventory

### 1. C++ Qt Desktop Client (`client-cpp/`)
| File | Role |
|---|---|
| `Client.cpp / .hpp` | Orchestrates all API calls and application logic |
| `NetworkUtils.cpp / .hpp` | Low-level HTTPS requests via **libcurl + OpenSSL** (TLS 1.3) |
| `TLSVerifier.cpp / .hpp` | Certificate chain verification; TOFU public-key pinning |
| `CryptoDaemonClient.cpp / .hpp` | IPC client — sends/receives JSON over TCP loopback to crypto-daemon |
| `LoginWindow / MainWindow` | Qt GUI windows |
| `MessageStore.cpp / .hpp` | Local encrypted message cache (SQLite) |
| `TofuStore.cpp / .hpp` | Persistent store of previously-seen server and peer public-key fingerprints |
| `Message.cpp / .hpp` | Message data model (ciphertext, nonce, sender, timestamp) |
| `User.cpp / .hpp` | User data model |

**Build:** CMake + Qt6 + OpenSSL + libcurl. See `client-cpp/CMakeLists.txt`.

### 2. Crypto Daemon (`crypto-daemon/`)
A local Python daemon listening on `127.0.0.1:47291` (TCP loopback, never exposed externally).  
The C++ client delegates all cryptographic operations here to avoid reimplementing complex primitives in C++.

| File | Role |
|---|---|
| `main.py` | Entry point; starts TCP listener |
| `transport.py` | Framed JSON request/response over TCP |
| `handlers.py` | Dispatches incoming requests to crypto operations |
| `x3dh.py` | Extended Triple Diffie-Hellman key agreement |
| `double_ratchet.py` | Double Ratchet session key derivation |
| `identity.py` | Long-term identity key management (X25519 keypair, Argon2id-encrypted at rest) |
| `session_store.py` | Persists active ratchet sessions |

**Threat model note:** The daemon is single-threaded and loopback-only. Its attack surface is confined to the local user session; it never accepts remote connections.

### 3. Frontend SPA (`frontend/`)
HTML/JavaScript single-page application served by the FastAPI backend. Uses the **Web Crypto API** for in-browser AEAD (AES-GCM).

| File | Role |
|---|---|
| `app.js` | Main application logic; authenticated session management |
| `crypto.js` | HPKE-style key encapsulation and AES-256-GCM encrypt/decrypt |
| `register.js` | User registration + key generation flow |
| `verify.html / verify.js` | Standalone blockchain fidelity verification page |

### 4. FastAPI Backend (`backend/`)
Python 3.12 async application running inside Docker. All inbound traffic is HTTPS (TLS terminated at the reverse proxy / cloud load balancer).

| Component | Path | Description |
|---|---|---|
| Auth Router | `/api/auth` | Register, login (JWT issue), logout, public-key upload/lookup |
| Messages Router | `/api/messages` | Send, receive, list, forward, revoke, delete, download |
| WebSocket Router | `/api/ws` | Real-time push delivery of new messages |
| Blockchain Router | `/api/blockchain` | Enqueue digest, verify on-chain hash |
| CSRF Middleware | `middleware/csrf.py` | Double-submit cookie CSRF protection |
| Security Headers Middleware | `middleware/security_headers.py` | HSTS, CSP, X-Frame-Options, X-Content-Type-Options |
| Rate Limiter | `services/rate_limit.py` | Per-IP request throttling (slowapi) |
| Auth Service | `services/auth_service.py` | Argon2id password hashing + JWT sign/verify |
| Blockchain Service | `services/blockchain_service.py` | web3.py: enqueue to Redis, read from Sepolia |
| Redis Service | `services/redis_service.py` | Async connection pool to Redis queue |
| WS Manager | `services/ws_manager.py` | Registry of active WebSocket connections per user |

### 5. PostgreSQL 16 (`db` service — Docker internal)
Accessible only on the Docker bridge network (`db:5432`). Never exposed to the public internet.

| Table | Contents |
|---|---|
| `users` | User ID, username, Argon2id password hash, public key bundle (identity key, signed prekey, one-time prekeys) |
| `messages` | Message ID, sender, recipient, ciphertext (base64), nonce, associated data, timestamp, blockchain tx hash |
| `signal_*` | X3DH prekey bundles for key agreement |
| `revocation` | Revoked message-share records |

### 6. Redis 7 (`redis` service — Docker internal)
Password-protected; accessible only on the Docker bridge network (`redis:6379`).  
Acts as a write queue (`RPUSH / BLPOP blockchain:queue`) so that blockchain transactions do not block HTTP request handlers.

### 7. Blockchain Layer (`blockchain/`)
| File | Role |
|---|---|
| `digestRecorder.js` | Background worker: `BLPOP` from Redis → `eth_sendRawTransaction` to Sepolia |
| `verifyDigestCli.js` | CLI to verify a tx hash against on-chain record |
| `recordDigestCli.js` | CLI to manually submit a digest |
| `MessageDigestRegistryABI.json` | Compiled ABI for the deployed Solidity contract |
| `deployedAddress.json` | Deployed contract address on Sepolia |

**Smart contract:** Solidity contract deployed on Ethereum Sepolia testnet. Stores `keccak256` hashes of conversation segments alongside block timestamps. Immutable once written; provides tamper-evident audit trail independent of the server.

---

## Network Connections

| Source | Destination | Protocol | Port | Direction | Notes |
|---|---|---|---|---|---|
| C++ Client | FastAPI Backend | HTTPS / TLS 1.3 | 443 | Outbound | Cert verified via TLSVerifier (TOFU) |
| C++ Client | FastAPI Backend | WSS | 443 | Bi-directional | Real-time message push |
| C++ Client | Crypto Daemon | TCP JSON | 47291 | Loopback | Never leaves local machine |
| Frontend SPA | FastAPI Backend | HTTPS / TLS 1.3 | 443 | Outbound | JWT Bearer tokens; CSRF cookie |
| Frontend SPA | FastAPI Backend | WSS | 443 | Bi-directional | Real-time delivery |
| Verify Page | FastAPI Backend | HTTPS | 443 | Outbound | Read-only blockchain query |
| Verify Page | Sepolia RPC | HTTPS | 443 | Outbound | Read-only eth_call |
| FastAPI Backend | PostgreSQL | asyncpg TCP | 5432 | Internal Docker | Private bridge; never public |
| FastAPI Backend | Redis | Redis protocol | 6379 | Internal Docker | Private bridge; password-protected |
| Blockchain Worker | Redis | Redis BLPOP | 6379 | Internal Docker | Consumer of write queue |
| Blockchain Worker | Sepolia RPC | HTTPS | 443 | Outbound | `eth_sendRawTransaction` |
| FastAPI Backend | Sepolia RPC | HTTPS | 443 | Outbound | `eth_call` for hash reads |

---

## Security Controls at Component Boundaries

### TLS / Certificate Verification
- All client-to-server traffic is TLS 1.3.
- The C++ client (`TLSVerifier.cpp`) verifies the server's certificate against a stored TOFU fingerprint on first connection, then pins it on subsequent connections. This guards against CA compromise.
- The web frontend inherits browser TLS verification (CA chain + HSTS preload via `Strict-Transport-Security` header).

### Authentication & Authorisation
- Passwords hashed with **Argon2id** (memory-hard; not recoverable from a DB breach).
- Short-lived **JWT** tokens (HS256; secret from environment variable, never hardcoded) issued on successful login.
- All message endpoints require a valid JWT (`Authorization: Bearer`).
- Access control checks that a user can only read/modify their own messages or those explicitly shared with them.

### Input Validation & Injection Prevention
- FastAPI Pydantic schemas validate all incoming JSON at the boundary.
- SQLAlchemy ORM parameterises all queries — no raw SQL string interpolation.
- CSRF double-submit cookie pattern enforced by `CSRFMiddleware` on all state-mutating endpoints.
- Rate limiting on auth endpoints to mitigate brute-force.

### Security Headers
Set by `SecurityHeadersMiddleware` on every response:
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy`: restricts script/style origins
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`

### Internal Service Isolation
- PostgreSQL and Redis are **not** bound to any public interface — Docker bridge network only.
- Redis requires a password (set via `REDIS_PASSWORD` environment variable).
- The crypto daemon binds only to `127.0.0.1`; an external port scan of the VM will not see port 47291.

### Sensitive Data Exposure
- No passwords, private keys, or JWTs are logged.
- Private keys are stored encrypted at rest (Argon2id-derived key) in the crypto daemon's identity store.
- The `.env` file containing secrets is in `.gitignore` and never committed.

---

## Deployment Topology

```
Internet
    │
    ▼ HTTPS/TLS 1.3 (port 443)
[ Reverse Proxy / Nginx on cryptmunks.theburkenator.com ]
    │
    ▼ HTTP (port 8000, internal)
[ Docker: api — FastAPI backend ]
    ├── [ Docker: db — PostgreSQL 16 ] (port 5432, bridge only)
    └── [ Docker: redis — Redis 7    ] (port 6379, bridge only)
              │
              ▼ BLPOP (internal)
    [ Blockchain worker — digestRecorder.js ]
              │
              ▼ HTTPS RPC
    [ Ethereum Sepolia testnet — MessageDigestRegistry contract ]
```

End-user machines connect to the VM only on port 443 (HTTPS + WSS). All other ports are firewalled.

---

## Artefacts

| Artefact | Path |
|---|---|
| PlantUML source diagram | `documentation/network_architecture.puml` |
| Docker Compose definition | `docker-compose.yml` |
| Backend Dockerfile | `backend/Dockerfile` |
| Deployed contract address | `blockchain/deployedAddress.json` |
| Contract ABI | `blockchain/MessageDigestRegistryABI.json` |
| Pentest report | `pentest/report/pentest_report.md` |
| Pentest results (JSON) | `pentest/logs/results.json` |
| Cryptographic design document | `crypto-design.md` |
