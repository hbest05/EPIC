# Network Architecture Documentation

**Project:** EPIC — SecureMsg (CS4455)
**Date:** 2026-06-02
**Note:** The backend runs on a remote VM accessible at `alpha-and-the-cryptmunks.theburkenator.com`. All local references (`db`, `redis`) are Docker-internal hostnames within that VM.

---

## 1. System Overview

SecureMsg has five networked components:

| Component | Language / Runtime | Role |
|---|---|---|
| FastAPI backend | Python 3.12 / Uvicorn | REST API, WebSocket hub, blockchain bridge |
| PostgreSQL 16 | Docker container | Persistent message + user storage |
| Redis 7 | Docker container | Auth-failure tracking, blockchain batch queue |
| Web frontend | Browser JS (served by FastAPI) | User-facing chat UI |
| C++ desktop client | Qt6 + libcurl | Native desktop chat client |

The backend submits transaction data to the Ethereum Sepolia testnet via an external Infura/public RPC endpoint.

---

## 2. Network Topology

```
[Browser / C++ Client]
        │
        │  HTTPS/WSS (port 443)
        ▼
[Reverse proxy — TLS terminator — NOT in repo]
        │
        │  HTTP (port 8000, plain)
        ▼
[FastAPI / Uvicorn — Docker container, port 8000]
        │
        ├──[redis://redis:6379/0]──► [Redis 7 — Docker internal]
        │
        ├──[postgresql+asyncpg://db:5432/securemsg]──► [PostgreSQL 16 — Docker internal]
        │
        └──[HTTPS — AsyncHTTPProvider]──► [Sepolia JSON-RPC (rpc2.sepolia.org or Infura)]
                                                │
                                                └──► [Ethereum Sepolia testnet]
```

**Port summary:**

| Connection | Port | Protocol | Notes |
|---|---|---|---|
| Client → backend | 443 | HTTPS / WSS | Via reverse proxy (not in repo) |
| Reverse proxy → Uvicorn | 8000 | HTTP (plain) | Internal VM only |
| Backend → PostgreSQL | 5432 | TCP | Docker internal network |
| Backend → Redis | 6379 | TCP | Docker internal network |
| Backend → Sepolia RPC | 443 | HTTPS | Outbound to public endpoint |
| Docker host → PostgreSQL | 5433 | TCP | Dev tool access only (`docker-compose.yml` line 62) |

---

## 3. TLS/SSL Configuration

### 3.1 Backend (Uvicorn)

**File:** `backend/Dockerfile`, line 41

```sh
uvicorn main:app --host 0.0.0.0 --port 8000
```

Uvicorn starts with **no `--ssl-keyfile` or `--ssl-certfile` arguments**. It serves plain HTTP on port 8000. TLS termination is delegated to a reverse proxy that must be deployed in front of it on the VM. That reverse proxy is **not present in this repository** — it is an operational concern (see §7).

### 3.2 Backend → PostgreSQL

**File:** `backend/app/config.py`, line 40; `backend/app/database.py`, line 78

Connection string: `postgresql+asyncpg://securemsg:securemsg@db:5432/securemsg`

No `sslmode` query parameter is set. The connection runs over the Docker-internal bridge network — traffic does not cross a network boundary that a passive attacker could observe. No TLS is configured.

### 3.3 Backend → Redis

**File:** `backend/app/services/redis_service.py`, lines 23–28; `backend/app/config.py`, line 50

URL scheme: `redis://:password@redis:6379/0` — **plain `redis://`**, not `rediss://`.

Password authentication is used (`--requirepass` in `docker-compose.yml` line 78) but no TLS layer is configured. Traffic is on the Docker-internal network.

### 3.4 Backend → Sepolia RPC (Infura / public node)

**File:** `backend/app/services/blockchain_service.py`, line 117

```python
_w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
```

`AsyncHTTPProvider` uses `aiohttp` internally. `aiohttp` verifies TLS certificates against the system CA bundle by default; no `ssl=False` or `verify=False` override is present in this codebase. The RPC URL defaults to `https://rpc2.sepolia.org` (`backend/.env.example` line 12), which is an HTTPS endpoint. TLS verification is on.

### 3.5 C++ Client → Backend

**Files:** `client-cpp/src/Client.hpp` lines 137–138; `client-cpp/src/Client.cpp` lines 88–90

```cpp
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);   // verify certificate chain
curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);   // verify hostname matches CN/SAN
curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);  // TLS 1.2 floor
```

The hardcoded base URL is `https://alpha-and-the-cryptmunks.theburkenator.com` (`Client.hpp` line 137). Full peer and hostname verification are enabled; TLS 1.2 is the minimum version. The `TLSVerifier` class (`TLSVerifier.cpp`) additionally runs an independent OpenSSL handshake with `SSL_VERIFY_PEER`, SNI (`SSL_set_tlsext_host_name`), and hostname binding (`SSL_set1_host`) to inspect the leaf certificate CN and expiry, surfacing any mismatch to the UI.

The WebSocket URL is derived from the same hostname with `wss://` (line 120 of `Client.hpp`): `wss://alpha-and-the-cryptmunks.theburkenator.com/ws`.

### 3.6 Web Frontend → Backend

**File:** `frontend/app.js`, lines 41–42, 709–710

```js
const API_BASE = (window.SECUREMSG_API_BASE ?? window.location.origin) + "/api";
// ...
const proto = location.protocol === "https:" ? "wss:" : "ws:";
ws = new WebSocket(`${proto}//${location.host}/ws`);
```

The API base URL and WebSocket protocol are **derived from the page's serving origin**. When served over HTTPS (as it will be via the reverse proxy), all API calls go to `https://...` and the WebSocket connects on `wss://`. There is no hardcoded `http://` URL in the production path. TLS certificate verification is handled by the browser's built-in certificate store.

---

## 4. External Service Connections

### 4.1 PostgreSQL

| Property | Value |
|---|---|
| Host (Docker) | `db:5432` |
| Database | `securemsg` |
| User | `securemsg` |
| Driver | `asyncpg` via SQLAlchemy async engine |
| TLS | None (Docker internal network) |
| sslmode | Not set |
| Source | `backend/app/config.py` line 39; `backend/app/database.py` line 78 |

### 4.2 Redis

| Property | Value |
|---|---|
| Host (Docker) | `redis:6379` |
| DB index | `0` |
| Auth | Password via `REDIS_PASSWORD` env var |
| TLS | None — `redis://` scheme |
| Usage | Auth failure counters; blockchain batch queue (Redis Streams) |
| Source | `backend/app/services/redis_service.py` lines 23–28; `backend/app/config.py` line 50 |

### 4.3 Ethereum / Sepolia RPC

| Property | Value |
|---|---|
| Default endpoint | `https://rpc2.sepolia.org` (`.env.example` line 12) |
| Library | `web3.py` — `AsyncWeb3(AsyncHTTPProvider(...))` |
| Protocol | HTTPS — TLS verified by `aiohttp` default CA bundle |
| Authentication | None (public endpoint); private key used to sign transactions locally before broadcast |
| Usage | `recordDigest`, `recordBatch`, `getRecord` calls on `MessageDigestRegistry` contract |
| Source | `backend/app/services/blockchain_service.py` line 117 |

### 4.4 Ethereum Testnet (Sepolia)

Transactions are signed locally with the server wallet private key (`PRIVATE_KEY` env var) before being broadcast via `w3.eth.send_raw_transaction`. The private key is never sent over the network; only the signed raw transaction is transmitted to the RPC endpoint. The `PRIVATE_KEY` value is read from the environment and is never logged (`blockchain_service.py` line 119 comment confirms this).

---

## 5. Client Secure Connectivity

### 5.1 Web Client

- **API calls:** `fetch()` with `credentials: "include"` so the `httpOnly` JWT cookie is sent automatically (`app.js` line 1047). All calls go to `${API_BASE}${path}` where `API_BASE` is origin-relative.
- **CSRF:** On every POST/PUT/DELETE/PATCH, the JavaScript reads the readable `csrf_token` cookie and echoes it in the `X-CSRF-Token` header (`app.js` lines 1042–1044).
- **WebSocket:** Uses `wss://` when the page is served over HTTPS. The JWT cookie is forwarded by the browser on the upgrade handshake. No separate WebSocket authentication is implemented beyond the cookie.
- **TLS verification:** Delegated to the browser's CA bundle — standard browser behaviour.
- **Certificate pinning:** Not implemented; the browser enforces the system/browser trust store only.

### 5.2 C++ Desktop Client

- **TLS floor:** TLS 1.2 minimum (`CURLOPT_SSLVERSION`, `Client.cpp` line 90).
- **Peer verification:** `CURLOPT_SSL_VERIFYPEER = 1` (`Client.cpp` line 88).
- **Hostname verification:** `CURLOPT_SSL_VERIFYHOST = 2` (`Client.cpp` line 89).
- **CA bundle:** System default via libcurl.
- **Certificate inspection:** `TLSVerifier.cpp` performs an independent OpenSSL connection with `SSL_VERIFY_PEER`, SNI, and hostname binding. It reads the leaf certificate CN and `notAfter` and reports them to the UI. An expired or mismatching certificate surfaces as `valid=false` with an error string.
- **Cookie persistence:** A per-process temporary cookie jar stores the `httpOnly` `access_token` and the readable `csrf_token` across API calls within a session. The jar is deleted on `Client::logout()` and on destructor (`Client.cpp` lines 42–46, 274–280).
- **CSRF:** The `X-CSRF-Token` header is echoed on all POST/PUT/DELETE requests using the CSRF token extracted from the cookie jar (`Client.cpp` lines 102–109).
- **WebSocket:** Connects to `wss://alpha-and-the-cryptmunks.theburkenator.com/ws` (`Client.hpp` line 120). Authentication uses the `access_token` cookie from the libcurl jar.
- **Certificate pinning:** Not implemented.

---

## 6. Authentication Over the Network

### 6.1 JWT Lifecycle

**Source:** `backend/app/services/auth_service.py`; `backend/app/routers/auth.py`

| Property | Value |
|---|---|
| Algorithm | HS256 (HMAC-SHA256) |
| Signing key | `JWT_SECRET_KEY` env var — 256-bit random value required in production |
| Default expiry | 30 minutes (`JWT_ACCESS_TOKEN_EXPIRE_MINUTES`, `config.py` line 73) |
| Expiry enforcement | Yes — PyJWT `decode()` raises `PyJWTError` on expired tokens (line 106 of `auth_service.py`) |
| Token payload | `{ "sub": "<user_uuid>", "exp": <unix_ts> }` |

### 6.2 Token Transmission

- The JWT is issued as an **`httpOnly`, `SameSite=Strict`** cookie named `access_token` (`auth.py` lines 165–173).
- In production (`APP_ENV != "development"`), the `secure` flag is also set — the browser will not transmit the cookie over plain HTTP (`auth.py` line 49).
- The token is **never returned in a response body** or accessible to JavaScript. The C++ client reads it from libcurl's cookie jar only to supply it on the WebSocket upgrade handshake.

### 6.3 CSRF Protection

- On login a separate `csrf_token` cookie is set: **not `httpOnly`** (JavaScript must read it) but `SameSite=Strict` and `secure` in production (`auth.py` lines 174–182).
- Every state-changing request must echo this value in the `X-CSRF-Token` header.
- The `CSRFMiddleware` in `backend/app/middleware/csrf.py` compares the header and cookie using `hmac.compare_digest` (constant-time comparison, `auth_service.py` line 77).

### 6.4 Session Validation on Each Request

`get_current_user()` (`auth_service.py` line 91) is a FastAPI dependency injected into every protected route. On each request it:
1. Reads `access_token` from cookies.
2. Decodes and validates the JWT signature and `exp` claim via PyJWT.
3. Extracts the `sub` (user UUID).
4. Fetches the `User` row from PostgreSQL.
5. Checks `user.is_active == True`.

Any failure in steps 1–5 returns HTTP 401.

### 6.5 Brute-Force / Lockout

- Failed login attempts are tracked per client IP in Redis with a 10-minute counter window.
- After 5 failures the IP is locked out for 1 hour (`redis_service.py` lines 67–86).
- Successful login clears the counter (`redis_service.py` line 97).
- The lockout check runs **before** any database query to deny enumeration attacks cheaply.

### 6.6 Token Revocation

**There is no server-side token revocation store.** A user who changes their password receives a new token pair, but the old token remains cryptographically valid until its 30-minute expiry. Logout deletes the cookie on the client but does not invalidate the token server-side. This is documented as a known gap below.

---

## 7. Known Gaps / TBD

| # | Gap | Location | Risk |
|---|---|---|---|
| 1 | **No reverse proxy config in repo.** The Dockerfile starts Uvicorn on plain HTTP port 8000. TLS termination is assumed to happen at an external reverse proxy, but no Nginx/Caddy/Traefik config is committed. The production HTTPS hostname `alpha-and-the-cryptmunks.theburkenator.com` is hardcoded in the C++ client (`Client.hpp` line 137) but how TLS is terminated on the VM is undocumented. | `backend/Dockerfile` line 41 | High — if the reverse proxy is misconfigured, traffic between client and server is unencrypted. |
| 2 | **CORS origins list only localhost.** `main.py` lines 44–50 allow `http://localhost:3000`, `http://localhost:8000`, `http://localhost:5500`, `http://127.0.0.1:5500`. The production hostname `alpha-and-the-cryptmunks.theburkenator.com` is **not listed**. Browser preflight requests from the production web UI will be rejected. | `backend/main.py` lines 44–50 | High — web frontend will be blocked by CORS in production unless the origin is added. |
| 3 | **No JWT revocation store.** Old tokens remain valid for up to 30 minutes after password change or logout. | `backend/app/services/auth_service.py` | Medium — short token lifetime limits exposure, but there is no immediate invalidation capability. |
| 4 | **Redis connection unencrypted.** The Redis URL uses `redis://` (plaintext). Traffic is on the Docker-internal network so it does not traverse an untrusted network segment, but any container on the same Docker bridge can observe it. Upgrade to `rediss://` with a self-signed cert if the threat model includes container compromise. | `backend/app/config.py` line 50 | Low (internal network) / Medium (if containers are shared) |
| 5 | **PostgreSQL connection unencrypted, no `sslmode`.** Same Docker-internal justification as Redis, but no `sslmode=require` in the connection string means PostgreSQL will silently fall back to plaintext even if configured for SSL. | `backend/app/config.py` line 39 | Low (internal network) |
| 6 | **Blockchain consumer loop not implemented.** `redis_service.py` lines 100–113 describe a TODO for a background worker that reads from the blockchain hash stream and ACKs entries. Until implemented, hashes queued in Redis are not being processed for on-chain submission in the worker path. | `backend/app/services/redis_service.py` lines 100–113 | Medium — blockchain audit trail may be incomplete |
| 7 | **No certificate pinning on either client.** The web client relies on the browser CA store; the C++ client relies on the system CA store with libcurl defaults. A CA compromise or MITM with a rogue-but-trusted certificate would not be detected. | `client-cpp/src/Client.cpp`; `frontend/app.js` | Low–Medium (depends on deployment environment) |
| 8 | **WebSocket authentication relies solely on the session cookie.** There is no secondary token or WebSocket-specific credential check beyond forwarding the JWT cookie on the HTTP upgrade. | `backend/app/routers/ws.py`; `frontend/app.js` line 709 | Low — the JWT cookie is `httpOnly` and `SameSite=Strict`; exploitation would require prior session cookie theft |
