
**Team:** Alpha and the Cryptmunks  
**Module:** CS4455 Cybersecurity  
**Tools Used:** Claude (claude.ai) and Claude Code

---

## Phase 1 — Planning and Architecture

---

### Artefact 1.1 — Sprint Planning and Task Prioritisation
**Module:** All  
**Date:** 21 May 2026  
**Context:** Early in the project, before any code was written. Needed to figure out what order to tackle everything in given that four modules had to integrate into one system.

**Prompt:**
> We're building a secure messaging app for the CS4455 EPIC project covering C++, Cryptography, Cybersecurity and Blockchain. I've uploaded the four module briefs and our initial architecture diagram. We have three team members and roughly two weeks to build and submit.
>
> Generate a complete sprint-based task list covering every stage of the SDLC — planning through testing and documentation. Organise tasks by module (C++, Crypto, Networks, Blockchain) and split them into sequential sprints where tasks within a sprint can run concurrently. The output should be detailed enough to drop straight into ClickUp and assign to individuals. Include dependencies between tasks explicitly so nothing gets built in the wrong order. Flag anything where getting the sequence wrong would cause rework.

**AI Response:**

> One sequencing decision matters more than all the others: the crypto layer must exist before the messaging API. If you build `POST /messages` and store content in the database first, then bolt on HPKE encryption later, you'll rewrite every endpoint. Do HKDF derivation and key establishment first, confirm the server only ever sees ciphertext, then build the storage layer on top of that guarantee.
>
> The Solidity contract is the other thing to do early — it has zero dependencies on your backend. One person can deploy to Sepolia in a browser using Remix IDE right now while the other two are setting up Docker and Postgres. You get the contract address and ABI immediately and don't have to pause later.
>
> The C++ client can run in parallel with the backend throughout — it just needs the API contract (endpoints, request/response shapes, auth headers) agreed upfront. Mock the server responses locally with a simple stub while the backend is being built, then point at the real one once it's up.
>
> **Sprint 1 (concurrent):** repo setup, Docker Compose skeleton, Postgres schema, VM access, Solidity contract deployed to Sepolia.
> **Sprint 2 (concurrent):** Argon2id auth, HPKE key generation + HKDF derivation, C++ socket layer + TLS handshake, Redis rate limiting.
> **Sprint 3:** messaging API endpoints (depend on Sprint 2 crypto), C++ HTTP client (depends on socket layer), blockchain digest recorder (depends on contract from Sprint 1).
> *(continues through testing and documentation sprints...)*

**What we accepted:**  
The sequencing logic was exactly right and we used it directly in ClickUp. The point about doing the Solidity contract early was something we hadn't considered — we had it deprioritised because it felt like it needed the backend to exist first, which was wrong.

**What we changed:**  
The original plan had the C++ networking tasks blocked on the backend being fully live. We adjusted this so the C++ dev mocked the server responses locally using a simple Python stub, which let both tracks run in parallel and saved roughly a week.

**What the AI got wrong / we had to correct:**  
The plan initially assumed HPKE Mode_Auth for key establishment throughout. After reading the lecture notes more carefully we moved to X3DH + Double Ratchet via libsignal, which changed several of the crypto sprint tasks. The AI plan was correct given what it knew at the time but we had to revise the crypto section manually.

---

### Artefact 1.2 — Architecture Documentation: External Connections
**Module:** Networks and Cybersecurity  
**Date:** 20 May 2026  
**Context:** Needed to document all external connections for the architecture doc — one of Burkley's explicit marking criteria.

**Prompt:**
> We need to produce the external connections section of our network architecture document. The brief requires all connections to external services to be documented with protocol, port and encryption status.
>
> Our stack is: FastAPI backend, PostgreSQL database, Redis for session caching and rate limiting, and a Solidity smart contract deployed on Ethereum Sepolia. The backend runs on a VM at alpha-and-the-cryptmunks.theburkenator.com.
>
> For each service give me: the correct Docker Compose config with security-appropriate port binding, the UFW rules needed, the schema or config needed for our use case, and a table I can paste directly into the architecture doc showing the connection details Burkley is asking for. Flag anything that would be a security issue or lose marks if done wrong.

**AI Response:**

> Two things to flag before anything else. First, port 5432 (Postgres) and 6379 (Redis) must be bound to `127.0.0.1` in your Docker Compose — not `0.0.0.0`. Exposing either to the public internet is an immediate security penalty in Burkley's rubric and there's no reason either service needs to be reachable externally. Second, add `.env` to `.gitignore` before your first commit. Credentials in version history are unrecoverable.
>
> For the messages table specifically: store ciphertext and nonce only, never plaintext. The crypto rubric requires demonstrating that a fully compromised server cannot read message content — if you store plaintext or anything decryptable without client keys, you fail that criterion regardless of what else you've implemented.
>
> Here's the architecture doc table:
>
> | Connection | Protocol | Port | Encrypted | Notes |
> |---|---|---|---|---|
> | Client → FastAPI | HTTPS | 443 | TLS 1.3 (Let's Encrypt) | Public-facing |
> | FastAPI → PostgreSQL | TCP | 5432 | localhost only | UFW blocks external |
> | FastAPI → Redis | TCP | 6379 | localhost only | UFW blocks external |
> | FastAPI → Sepolia RPC | HTTPS | 443 | TLS | Via rpc2.sepolia.org |
>
> *(Docker Compose configs, UFW rules and full schema followed...)*

**What we accepted:**  
The full schema was used almost verbatim. The architecture doc table format (Connection / Protocol / Port / Encrypted?) was exactly what was needed and we kept that structure. The reminder about adding `.env` to `.gitignore` before the first commit was something easy to forget under pressure.

**What we changed:**  
The schema Claude suggested had a single public key column per user. Once we moved to a per-device key model (see Artefact 2.3), we had to refactor this to a `devices` table with separate prekey storage. The AI couldn't have anticipated this because we hadn't made that architectural decision yet.

---

## Phase 2 — Design and Cryptographic Decisions

---

### Artefact 2.1 — httpOnly Cookie vs Bearer Token: Security Decision
**Module:** Networks and Cybersecurity / Cryptography  
**Date:** 21 May 2026  
**Context:** During backend auth implementation, there was a conflict between what the spec recommended and how the existing code was set up. The existing code used `localStorage` and `Authorization: Bearer` headers.

**Prompt:**
> We have a conflict in our auth implementation that I need a decision on before we go further.
>
> Current setup: `oauth2_scheme = OAuth2PasswordBearer(...)` in `auth_service.py` reads the token from the `Authorization` header. `app.js` stores the token in `localStorage` and attaches it manually as `Authorization: Bearer <token>`. `TokenResponse` returns the token in the JSON body.
>
> The spec and lecture content point toward httpOnly cookies as the more secure approach — the token is set by the server and JavaScript can never read it, which eliminates the XSS-to-token-theft attack. But switching means rewriting `get_current_user` to read from `request.cookies`, removing the token from `TokenResponse`, and changing `apiFetch` to use `credentials: 'include'` instead of the manual header.
>
> Which approach scores better marks against the Burkley and O'Brien rubrics, and what is the correct security argument for the one we choose? I need to be able to defend this decision in the interview.

**AI Response:**

> Go with httpOnly cookies — this is the right answer for marks and for security, and your lecture notes flag it explicitly with a star marker as the combination to implement.
>
> The problem with your current `localStorage` setup is that any JavaScript running on the page can read `localStorage`. One XSS vulnerability — a single unsanitised input that reflects script — and an attacker exfiltrates the token and takes over the session. httpOnly cookies cannot be read by JavaScript at all; the browser attaches them to requests automatically but they're invisible to any script on the page.
>
> The tradeoff you take on is CSRF: cookies are sent automatically on cross-origin requests, which means a malicious third-party site could trigger authenticated actions on your API. You mitigate this with a `X-CSRF-Token` header — generate a random value server-side, store it in a readable (non-httpOnly) cookie, and require clients to echo it back in a header on every `POST`, `PUT`, `PATCH` and `DELETE`. A cross-origin attacker can trigger the request but can't read the cookie value to forge the header.
>
> Set the cookie with `httpOnly=True`, `secure=True`, `SameSite="Strict"`, and a short `max_age` matching your JWT expiry. In `get_current_user`, replace `Depends(oauth2_scheme)` with `request.cookies.get("access_token")`.

**What we accepted:**  
Switched to httpOnly cookies with CSRF tokens. This was a significant refactor — `get_current_user` had to be rewritten to read from `request.cookies` instead of the auth header, `TokenResponse` no longer needed to return the token in the body, and the frontend `apiFetch` wrapper needed `credentials: 'include'`.

**What we changed:**  
The AI suggested `SameSite=Strict`. We changed this to `SameSite=Lax` because `Strict` broke the redirect flow from the landing page to the chat page — the cookie wasn't sent on top-level navigations, which logged users out on every page load. `Lax` is still secure against CSRF for our threat model.

---

### Artefact 2.2 — Cryptographic Library Choice: libsignal vs libsodium
**Module:** Cryptography  
**Date:** 31 May 2026  
**Context:** After reviewing the plan against the spec, there was uncertainty about whether to use libsignal or libsodium for the crypto layer, and whether the choice differed by component.

**Prompt:**
> We need to decide on cryptographic libraries across the project. The spec says to use vetted libraries and explicitly forbids hand-rolling primitives or protocols.
>
> We have three components: a Python crypto daemon that handles X3DH and the Double Ratchet, a JavaScript web client using the Web Crypto API, and a C++ desktop client. The lecturer named libsignal specifically on slide 49 and said not to roll your own protocol.
>
> Should we use libsignal or libsodium, and does the answer differ by component? I need a clear recommendation with the reasoning so we can justify the choice in the crypto design document and in the interview with O'Brien.

**AI Response:**

> These aren't alternatives for the same job — they operate at different layers, and the right answer differs by component.
>
> **libsodium** is a primitives library. It gives you X25519 key exchange, ChaCha20-Poly1305 AEAD, Argon2id, Ed25519 signing — the building blocks. You still have to assemble those building blocks into a protocol yourself. **libsignal** is a complete protocol implementation — X3DH session setup, Double Ratchet per-message ratcheting, prekey bundle management, one-time prekey consumption — correctly assembled and audited.
>
> The critical point from slide 49 is "don't roll your own crypto, and that includes protocols." An X3DH implementation you write yourself using libsodium primitives is still hand-rolling a protocol, even if every individual operation is correct. The spec forbids this.
>
> **Python crypto daemon:** libsignal (`python-libsignal` bindings). It needs the full Signal Protocol and the lecturer named it by name. **C++ client:** libsodium or OpenSSL EVP. The client delegates all crypto to the daemon — it only needs primitives for the TLS connection and local key operations, which is exactly what libsodium is for. **Web client:** Web Crypto API for primitives; the browser-side Signal Protocol session is managed by the daemon via the local API.

**What we accepted:**  
This split exactly matched what the lecture said and we implemented it this way — libsignal for the Python crypto daemon, libsodium for the C++ client.

**What we changed:**  
Claude initially framed the answer as if the two libraries were interchangeable alternatives for the same task. We pushed for a per-component answer and that's what made the response useful.

---

### Artefact 2.3 — Multi-Device Account Sync: Architecture Decision
**Module:** Cryptography / Networks  
**Date:** 30 May 2026  
**Context:** The team wanted users to be able to log in on both the web client and the C++ client and access the same messages. Initial idea was some kind of 2FA linking.

**Prompt:**
> We need users to be able to access their messages on both the C++ desktop client and the web client under the same account, similar to how WhatsApp Web works alongside the mobile app.
>
> The challenge is that our E2EE implementation generates identity keys per client during registration, so the two clients have different key material and can't share messages without decryption happening server-side — which breaks our threat model.
>
> Our team initially thought about a 2FA-style linking mechanism but we're not sure that actually solves the key synchronisation problem. What is the cryptographically correct way to handle this, and what schema and API changes does it require? The solution needs to work with our existing X3DH and Double Ratchet setup.

**AI Response:**

> Your instinct about 2FA is right to question — it doesn't solve the problem. 2FA proves you own the account; it does nothing about the key material. The web client's identity key and the C++ client's identity key are different keypairs. A message encrypted to one cannot be decrypted by the other regardless of how the devices are linked at the auth layer.
>
> The correct model is per-device key bundles with server-side fanout, which is exactly how Signal handles linked devices. Each device registers independently with its own IK, SPK and OPK pool. When Alice sends a message to Bob, the server looks up all of Bob's registered devices, fetches each device's key bundle, and sends a separate encrypted copy to each. Each device decrypts its own copy independently. The server stores multiple ciphertexts — one per recipient device — but never sees plaintext.
>
> Schema changes needed: replace the single `public_key` column on `users` with a `devices` table (`device_id`, `user_id`, `device_label`, `ik_pub`, `created_at`, `last_seen`) and a `device_prekeys` table (`device_id`, `spk_pub`, `spk_sig`, `opk_pub[]`). Your message fanout logic in `POST /messages` loops over all active devices for each recipient rather than looking up a single key.

**What we accepted:**  
The per-device key architecture was exactly right and matched the Signal Protocol multi-device model from the lecture notes. We implemented the `devices` and `device_prekeys` schema as suggested.

**What we changed:**  
The AI's suggested device linking flow involved QR code scanning to prove physical possession of the primary device. We simplified this to a short-lived token sent to the already-authenticated session — less elegant but functionally equivalent for our threat model and actually implementable in the time we had.

---

### Artefact 2.4 — Blockchain Gas Strategy Design
**Module:** Blockchain  
**Date:** 20 May 2026  
**Context:** Needed to decide and document the blockchain recording strategy before implementing — batched every N messages, event-triggered or per-message.

**Prompt:**
> We need to decide on and document our blockchain recording strategy before we start implementation. The brief says to record message conversation digest hashes on the Sepolia testnet, and to pay attention to trade-offs — a hash for each message may be excessive.
>
> Our options as we see them are: per-message (every message triggers a transaction), batched every N messages (only write when the count hits a threshold) or event-triggered (write on specific actions regardless of count). There may be a hybrid approach too.
>
> Give us a recommendation with a clear rationale for each design choice. We need to be able to justify the strategy to Le Gear in the interview — specifically why we chose the batch size we did and why certain events force an immediate write regardless of the batch counter.

**AI Response:**

> The right answer is a hybrid: batch by default with forced writes on specific events. Per-message is wasteful — each transaction has overhead and the integrity guarantee doesn't improve. Pure batching misses cases where the integrity record is needed immediately.
>
> Three events should force an immediate write regardless of the batch counter: **forwarding** (the content is leaving its original E2E encryption boundary — an immediate snapshot proves it wasn't altered before being passed on), **access revocation** (the timestamp must be immutable, since a server-side DB record can be backdated by a compromised server), and **conversation close** (the batch counter won't reach N again, so tail messages would never reach the chain).
>
> For batch size, N=10 is a reasonable default — it balances gas cost against recency of the integrity anchor. One important constraint on user-controlled frequency: if users can set their own recording strategy they can also set it to never record, which lets a malicious user make a conversation undiscoverable. Server-enforced minimums with user upgrades only is the correct design — users can increase frequency above the default but cannot decrease below it.

**What we accepted:**  
The hybrid strategy (N=10 batch + three event triggers) was implemented exactly as described. The server-enforced minimum design was used directly in the architecture doc.

**What we changed:**  
N=10 was chosen somewhat arbitrarily by the AI. We justified it in the design doc using gas cost calculations — each Sepolia transaction costs roughly 21,000 gas base fee plus ~5,000 gas per 32-byte hash, so N=10 costs 1/10th of a per-message strategy. That specific justification was our own research.

---

### Artefact 2.5 — Decryption Oracle Problem: Blockchain + E2EE Conflict
**Module:** Blockchain / Cryptography  
**Date:** 21 May 2026  
**Context:** Classmates were discussing a fundamental tension between blockchain and E2EE that could undermine the security of both if handled incorrectly.

**Prompt:**
> There's a concept coming up in discussion around the blockchain integration that I want to make sure I understand before we implement anything. The concern is something like a decryption oracle problem — the idea that putting E2EE message data on a public blockchain could undermine the encryption, because the blockchain is permanently public and anyone can probe it.
>
> Can you explain exactly what the risk is, why our specific design (keccak256 hashes of message content written to Sepolia) does or doesn't have this problem, and how Merkle proofs let us verify individual messages without decrypting anything server-side? I need to understand this well enough to explain it to the blockchain marker.

**AI Response:**

> The risk is real but your design avoids it. Here's the precise problem: a blockchain is permanent and public. If you store encrypted message content on-chain — even well-encrypted content — you've created a permanent archive that anyone can collect and probe indefinitely. If the encryption scheme is ever weakened or broken in the future, that historical ciphertext becomes readable retroactively. The blockchain's immutability, which is supposed to be a feature, becomes a liability.
>
> Your design stores keccak256 hashes, not ciphertext. A hash is one-way — you can verify that a given input produces a given hash, but you cannot recover the input from the hash. There's nothing on-chain that an attacker can probe. Keys never touch the blockchain at any point.
>
> Merkle proofs are what let you verify a single message without touching any other message's content. Each message is a leaf: `H_i = keccak256(message_i)`. You build a binary tree over the batch, store only the root on Sepolia, and keep the full tree in Postgres. To verify message 5 of a batch of 10, the verifier gets the plaintext of message 5, recomputes `H_5`, then receives a proof — a list of sibling hashes up the tree. They compute upward and check whether the result matches the on-chain root. Messages 0–4 and 6–9 stay encrypted throughout. No decryption happens server-side.

**What we accepted:**  
The hash-only design was already what we planned, but this interaction clarified the specific threat and gave us precise language to explain it. The Merkle proof explanation was directly useful for the verification page implementation and the interview.

**What we added beyond the AI output:**  
The AI explained Merkle proofs conceptually. The actual keccak256 Merkle tree construction in Solidity and JavaScript was our own implementation work.

---

## Phase 3 — Implementation

---

### Artefact 3.1 — Redis: Session Caching and Rate Limiting
**Module:** Networks and Cybersecurity  
**Date:** 21 May 2026  
**Context:** Implementing Redis for JWT blacklisting on logout and brute-force rate limiting on the login endpoint.

**Prompt:**
> I need to implement Redis for two things in our FastAPI backend: JWT token blacklisting on logout, and brute-force rate limiting on the login endpoint.
>
> For token blacklisting: our JWTs are stateless so we need a way to invalidate them before expiry when a user logs out. For rate limiting: the brief requires protection against brute-force on the login endpoint — we want to block after repeated failed attempts within a time window.
>
> Give me the full implementation for both: Docker Compose config, the Python redis.asyncio setup, the blacklisting logic and where it hooks into our JWT middleware, and the rate limiter with the FastAPI dependency injection. Make sure the Redis port is not exposed externally and credentials come from environment variables — those are explicit marking criteria in the networks rubric.

**AI Response:**

> One implementation detail on the rate limiter that's easy to miss: the `INCR` and `EXPIRE` calls must be in a pipeline, not called sequentially. If `INCR` succeeds but the process crashes before `EXPIRE` runs, the counter sits at 1 forever with no TTL — a single failed login permanently locks that IP with no automatic recovery. The pipeline makes both operations atomic.
>
> ```python
> pipe = redis_client.pipeline()
> pipe.incr(key)
> pipe.expire(key, WINDOW_SECONDS)
> await pipe.execute()
> ```
>
> Also clear the counter on successful login, not just when the lockout window expires — otherwise a user who eventually gets their password right is still penalised for previous failed attempts in the same window.
>
> For the Docker Compose config, bind Redis to `127.0.0.1:6379` and set `requirepass` in the command — never run Redis without authentication even on localhost. Credentials go in `.env` as `REDIS_PASSWORD`, read via `os.getenv("REDIS_PASSWORD")` in the client setup.
>
> *(Full Docker Compose service config, redis.asyncio client, blacklist and rate limiter implementations followed...)*

**What we accepted:**  
The implementation was used almost exactly as provided. The atomic pipeline for `INCR + EXPIRE` was a detail we wouldn't have thought of — without it there's a race condition where the counter increments but the TTL never gets set, permanently locking the account.

**What we changed:**  
The AI suggested banning by IP address alone. We added a secondary key on `username` — the combined `login_attempts:{ip}:{username}` key catches attackers who rotate IPs while targeting the same account.

---

### Artefact 3.2 — Cryptographic Design Document Review
**Module:** Cryptography  
**Date:** 26 May 2026  
**Context:** The crypto design document was written and needed checking against O'Brien's rubric before submission.

**Prompt:**
> I've written our cryptographic design document and need it reviewed against O'Brien's rubric before we submit. The rubric has five criteria each worth 5%: Authenticated Encryption, Key Establishment and Sender Auth, Password and Key Derivation, Design Document quality, and Understanding and Defence.
>
> Review the document below against each criterion specifically. For each one tell me whether it currently meets the Excellent band, what's missing or weak, and what needs to be added or changed to hit the top band. Be specific — "it's missing X from the Excellent descriptor" rather than general feedback.
>
> [pasted full document]

**AI Response:**

> Going through each criterion against the Excellent band descriptors:
>
> **Authenticated Encryption:** Covered. AES-256-GCM correctly chosen, nonce strategy (one fresh message key per message via Double Ratchet, structurally impossible to reuse) is principled and demonstrably collision-free, AAD construction binds ciphertext to session and message index. The server opacity claim is explicitly demonstrable. ✓
>
> **Key Establishment and Sender Auth:** Covered. X3DH with all four DH operations, Ed25519 SPK signature, TOFU pinning with IndexedDB persistence. The trust model is stated and the deniability property is acknowledged. ✓
>
> **Password and Key Derivation:** Covered. Argon2id with memory=64MiB, iterations=3, parallelism=4 — parameters are justified. HKDF with explicit `info` strings achieving domain separation. Private key at rest encrypted under a separately-derived key. ✓
>
> **Design Document:** Covered. All four attacker classes addressed, limitations stated honestly, primitives justified at parameter level. ✓
>
> **One gap across all sections:** there's no mention of the JWT session token anywhere — httpOnly cookie, 15-minute expiry, HS256. This is covered in the lecture material and is a mark opportunity in the Networks rubric if not the Crypto one. Make sure it's documented somewhere in your submission.

**What we accepted:**  
The rubric-by-rubric structure of the review was exactly what was needed. The JWT gap was real — it wasn't in either doc. We added it to the networks architecture doc.

**What we pushed back on:**  
Claude marked Understanding and Defence as covered based on the document alone. That criterion is assessed in the interview, not from the document — we used the AI's summary as a study guide rather than confirmation we'd scored it.

---

### Artefact 3.3 — C++ Client: Build and Deployment Debugging
**Module:** C++  
**Date:** 29 May 2026  
**Context:** The C++ client built successfully with CMake but crashed immediately on launch on Windows with a generic missing DLL dialog.

**Prompt:**
> The C++ client builds cleanly with CMake but crashes immediately on launch with a missing DLL error. No DLL name is shown in the dialog. The client is built with Qt6, libsodium and OpenSSL via vcpkg, targeting Windows 10 with MSVC.
>
> The build was done in the x64 Native Tools Command Prompt using:
> ```
> cmake .. -DCMAKE_BUILD_TYPE=Debug -DQt6_DIR="C:/Qt/6.11.1/msvc2022_64/lib/cmake/Qt6"
> cmake --build . --parallel
> ```
> The exe is at `client-cpp/build/Debug/SecureMsg.exe`. The crypto daemon is running on 127.0.0.1:47291 and the backend is live at https://alpha-and-the-cryptmunks.theburkenator.com.
>
> What's causing the DLL error and how do I fix it?

**AI Response:**

> This is a Qt deployment issue — the exe built fine but the Qt runtime DLLs aren't next to it. Windows looks for DLLs in the same directory as the exe first, then `PATH`. When you build with CMake, Qt links against the DLLs but doesn't copy them to the output directory. The dialog gives no filename because it fails before any meaningful output can be produced.
>
> Fix: run `windeployqt.exe` against your exe. It scans the binary, works out which Qt modules are used, and copies every required DLL alongside it:
>
> ```cmd
> C:\Qt\6.11.1\msvc2022_64\bin\windeployqt.exe C:\Users\user\EPIC\client-cpp\build\Debug\SecureMsg.exe
> ```
>
> Run that once, then launch the exe again — it should open. If you still get a DLL error after that, it'll be a vcpkg dependency (libsodium or OpenSSL) rather than Qt. Those need to be copied manually from your vcpkg installed directory or added to `PATH`.

**What we accepted:**  
The `windeployqt` fix was correct and not something we knew to look for. The generic Windows DLL dialog gives no indication of which DLLs are missing, making this hard to diagnose without knowing it exists.

**What we changed:**  
An earlier version of this prompt was much vaguer and triggered several diagnostic questions before Claude could help. Providing the full build command, exe path and running services upfront got a direct answer immediately.

---

### Artefact 3.4 — TOFU Key Pinning: In-Memory vs Persistent Storage
**Module:** Cryptography / Networks  
**Date:** 21 May 2026  
**Context:** The existing TOFU implementation stored key fingerprints in a JavaScript `Map` in memory, wiping pins on every page reload.

**Prompt:**
> Our current TOFU implementation in `app.js` uses an in-memory JavaScript `Map` to store identity key fingerprints. This means the pins are wiped on every page reload — a user could be talking to a different key after refreshing and the TOFU check would pass as if it were the first contact.
>
> I need to fix this so key pins survive across sessions. Based on the spec and lecture content what's the right browser storage mechanism, what schema should we use, and what exactly should happen when a key fingerprint changes on a subsequent fetch — should we warn, block or silently update?
>
> Also, while we're touching the keybundle system: what should the server return if the SPK is missing entirely, and what should the client do if the OPK pool is exhausted?

**AI Response:**

> In-memory TOFU is not real TOFU. The attacker doesn't need to intercept your connection — they just need to wait for a page reload and serve a substituted key. At that point the client treats it as first contact and pins the attacker's key. Use IndexedDB for persistence; it survives page reloads, browser restarts and sessions. Schema: `{ username, ikFingerprint, pinnedAt }` where `ikFingerprint` is the SHA-256 hex of the raw IK public key bytes.
>
> On key mismatch: block, never silently update. Show a visible modal that the user must acknowledge before proceeding — "Security warning: the identity key for [username] has changed." Silent acceptance defeats the entire purpose of pinning. A key change is either an attack or an account compromise; either way the user needs to know.
>
> For the edge cases: SPK missing → return 503. X3DH requires the signed prekey — without it the handshake cannot proceed and the correct response is to tell the client to try again later. OPK pool exhausted → return the bundle without an OPK and let the client fall back to 3-DH (omitting DH4). This slightly reduces forward secrecy on the initial message but is the specified fallback in the Signal Protocol.
>
> One thing to add to your logout handler: clear the IndexedDB store when the user logs out so pins don't persist across different accounts on the same browser.

**What we accepted:**  
IndexedDB implemented exactly as described. The key-change warning is a blocking modal — the user cannot proceed until they acknowledge it.

**What we rejected:**  
Claude suggested clearing the IndexedDB store on logout. We rejected this — TOFU pins must survive logout and login because you pin a key once and compare against it forever. Clearing on logout means every new session is a fresh TOFU, which defeats the purpose entirely. This was a genuine error in the AI output.

---

### Artefact 3.5 — Web Client Message Features: Prompt Engineering for Claude Code
**Module:** All  
**Date:** 2 June 2026  
**Context:** Delete, revoke, download and forward existed in the C++ client. Used Claude.ai to produce a structured Claude Code prompt to replicate them in the web client without security regressions.

**Prompt (to Claude.ai):**
> I need to produce a Claude Code prompt to implement four message management features in the web client: delete, revoke access, download and forward. These features are already fully implemented in the C++ client.
>
> The prompt needs to instruct Claude Code to: read the C++ client source first and mirror the logic exactly rather than reimplementing from scratch; implement the FastAPI backend endpoints if they're missing; and implement the frontend in JS and HTML matching the existing styling.
>
> Security constraints that must be in the prompt: forward must re-encrypt to the new recipient's public key using Web Crypto, not reuse the original ciphertext. Download must decrypt locally in the browser, never send plaintext to the server. Revoke must remove the DB access grant and trigger an on-chain event write. All four endpoints must enforce ownership or explicit share grant — no other access path. The prompt also needs a security checklist for Claude Code to self-verify before it's done.
>
> The C++ source is in `/client-cpp/src/`, the web client is in `/web-client/` and the FastAPI backend is in `/backend/`.

**AI Response:**

> Here's the Claude Code prompt. The most important instruction is Step 1 — Claude Code will improvise if you don't explicitly require it to read the C++ source first. Without that constraint it'll generate plausible-looking code that doesn't match your existing patterns, naming conventions or API shapes.
>
> ---
> *Step 1 — Read before writing. Open `/client-cpp/src/` and read every file related to delete, revoke, download and forward before writing a single line. Understand the API calls made, the payloads sent, the crypto operations performed and the state changes expected. Mirror this logic faithfully — do not reimagine it.*
>
> *Step 2 — Backend. For each missing FastAPI endpoint: enforce that the requesting user either owns the message or holds an explicit share grant — no other access path. Revoke must delete the DB grant record AND write a blockchain event hash to the smart contract. All four endpoints need rate limiting and input validation.*
>
> *Step 3 — Frontend. Forward must fetch the recipient's public key, decrypt the message locally using Web Crypto, and re-encrypt to the new recipient — never reuse the original ciphertext. Download must decrypt in the browser; the server must never receive plaintext.*
>
> *Step 4 — Security checklist before finishing: test IDOR by changing message IDs in requests, verify SQL injection protection on all new parameters, confirm CORS config is not wildcard, check TOFU pin is verified before forward re-encryption...*
>
> ---
>
> Add the actual file paths for your C++ source and web client directories before running this — I've left them as descriptive placeholders but Claude Code needs concrete paths.

**What we accepted:**  
The six-step structure was used as written. The "read before writing" instruction was essential — without it Claude Code generates plausible-looking implementations that don't match the existing code structure.

**What we added:**  
We appended actual file paths before running in Claude Code. Without concrete paths Claude Code reads the wrong files. The AI flagged this was necessary but left it as a placeholder.

---

## Phase 4 — Server Setup and Deployment

---

### Artefact 4.1 — TLS Certificate Setup: Let's Encrypt on theburkenator.com
**Module:** Networks and Cybersecurity  
**Date:** 20 May 2026  
**Context:** Needed a valid TLS certificate on the team subdomain for the SSL/TLS marking criteria.

**Prompt:**
> I need to get a Let's Encrypt TLS certificate set up on our team subdomain alpha-and-the-cryptmunks.theburkenator.com. The VM is running Ubuntu and Nginx. Port 80 has just been opened and the DNS A record is now pointing at the VM's IP.
>
> Give me the exact commands to install certbot, obtain the certificate, verify it's working (I need the openssl s_client output for the pentest report), and confirm auto-renewal is set up. Also tell me where the cert files will end up so I can point the Nginx config and the C++ SSL context at them.

**AI Response:**

> Before running certbot, confirm the DNS is actually resolving to your VM — `dig alpha-and-the-cryptmunks.theburkenator.com` should return your IP. If the A record hasn't propagated yet, certbot will fail the ACME challenge silently and give you a confusing error.
>
> ```bash
> sudo apt update && sudo apt install certbot python3-certbot-nginx -y
> sudo certbot --nginx -d alpha-and-the-cryptmunks.theburkenator.com
> ```
>
> For the pentest report, run both of these and screenshot the output:
> ```bash
> openssl s_client -connect alpha-and-the-cryptmunks.theburkenator.com:443
> openssl s_client -showcerts -connect alpha-and-the-cryptmunks.theburkenator.com:443
> ```
> The `-showcerts` flag shows the full chain — leaf cert, intermediate CA, root — which is what you need for chain of trust verification evidence.
>
> Cert files land at `/etc/letsencrypt/live/alpha-and-the-cryptmunks.theburkenator.com/` — `fullchain.pem` for the cert and chain, `privkey.pem` for the private key. Point your Nginx config and your C++ `SSL_CTX_load_verify_locations()` call at these paths. Auto-renewal is handled by a systemd timer certbot installs automatically; verify it with `sudo systemctl status certbot.timer`.

**What we accepted:**  
All certbot commands used exactly as given. The `openssl s_client -showcerts` output was used directly in the pentest report as evidence of certificate chain verification. The DNS check reminder was useful — we had tried certbot before the A record propagated and got an opaque error.

---

### Artefact 4.2 — Firewall Configuration After UFW Inactive State
**Module:** Networks and Cybersecurity  
**Date:** 26 May 2026  
**Context:** UFW was installed on the VM but `sudo ufw status` returned `inactive` — all the allow rules we'd added were doing nothing.

**Prompt:**
> Our VM's firewall isn't working. We've been adding UFW rules but just noticed `sudo ufw status` returns `Status: inactive`. Here's the current state:
>
> ```
> student@alpha-and-the-cryptmunks:~/EPIC$ sudo ufw allow 8000/tcp
> Rules updated
> Rules updated (v6)
> student@alpha-and-the-cryptmunks:~/EPIC$ sudo ufw status
> Status: inactive
> ```
>
> We need ports 22, 80, 443 and 8000 open. What's the correct sequence of commands to enable UFW without locking ourselves out of the VM?

**AI Response:**

> The rules exist but UFW isn't enforcing them — it only does that once enabled. The order here matters: you must allow SSH before you enable, or the firewall activates with its default deny-all policy and blocks your current SSH connection immediately.
>
> ```bash
> sudo ufw allow ssh        # port 22 — do this FIRST
> sudo ufw allow 80/tcp
> sudo ufw allow 443/tcp
> sudo ufw allow 8000/tcp
> sudo ufw enable           # safe to run now
> sudo ufw status           # confirm
> ```
>
> Once enabled, `sudo ufw status` should show all four rules as ALLOW and status as active. Don't add any other ports — Postgres (5432) and Redis (6379) should stay internal only.

**What we accepted:**  
The ordering was exactly right and used as given. Enabling UFW without the SSH rule first would have required contacting module staff to restore VM access.

---

## Phase 5 — Frontend Design

---

### Artefact 5.1 — Translating a Canva Design to a Claude Code Prompt
**Module:** N/A (implementation quality)  
**Date:** 2 June 2026  
**Context:** The frontend had been designed in Canva. Needed to convert that visual design into a precise Claude Code prompt to implement it in HTML and CSS.

**Prompt:**
> I've designed the web client frontend in Canva and need to turn it into a Claude Code prompt that will produce a faithful implementation. I'm attaching a screenshot of the design.
>
> The design has: a split-panel login page (branding left, form right) with a looping video background and glassmorphism form panels, a main chat view with a sidebar contacts list and message bubbles, and a separate blockchain verification page that needs to look like a forensic audit tool rather than part of the app.
>
> The existing CSS design system uses these tokens and nothing else: background `#0f1117`, surface `#1a1d2e`, border `#2d3148`, accent `#7c3aed`, blockchain-verified green `#34d399`, text `#e2e8f0`.
>
> Produce a Claude Code prompt that: describes every layout decision precisely enough that it doesn't need to see the image, specifies the glassmorphism CSS values for the login panels, covers the blockchain status states (verified checkmark vs pending hourglass) in the chat header, and explicitly constrains the verify page to a different aesthetic — monospace font, light background, no dark theme, no decorative elements. The existing JS logic must not be touched — styling only.

**AI Response:**

> Export from Canva before writing any code: background video as `.mp4` (trim to a loop-able clip, target under 5MB), a static `.webp` fallback frame, the chipmunk logo as a transparent `.png`, and the blockchain symbol as a transparent `.png`. Put all four in `/web-client/public/assets/`.
>
> Here's the Claude Code prompt:
>
> ---
> *Style the web client to match the Alphra design. CSS variables only — do not introduce any colour not in this list: `--bg: #0f1117`, `--surface: #1a1d2e`, `--border: #2d3148`, `--accent: #7c3aed`, `--verified: #34d399`, `--text: #e2e8f0`.*
>
> *Login page: split 50/50 horizontally. Left panel: looping `<video>` background (src: `/assets/bg-loop.mp4`), dark overlay `rgba(0,0,0,0.55)`, bottom-left headline in Playfair Display 64px. Right panel: glassmorphism form card — `background: rgba(26,29,46,0.7)`, `backdrop-filter: blur(20px)`, `border: 1px solid rgba(255,255,255,0.08)`, `border-radius: 16px`.*
>
> *Chat view: sent and received bubbles are both light grey/white — do NOT use a coloured sent bubble. The chat header shows a blockchain status chip: `⛓ Anchored` in `--verified` green when verified, `⏳ Pending` in amber when not.*
>
> *Verify page: this is a forensic audit tool. Monospace font throughout, light `#f8f8f8` background, black text, no dark theme, no glassmorphism, no decorative elements. It must look completely different from the rest of the app.*
>
> *Do not touch any JavaScript, API calls, event listeners or data flow. Styling only.*
>
> ---
>
> The monochrome bubble instruction is critical — Claude Code will default to a coloured sent bubble without it.

**What we accepted:**  
The prompt structure was used and Claude Code produced a faithful implementation. The monochrome bubble instruction was correct — in testing without it Claude Code added a blue sent bubble immediately.

**What we changed:**  
The verify page constraint wasn't strong enough on first pass — Claude Code still applied the dark theme to it. We strengthened the instruction to include "no dark theme" explicitly, which fixed it.