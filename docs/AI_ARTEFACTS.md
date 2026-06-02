# AI Prompt Artefacts — SecureMsg (CS4455)
## Team Cryptmunks | 2026

---

## 1. Overview

This document records how AI coding assistants — primarily Claude (Anthropic, via Claude Code CLI) — were used during the development of SecureMsg. It includes representative examples of prompts and responses, reflective commentary on what worked and what required correction, and evidence of critical evaluation of AI-generated code.

---

## 2. Tools Used

| Tool | Usage |
|---|---|
| Claude (claude-sonnet-4-6, via Claude Code CLI) | Primary tool. Architecture decisions, code generation, debugging, documentation |
| GitHub Copilot | Inline autocomplete during C++ and Python editing |

---

## 3. Representative AI Interactions

### 3.1 Designing the Double Ratchet AAD

**Context:** I needed to decide what to include in the AES-256-GCM associated data for Double Ratchet messages. The spec says "use associated data meaningfully where appropriate."

**Prompt (to Claude):**
> I'm implementing the Double Ratchet in Python using AES-256-GCM. What should I put in the associated data? I have access to both parties' long-term identity key public bytes, the sender's current ratchet public key, and the message sequence numbers PN and N.

**Summary of AI response:**
Claude suggested including SHA-256 hashes of both identity keys (to bind the ciphertext to a specific conversation between two parties), the sender's ratchet public key bytes (to bind to the ratchet epoch), and PN and N as 4-byte big-endian integers. It explained that including the raw identity keys directly would work but hashing them keeps the AAD a fixed-size structure and prevents leaking the full public key to a log-scraping server.

**What I kept:** The overall structure — SHA-256(IK_A) || SHA-256(IK_B) || ratchet_pub || PN || N. This is reflected in `crypto-daemon/double_ratchet.py`.

**What I changed:** Claude initially suggested including the message UUID in the AAD. I removed this after recognising it would require the server to provide the UUID before encryption, which created a round-trip ordering problem with our async send flow. I noted this as a known limitation in `docs/CRYPTO_DESIGN.md §4.3`.

**Critical evaluation:** The AAD design was sound. The tradeoff I made (excluding message_id) was a conscious engineering decision that I can defend: the ratchet sequence numbers already prevent out-of-order or replayed messages within a conversation; the excluded UUID creates a narrow theoretical weakness documented honestly.

---

### 3.2 Argon2id Parameter Selection

**Context:** Choosing Argon2id parameters for password hashing. I knew we needed Argon2id but not the right parameter values for a server running on a shared VM.

**Prompt:**
> What Argon2id parameters should I use for a university project server that might be a 2-core VM with 4 GB RAM? I want to follow OWASP recommendations. Using passlib in Python.

**Summary of AI response:**
Claude cited the OWASP Password Storage Cheat Sheet 2024 and RFC 9106, recommending `m=65536` (64 MiB), `t=3`, `p=4` as the OWASP "recommended" profile, and `m=19456` as the minimum. It noted that on a 2-core machine, `p=4` (parallelism) would be set higher than the physical core count, which is fine — Argon2 uses parallelism to resist GPU attacks, not just CPU multi-threading. It also warned against using `p=1` which would make the hash cheaper to parallelise on an attacker's GPU.

**What I kept:** `m=65536, t=3, p=4` verbatim in `backend/app/services/auth_service.py`.

**What I verified:** I timed the hash on our VM: ~180 ms per operation — acceptable for login but not for high-frequency operations. I confirmed the passlib defaults do not override our explicit parameters by writing a unit test.

**What I rejected:** Claude also suggested considering bcrypt as a simpler alternative "if Argon2 adds complexity." I rejected this because bcrypt is limited to 72-byte passwords (silent truncation for longer inputs), and the spec explicitly asks us to justify our choice against alternatives. Argon2id is strictly better here.

---

### 3.3 C++ TLSVerifier Implementation

**Context:** The C++ client needed to verify the server's TLS certificate to prevent MITM. I wanted to use OpenSSL directly rather than relying solely on libcurl's built-in verification.

**Prompt (to Claude Code):**
> Write a C++ class TLSVerifier that uses OpenSSL to verify a server's TLS certificate against the system CA store and optionally pin a specific SHA-256 certificate fingerprint. It should work on macOS and Linux and integrate with Qt6.

**Summary of AI response:**
Claude generated a class with `SSL_CTX_set_verify`, `X509_verify_cert`, and `X509_digest` calls. It used `OpenSSL/ssl.h` and `OpenSSL/x509.h` correctly.

**Issues found and fixed:**
1. The generated code called `SSL_CTX_load_verify_locations` with the system CA path hardcoded to `/etc/ssl/certs/ca-certificates.crt`. This fails on macOS where the CA store is in the Keychain, not a flat file. I replaced this with `SSL_CTX_set_default_verify_paths()` which uses the OpenSSL-compiled-in default and works cross-platform.
2. The fingerprint pinning used `EVP_MD_CTX` on the heap without a corresponding `EVP_MD_CTX_free`. I fixed this with an RAII wrapper and `std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>`.
3. The generated code did not handle the case where the server certificate chain had an intermediate CA not in the system store (relevant for our VM which uses a Let's Encrypt chain). I added `SSL_CTX_set_verify_depth(ctx, 5)`.

**What this shows:** AI-generated OpenSSL code frequently misses platform-specific CA store paths and memory management of EVP contexts. Both required domain knowledge that the AI lacked in context.

---

### 3.4 Pentest Suite — SQL Injection Test

**Context:** Writing the automated penetration test suite. I wanted to test for SQL injection in the message search endpoint.

**Prompt:**
> Write a pytest test that sends a SQL injection payload in a message search query parameter to a FastAPI endpoint and verifies the server returns either a 400 or a 422, not a 500 (which would suggest the injection reached the database).

**Summary of AI response:**
Claude generated a test with payloads from the OWASP Testing Guide (apostrophe, UNION SELECT, stacked queries with semicolons, boolean-based blind injection). The test structure was correct.

**Issue found:** The generated test used `requests.Session` directly and assumed the auth cookie was available as a module-level fixture. Our suite uses a `pytest` fixture pattern for session setup. I refactored the test to use the `auth_session` fixture pattern already established in `test_auth.py`.

**Result:** All 3 SQL injection tests pass — FastAPI's Pydantic validation and SQLAlchemy's parameterised queries prevent injection at both layers. Evidence is in `pentest/report/pentest_report.md §INJ-01` through `INJ-03`.

---

### 3.5 Blockchain Batching Design

**Context:** The spec notes "a hash for each message may be excessive" (gas cost concern). I needed to decide on a batching strategy.

**Prompt:**
> For a messaging app writing keccak256 hashes to an Ethereum smart contract, what's a sensible batching strategy to reduce gas costs while still providing meaningful tamper-evidence? We're on Sepolia testnet.

**Summary of AI response:**
Claude explained the gas cost structure of Ethereum transactions (base cost ~21,000 gas + ~20,000 gas per SSTORE for a new storage slot), estimated ~0.0002 ETH per transaction on mainnet at 10 gwei. It suggested batching on a time window (e.g. every 60 seconds) or a message count threshold (e.g. every 10 messages), whichever comes first. It recommended using a `bytes32[]` array in the Solidity function to store multiple hashes per transaction.

**What I kept:** The time-window approach — our Redis queue (`backend/app/services/redis_service.py`) accumulates message IDs and a background worker flushes them every 60 seconds via `storeHashBatch()` on the contract. This is reflected in `blockchain/contracts/MessageDigest.sol`.

**What I modified:** The AI suggested a maximum batch size of 50 hashes. I reduced this to 20 after checking Sepolia block gas limits (30M gas) and calculating that 50 × 20,000 gas = 1,000,000 gas per batch, which might compete with other transactions during high-traffic periods on testnet. 20 × 20,000 = 400,000 gas is more conservative.

---

## 4. Reflective Commentary

### What worked well

- **Architecture-level questions**: Claude was most useful when asked to explain tradeoffs at the design level (e.g., why TOFU vs. PKI, what to include in AAD, how Argon2id parameters scale). These responses were accurate, cited relevant RFCs and standards, and matched what we later verified in the primary sources.
- **Boilerplate generation**: JWT middleware, Pydantic schemas, FastAPI route structure, Alembic migration stubs — Claude generated correct, idiomatic code quickly. This freed time for the security-critical components.
- **Test structure**: The pentest suite skeleton (fixture setup, parametrised payloads, structured reporting) was AI-generated and required minimal modification.

### What required manual correction

- **Platform-specific assumptions**: OpenSSL CA path (macOS vs. Linux), Qt6 signal/slot syntax changes from Qt5, libsodium vcpkg package name (`unofficial-sodium` not `libsodium`).
- **Memory management in C++**: Generated OpenSSL code routinely missed `EVP_MD_CTX_free`, `X509_free`, and similar cleanup. Required adding RAII wrappers in every case.
- **Crypto protocol subtleties**: The AI occasionally suggested shortcuts inconsistent with the Signal Protocol specification (e.g. omitting the signed prekey verification step before X3DH). These were caught by cross-referencing the primary specification documents.
- **Over-engineering**: Claude frequently suggested adding features beyond the task (e.g. key rotation, certificate transparency log verification, multiple concurrent Double Ratchet sessions per user-pair). All of these were explicitly deferred as out of scope.

### Evidence of critical evaluation

- The `message_id` AAD decision (§3.1 above) — AI suggestion rejected for engineering reasons, documented as a known limitation.
- bcrypt rejection in favour of Argon2id (§3.2) — AI alternative rejected with explicit technical justification.
- OpenSSL CA path fix (§3.3) — AI output incorrect for macOS; corrected with platform-appropriate API.
- Batch size reduction (§3.5) — AI suggestion modified based on Sepolia gas limit calculations.

---

## 5. Summary Statement

AI tools accelerated development of SecureMsg significantly, particularly for boilerplate, test scaffolding, and initial drafts of documentation. Every security-critical component — the Double Ratchet implementation, the X3DH key agreement, the Argon2id parameter selection, the AEAD associated data design — was verified against primary sources (RFCs, NIST standards, Signal Protocol specifications) before being accepted. AI-generated C++ code involving OpenSSL and memory management required correction in every case and was not accepted without review. The team is prepared to explain, justify, and defend every cryptographic and architectural decision in the codebase during the interview.
