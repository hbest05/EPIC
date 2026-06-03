# SecureMsg — C++ Qt6 Desktop Client

A Qt6 desktop client for the SecureMsg E2EE messaging system. Cryptographic operations (X3DH, Double Ratchet) are handled by the **crypto daemon** running locally over TCP; the C++ client sends and receives opaque ciphertext only.

---

## Prerequisites

| Dependency | Version | Install |
|---|---|---|
| Qt6 | 6.6+ (Core, Widgets, Network, WebSockets) | `winget install Qt.Qt.6.6.3` (Windows) / `brew install qt` (macOS) / `apt install qt6-base-dev qt6-websockets-dev` (Linux) |
| CMake | 3.20+ | Bundled with Qt installer or `apt install cmake` |
| libcurl | any recent | `vcpkg install curl` / `apt install libcurl4-openssl-dev` / `brew install curl` |
| OpenSSL | 3.x | `vcpkg install openssl` / `apt install libssl-dev` / `brew install openssl` |
| libsodium | 1.0.18+ | `vcpkg install libsodium` (CMake finds it via the `unofficial-sodium` vcpkg port) |

If using [vcpkg](https://github.com/microsoft/vcpkg), install all native deps in one step:

```bash
vcpkg install curl openssl libsodium
```

---

## Build

```bash
cd client-cpp
mkdir build && cd build

# Basic build (Qt6 on PATH):
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build . --parallel

# If Qt6 is not on PATH, provide its CMake dir:
cmake .. -DCMAKE_BUILD_TYPE=Debug -DQt6_DIR=/path/to/qt6/lib/cmake/Qt6
cmake --build . --parallel
```

The compiled binary is `build/Debug/SecureMsg` (Linux/macOS) or `build\Debug\SecureMsg.exe` (Windows).

### Non-default daemon port

To run two clients on one machine pointing at separate daemon instances:

```bash
cmake .. -DDAEMON_PORT=47292   # default is 47291
```

---

## Run

1. Start the **crypto daemon** first (see `crypto-daemon/` in the repo root):

```bash
cd crypto-daemon
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py           # listens on 127.0.0.1:47291 by default
```

2. Launch the client:

```bash
./build/Debug/SecureMsg
```

The client connects to the daemon on startup. If the daemon is not running it will show a connection error — start the daemon first.

---

## Source layout

```
client-cpp/
├── CMakeLists.txt
└── src/
    ├── main.cpp                    Entry point — creates QApplication and LoginWindow
    ├── Client.hpp / .cpp           REST/HTTP controller (libcurl) — all server calls
    ├── CryptoDaemonClient.hpp/.cpp TCP client for the local crypto daemon (IPC)
    ├── TLSVerifier.hpp / .cpp      Standalone OpenSSL certificate chain verification
    ├── User.hpp / .cpp             User identity + public key bundle
    ├── Message.hpp / .cpp          Encrypted message data holder (ciphertext + nonce)
    ├── MessageStore.hpp / .cpp     Per-contact conversation cache (no crypto — UI only)
    ├── TofuStore.hpp / .cpp        TOFU key-pin storage (SHA-256 fingerprints by contact)
    ├── MessageItemDelegate.hpp/.cpp Custom Qt painter for message-thread rows
    ├── LoginWindow.hpp / .cpp      Login / register UI
    └── MainWindow.hpp / .cpp       Main chat UI (send, receive, verify, revoke, forward)
```

### Class responsibilities

| Class | Role |
|---|---|
| `Client` | All HTTP calls to the FastAPI backend via libcurl. Owns the session cookie and CSRF token. |
| `CryptoDaemonClient` | TCP socket client for the crypto daemon. Sends JSON requests, receives JSON responses. Owns the IPC framing. |
| `TLSVerifier` | Verifies the server's TLS certificate chain using OpenSSL directly (independent of Qt's TLS stack). |
| `User` | Holds a user's identity (username, IK public key, signing key). Value type — no heap ownership. |
| `Message` | Holds an encrypted message blob (ciphertext, nonce, ratchet header). No crypto logic. |
| `MessageStore` | `std::map<std::string, std::vector<Message>>` — per-contact ordered message list for UI rendering. |
| `TofuStore` | SHA-256 fingerprint pinning: load/save a `std::unordered_map<username, fingerprint>` to `tofu_pins.json`. |
| `LoginWindow` | Qt login/register form. Calls `Client` on submit; transitions to `MainWindow` on success. |
| `MainWindow` | Main UI. Owns `Client`, `CryptoDaemonClient`, `MessageStore`, `TofuStore`. Drives the send/receive/verify flow. |

---

## How it works

1. **Login** — `LoginWindow` calls `POST /api/auth/login` via `Client`. On success the session cookie is stored inside `Client`.
2. **Key setup** — on first run the user registers: `CryptoDaemonClient` asks the daemon to generate an X25519 identity key + Ed25519 signing key + SPK + OPK batch; `Client` uploads the public bundle to `POST /api/auth/prekeys`.
3. **Sending a message** — `MainWindow` calls `CryptoDaemonClient::encryptMessage()`. The daemon runs X3DH (first message) or a Double Ratchet step (subsequent messages) and returns ciphertext + nonce. `Client` posts this to `POST /api/messages/send`.
4. **Receiving messages** — `MainWindow` polls `GET /api/messages/inbox`. Ciphertext is passed to `CryptoDaemonClient::decryptMessage()`; the daemon returns plaintext. Messages are stored in `MessageStore` and rendered via `MessageItemDelegate`.
5. **TOFU pinning** — on first contact, `TofuStore::pin()` stores the SHA-256 of the recipient's IK. On subsequent fetches, `TofuStore::verify()` compares; a mismatch shows a `QMessageBox::critical` and blocks the message.
6. **TLS verification** — `TLSVerifier::verify()` checks the server's certificate chain against the system trust store using OpenSSL `X509_verify_cert`. This runs independently of Qt's network stack.

---

## Memory management

The component follows modern C++ ownership rules throughout — no raw `new`/`delete`.

| Pattern | Where used |
|---|---|
| **Stack / value types** | `User`, `Message` — small structs passed by value or `const&`. No heap allocation. |
| **`std::vector<Message>`** | Per-contact message list inside `MessageStore`. Owned by the map; grows as messages arrive, no manual lifecycle. |
| **`std::map<std::string, std::vector<Message>>`** | `MessageStore` internal store — RAII, destroyed with the `MessageStore` object. |
| **`std::unordered_map<std::string, std::string>`** | `TofuStore` pin table — same RAII ownership. |
| **Qt parent-child ownership** | All `QWidget` subclasses (`LoginWindow`, `MainWindow`, `MessageItemDelegate`) use Qt's parent-child tree. Qt deletes children when the parent is destroyed — no `std::unique_ptr` needed for UI objects. |
| **CURL handle** | `Client` holds a `CURL*` wrapped in a `std::unique_ptr<CURL, CurlDeleter>` with a custom deleter that calls `curl_easy_cleanup`. No raw `delete`. |
| **OpenSSL objects** | `TLSVerifier` wraps `X509_STORE_CTX*` and friends in RAII guards that call the corresponding `_free` functions on scope exit. |

No raw owning pointers appear in public interfaces. `std::shared_ptr` is not used — all ownership is either exclusive (unique_ptr) or managed by Qt's object tree.

---

## STL containers and algorithms used

| Container / algorithm | Location | Why |
|---|---|---|
| `std::vector<Message>` | `MessageStore` | Ordered message list per contact; O(1) append, random access for display |
| `std::map<std::string, std::vector<Message>>` | `MessageStore` | Sorted contact index; deterministic iteration order for the sidebar |
| `std::unordered_map<std::string, std::string>` | `TofuStore` | O(1) fingerprint lookup by username |
| `std::string` | Throughout | Value-semantic string ownership; avoids manual `char*` lifetime |
| `std::sort` | `MessageStore::sortByTimestamp()` | Sorts a contact's message list by timestamp after an out-of-order arrival |
| `std::find_if` | `Client` header parsing | Locates a specific response header in a `std::vector<std::string>` of raw headers |
| Range-based `for` + lambda | `MainWindow` render loop | Iterates `MessageStore` entries to populate the UI list widget |
| `std::optional<std::string>` | `TofuStore::get()` return type | Distinguishes "pin exists" from "contact not seen before" without a sentinel value |

---

## AI tool use

Claude (claude.ai / Claude Code CLI) was used during development of the C++ component. Key interactions:

- **Build system setup** — initial `CMakeLists.txt` structure for Qt6 + vcpkg was scaffolded by Claude and then adjusted for the Windows build environment (vcpkg toolchain path, Qt6 WebSockets module addition).
- **TLSVerifier** — Claude provided the OpenSSL `X509_verify_cert` call sequence; the RAII guard wrappers and the decision to run verification independently of Qt's TLS stack were added manually after reviewing the generated code.
- **CryptoDaemonClient framing** — Claude suggested a simple length-prefixed JSON framing; we switched to newline-delimited JSON to match the daemon's existing `transport.py` protocol (Claude's suggestion assumed a different wire format).
- **What we changed** — Claude consistently generated code that assumed Unix paths and `POSIX`-style error handling; all path handling was rewritten to use `QStandardPaths` and Qt's cross-platform abstractions. Memory management was audited manually — one generated function used a raw `char*` buffer that was replaced with `std::string`.

Full AI interaction logs are in `documentation/JuliaHooperAIartefact.md`.
