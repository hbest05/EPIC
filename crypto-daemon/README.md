# SecureMsg crypto daemon

A local Python process that handles every cryptographic operation for the
SecureMsg client — identity keys, X3DH key agreement, the Double Ratchet,
and at-rest key/session encryption. The C++ Qt UI never touches a private
key; it talks to this daemon over a Unix domain socket (or named pipe on
Windows) using line-delimited JSON.

The daemon is long-running and stateful: identity and Double Ratchet
sessions live in memory for the lifetime of the process and are
persisted, encrypted, to `~/.securemsg/` so they survive restarts.

## Running

```
pip install -r requirements.txt
python main.py                # bind to default address
python main.py --address /tmp/securemsg-crypto.sock     # POSIX
python main.py --address \\.\pipe\securemsg-crypto       # Windows
```

Default address:
- POSIX:   `/tmp/securemsg-crypto.sock` (AF_UNIX stream, mode 0600)
- Windows: `\\.\pipe\securemsg-crypto`  (named pipe via `multiprocessing.connection`)

## Files written

```
~/.securemsg/identity.enc           # IK + signing key, Argon2id+AES-256-GCM
~/.securemsg/sessions/<id>.json     # one file per Double Ratchet session
```

Both are written with mode 0600 on POSIX. Sessions are encrypted under the
same wrap key as the identity file, so an attacker without the passphrase
sees only ciphertext.

## Wire protocol

One JSON object per message. On POSIX each request is a single line ending
in `\n`; on Windows each request is one length-prefixed `send_bytes` frame
(stdlib `multiprocessing.connection` handles framing).

### Request
```json
{ "op": "<operation>", "params": { ... } }
```

### Response
```json
{ "status": "ok",    "data": { ... } }
{ "status": "error", "code": "<short>", "message": "<human>" }
```

Error codes are stable strings: `bad_request`, `unknown_op`, `not_loaded`,
`not_found`, `bad_passphrase`, `no_prekeys`, `invalid_bundle`,
`unknown_opk`, `x3dh_failed`, `no_session`, `no_send_chain`,
`decrypt_failed`, `transport`, `internal`.

## Operations

### `generate_identity`

Generates a fresh X25519 identity key (IK) and Ed25519 signing key,
encrypts them with Argon2id-derived AES-256-GCM, and writes the result
to `~/.securemsg/identity.enc`.

```json
// request
{ "op": "generate_identity", "params": { "passphrase": "..." } }
// response.data
{ "ik_pub": "<b64 32 bytes>", "sign_pub": "<b64 32 bytes>" }
```

### `load_identity`

Reads and decrypts the identity file with the user's passphrase. Also
loads every saved Double Ratchet session that decrypts under the same
wrap key.

```json
// request
{ "op": "load_identity", "params": { "passphrase": "..." } }
// response.data
{ "ik_pub": "...", "sign_pub": "...", "sessions_loaded": 0 }
```

### `rekey_identity`

Re-encrypts the loaded identity and every loaded Double Ratchet session
under a new passphrase. **No new keypairs are generated** — the existing
X25519 IK and Ed25519 signing key are preserved exactly; only the at-rest
encryption changes. A fresh salt and nonce are drawn, a new wrap key is
derived via Argon2id, `identity.enc` is rewritten atomically, and each
session file is re-encrypted under the new wrap key (their on-disk copies
were encrypted under the old key). Requires a loaded identity. The
passphrase is never logged.

```json
// request
{ "op": "rekey_identity", "params": { "new_passphrase": "..." } }
// response.data
{ }
```

### `generate_prekeys`

Generates a Signed Prekey (X25519) signed with the Ed25519 IK and a batch
of 10 One-Time Prekeys. Private halves are kept in memory for use by
`x3dh_receive`; public halves + signature are returned for upload to the
server's prekey bundle endpoint.

```json
// response.data
{
  "spk_pub": "<b64>",
  "spk_sig": "<b64 64 bytes>",
  "opks":   ["<b64>", ... 10 entries]
}
```

### `x3dh_send`

Verifies the SPK signature, performs the four (or three, if no OPK) DH
operations, derives the root key `SK = HKDF(DH1||DH2||DH3||DH4, salt=0,
info='SecureMsg_X3DH_v1')`, initialises a Double Ratchet session as
initiator, and encrypts the first message.

```json
// request
{
  "op": "x3dh_send",
  "params": {
    "peer_user_id": "bob",
    "plaintext": "hello bob",
    "bundle": {
      "ik_pub":   "<b64 32>",
      "sign_pub": "<b64 32>",
      "spk_pub":  "<b64 32>",
      "spk_sig":  "<b64 64>",
      "opk_pub":  "<b64 32 | omit if none>"
    }
  }
}
// response.data
{
  "session_id":   "<hex>",
  "ik_pub":       "<our IK b64>",
  "ek_pub":       "<ephemeral b64>",
  "used_opk_pub": "<b64 of consumed OPK or null>",
  "message": {
    "ciphertext":  "<b64>",
    "nonce":       "<b64 12>",
    "ratchet_pub": "<b64 32>",
    "pn": 0, "n": 0,
    "aad": "<b64>"
  }
}
```

### `x3dh_receive`

Recomputes `SK` from the inbound header (`ik_a`, `ek_a`, optional
`used_opk_pub`) using our IK, the most recent SPK, and the named OPK
private (which is then deleted from the in-memory store). Initialises a
Double Ratchet session as responder.

```json
// request
{
  "op": "x3dh_receive",
  "params": {
    "peer_user_id": "alice",
    "header": {
      "ik_a":         "<b64 32>",
      "ek_a":         "<b64 32>",
      "used_opk_pub": "<b64 or omit>"
    }
  }
}
// response.data
{ "session_id": "<hex>" }
```

### `encrypt_message`

Advances the sending chain, derives a fresh message key MK, AES-256-GCM
encrypts the (PKCS#7-padded-to-256-byte-boundary) plaintext under MK with
a random 12-byte nonce. The AAD binds `IK_A || IK_B || ratchet_pub ||
PN || N`. MK is overwritten in memory immediately after use.

```json
// request
{ "op": "encrypt_message",
  "params": { "session_id": "<hex>", "plaintext": "..." } }
// response.data
{ "ciphertext": "<b64>", "nonce": "<b64>", "ratchet_pub": "<b64>",
  "pn": 0, "n": 1, "aad": "<b64>" }
```

### `decrypt_message`

Performs a DH ratchet step if `ratchet_pub` is new, skips forward in the
recv chain to message `n` (storing intermediate MKs in a 100-entry cache
for late deliveries), verifies the AES-GCM tag, strips padding, returns
the plaintext. Out-of-order messages whose key is in the skipped cache
are decrypted directly from the cache.

```json
// request
{ "op": "decrypt_message",
  "params": { "session_id": "<hex>",
              "ciphertext": "<b64>", "nonce": "<b64>",
              "ratchet_pub": "<b64>", "pn": 0, "n": 1 } }
// response.data
{ "plaintext": "..." }
```

A bad tag, bad padding, or message older than the chain with no cached
key returns `{status: error, code: decrypt_failed}` — never partial
plaintext.

### `dh_ratchet_step`

Forces a DH ratchet step against the supplied peer ratchet public key.
Useful for the responder's first outbound message after `x3dh_receive`
(at that point they have no `ck_send` yet). Returns our new ratchet pub
that the peer will see on the next message we send.

```json
// request
{ "op": "dh_ratchet_step",
  "params": { "session_id": "<hex>", "their_ratchet_pub": "<b64>" } }
// response.data
{ "ratchet_pub": "<b64>" }
```

## Cryptographic parameters

| Primitive            | Choice                                                    |
|----------------------|-----------------------------------------------------------|
| DH                   | X25519                                                    |
| Signature            | Ed25519                                                   |
| KDF                  | HKDF-SHA256                                               |
| AEAD                 | AES-256-GCM (12-byte nonce, 16-byte tag)                  |
| Password hashing     | Argon2id, t=3, m=64 MiB, p=1, 32-byte output              |
| Padding              | PKCS#7-style to 256-byte boundary                         |
| Skipped key cache    | up to 100 entries per session                             |
| X3DH info string     | `b"SecureMsg_X3DH_v1"` (salt = 32 zero bytes)             |
| Chain step info      | `b"SecureMsg_MsgKey_v1"`                                  |
| Ratchet step info    | `b"SecureMsg_Ratchet_v1"`                                 |

## Security notes

- All random bytes use `secrets.token_bytes()` — never `random`.
- Plaintext, private keys, and raw key material are never logged.
- SPK signatures are verified before any DH happens; a bad signature
  aborts the operation with `invalid_bundle`.
- AEAD failure is generic — the response does not distinguish bad
  passphrase from corrupt file, or bad tag from bad header.
- Identity and session files are written atomically (`os.replace`) at
  mode 0600 on POSIX.
- The daemon catches all unhandled exceptions and returns
  `code: internal` with only the exception type name, so internal state
  and key bytes can't leak via error messages.

## Testing

```
python crypto-daemon/test_daemon.py
```

Spawns two isolated daemons (Alice and Bob with separate `$HOME`s),
runs the full X3DH handshake, exchanges five in-order messages, three
out-of-order messages, a DH-ratcheted reply from Bob, and finally a
tag-corruption rejection check. Prints `ALL TESTS PASSED` on success.
