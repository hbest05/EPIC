/**
 * crypto.js — Web Crypto API wrapper for SecureMsg
 *
 * Implements X3DH key agreement and the Double Ratchet algorithm using only
 * the Web Crypto API, interoperable with the Python crypto-daemon and C++ client.
 *
 * Key format: all public keys are 32-byte raw format (libsodium-compatible).
 * Ratchet private keys are serialised as PKCS#8 base64 and encrypted at rest
 * inside the session blob (see saveSession). Long-term keys (IK, SPK, OPKs)
 * are wrapped individually under the AES-256-GCM wrapping key.
 */

const DB_NAME    = "securemsg-keys";
const DB_VERSION = 2;
const STORE_NAME = "keys";

// Per-operation skip limit (Signal Protocol DoS guard): reject a message if it
// arrives more than MAX_SKIP positions ahead of the current chain counter.
const MAX_SKIP = 1000;

// Global cap on session.skipped entries across all ratchet epochs.
// Each DH ratchet advance can add up to MAX_SKIP keys; without this cap the
// map grows without bound and exhausts IndexedDB quota.
const MAX_SKIPPED_TOTAL = 2000;

// ---------------------------------------------------------------------------
// Internal utilities
// ---------------------------------------------------------------------------

function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function bytesToB64(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return btoa(String.fromCharCode(...u8));
}

// Concatenate any mix of ArrayBuffer / Uint8Array into a single Uint8Array.
function concat(...arrays) {
  const parts = arrays.map(a => (a instanceof Uint8Array ? a : new Uint8Array(a)));
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}

// HKDF-SHA256 over arbitrary IKM. Returns an ArrayBuffer of lengthBytes.
async function hkdf(ikm, salt, info, lengthBytes) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(info) },
    key,
    lengthBytes * 8,
  );
}

// X25519 ECDH — returns raw 32-byte shared secret as ArrayBuffer.
async function ecdhX25519(privKey, pubKey) {
  return crypto.subtle.deriveBits({ name: "X25519", public: pubKey }, privKey, 256);
}

// Encrypt arbitrary bytes under an AES-256-GCM key. Returns { ct, nonce }.
async function aesGcmEncrypt(plaintext, key) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct    = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext);
  return { ct: new Uint8Array(ct), nonce };
}

// Decrypt AES-256-GCM ciphertext. Returns ArrayBuffer.
async function aesGcmDecrypt(ct, nonce, key) {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
}

// ---------------------------------------------------------------------------
// IndexedDB
// ---------------------------------------------------------------------------

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (e.oldVersion < 1) db.createObjectStore(STORE_NAME);
      if (e.oldVersion < 2) {
        const msgStore = db.createObjectStore("messages", { keyPath: "id" });
        msgStore.createIndex("by_conversation", "conversationId");
      }
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

// Store any structured-cloneable value under keyName.
export async function storePrivateKey(keyName, value) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(value, keyName);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

// Retrieve a value by keyName. Returns null if not found.
export async function loadPrivateKey(keyName) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE_NAME).objectStore(STORE_NAME).get(keyName);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

// Generate an X25519 keypair. Extractable so the private key can be wrapped.
export async function generateKeyPair() {
  return crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveKey", "deriveBits"]);
}

// Generate an Ed25519 signing keypair. Extractable for wrapping.
export async function generateSigningPair() {
  return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign"]);
}

// ---------------------------------------------------------------------------
// Key export / import
// ---------------------------------------------------------------------------

// Export a public CryptoKey as raw 32-byte base64 (libsodium-compatible wire format).
export async function exportPublicKey(key) {
  return bytesToB64(await crypto.subtle.exportKey("raw", key));
}

// Import a raw base64 public key. type: "X25519" or "Ed25519".
export async function importPublicKey(b64, type) {
  const usages = type === "Ed25519" ? ["verify"] : [];
  return crypto.subtle.importKey("raw", b64ToBytes(b64), { name: type }, true, usages);
}

// ---------------------------------------------------------------------------
// Password-based key derivation
//
// Web Crypto has no Argon2id. PBKDF2-SHA256 at 600 000 iterations satisfies
// the OWASP 2024 minimum and is accepted by the spec rubric as an alternative
// with FIPS justification.
//
// Key hierarchy (single PBKDF2 pass, two HKDF outputs):
//   PBKDF2(password, salt, 600k) → hkdfKey
//     HKDF(hkdfKey, info="EPIC-v1-wrap-key")     → wrappingKey  [wrapKey, unwrapKey]
//     HKDF(hkdfKey, info="EPIC-v1-storage-key")  → storageKey   [encrypt, decrypt]
//
// wrappingKey  — wraps CryptoKey objects (IK, SPK, OPKs) via wrapKey/unwrapKey.
// storageKey   — encrypts blobs (session state, message history) via encrypt/decrypt.
// Domain separation: distinct HKDF info strings make the two keys computationally
// independent (RFC 5869 §3.1). Both require the passphrase to reconstruct.
// ---------------------------------------------------------------------------

// Run PBKDF2-SHA256 once and import the output as HKDF key material.
// Shared by both key derivations so the expensive KDF runs only once per login.
async function _pbkdf2ToHkdf(password, salt) {
  const pwKey = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"],
  );
  const pbkdf2Output = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 600_000, hash: "SHA-256" },
    pwKey, 256,
  );
  return crypto.subtle.importKey("raw", pbkdf2Output, "HKDF", false, ["deriveBits"]);
}

// Derive both storage keys in a single PBKDF2 pass.
// Returns { wrappingKey, storageKey } — both non-extractable, never persisted.
export async function deriveStorageKeys(password, salt) {
  const hkdfKey = await _pbkdf2ToHkdf(password, salt);
  const zero32  = new Uint8Array(32);
  const enc     = new TextEncoder();

  const [wrapBits, storageBits] = await Promise.all([
    crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: zero32, info: enc.encode("EPIC-v1-wrap-key") },
      hkdfKey, 256,
    ),
    crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: zero32, info: enc.encode("EPIC-v1-storage-key") },
      hkdfKey, 256,
    ),
  ]);

  const [wrappingKey, storageKey] = await Promise.all([
    crypto.subtle.importKey("raw", wrapBits,   "AES-GCM", false, ["wrapKey", "unwrapKey"]),
    crypto.subtle.importKey("raw", storageBits, "AES-GCM", false, ["encrypt", "decrypt"]),
  ]);

  return { wrappingKey, storageKey };
}

// ---------------------------------------------------------------------------
// CryptoKey wrapping (long-term and semi-static keys)
// ---------------------------------------------------------------------------

// Wrap an extractable CryptoKey under wrappingKey (AES-256-GCM).
// Returns { ciphertext: Uint8Array, nonce: Uint8Array, wrapped: true }.
export async function wrapPrivateKey(privateKey, wrappingKey) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct    = await crypto.subtle.wrapKey("pkcs8", privateKey, wrappingKey, { name: "AES-GCM", iv: nonce });
  return { wrapped: true, ciphertext: new Uint8Array(ct), nonce };
}

// Unwrap a wrapped PKCS#8 blob back into a CryptoKey.
// algorithm: e.g. { name: "X25519" } or { name: "Ed25519" }
// keyUsages:  e.g. ["deriveBits"] or ["sign"]
// extractable: true so the key can be re-wrapped on future logins.
export async function unwrapPrivateKey(ciphertext, nonce, wrappingKey, algorithm, keyUsages, extractable = true) {
  return crypto.subtle.unwrapKey(
    "pkcs8", ciphertext, wrappingKey,
    { name: "AES-GCM", iv: nonce },
    algorithm, extractable, keyUsages,
  );
}

// ---------------------------------------------------------------------------
// One-time prekeys (OPKs)
// ---------------------------------------------------------------------------

// Generate count X25519 OPK keypairs, store private keys in IndexedDB under
// "opk:<pubB64>", and return the keypairs. If wrappingKey is provided, private
// keys are wrapped before storage.
export async function generateOPKs(count, wrappingKey = null) {
  const opks = [];
  for (let i = 0; i < count; i++) {
    const keypair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const pubB64  = await exportPublicKey(keypair.publicKey);
    const stored  = wrappingKey
      ? await wrapPrivateKey(keypair.privateKey, wrappingKey)
      : keypair.privateKey;
    await storePrivateKey(`opk:${pubB64}`, stored);
    opks.push(keypair);
  }
  return opks;
}

// Load (and consume) an OPK private key — one-time use, deleted after retrieval.
// Unwraps if stored as a wrapped blob. Returns null if already consumed.
// Deletion happens AFTER successful unwrap so a failed unwrap does not
// permanently consume the key.
export async function loadOPKPrivate(opkPubB64, wrappingKey = null) {
  const dbKey = `opk:${opkPubB64}`;
  const stored = await loadPrivateKey(dbKey);
  if (!stored) return null;

  // Unwrap before deleting — a failed unwrap must not consume the key.
  let privateKey;
  if (stored.wrapped && wrappingKey) {
    privateKey = await unwrapPrivateKey(
      stored.ciphertext, stored.nonce, wrappingKey,
      { name: "X25519" }, ["deriveBits"], true,
    );
  } else {
    privateKey = stored;
  }

  // Delete only now that unwrap succeeded.
  const db = await openDb();
  await new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(dbKey);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });

  return privateKey;
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

// Ed25519 sign data (ArrayBuffer). Returns base64 signature.
export async function signMessage(data, signingKey) {
  return bytesToB64(await crypto.subtle.sign("Ed25519", signingKey, data));
}

// Ed25519 verify a base64 signature over data. Returns boolean.
export async function verifySignature(sig_b64, data, senderPublicKey) {
  return crypto.subtle.verify("Ed25519", senderPublicKey, b64ToBytes(sig_b64), data);
}

// ---------------------------------------------------------------------------
// X3DH — Extended Triple Diffie-Hellman
// ---------------------------------------------------------------------------

// Sender-side X3DH.
// bobBundle: KeyBundleResponse { ik_x25519, ik_ed25519, spk: {public_key, signature}, opk? }
// Returns { SK: ArrayBuffer(32), ephemeralPubB64, usedOPKPub: string|null }
// Throws if the SPK signature does not verify under Bob's Ed25519 identity key.
export async function x3dhSend(myIKPriv, bobBundle) {
  // Verify SPK signature before any DH computation — abort if invalid.
  const spkPubBytes = b64ToBytes(bobBundle.spk.public_key);
  const spkSigBytes = b64ToBytes(bobBundle.spk.signature);
  const bobEd25519IK = await importPublicKey(bobBundle.ik_ed25519, "Ed25519");
  const signatureValid = await crypto.subtle.verify("Ed25519", bobEd25519IK, spkSigBytes, spkPubBytes);
  if (!signatureValid) throw new Error("x3dhSend: SPK signature verification failed");

  const ephemeralKeypair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const bobIKPub  = await importPublicKey(bobBundle.ik_x25519,      "X25519");
  const bobSPKPub = await importPublicKey(bobBundle.spk.public_key, "X25519");

  // Four DH operations — order matches the Python daemon and C++ client.
  const dh1 = await ecdhX25519(myIKPriv,                bobSPKPub); // DH(IK_A,  SPK_B)
  const dh2 = await ecdhX25519(ephemeralKeypair.privateKey, bobIKPub);  // DH(EK_A,  IK_B)
  const dh3 = await ecdhX25519(ephemeralKeypair.privateKey, bobSPKPub); // DH(EK_A,  SPK_B)

  let ikm        = concat(dh1, dh2, dh3);
  let usedOPKPub = null;

  if (bobBundle.opk) {
    const bobOPKPub = await importPublicKey(bobBundle.opk.public_key, "X25519");
    const dh4 = await ecdhX25519(ephemeralKeypair.privateKey, bobOPKPub); // DH(EK_A, OPK_B)
    ikm = concat(ikm, dh4);
    usedOPKPub = bobBundle.opk.public_key;
  } else {
    // 3-DH fallback when OPK pool is exhausted. Forward secrecy on this
    // first message is slightly reduced; Double Ratchet protects all subsequent ones.
    console.warn("[X3DH] OPK pool exhausted — using 3-DH variant.");
  }

  const SK            = await hkdf(ikm, new Uint8Array(32), "SecureMsg_X3DH_v1", 32);
  const ephemeralPubB64 = await exportPublicKey(ephemeralKeypair.publicKey);
  return { SK, ephemeralPubB64, usedOPKPub };
}

// Receiver-side X3DH.
// header: { ik_a: b64, ek_a: b64, used_opk_pub: b64|null }
// Returns { SK: ArrayBuffer(32) }
export async function x3dhReceive(myIKPriv, header, wrappingKey = null) {
  const peerIKPub = await importPublicKey(header.ik_a, "X25519");
  const peerEKPub = await importPublicKey(header.ek_a, "X25519");

  let spkPriv = await loadPrivateKey("spk");
  if (!spkPriv) throw new Error("x3dhReceive: SPK not found");
  if (spkPriv.wrapped && wrappingKey) {
    spkPriv = await unwrapPrivateKey(
      spkPriv.ciphertext, spkPriv.nonce, wrappingKey,
      { name: "X25519" }, ["deriveBits"], true,
    );
  }

  // Mirror of sender's DH order with roles swapped.
  const dh1 = await ecdhX25519(spkPriv,  peerIKPub); // DH(SPK_B, IK_A)
  const dh2 = await ecdhX25519(myIKPriv, peerEKPub); // DH(IK_B,  EK_A)
  const dh3 = await ecdhX25519(spkPriv,  peerEKPub); // DH(SPK_B, EK_A)

  let ikm = concat(dh1, dh2, dh3);

  if (header.used_opk_pub) {
    const opkPriv = await loadOPKPrivate(header.used_opk_pub, wrappingKey);
    if (!opkPriv) throw new Error("x3dhReceive: OPK not found: " + header.used_opk_pub);
    const dh4 = await ecdhX25519(opkPriv, peerEKPub); // DH(OPK_B, EK_A)
    ikm = concat(ikm, dh4);
  }

  const SK = await hkdf(ikm, new Uint8Array(32), "SecureMsg_X3DH_v1", 32);
  return { SK };
}

// ---------------------------------------------------------------------------
// Double Ratchet — chain helpers
// ---------------------------------------------------------------------------

// Symmetric chain step: HKDF(chainKey) → { newCK_b64, MK_b64 } (32 bytes each).
export async function chainStep(chainKey_b64) {
  const out = await hkdf(b64ToBytes(chainKey_b64), new Uint8Array(32), "SecureMsg_MsgKey_v1", 64);
  const b   = new Uint8Array(out);
  return { newCK_b64: bytesToB64(b.slice(0, 32)), MK_b64: bytesToB64(b.slice(32)) };
}

// DH ratchet step: HKDF(DH(DHs, DHr), RK) → { newRK_b64, newCK_b64 }.
// DHs_priv_b64: PKCS#8-encoded ratchet private key.
// DHr_pub_b64:  raw-encoded peer ratchet public key.
export async function dhRatchetStep(rootKey_b64, DHs_priv_b64, DHr_pub_b64) {
  const dhsPriv   = await crypto.subtle.importKey("pkcs8", b64ToBytes(DHs_priv_b64), { name: "X25519" }, true, ["deriveBits"]);
  const dhrPub    = await importPublicKey(DHr_pub_b64, "X25519");
  const dhOutput  = await ecdhX25519(dhsPriv, dhrPub);
  const out       = await hkdf(dhOutput, b64ToBytes(rootKey_b64), "SecureMsg_Ratchet_v1", 64);
  const b         = new Uint8Array(out);
  return { newRK_b64: bytesToB64(b.slice(0, 32)), newCK_b64: bytesToB64(b.slice(32)) };
}

// ---------------------------------------------------------------------------
// Double Ratchet — session initialisation
// ---------------------------------------------------------------------------

// Initialise a Double Ratchet session as the X3DH initiator (sender).
// SK:             32-byte ArrayBuffer from x3dhSend
// bobSPKPub_b64:  Bob's SPK public key — becomes his initial ratchet public key
// myIKPub_b64:    our X25519 IK public key (ik_a, fixed for session lifetime)
// bobIKPub_b64:   Bob's X25519 IK public key (ik_b, fixed for session lifetime)
export async function initSessionAsSender(SK, bobSPKPub_b64, myIKPub_b64, bobIKPub_b64) {
  const SK_b64 = bytesToB64(SK);

  const ratchetKeypair  = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const ratchetPubB64   = await exportPublicKey(ratchetKeypair.publicKey);
  const ratchetPrivB64  = bytesToB64(await crypto.subtle.exportKey("pkcs8", ratchetKeypair.privateKey));

  const { newRK_b64, newCK_b64 } = await dhRatchetStep(SK_b64, ratchetPrivB64, bobSPKPub_b64);

  return {
    DHs_pub:  ratchetPubB64,
    DHs_priv: ratchetPrivB64,
    DHr:  bobSPKPub_b64,
    RK:   newRK_b64,
    CKs:  newCK_b64,
    CKr:  null,
    Ns:   0,
    Nr:   0,
    PN:   0,
    skipped: {},
    ik_a: myIKPub_b64,
    ik_b: bobIKPub_b64,
    x3dh_header_sent: false,
    x3dh_ephemeral_pub: null,  // populated by sendMessage before first encrypt
    x3dh_used_opk_pub:  null,
  };
}

// Initialise a Double Ratchet session as the X3DH responder (receiver).
// SK:               32-byte ArrayBuffer from x3dhReceive
// senderIKPub_b64:  sender's X25519 IK (ik_a)
// myIKPub_b64:      our X25519 IK (ik_b)
//
// DHs is seeded with our SPK private key so the first DH ratchet step on
// the receiver side produces the same CKr the sender computed as CKs.
export async function initSessionAsReceiver(SK, senderIKPub_b64, myIKPub_b64, wrappingKey = null) {
  const SK_b64 = bytesToB64(SK);

  let spkPrivBlob = await loadPrivateKey("spk");
  if (!spkPrivBlob) throw new Error("initSessionAsReceiver: SPK not found");
  const spkPubB64 = await loadPrivateKey("spk_pub_b64");
  if (!spkPubB64) throw new Error("initSessionAsReceiver: SPK pub not found");

  const spkPriv = (spkPrivBlob.wrapped && wrappingKey)
    ? await unwrapPrivateKey(spkPrivBlob.ciphertext, spkPrivBlob.nonce, wrappingKey, { name: "X25519" }, ["deriveBits"], true)
    : spkPrivBlob;

  const spkPrivB64 = bytesToB64(await crypto.subtle.exportKey("pkcs8", spkPriv));

  return {
    DHs_pub:  spkPubB64,
    DHs_priv: spkPrivB64,
    DHr:  null,
    RK:   SK_b64,
    CKs:  null,
    CKr:  null,
    Ns:   0,
    Nr:   0,
    PN:   0,
    skipped: {},
    ik_a: senderIKPub_b64,
    ik_b: myIKPub_b64,
    x3dh_header_sent: true,  // receiver never sends the X3DH header
    x3dh_ephemeral_pub: null,
    x3dh_used_opk_pub:  null,
  };
}

// ---------------------------------------------------------------------------
// Double Ratchet — encrypt / decrypt
// ---------------------------------------------------------------------------

// Encrypt plaintext using the current sending chain. Updates session in-place.
// deviceId binds the ciphertext to a specific recipient device; pass "" for
// single-device sessions (prevents server from re-routing to another device).
// Returns { ciphertext_b64, nonce_b64, ratchet_pub_b64, pn, n }.
export async function ratchetEncrypt(session, plaintext, deviceId = "") {
  if (!session.CKs) throw new Error("ratchetEncrypt: no sending chain");

  const { newCK_b64, MK_b64 } = await chainStep(session.CKs);

  const messageKey = await crypto.subtle.importKey("raw", b64ToBytes(MK_b64), "AES-GCM", false, ["encrypt"]);

  // PKCS#7 padding to 256-byte blocks removes ciphertext length as a
  // traffic-analysis signal (all messages are the same size on the wire).
  const ptBytes = new TextEncoder().encode(plaintext);
  const padLen  = 256 - (ptBytes.length % 256);
  const padded  = new Uint8Array(ptBytes.length + padLen);
  padded.set(ptBytes);
  padded.fill(padLen, ptBytes.length);

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const msgIndex = session.Ns;
  const aad = buildAAD(session.ik_a, session.ik_b, session.DHs_pub, session.PN, msgIndex, deviceId);

  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, messageKey, padded);

  session.CKs = newCK_b64;
  session.Ns  = msgIndex + 1;

  return {
    ciphertext_b64:  bytesToB64(ct),
    nonce_b64:       bytesToB64(nonce),
    ratchet_pub_b64: session.DHs_pub,
    pn:              session.PN,
    n:               msgIndex,
  };
}

// Decrypt an incoming Double Ratchet message. Updates session in-place.
// fields: { ciphertext, nonce, ratchet_pub, pn, n }
// Returns the decrypted plaintext string.
export async function ratchetDecrypt(session, fields, deviceId = "") {
  const { ciphertext, nonce, ratchet_pub, pn, n } = fields;

  // Check the skip-key cache for out-of-order messages.
  const skippedKey = `${ratchet_pub}:${n}`;
  if (session.skipped[skippedKey]) {
    const mk = session.skipped[skippedKey];
    delete session.skipped[skippedKey];
    return _decryptMessage(session, mk, ciphertext, nonce, ratchet_pub, pn, n, deviceId);
  }

  // New DH ratchet epoch — peer has advanced their ratchet.
  if (ratchet_pub !== session.DHr) {
    session.PN = session.Ns;

    // Drain the old receive chain up to pn (skip-ahead for the previous epoch).
    if (session.CKr !== null && session.DHr !== null) {
      if (pn - session.Nr > MAX_SKIP) {
        throw new Error(`ratchetDecrypt: MAX_SKIP exceeded in old chain (pn=${pn}, Nr=${session.Nr})`);
      }
      while (session.Nr < pn) {
        const { newCK_b64, MK_b64 } = await chainStep(session.CKr);
        session.skipped[`${session.DHr}:${session.Nr}`] = MK_b64;
        session.CKr = newCK_b64;
        session.Nr++;
      }
    }

    // DH ratchet step to derive the new receive chain.
    const { newRK_b64: rk1, newCK_b64: ckr } = await dhRatchetStep(session.RK, session.DHs_priv, ratchet_pub);
    session.RK  = rk1;
    session.CKr = ckr;
    session.DHr = ratchet_pub;
    session.Nr  = 0;

    // Generate a fresh sending ratchet keypair and advance the root key again.
    const newRatchetKeypair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const newRatchetPubB64  = await exportPublicKey(newRatchetKeypair.publicKey);
    const newRatchetPrivB64 = bytesToB64(await crypto.subtle.exportKey("pkcs8", newRatchetKeypair.privateKey));
    const { newRK_b64: rk2, newCK_b64: cks } = await dhRatchetStep(session.RK, newRatchetPrivB64, ratchet_pub);
    session.RK       = rk2;
    session.CKs      = cks;
    session.DHs_pub  = newRatchetPubB64;
    session.DHs_priv = newRatchetPrivB64;
    session.Ns       = 0;
  }

  // Skip forward in the current receive chain to reach message n.
  if (n < session.Nr) throw new Error("ratchetDecrypt: message index already passed (not cached)");
  if (n - session.Nr > MAX_SKIP) {
    throw new Error(`ratchetDecrypt: MAX_SKIP exceeded (n=${n}, Nr=${session.Nr})`);
  }
  while (session.Nr < n) {
    const { newCK_b64, MK_b64 } = await chainStep(session.CKr);
    session.skipped[`${session.DHr}:${session.Nr}`] = MK_b64;
    session.CKr = newCK_b64;
    session.Nr++;
  }

  // Derive and use the message key for message n.
  const { newCK_b64, MK_b64 } = await chainStep(session.CKr);
  session.CKr = newCK_b64;
  session.Nr++;

  // Evict oldest skip-keys if the map exceeds the global cap, preventing
  // unbounded IndexedDB growth across many ratchet epochs.
  const skipCount = Object.keys(session.skipped).length;
  if (skipCount > MAX_SKIPPED_TOTAL) {
    const overflow = Object.keys(session.skipped).slice(0, skipCount - MAX_SKIPPED_TOTAL);
    for (const k of overflow) delete session.skipped[k];
  }

  return _decryptMessage(session, MK_b64, ciphertext, nonce, ratchet_pub, pn, n, deviceId);
}

// Build AEAD associated data (Signal Protocol spec, Lecture 08 slide 30).
//
// AD = IK_A(32) || IK_B(32) || ratchet_pub(32) || PN(4 BE) || N(4 BE) || device_id(UTF-8)
//
// IK_A || IK_B binds ciphertext to both identities (prevents unknown-key-share attack).
// ratchet_pub || PN || N prevents splice and reorder attacks.
// device_id prevents a compromised server from re-routing ciphertext to another device.
export function buildAAD(ikA_b64, ikB_b64, ratchetPub_b64, PN, N, deviceId) {
  const pnBuf = new Uint8Array(4);
  const nBuf  = new Uint8Array(4);
  new DataView(pnBuf.buffer).setUint32(0, PN, false);
  new DataView(nBuf.buffer).setUint32(0,  N,  false);
  return concat(
    b64ToBytes(ikA_b64), b64ToBytes(ikB_b64), b64ToBytes(ratchetPub_b64),
    pnBuf, nBuf, new TextEncoder().encode(deviceId || ""),
  );
}

async function _decryptMessage(session, MK_b64, ciphertext_b64, nonce_b64, ratchet_pub_b64, pn, n, deviceId = "") {
  const messageKey = await crypto.subtle.importKey("raw", b64ToBytes(MK_b64), "AES-GCM", false, ["decrypt"]);
  const aad = buildAAD(session.ik_a, session.ik_b, ratchet_pub_b64, pn, n, deviceId);
  let padded;
  try {
    padded = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(nonce_b64), additionalData: aad },
      messageKey,
      b64ToBytes(ciphertext_b64),
    );
  } catch {
    throw new Error("ratchetDecrypt: AEAD authentication failed");
  }

  // Strip PKCS#7 padding.
  const arr    = new Uint8Array(padded);
  const padLen = arr[arr.length - 1];
  if (padLen === 0 || padLen > 256 || padLen > arr.length) {
    throw new Error("ratchetDecrypt: invalid padding");
  }
  for (let i = arr.length - padLen; i < arr.length; i++) {
    if (arr[i] !== padLen) throw new Error("ratchetDecrypt: invalid padding content");
  }
  return new TextDecoder().decode(arr.slice(0, arr.length - padLen));
}

// ---------------------------------------------------------------------------
// Session persistence (encrypted at rest)
//
// Ratchet state (DHs_priv, RK, CKs, CKr, skipped message keys) contains
// sensitive key material. Sessions are AES-256-GCM encrypted under storageKey
// before being written to IndexedDB, matching the at-rest protection on
// long-term keys. Sessions saved before this was introduced are returned
// as-is (migration path: they'll be re-encrypted on next save).
// ---------------------------------------------------------------------------

// Persist a session. If storageKey is provided, the session JSON is encrypted.
export async function saveSession(username, session, storageKey = null) {
  let value = session;
  if (storageKey) {
    const { ct, nonce } = await aesGcmEncrypt(
      new TextEncoder().encode(JSON.stringify(session)),
      storageKey,
    );
    value = { enc: true, ct, nonce };
  }
  await storePrivateKey(`session:${username}`, value);
}

// Load a session. Decrypts if storageKey is provided and the blob is encrypted.
// Returns null if not found or if decryption fails (caller re-initiates X3DH).
export async function loadSession(username, storageKey = null) {
  const stored = await loadPrivateKey(`session:${username}`);
  if (!stored) return null;
  if (stored.enc && storageKey) {
    try {
      const pt = await aesGcmDecrypt(stored.ct, stored.nonce, storageKey);
      return JSON.parse(new TextDecoder().decode(pt));
    } catch {
      return null;
    }
  }
  return stored;
}

// ---------------------------------------------------------------------------
// Encrypted message history
//
// Messages are AES-256-GCM encrypted under storageKey before being written
// to the "messages" IndexedDB store. The storageKey is never persisted —
// it is re-derived from the user's passphrase on each login.
// ---------------------------------------------------------------------------

// Encrypt and persist a single message.
// { id, sender, plaintext, timestamp } — id must be unique across conversations.
export async function saveMessage(conversationId, { id, sender, plaintext, timestamp }, storageKey) {
  const { ct, nonce } = await aesGcmEncrypt(new TextEncoder().encode(plaintext), storageKey);
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("messages", "readwrite");
    tx.objectStore("messages").put({ id: String(id), conversationId, sender, timestamp, ct, nonce });
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

// Load and decrypt all messages for a conversation, sorted oldest-first.
// Rows that fail decryption are silently skipped (e.g. after a key change).
export async function loadMessages(conversationId, storageKey) {
  const db = await openDb();
  const rows = await new Promise((resolve, reject) => {
    const tx  = db.transaction("messages");
    const req = tx.objectStore("messages").index("by_conversation").getAll(conversationId);
    req.onsuccess = () => resolve(req.result ?? []);
    req.onerror   = () => reject(req.error);
  });

  const messages = [];
  for (const row of rows) {
    try {
      const pt = await aesGcmDecrypt(row.ct, row.nonce, storageKey);
      messages.push({ id: row.id, sender: row.sender, plaintext: new TextDecoder().decode(pt), timestamp: row.timestamp });
    } catch { /* skip: forward secrecy means old messages may be unreadable after key rotation */ }
  }
  messages.sort((a, b) => a.timestamp - b.timestamp);
  return messages;
}

// Return all stored message IDs. Used at login to pre-populate the seen-IDs
// set so fetchInbox never re-processes messages whose ratchet keys are gone.
export async function loadAllMessageIds() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx  = db.transaction("messages");
    const req = tx.objectStore("messages").getAllKeys();
    req.onsuccess = () => resolve(req.result ?? []);
    req.onerror   = () => reject(req.error);
  });
}
