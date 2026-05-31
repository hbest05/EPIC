/**
 * crypto.js — Web Crypto API wrapper for SecureMsg
 *
 * Implements X3DH key agreement and the Double Ratchet algorithm using only
 * the Web Crypto API, interoperable with the Python crypto-daemon and C++ client.
 *
 * Key format: all public keys are 32-byte raw format (libsodium-compatible).
 * Private ratchet keys are stored as PKCS#8 (only export format Web Crypto
 * supports for X25519 private keys); non-ratchet private keys are stored as
 * non-extractable CryptoKey objects directly in IndexedDB.
 */

const DB_NAME    = "securemsg-keys";
const DB_VERSION = 1;
const STORE_NAME = "keys";

// Cap on cached skipped message keys — matches MAX_SKIPPED in double_ratchet.py.
const MAX_SKIPPED = 100;

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function b64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

function bytesToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength))));
}

// Concatenates any mix of ArrayBuffer / Uint8Array → Uint8Array
function concat(...arrays) {
  const parts = arrays.map(a => (a instanceof Uint8Array ? a : new Uint8Array(a)));
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out   = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

// HKDF-SHA256: ikm and salt are ArrayBuffer or Uint8Array; info is a string.
// Returns ArrayBuffer of lengthBytes bytes.
async function hkdf(ikm, salt, info, lengthBytes) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode(info) },
    key,
    lengthBytes * 8,
  );
}

// X25519 ECDH: returns raw 32-byte shared secret as ArrayBuffer
async function ecdhX25519(privKey, pubKey) {
  return crypto.subtle.deriveBits({ name: "X25519", public: pubKey }, privKey, 256);
}

// ---------------------------------------------------------------------------
// Key generation (do not modify existing stubs)
// ---------------------------------------------------------------------------

export async function generateKeyPair() {
  return crypto.subtle.generateKey(
    { name: "X25519" },
    false,
    ["deriveKey", "deriveBits"],
  );
}

export async function generateSigningPair() {
  return crypto.subtle.generateKey(
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

// ---------------------------------------------------------------------------
// Key export / import
// ---------------------------------------------------------------------------

// Export a public CryptoKey as raw 32-byte base64 (libsodium-compatible wire format).
export async function exportPublicKey(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bytesToB64(raw);
}

// Import a raw base64 public key as a CryptoKey.
// type: "X25519" (for ECDH) or "Ed25519" (for verify).
export async function importPublicKey(b64, type) {
  const raw    = b64ToBytes(b64);
  const usages = type === "Ed25519" ? ["verify"] : [];
  return crypto.subtle.importKey("raw", raw, { name: type }, true, usages);
}

// ---------------------------------------------------------------------------
// IndexedDB persistence
// ---------------------------------------------------------------------------

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => { e.target.result.createObjectStore(STORE_NAME); };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

// Store any structured-cloneable value (CryptoKey, plain object, string, …).
export async function storePrivateKey(keyName, key) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(key, keyName);
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

// Retrieve a value from IndexedDB by key name. Returns null if not found.
export async function loadPrivateKey(keyName) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE_NAME).objectStore(STORE_NAME).get(keyName);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

// ---------------------------------------------------------------------------
// One-Time Prekeys
// ---------------------------------------------------------------------------

// Generate count X25519 OPK keypairs. Private keys are stored in IndexedDB
// under "opk:<pubB64>" and deleted on first use (loadOPKPrivate).
export async function generateOPKs(count) {
  const opks = [];
  for (let i = 0; i < count; i++) {
    const kp = await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    );
    const pubB64 = await exportPublicKey(kp.publicKey);
    await storePrivateKey(`opk:${pubB64}`, kp.privateKey);
    opks.push({ publicKey: kp.publicKey, privateKey: kp.privateKey });
  }
  return opks;
}

// Retrieve and DELETE an OPK private CryptoKey from IndexedDB (one-time use).
// Returns null if the key was already consumed.
export async function loadOPKPrivate(opkPubB64) {
  const db    = await openDb();
  const dbKey = `opk:${opkPubB64}`;
  return new Promise((resolve, reject) => {
    const tx    = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const req   = store.get(dbKey);
    req.onsuccess = () => {
      const val = req.result ?? null;
      if (val !== null) store.delete(dbKey);
      tx.oncomplete = () => resolve(val);
    };
    req.onerror = () => reject(req.error);
  });
}

// ---------------------------------------------------------------------------
// Signing / Verification
// ---------------------------------------------------------------------------

// Ed25519 sign data (ArrayBuffer) with signingKey (Ed25519 private CryptoKey).
// Returns base64 signature string.
export async function signMessage(data, signingKey) {
  const sig = await crypto.subtle.sign("Ed25519", signingKey, data);
  return bytesToB64(sig);
}

// Verify an Ed25519 sig_b64 over data (ArrayBuffer) with senderPublicKey.
// Returns boolean.
export async function verifySignature(sig_b64, data, senderPublicKey) {
  return crypto.subtle.verify("Ed25519", senderPublicKey, b64ToBytes(sig_b64), data);
}

// ---------------------------------------------------------------------------
// X3DH — Extended Triple Diffie-Hellman
// ---------------------------------------------------------------------------

// Sender-side X3DH.
//
// myIKPriv:  our X25519 identity private CryptoKey
// bobBundle: KeyBundleResponse from GET /api/auth/user/{u}/keybundle:
//            { ik_x25519, ik_ed25519, spk: { public_key, signature }, opk: { public_key } | null }
//
// Returns { SK: ArrayBuffer(32), EK_A_pub_b64, usedOPKPub_b64 | null }
// Throws if SPK signature verification fails.
export async function x3dhSend(myIKPriv, bobBundle) {
  // 1. Verify SPK signature before any DH — abort on failure.
  const spkPubBytes = b64ToBytes(bobBundle.spk.public_key);
  const spkSigBytes = b64ToBytes(bobBundle.spk.signature);
  const bobIKed25519 = await importPublicKey(bobBundle.ik_ed25519, "Ed25519");
  const valid = await crypto.subtle.verify("Ed25519", bobIKed25519, spkSigBytes, spkPubBytes);
  if (!valid) throw new Error("x3dhSend: SPK signature verification failed");

  // 2. Generate ephemeral X25519 keypair EK_A.
  const ekKP = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);

  // 3. Import peer long-term keys.
  const bobIKPub  = await importPublicKey(bobBundle.ik_x25519,       "X25519");
  const bobSPKPub = await importPublicKey(bobBundle.spk.public_key,  "X25519");

  // 4. DH1–DH4: same order as the Python daemon.
  const dh1 = await ecdhX25519(myIKPriv,       bobSPKPub);  // DH(IK_A,  SPK_B)
  const dh2 = await ecdhX25519(ekKP.privateKey, bobIKPub);  // DH(EK_A,  IK_B)
  const dh3 = await ecdhX25519(ekKP.privateKey, bobSPKPub); // DH(EK_A,  SPK_B)

  let ikm = concat(dh1, dh2, dh3);
  let usedOPKPub_b64 = null;

  if (bobBundle.opk) {
    const bobOPKPub = await importPublicKey(bobBundle.opk.public_key, "X25519");
    const dh4 = await ecdhX25519(ekKP.privateKey, bobOPKPub); // DH(EK_A, OPK_B)
    ikm = concat(ikm, dh4);
    usedOPKPub_b64 = bobBundle.opk.public_key;
  }

  // 5. SK = HKDF-SHA256(ikm, salt=0x00*32, info="SecureMsg_X3DH_v1")
  const SK = await hkdf(ikm, new Uint8Array(32), "SecureMsg_X3DH_v1", 32);

  const EK_A_pub_b64 = await exportPublicKey(ekKP.publicKey);
  return { SK, EK_A_pub_b64, usedOPKPub_b64 };
}

// Receiver-side X3DH.
//
// myIKPriv: our X25519 identity private CryptoKey
// header:   { ik_a: b64, ek_a: b64, used_opk_pub: b64 | null }
//
// Returns { SK: ArrayBuffer(32) }
export async function x3dhReceive(myIKPriv, header) {
  const peerIKPub = await importPublicKey(header.ik_a, "X25519");
  const peerEKPub = await importPublicKey(header.ek_a, "X25519");

  const spkPriv = await loadPrivateKey("spk");
  if (!spkPriv) throw new Error("x3dhReceive: SPK not found in IndexedDB");

  // Mirror of sender's DH order, roles swapped:
  const dh1 = await ecdhX25519(spkPriv,  peerIKPub); // DH(SPK_B, IK_A)
  const dh2 = await ecdhX25519(myIKPriv, peerEKPub); // DH(IK_B,  EK_A)
  const dh3 = await ecdhX25519(spkPriv,  peerEKPub); // DH(SPK_B, EK_A)

  let ikm = concat(dh1, dh2, dh3);

  if (header.used_opk_pub) {
    const opkPriv = await loadOPKPrivate(header.used_opk_pub);
    if (!opkPriv) throw new Error("x3dhReceive: OPK not found: " + header.used_opk_pub);
    const dh4 = await ecdhX25519(opkPriv, peerEKPub); // DH(OPK_B, EK_A)
    ikm = concat(ikm, dh4);
  }

  const SK = await hkdf(ikm, new Uint8Array(32), "SecureMsg_X3DH_v1", 32);
  return { SK };
}

// ---------------------------------------------------------------------------
// Double Ratchet — chain / DH helpers
// ---------------------------------------------------------------------------

// Symmetric chain step.
// Returns { newCK_b64, MK_b64 } — each is 32 bytes.
// Python: advance_chain uses HKDF(ck, length=64, salt=None) → salt=None means
// 32 zero bytes per RFC 5869 for SHA-256.
export async function chainStep(chainKey_b64) {
  const out = await hkdf(b64ToBytes(chainKey_b64), new Uint8Array(32), "SecureMsg_MsgKey_v1", 64);
  const b   = new Uint8Array(out);
  return { newCK_b64: bytesToB64(b.slice(0, 32)), MK_b64: bytesToB64(b.slice(32, 64)) };
}

// DH ratchet step.
// DHs_priv_b64: PKCS#8-base64 ratchet private key.
// DHr_pub_b64:  raw-base64 peer ratchet public key.
// Returns { newRK_b64, newCK_b64 }.
export async function dhRatchetStep(RK_b64, DHs_priv_b64, DHr_pub_b64) {
  const dhsPriv = await crypto.subtle.importKey(
    "pkcs8", b64ToBytes(DHs_priv_b64), { name: "X25519" }, true, ["deriveBits"],
  );
  const dhrPub    = await importPublicKey(DHr_pub_b64, "X25519");
  const dhOutput  = await ecdhX25519(dhsPriv, dhrPub);
  const out       = await hkdf(dhOutput, b64ToBytes(RK_b64), "SecureMsg_Ratchet_v1", 64);
  const b         = new Uint8Array(out);
  return { newRK_b64: bytesToB64(b.slice(0, 32)), newCK_b64: bytesToB64(b.slice(32, 64)) };
}

// ---------------------------------------------------------------------------
// Double Ratchet — session initialisation
// ---------------------------------------------------------------------------

// Initialise a Double Ratchet session as the X3DH initiator.
//
// SK:              32-byte ArrayBuffer from x3dhSend
// bobRatchetPub:   Bob's SPK public key (b64) — serves as his initial ratchet pub
// myIKPub_b64:     our X25519 identity public key (b64) → ik_a
// bobIKPub_b64:    Bob's X25519 identity public key (b64) → ik_b
//
// Returns a session object ready for ratchetEncrypt.
export async function initSessionAsSender(SK, bobRatchetPub_b64, myIKPub_b64, bobIKPub_b64) {
  const SK_b64 = bytesToB64(SK);

  // Fresh extractable ratchet keypair — private key must be serialisable.
  const dhsKP      = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const dhsPubB64  = await exportPublicKey(dhsKP.publicKey);
  const dhsPrivB64 = bytesToB64(await crypto.subtle.exportKey("pkcs8", dhsKP.privateKey));

  // One DH ratchet step against Bob's SPK to derive the first sending chain key.
  const { newRK_b64, newCK_b64 } = await dhRatchetStep(SK_b64, dhsPrivB64, bobRatchetPub_b64);

  return {
    DHs_pub: dhsPubB64,
    DHs_priv: dhsPrivB64,
    DHr: bobRatchetPub_b64,
    RK: newRK_b64,
    CKs: newCK_b64,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    skipped: {},
    ik_a: myIKPub_b64,    // initiator's IK — fixed for AAD throughout session
    ik_b: bobIKPub_b64,   // responder's IK — fixed for AAD throughout session
    x3dh_header_sent: false,
    x3dh_ek_pub: null,    // filled in by sendMessage before first encrypt
    x3dh_opk_pub: null,
  };
}

// Initialise a Double Ratchet session as the X3DH responder.
//
// SK:               32-byte ArrayBuffer from x3dhReceive
// senderIKPub_b64:  sender's X25519 IK public key (b64) → ik_a
// myIKPub_b64:      our X25519 identity public key (b64) → ik_b
//
// DHs is seeded with our SPK private key so the first recv DH ratchet step
// produces the same chain key as the sender computed via DH(sender_DHs, SPK_B).
export async function initSessionAsReceiver(SK, senderIKPub_b64, myIKPub_b64) {
  const SK_b64 = bytesToB64(SK);

  // Load SPK (generated as extractable during registration).
  const spkPriv = await loadPrivateKey("spk");
  if (!spkPriv) throw new Error("initSessionAsReceiver: SPK not found");
  const spkPubB64 = await loadPrivateKey("spk_pub_b64");
  if (!spkPubB64) throw new Error("initSessionAsReceiver: SPK pub not found");

  const spkPrivB64 = bytesToB64(await crypto.subtle.exportKey("pkcs8", spkPriv));

  return {
    DHs_pub: spkPubB64,
    DHs_priv: spkPrivB64,
    DHr: null,
    RK: SK_b64,
    CKs: null,
    CKr: null,
    Ns: 0,
    Nr: 0,
    PN: 0,
    skipped: {},
    ik_a: senderIKPub_b64,
    ik_b: myIKPub_b64,
    x3dh_header_sent: true,  // receiver never sends x3dh header
    x3dh_ek_pub: null,
    x3dh_opk_pub: null,
  };
}

// ---------------------------------------------------------------------------
// Double Ratchet — encrypt / decrypt
// ---------------------------------------------------------------------------

// Encrypt plaintext_string using the current sending chain.
// Updates session in-place.
// Returns { ciphertext_b64, nonce_b64, ratchet_pub_b64, pn, n }.
export async function ratchetEncrypt(session, plaintext_string) {
  if (!session.CKs) throw new Error("ratchetEncrypt: no sending chain");

  // 1. Advance sending chain.
  const { newCK_b64, MK_b64 } = await chainStep(session.CKs);

  // 2. AES-256-GCM key from MK.
  const aesgcmKey = await crypto.subtle.importKey(
    "raw", b64ToBytes(MK_b64), "AES-GCM", false, ["encrypt"],
  );

  // 3. PKCS#7 pad to 256-byte boundary.
  const ptBytes = new TextEncoder().encode(plaintext_string);
  const padLen  = 256 - (ptBytes.length % 256);   // always 1–256
  const padded  = new Uint8Array(ptBytes.length + padLen);
  padded.set(ptBytes);
  padded.fill(padLen, ptBytes.length);

  // 4. Random 12-byte nonce.
  const nonce = crypto.getRandomValues(new Uint8Array(12));

  // 5. AAD: ik_a || ik_b || ratchet_pub || PN (4-byte BE) || N (4-byte BE)
  const N   = session.Ns;
  const aad = _buildAad(session.ik_a, session.ik_b, session.DHs_pub, session.PN, N);

  // 6. Encrypt.
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad },
    aesgcmKey,
    padded,
  );

  // 7. Advance state.
  session.CKs = newCK_b64;
  session.Ns  = N + 1;

  return {
    ciphertext_b64:  bytesToB64(ct),
    nonce_b64:       bytesToB64(nonce),
    ratchet_pub_b64: session.DHs_pub,
    pn:              session.PN,
    n:               N,
  };
}

// Decrypt an incoming Double Ratchet message.
// fields: { ciphertext, nonce, ratchet_pub, pn, n } (all strings/numbers).
// Updates session in-place. Returns decrypted plaintext string.
export async function ratchetDecrypt(session, fields, _senderIKPub_b64, _myIKPub_b64) {
  const { ciphertext, nonce, ratchet_pub, pn, n } = fields;

  // 1. Check skipped-key cache.
  const skippedKey = `${ratchet_pub}:${n}`;
  if (session.skipped[skippedKey]) {
    const MK_b64 = session.skipped[skippedKey];
    delete session.skipped[skippedKey];
    return _openMessage(session, MK_b64, ciphertext, nonce, ratchet_pub, pn, n);
  }

  // 2. New DH ratchet epoch.
  if (ratchet_pub !== session.DHr) {
    session.PN = session.Ns;

    // Drain remaining keys from the OLD receive chain up to pn.
    if (session.CKr !== null && session.DHr !== null) {
      // Reject before the loop: a malicious pn must never spin the chain.
      if (pn - session.Nr > MAX_SKIPPED) throw new Error("ratchetDecrypt: too many skipped keys");
      while (session.Nr < pn) {
        _evictSkippedIfFull(session);
        const { newCK_b64, MK_b64 } = await chainStep(session.CKr);
        session.skipped[`${session.DHr}:${session.Nr}`] = MK_b64;
        session.CKr = newCK_b64;
        session.Nr++;
      }
    }

    // DH(DHs, new_peer_ratchet) → new RK and CKr.
    const { newRK_b64: rk1, newCK_b64: ckr } = await dhRatchetStep(session.RK, session.DHs_priv, ratchet_pub);
    session.RK  = rk1;
    session.CKr = ckr;
    session.DHr = ratchet_pub;
    session.Nr  = 0;

    // Generate fresh DHs and derive new CKs.
    const newDhsKP      = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const newDhsPubB64  = await exportPublicKey(newDhsKP.publicKey);
    const newDhsPrivB64 = bytesToB64(await crypto.subtle.exportKey("pkcs8", newDhsKP.privateKey));
    const { newRK_b64: rk2, newCK_b64: cks } = await dhRatchetStep(session.RK, newDhsPrivB64, ratchet_pub);
    session.RK       = rk2;
    session.CKs      = cks;
    session.DHs_pub  = newDhsPubB64;
    session.DHs_priv = newDhsPrivB64;
    session.Ns       = 0;
  }

  // 3. Skip forward to message n, caching skipped keys.
  if (n < session.Nr) throw new Error("ratchetDecrypt: message older than chain (not cached)");
  // Reject before the loop: a malicious n must never spin the chain billions of times.
  if (n - session.Nr > MAX_SKIPPED) throw new Error("ratchetDecrypt: too many skipped keys");
  while (session.Nr < n) {
    _evictSkippedIfFull(session);
    const { newCK_b64, MK_b64 } = await chainStep(session.CKr);
    session.skipped[`${session.DHr}:${session.Nr}`] = MK_b64;
    session.CKr = newCK_b64;
    session.Nr++;
  }

  // 4. Derive MK for message n.
  const { newCK_b64, MK_b64 } = await chainStep(session.CKr);
  session.CKr = newCK_b64;
  session.Nr++;

  return _openMessage(session, MK_b64, ciphertext, nonce, ratchet_pub, pn, n);
}

function _buildAad(ikA_b64, ikB_b64, ratchetPub_b64, pn, n) {
  const pnBuf = new Uint8Array(4);
  const nBuf  = new Uint8Array(4);
  new DataView(pnBuf.buffer).setUint32(0, pn, false);
  new DataView(nBuf.buffer).setUint32(0, n,  false);
  return concat(b64ToBytes(ikA_b64), b64ToBytes(ikB_b64), b64ToBytes(ratchetPub_b64), pnBuf, nBuf);
}

function _evictSkippedIfFull(session) {
  const keys = Object.keys(session.skipped);
  if (keys.length >= MAX_SKIPPED) delete session.skipped[keys[0]];
}

async function _openMessage(session, MK_b64, ciphertext_b64, nonce_b64, ratchet_pub_b64, pn, n) {
  const aesgcmKey = await crypto.subtle.importKey(
    "raw", b64ToBytes(MK_b64), "AES-GCM", false, ["decrypt"],
  );
  const aad = _buildAad(session.ik_a, session.ik_b, ratchet_pub_b64, pn, n);
  let padded;
  try {
    padded = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(nonce_b64), additionalData: aad },
      aesgcmKey,
      b64ToBytes(ciphertext_b64),
    );
  } catch {
    throw new Error("ratchetDecrypt: AEAD tag verification failed");
  }

  // Strip PKCS#7 padding.
  const arr    = new Uint8Array(padded);
  const padLen = arr[arr.length - 1];
  if (padLen === 0 || padLen > 256 || padLen > arr.length) throw new Error("ratchetDecrypt: bad padding");
  for (let i = arr.length - padLen; i < arr.length; i++) {
    if (arr[i] !== padLen) throw new Error("ratchetDecrypt: bad padding content");
  }
  return new TextDecoder().decode(arr.slice(0, arr.length - padLen));
}

// ---------------------------------------------------------------------------
// Session persistence
// ---------------------------------------------------------------------------

export async function saveSession(username, session) {
  await storePrivateKey(`session:${username}`, session);
}

export async function loadSession(username) {
  return loadPrivateKey(`session:${username}`);
}

// ---------------------------------------------------------------------------
// Legacy stubs (not used in Double Ratchet flow)
// ---------------------------------------------------------------------------

export async function encryptMessage(_plaintext, _recipientPublicKey) {
  throw new Error("encryptMessage: replaced by ratchetEncrypt");
}

export async function decryptMessage(_ciphertext, _ephemeralPublicKey, _iv, _privateKey) {
  throw new Error("decryptMessage: replaced by ratchetDecrypt");
}
