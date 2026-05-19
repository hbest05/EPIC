/**
 * crypto.js — Web Crypto API wrapper for SecureMsg
 *
 * Provides:
 *   generateKeyPair()     — generate an X25519 ECDH keypair for key exchange
 *   generateSigningPair() — generate an Ed25519 keypair for message signing
 *   encryptMessage()      — ECDH + AES-GCM encrypt a plaintext string
 *   decryptMessage()      — ECDH + AES-GCM decrypt a ciphertext blob
 *   signMessage()         — Ed25519 sign a ciphertext buffer
 *   verifySignature()     — verify an Ed25519 signature
 *   exportPublicKey()     — export a CryptoKey as a base64 string for the API
 *   storePrivateKey()     — persist a CryptoKey in IndexedDB (non-extractable)
 *   loadPrivateKey()      — retrieve a CryptoKey from IndexedDB
 *
 * IMPORTANT: Private keys are stored as non-extractable CryptoKey objects in
 * IndexedDB under the "securemsg-keys" database. They never leave the browser.
 *
 * Encryption scheme:
 *   1. Sender generates ephemeral X25519 keypair
 *   2. ECDH(ephemeral_private, recipient_public) → shared secret
 *   3. HKDF(shared_secret) → 256-bit AES-GCM key
 *   4. AES-GCM encrypt plaintext → {ciphertext, iv}
 *   5. Send ciphertext + ephemeral_public_key to server
 *
 * NOTE: The Web Crypto API supports ECDH with P-256/P-384/P-521 curves natively.
 * X25519 support landed in Chrome 133 / Firefox 130. For older browsers,
 * consider tweetnacl-js as a polyfill.
 */

const DB_NAME = "securemsg-keys";
const DB_VERSION = 1;
const STORE_NAME = "keys";

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/**
 * Generate an X25519 (ECDH) keypair.
 * The private key is non-extractable — it can only be used for ECDH derivation.
 *
 * TODO: Implement and export from this module.
 */
export async function generateKeyPair() {
  // TODO: crypto.subtle.generateKey({ name: "X25519" }, false, ["deriveKey"])
  throw new Error("generateKeyPair: not implemented yet");
}

/**
 * Generate an Ed25519 (signing) keypair.
 * The private key is non-extractable.
 *
 * TODO: Implement and export from this module.
 */
export async function generateSigningPair() {
  // TODO: crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign"])
  throw new Error("generateSigningPair: not implemented yet");
}

// ---------------------------------------------------------------------------
// Encryption / Decryption
// ---------------------------------------------------------------------------

/**
 * Encrypt plaintext for a recipient using their X25519 public key.
 *
 * @param {string} plaintext - UTF-8 message to encrypt
 * @param {CryptoKey} recipientPublicKey - recipient's X25519 public key
 * @returns {{ ciphertext: string, ephemeralPublicKey: string, iv: string }}
 *          All fields are base64-encoded strings ready for the API.
 *
 * TODO: Implement ECDH → HKDF → AES-GCM pipeline.
 */
export async function encryptMessage(plaintext, recipientPublicKey) {
  throw new Error("encryptMessage: not implemented yet");
}

/**
 * Decrypt a message ciphertext using the current user's X25519 private key.
 *
 * @param {string} ciphertext - base64-encoded ciphertext from the API
 * @param {string} ephemeralPublicKey - base64 ephemeral public key from sender
 * @param {string} iv - base64 AES-GCM nonce
 * @param {CryptoKey} privateKey - current user's X25519 private key
 * @returns {string} Decrypted plaintext
 *
 * TODO: Implement ECDH → HKDF → AES-GCM decryption.
 */
export async function decryptMessage(ciphertext, ephemeralPublicKey, iv, privateKey) {
  throw new Error("decryptMessage: not implemented yet");
}

// ---------------------------------------------------------------------------
// Signing / Verification
// ---------------------------------------------------------------------------

/**
 * Sign a ciphertext buffer with the current user's Ed25519 private key.
 * The signature lets recipients verify authenticity without trusting the server.
 *
 * @param {ArrayBuffer} data - ciphertext bytes to sign
 * @param {CryptoKey} signingKey - Ed25519 private key
 * @returns {string} base64-encoded signature
 *
 * TODO: crypto.subtle.sign("Ed25519", signingKey, data)
 */
export async function signMessage(data, signingKey) {
  throw new Error("signMessage: not implemented yet");
}

/**
 * Verify an Ed25519 signature against a sender's public key.
 *
 * @param {string} signature - base64 signature from the API
 * @param {ArrayBuffer} data - ciphertext bytes that were signed
 * @param {CryptoKey} senderPublicKey - sender's Ed25519 public key
 * @returns {boolean}
 *
 * TODO: crypto.subtle.verify("Ed25519", senderPublicKey, sigBytes, data)
 */
export async function verifySignature(signature, data, senderPublicKey) {
  throw new Error("verifySignature: not implemented yet");
}

// ---------------------------------------------------------------------------
// Key export / import
// ---------------------------------------------------------------------------

/**
 * Export a public CryptoKey as a base64-encoded SPKI string for the REST API.
 *
 * TODO: crypto.subtle.exportKey("spki", key) → base64
 */
export async function exportPublicKey(key) {
  throw new Error("exportPublicKey: not implemented yet");
}

// ---------------------------------------------------------------------------
// IndexedDB persistence (private keys only)
// ---------------------------------------------------------------------------

function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      e.target.result.createObjectStore(STORE_NAME);
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror = (e) => reject(e.target.error);
  });
}

/**
 * Store a non-extractable CryptoKey in IndexedDB under `keyName`.
 * TODO: Implement.
 */
export async function storePrivateKey(keyName, key) {
  throw new Error("storePrivateKey: not implemented yet");
}

/**
 * Retrieve a CryptoKey from IndexedDB by `keyName`.
 * Returns null if not found.
 * TODO: Implement.
 */
export async function loadPrivateKey(keyName) {
  throw new Error("loadPrivateKey: not implemented yet");
}
