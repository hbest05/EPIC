/**
 * app.js — SecureMsg web client
 *
 * Auth: httpOnly cookie (set by server on login) + double-submit CSRF token.
 * All requests use credentials: 'include' so cookies are sent automatically.
 * State-changing requests (POST/PUT/DELETE) attach the X-CSRF-Token header
 * by reading the readable csrf_token cookie.
 */

import {
  generateKeyPair,
  generateSigningPair,
  exportPublicKey,
  encryptMessage,
  decryptMessage,
  storePrivateKey,
  loadPrivateKey,
} from "./crypto.js";

const API_BASE = "http://localhost:8000/api";
const POLL_INTERVAL_MS = 5000; // TODO: replace with WebSocket

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

let currentUser = null;        // { id, username }
let myPrivateKey = null;       // X25519 CryptoKey (loaded from IndexedDB)
let mySigningKey = null;       // Ed25519 CryptoKey (loaded from IndexedDB)
const contacts = new Map();    // username → full KeyBundleResponse (session cache only)
let activeRecipient = null;
let inboxPoller = null;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  try {
    // GET /me succeeds if the access_token cookie is still valid
    currentUser = await apiFetch("/auth/me");
    myPrivateKey = await loadPrivateKey("x25519");
    mySigningKey = await loadPrivateKey("ed25519");
    showApp();
    startInboxPoller();
  } catch {
    showAuth();
  }

  attachEventListeners();
});

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async function register() {
  const username = document.getElementById("reg-username").value.trim();
  const email    = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;

  try {
    // Generate both long-term keypairs client-side — private keys never leave the browser
    const { publicKey: x25519Pub, privateKey: x25519Priv } = await generateKeyPair();
    const { publicKey: ed25519Pub, privateKey: ed25519Priv } = await generateSigningPair();

    // Upload public keys and create account
    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        email,
        password,
        x25519_public_key: await exportPublicKey(x25519Pub),
        ed25519_public_key: await exportPublicKey(ed25519Pub),
      }),
    });

    // Persist private keys in IndexedDB only after server confirms the account
    await storePrivateKey("x25519", x25519Priv);
    await storePrivateKey("ed25519", ed25519Priv);

    // Auto-login — sets httpOnly access_token cookie and readable csrf_token cookie
    currentUser = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    myPrivateKey = await loadPrivateKey("x25519");
    mySigningKey = await loadPrivateKey("ed25519");
    showApp();
    startInboxPoller();
  } catch (err) {
    alert(err.message);
  }
}

async function login() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  try {
    currentUser = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    myPrivateKey = await loadPrivateKey("x25519");
    mySigningKey = await loadPrivateKey("ed25519");
    showApp();
    startInboxPoller();
  } catch (err) {
    alert(err.message);
  }
}

async function logout() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } finally {
    currentUser = null;
    myPrivateKey = null;
    mySigningKey = null;
    stopInboxPoller();
    showAuth();
  }
}

// ---------------------------------------------------------------------------
// TOFU key pinning — persistent IndexedDB store
// ---------------------------------------------------------------------------

const TOFU_DB_NAME    = "tofu-store";
const TOFU_STORE_NAME = "pins";

function openTofuDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(TOFU_DB_NAME, 1);
    req.onupgradeneeded = (e) => {
      // Schema: { username (keyPath), ikFingerprint, pinnedAt }
      e.target.result.createObjectStore(TOFU_STORE_NAME, { keyPath: "username" });
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror  = (e) => reject(e.target.error);
  });
}

async function getPin(username) {
  const db = await openTofuDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(TOFU_STORE_NAME).objectStore(TOFU_STORE_NAME).get(username);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror  = () => reject(req.error);
  });
}

async function storePin(username, ikFingerprint) {
  const db = await openTofuDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(TOFU_STORE_NAME, "readwrite");
    tx.objectStore(TOFU_STORE_NAME).put({
      username,
      ikFingerprint,
      pinnedAt: new Date().toISOString(),
    });
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

async function computeFingerprint(rawB64) {
  // SHA-256 of raw key bytes — matches hashlib.sha256(key_bytes).hexdigest() server-side
  const raw  = Uint8Array.from(atob(rawB64), c => c.charCodeAt(0));
  const hash = await crypto.subtle.digest("SHA-256", raw);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function showKeyChangeWarning(username) {
  // Prominent, non-dismissable-by-accident banner — never silently accept a key change
  const banner = document.createElement("div");
  banner.style.cssText = [
    "position:fixed", "top:0", "left:0", "right:0",
    "background:#c0392b", "color:#fff", "padding:16px 24px",
    "font-size:15px", "font-weight:bold", "z-index:9999", "text-align:center",
  ].join(";");
  banner.textContent = `⚠ Security warning: key changed for ${username}. Possible MITM attack. Contact blocked.`;
  const dismiss = document.createElement("button");
  dismiss.textContent = "Dismiss";
  dismiss.style.cssText = "margin-left:20px;padding:4px 14px;font-size:14px;cursor:pointer;";
  dismiss.onclick = () => banner.remove();
  banner.appendChild(dismiss);
  document.body.prepend(banner);
}

/**
 * Fetch a contact's full X3DH key bundle and enforce TOFU pinning.
 *
 * First contact: fingerprint is computed from ik_x25519 and pinned in IndexedDB.
 * Subsequent contacts: fingerprint is compared — mismatch blocks the contact
 * and shows a visible security warning. Never silently accepts a key change.
 *
 * @param {string} username
 * @returns {object} KeyBundleResponse from the server
 * @throws if TOFU check fails or the server returns an error
 */
async function fetchContactKeybundle(username) {
  const bundle      = await apiFetch(`/auth/user/${username}/keybundle`);
  const fingerprint = await computeFingerprint(bundle.ik_x25519);

  const pin = await getPin(username);
  if (pin === null) {
    // First contact — trust on first use and pin the identity key
    await storePin(username, fingerprint);
  } else if (pin.ikFingerprint !== fingerprint) {
    // Key changed — block this contact and surface a visible warning
    showKeyChangeWarning(username);
    throw new Error(`TOFU violation: key changed for ${username}`);
  }
  // Pin matches or was just set — cache bundle for this session
  contacts.set(username, bundle);
  return bundle;
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

async function sendMessage() {
  // TODO: implement once crypto.js encryption is complete
  console.warn("sendMessage: crypto.js not yet implemented");
}

async function fetchInbox() {
  // TODO: implement once crypto.js decryption is complete
}

// ---------------------------------------------------------------------------
// Inbox polling
// ---------------------------------------------------------------------------

function startInboxPoller() {
  inboxPoller = setInterval(fetchInbox, POLL_INTERVAL_MS);
}

function stopInboxPoller() {
  clearInterval(inboxPoller);
  inboxPoller = null;
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

function showAuth() {
  document.getElementById("auth-section").style.display = "block";
  document.getElementById("app-section").style.display = "none";
}

function showApp() {
  document.getElementById("auth-section").style.display = "none";
  document.getElementById("app-section").style.display = "flex";
}

function attachEventListeners() {
  document.getElementById("btn-login").addEventListener("click", login);
  document.getElementById("btn-register").addEventListener("click", register);
  document.getElementById("btn-logout").addEventListener("click", logout);
  document.getElementById("btn-send").addEventListener("click", sendMessage);
  document.getElementById("show-register").addEventListener("click", () => {
    document.getElementById("login-form").style.display = "none";
    document.getElementById("register-form").style.display = "block";
  });
  document.getElementById("show-login").addEventListener("click", () => {
    document.getElementById("register-form").style.display = "none";
    document.getElementById("login-form").style.display = "block";
  });
  // TODO: btn-add-contact → fetch keybundle and cache in contacts Map
}

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------

function getCsrfToken() {
  const match = document.cookie
    .split("; ")
    .find(row => row.startsWith("csrf_token="));
  return match ? match.split("=")[1] : null;
}

async function apiFetch(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...options.headers };

  // Attach CSRF token on all state-changing requests
  if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",  // send httpOnly cookie on every request
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }

  return res.json();
}
