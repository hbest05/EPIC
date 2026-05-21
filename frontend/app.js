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
const contacts = new Map();    // username → { x25519PublicKey, ed25519PublicKey }
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

  // TODO: implement once crypto.js key generation is complete
  // const { publicKey: x25519Pub, privateKey: x25519Priv } = await generateKeyPair();
  // const { publicKey: ed25519Pub, privateKey: ed25519Priv } = await generateSigningPair();
  // const x25519_public_key = await exportPublicKey(x25519Pub);
  // const ed25519_public_key = await exportPublicKey(ed25519Pub);
  // await storePrivateKey("x25519", x25519Priv);
  // await storePrivateKey("ed25519", ed25519Priv);
  // await apiFetch("/auth/register", {
  //   method: "POST",
  //   body: JSON.stringify({ username, email, password, x25519_public_key, ed25519_public_key }),
  // });
  // await login(username, password);
  console.warn("register: crypto.js not yet implemented");
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
