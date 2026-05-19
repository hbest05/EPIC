/**
 * app.js — SecureMsg web client application logic
 *
 * Responsibilities:
 *   - Auth: register (generate keys, POST /api/auth/register), login, logout
 *   - Key management: load private keys from IndexedDB on startup
 *   - Inbox: poll GET /api/messages/inbox, decrypt messages, render them
 *   - Send: encrypt plaintext with recipient's public key, POST /api/messages/send
 *   - Blockchain status: show on-chain confirmation badge next to each message
 *
 * State held in memory (not persisted across page reloads except for keys):
 *   currentUser      — { id, username, token }
 *   contacts         — Map<username, { x25519PublicKey, ed25519PublicKey }>
 *   activeRecipient  — username string
 *   myPrivateKey     — X25519 CryptoKey (loaded from IndexedDB)
 *   mySigningKey     — Ed25519 CryptoKey (loaded from IndexedDB)
 */

import {
  generateKeyPair,
  generateSigningPair,
  exportPublicKey,
  encryptMessage,
  decryptMessage,
  signMessage,
  verifySignature,
  storePrivateKey,
  loadPrivateKey,
} from "./crypto.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const API_BASE = "http://localhost:8000/api";
const POLL_INTERVAL_MS = 5000; // TODO: Replace polling with WebSocket

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

let currentUser = null;
let myPrivateKey = null;
let mySigningKey = null;
const contacts = new Map();
let activeRecipient = null;
let inboxPoller = null;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  const token = localStorage.getItem("jwt");
  if (token) {
    // TODO: Validate token expiry client-side before trying to load the app
    // TODO: Load user profile from /api/auth/me
    // TODO: Load private keys from IndexedDB
    showApp();
  } else {
    showAuth();
  }

  attachEventListeners();
});

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async function register() {
  const username = document.getElementById("reg-username").value.trim();
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;

  // TODO: Generate X25519 and Ed25519 keypairs via crypto.js
  // TODO: Store private keys in IndexedDB
  // TODO: Export public keys as base64
  // TODO: POST /api/auth/register with { username, email, password, x25519_public_key, ed25519_public_key }
  // TODO: On success → auto-login
  alert("Register: not implemented yet");
}

async function login() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  // TODO: POST /api/auth/login with { username, password }
  // TODO: Store JWT in localStorage
  // TODO: Load private keys from IndexedDB (user must have registered on this browser)
  // TODO: Start inbox polling
  alert("Login: not implemented yet");
}

function logout() {
  localStorage.removeItem("jwt");
  currentUser = null;
  myPrivateKey = null;
  mySigningKey = null;
  clearInterval(inboxPoller);
  showAuth();
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

async function sendMessage() {
  if (!activeRecipient) return;

  const plaintext = document.getElementById("plaintext-input").value.trim();
  if (!plaintext) return;

  // TODO: Look up recipient's X25519 public key from contacts Map
  // TODO: encryptMessage(plaintext, recipientPublicKey) → { ciphertext, ephemeralPublicKey, iv }
  // TODO: signMessage(ciphertextBytes, mySigningKey) → signature
  // TODO: POST /api/messages/send with ciphertext, ephemeralPublicKey, signature
  // TODO: Append sent message to UI
  alert("sendMessage: not implemented yet");
}

async function fetchInbox() {
  // TODO: GET /api/messages/inbox with Authorization: Bearer <token>
  // TODO: For each new message:
  //   1. Fetch sender's public keys if not cached in contacts Map
  //   2. verifySignature(signature, ciphertext, senderPublicKey)
  //   3. decryptMessage(ciphertext, ephemeralPublicKey, iv, myPrivateKey) → plaintext
  //   4. Render message in UI
  //   5. Show blockchain confirmation badge if message.blockchain_confirmed
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
  // TODO: btn-add-contact → fetch pubkeys and add to contacts Map
}

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------

async function apiFetch(path, options = {}) {
  const token = localStorage.getItem("jwt");
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };
  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}
