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
  importPublicKey,
  signMessage,
  verifySignature,
  storePrivateKey,
  loadPrivateKey,
  generateOPKs,
  x3dhSend,
  x3dhReceive,
  initSessionAsSender,
  initSessionAsReceiver,
  ratchetEncrypt,
  ratchetDecrypt,
  saveSession,
  loadSession,
} from "./crypto.js";

const API_BASE        = "http://localhost:8000/api";
const POLL_INTERVAL_MS = 5000; // TODO: replace with WebSocket

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

let currentUser    = null;        // { id, username }
let myPrivateKey   = null;        // X25519 CryptoKey (loaded from IndexedDB)
let mySigningKey   = null;        // Ed25519 CryptoKey (loaded from IndexedDB)
let myPublicKeyB64 = null;        // our X25519 IK public key, base64
const contacts     = new Map();   // username → KeyBundleResponse
const sessions     = new Map();   // username → session object (mirrors IndexedDB)
const seenMessageIds = new Set(); // prevents re-processing fetched messages
let activeRecipient = null;
let inboxPoller     = null;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  try {
    currentUser    = await apiFetch("/auth/me");
    myPrivateKey   = await loadPrivateKey("x25519");
    mySigningKey   = await loadPrivateKey("ed25519");
    myPublicKeyB64 = await loadPrivateKey("my_ik_pub_b64");
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
    // Generate long-term keypairs — private keys never leave the browser.
    const { publicKey: x25519Pub, privateKey: x25519Priv } = await generateKeyPair();
    const { publicKey: ed25519Pub, privateKey: ed25519Priv } = await generateSigningPair();

    const x25519PubB64 = await exportPublicKey(x25519Pub);
    const ed25519PubB64 = await exportPublicKey(ed25519Pub);

    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        email,
        password,
        x25519_public_key: x25519PubB64,
        ed25519_public_key: ed25519PubB64,
      }),
    });

    // Persist long-term private keys in IndexedDB only after server confirms.
    await storePrivateKey("x25519",        x25519Priv);
    await storePrivateKey("ed25519",       ed25519Priv);
    await storePrivateKey("my_ik_pub_b64", x25519PubB64);

    // Generate SPK (extractable so it can be used as initial DHs in X3DH receive).
    const spkKP = await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    );
    const spkPubB64 = await exportPublicKey(spkKP.publicKey);

    // Sign raw SPK pub bytes with Ed25519 IK.
    const spkPubBytes = Uint8Array.from(atob(spkPubB64), c => c.charCodeAt(0));
    const spkSigB64   = await signMessage(spkPubBytes.buffer, ed25519Priv);

    // Store SPK private CryptoKey and its public key b64 for use in X3DH receive.
    await storePrivateKey("spk",        spkKP.privateKey);
    await storePrivateKey("spk_pub_b64", spkPubB64);

    // Generate 10 OPKs (private keys stored in IndexedDB by generateOPKs).
    const opks = await generateOPKs(10);

    // Upload prekeys.
    const keyId = Math.floor(Date.now() / 1000);
    await apiFetch("/auth/prekeys", {
      method: "POST",
      body: JSON.stringify({
        signed_prekey: {
          key_id:    keyId,
          public_key: spkPubB64,
          signature:  spkSigB64,
        },
        one_time_prekeys: await Promise.all(
          opks.map(async (kp, i) => ({
            key_id:    keyId * 100 + i,
            public_key: await exportPublicKey(kp.publicKey),
          })),
        ),
      }),
    });

    // Auto-login.
    currentUser = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    myPrivateKey   = await loadPrivateKey("x25519");
    mySigningKey   = await loadPrivateKey("ed25519");
    myPublicKeyB64 = x25519PubB64;
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
    currentUser    = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    myPrivateKey   = await loadPrivateKey("x25519");
    mySigningKey   = await loadPrivateKey("ed25519");
    myPublicKeyB64 = await loadPrivateKey("my_ik_pub_b64");
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
    currentUser    = null;
    myPrivateKey   = null;
    mySigningKey   = null;
    myPublicKeyB64 = null;
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
      e.target.result.createObjectStore(TOFU_STORE_NAME, { keyPath: "username" });
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

async function getPin(username) {
  const db = await openTofuDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(TOFU_STORE_NAME).objectStore(TOFU_STORE_NAME).get(username);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

async function storePin(username, ikFingerprint) {
  const db = await openTofuDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(TOFU_STORE_NAME, "readwrite");
    tx.objectStore(TOFU_STORE_NAME).put({ username, ikFingerprint, pinnedAt: new Date().toISOString() });
    tx.oncomplete = () => resolve();
    tx.onerror    = () => reject(tx.error);
  });
}

async function computeFingerprint(rawB64) {
  const raw  = Uint8Array.from(atob(rawB64), c => c.charCodeAt(0));
  const hash = await crypto.subtle.digest("SHA-256", raw);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function showKeyChangeWarning(username) {
  const banner = document.createElement("div");
  banner.style.cssText = [
    "position:fixed","top:0","left:0","right:0",
    "background:#c0392b","color:#fff","padding:16px 24px",
    "font-size:15px","font-weight:bold","z-index:9999","text-align:center",
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
 */
async function fetchContactKeybundle(username) {
  const bundle      = await apiFetch(`/auth/user/${username}/keybundle`);
  const fingerprint = await computeFingerprint(bundle.ik_x25519);

  const pin = await getPin(username);
  if (pin === null) {
    await storePin(username, fingerprint);
  } else if (pin.ikFingerprint !== fingerprint) {
    showKeyChangeWarning(username);
    throw new Error(`TOFU violation: key changed for ${username}`);
  }
  contacts.set(username, bundle);
  return bundle;
}

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

async function sendMessage() {
  if (!activeRecipient) return;
  const input     = document.getElementById("plaintext-input");
  const plaintext = input.value.trim();
  if (!plaintext) return;

  try {
    let session = sessions.get(activeRecipient) ?? await loadSession(activeRecipient);

    if (!session) {
      // First message to this contact: run X3DH to establish session.
      const bundle = contacts.get(activeRecipient) ?? await fetchContactKeybundle(activeRecipient);
      const { SK, EK_A_pub_b64, usedOPKPub_b64 } = await x3dhSend(myPrivateKey, bundle);

      session = await initSessionAsSender(SK, bundle.spk.public_key, myPublicKeyB64, bundle.ik_x25519);
      // Store ephemeral key so the first message can carry the X3DH header.
      session.x3dh_ek_pub  = EK_A_pub_b64;
      session.x3dh_opk_pub = usedOPKPub_b64;
    }

    const result = await ratchetEncrypt(session, plaintext);

    let x3dhHeader = null;
    if (!session.x3dh_header_sent) {
      x3dhHeader = {
        ik_a:         myPublicKeyB64,
        ek_a:         session.x3dh_ek_pub,
        used_opk_pub: session.x3dh_opk_pub,
      };
      session.x3dh_header_sent = true;
    }

    sessions.set(activeRecipient, session);
    await saveSession(activeRecipient, session);

    await apiFetch("/messages/send", {
      method: "POST",
      body: JSON.stringify({
        recipient_username: activeRecipient,
        ciphertext:   result.ciphertext_b64,
        nonce:        result.nonce_b64,
        ratchet_pub:  result.ratchet_pub_b64,
        pn:           result.pn,
        n:            result.n,
        x3dh_header:  x3dhHeader,
      }),
    });

    renderMessage(currentUser.username, plaintext);
    input.value = "";
  } catch (err) {
    console.error("sendMessage failed:", err);
    alert("Send failed: " + err.message);
  }
}

async function fetchInbox() {
  try {
    const messages = await apiFetch("/messages/inbox");
    for (const msg of messages) {
      if (seenMessageIds.has(msg.id)) continue;
      seenMessageIds.add(msg.id);

      const sender = msg.sender_username;

      try {
        let session = sessions.get(sender) ?? await loadSession(sender);

        if (!session && msg.x3dh_header) {
          const { SK } = await x3dhReceive(myPrivateKey, msg.x3dh_header);
          session = await initSessionAsReceiver(SK, msg.x3dh_header.ik_a, myPublicKeyB64);
        }

        if (!session) {
          console.warn("fetchInbox: no session for", sender, "— skipping");
          continue;
        }

        const plaintext = await ratchetDecrypt(
          session,
          { ciphertext: msg.ciphertext, nonce: msg.nonce, ratchet_pub: msg.ratchet_pub, pn: msg.pn, n: msg.n },
          session.ik_a,
          session.ik_b,
        );

        sessions.set(sender, session);
        await saveSession(sender, session);

        renderMessage(sender, plaintext);
      } catch (err) {
        console.error("fetchInbox: failed to decrypt message from", sender, err);
      }
    }
  } catch (err) {
    console.error("fetchInbox: inbox fetch failed", err);
  }
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
  document.getElementById("app-section").style.display  = "none";
}

function showApp() {
  document.getElementById("auth-section").style.display = "none";
  document.getElementById("app-section").style.display  = "flex";
}

function renderMessage(senderUsername, plaintext) {
  const list = document.getElementById("message-list");
  if (!list) return;
  const item = document.createElement("div");
  item.className = "message";
  const isMine = senderUsername === currentUser?.username;
  item.style.textAlign = isMine ? "right" : "left";
  item.innerHTML = `<strong>${escapeHtml(senderUsername)}:</strong> ${escapeHtml(plaintext)}`;
  list.appendChild(item);
  list.scrollTop = list.scrollHeight;
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function attachEventListeners() {
  document.getElementById("btn-login").addEventListener("click", login);
  document.getElementById("btn-register").addEventListener("click", register);
  document.getElementById("btn-logout").addEventListener("click", logout);
  document.getElementById("btn-send").addEventListener("click", sendMessage);
  document.getElementById("show-register").addEventListener("click", () => {
    document.getElementById("login-form").style.display    = "none";
    document.getElementById("register-form").style.display = "block";
  });
  document.getElementById("show-login").addEventListener("click", () => {
    document.getElementById("register-form").style.display = "none";
    document.getElementById("login-form").style.display    = "block";
  });

  document.getElementById("btn-add-contact").addEventListener("click", async () => {
    const input    = document.getElementById("new-contact");
    const username = input.value.trim();
    if (!username) return;
    try {
      await fetchContactKeybundle(username);
      addContactToSidebar(username);
      input.value = "";
    } catch (err) {
      alert(err.message);
    }
  });

  // Allow Send on Enter (Shift+Enter for newline).
  document.getElementById("plaintext-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
}

function addContactToSidebar(username) {
  const list = document.getElementById("contact-list");
  if (!list) return;
  // Avoid duplicates.
  if (list.querySelector(`[data-username="${CSS.escape(username)}"]`)) return;
  const li = document.createElement("li");
  li.dataset.username = username;
  li.textContent      = username;
  li.style.cursor     = "pointer";
  li.addEventListener("click", () => {
    activeRecipient = username;
    document.getElementById("chat-recipient").textContent = username;
    document.getElementById("message-list").innerHTML = "";
  });
  list.appendChild(li);
}

// ---------------------------------------------------------------------------
// API helper
// ---------------------------------------------------------------------------

function getCsrfToken() {
  const match = document.cookie.split("; ").find(row => row.startsWith("csrf_token="));
  return match ? match.split("=")[1] : null;
}

async function apiFetch(path, options = {}) {
  const method  = (options.method || "GET").toUpperCase();
  const headers = { "Content-Type": "application/json", ...options.headers };

  if (["POST", "PUT", "DELETE", "PATCH"].includes(method)) {
    const csrf = getCsrfToken();
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
    credentials: "include",
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }

  return res.json();
}
