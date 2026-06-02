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
  signMessage,
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
  deriveWrappingKey,
  wrapPrivateKey,
  unwrapPrivateKey,
} from "./crypto.js";

const API_BASE         = "http://localhost:8000/api";
const POLL_INTERVAL_MS = 5000;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

let currentUser    = null;        // { id, username }
let myPrivateKey   = null;        // X25519 CryptoKey (loaded from IndexedDB)
let mySigningKey   = null;        // Ed25519 CryptoKey (loaded from IndexedDB)
let myPublicKeyB64 = null;        // our X25519 IK public key, base64
let wrappingKey    = null;        // AES-GCM key derived from password — in memory only, never stored
let ws             = null;        // WebSocket connection (null when not connected)
let wsReconnectTimer = null;      // setTimeout handle for reconnect backoff
const contacts     = new Map();   // username → KeyBundleResponse (session cache only)
const sessions     = new Map();   // username → session object (mirrors IndexedDB)
const seenMessageIds = new Set(); // prevents re-processing fetched messages
let activeRecipient = null;
let inboxPoller     = null;

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  try {
    currentUser = await apiFetch("/auth/me");

    const ikBlob = await loadPrivateKey("x25519");
    if (ikBlob instanceof CryptoKey) {
      // Old-format non-extractable key — usable directly.
      myPrivateKey = ikBlob;
      mySigningKey = await loadPrivateKey("ed25519");
      myPublicKeyB64 = await loadPrivateKey("my_ik_pub_b64");
      showApp();
      startInboxPoller();
    } else {
      // Wrapped or missing — need password to unwrap; show login.
      showAuth();
    }
  } catch {
    showAuth();
  }

  attachEventListeners();
});

// Handle bfcache restore — browser may show a frozen snapshot on back-nav
// without re-running DOMContentLoaded. Re-check session state and clear forms.
window.addEventListener("pageshow", (e) => {
  if (e.persisted) {
    disconnectWebSocket();
    showAuth();
  }
});

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function setFieldError(inputId, errorId, message) {
  const input = document.getElementById(inputId);
  const span  = document.getElementById(errorId);
  if (!input || !span) return;
  span.textContent = message;
  if (message) input.classList.add("invalid");
  else         input.classList.remove("invalid");
}

function clearFormError(errorId) {
  const el = document.getElementById(errorId);
  if (el) el.textContent = "";
}

function setFormError(errorId, message) {
  const el = document.getElementById(errorId);
  if (el) el.textContent = message;
}

function validateLoginFields() {
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  let valid = true;

  if (!username) {
    setFieldError("login-username", "login-username-error", "Username is required.");
    valid = false;
  } else {
    setFieldError("login-username", "login-username-error", "");
  }

  if (!password) {
    setFieldError("login-password", "login-password-error", "Password is required.");
    valid = false;
  } else {
    setFieldError("login-password", "login-password-error", "");
  }

  return valid;
}

function validateRegisterFields() {
  const username = document.getElementById("reg-username").value.trim();
  const email    = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  let valid = true;

  if (!USERNAME_RE.test(username)) {
    setFieldError("reg-username", "reg-username-error", "3–20 chars, letters/numbers/underscore only.");
    valid = false;
  } else {
    setFieldError("reg-username", "reg-username-error", "");
  }

  if (!EMAIL_RE.test(email)) {
    setFieldError("reg-email", "reg-email-error", "Enter a valid email address.");
    valid = false;
  } else {
    setFieldError("reg-email", "reg-email-error", "");
  }

  if (password.length < 12) {
    setFieldError("reg-password", "reg-password-error", "Password must be at least 12 characters.");
    valid = false;
  } else {
    setFieldError("reg-password", "reg-password-error", "");
  }

  return valid;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

async function register() {
  clearFormError("reg-form-error");
  if (!validateRegisterFields()) return;

  const username = document.getElementById("reg-username").value.trim();
  const email    = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;

  try {
    // Generate long-term keypairs — private keys never leave the browser.
    const { publicKey: x25519Pub, privateKey: x25519Priv } = await generateKeyPair();
    const { publicKey: ed25519Pub, privateKey: ed25519Priv } = await generateSigningPair();

    const x25519PubB64  = await exportPublicKey(x25519Pub);
    const ed25519PubB64 = await exportPublicKey(ed25519Pub);

    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        email,
        password,
        x25519_public_key:  x25519PubB64,
        ed25519_public_key: ed25519PubB64,
        client_type:        "web",
      }),
    });

    // Generate SPK.
    const spkKP = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const spkPubB64   = await exportPublicKey(spkKP.publicKey);
    const spkPubBytes = Uint8Array.from(atob(spkPubB64), c => c.charCodeAt(0));
    const spkSigB64   = await signMessage(spkPubBytes.buffer, ed25519Priv);

    // Login first so the auth cookie is set before uploading prekeys.
    const regBtn = document.getElementById("btn-register");
    if (regBtn) regBtn.textContent = "Generating keys…";
    currentUser = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, client_type: "web" }),
    });

    // Derive wrapping key from password (PBKDF2 600k → HKDF → AES-GCM).
    const wrapSalt = crypto.getRandomValues(new Uint8Array(16));
    wrappingKey    = await deriveWrappingKey(password, wrapSalt);

    // Wrap all private keys and store encrypted blobs + salt.
    await storePrivateKey("wrap_salt",     wrapSalt);
    await storePrivateKey("x25519",        await wrapPrivateKey(x25519Priv,      wrappingKey));
    await storePrivateKey("ed25519",       await wrapPrivateKey(ed25519Priv,     wrappingKey));
    await storePrivateKey("spk",           await wrapPrivateKey(spkKP.privateKey, wrappingKey));
    await storePrivateKey("my_ik_pub_b64", x25519PubB64);
    await storePrivateKey("spk_pub_b64",   spkPubB64);
    await storePrivateKey("spk_created_at", Date.now());

    // Generate 10 OPKs with wrapping.
    const opks  = await generateOPKs(10, wrappingKey);
    const keyId = Math.floor(Date.now() / 1000);

    await apiFetch("/auth/prekeys", {
      method: "POST",
      body: JSON.stringify({
        signed_prekey: {
          key_id:     keyId,
          public_key: spkPubB64,
          signature:  spkSigB64,
        },
        one_time_prekeys: await Promise.all(
          opks.map(async (kp, i) => ({
            key_id:     keyId * 100 + i,
            public_key: await exportPublicKey(kp.publicKey),
          })),
        ),
      }),
    });

    myPrivateKey   = x25519Priv;
    mySigningKey   = ed25519Priv;
    myPublicKeyB64 = x25519PubB64;
    if (regBtn) regBtn.textContent = "Register & Generate Keys";
    showApp();
    startInboxPoller();
  } catch (err) {
    setFormError("reg-form-error", err.message);
  }
}

async function login() {
  clearFormError("login-form-error");
  if (!validateLoginFields()) return;

  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;

  const loginBtn = document.getElementById("btn-login");
  try {
    currentUser = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, client_type: "web" }),
    });

    const ikBlob = await loadPrivateKey("x25519");
    if (ikBlob instanceof CryptoKey) {
      // Old-format (pre-wrapping) keys — use directly and show migration notice.
      myPrivateKey = ikBlob;
      mySigningKey = await loadPrivateKey("ed25519");
      showMigrationNotice();
    } else if (ikBlob?.wrapped) {
      // New-format wrapped keys — derive the wrapping key then unwrap.
      const salt = await loadPrivateKey("wrap_salt");
      if (!salt) throw new Error("Corrupt key store — please re-register.");
      if (loginBtn) loginBtn.textContent = "Unlocking keys…";
      wrappingKey  = await deriveWrappingKey(password, salt);
      const sigBlob = await loadPrivateKey("ed25519");
      myPrivateKey  = await unwrapPrivateKey(ikBlob.ciphertext, ikBlob.nonce, wrappingKey, { name: "X25519" }, ["deriveKey", "deriveBits"], true);
      mySigningKey  = await unwrapPrivateKey(sigBlob.ciphertext, sigBlob.nonce, wrappingKey, { name: "Ed25519" }, ["sign"], true);
    } else {
      throw new Error("No keys found — please register.");
    }

    myPublicKeyB64 = await loadPrivateKey("my_ik_pub_b64");
    showApp();
    startInboxPoller();
    maybeReplenishPrekeys().catch(err => console.error("prekey replenishment failed:", err));
  } catch (err) {
    setFormError("login-form-error", err.message);
  } finally {
    if (loginBtn) loginBtn.textContent = "Login";
  }
}

function showMigrationNotice() {
  const banner = document.createElement("div");
  banner.style.cssText = "position:fixed;top:0;left:0;right:0;background:#92400e;color:#fff;padding:12px 20px;font-size:14px;z-index:9999;text-align:center;";
  banner.textContent = "Your keys were stored without encryption. Re-register to enable at-rest key protection.";
  const btn = document.createElement("button");
  btn.textContent = "Dismiss";
  btn.style.cssText = "margin-left:16px;padding:3px 12px;font-size:13px;cursor:pointer;";
  btn.onclick = () => banner.remove();
  banner.appendChild(btn);
  document.body.prepend(banner);
}

async function logout() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } finally {
    currentUser    = null;
    myPrivateKey   = null;
    mySigningKey   = null;
    myPublicKeyB64 = null;
    wrappingKey    = null;
    disconnectWebSocket();
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

  const pin   = await getPin(username);
  const isNew = pin === null;
  if (isNew) {
    await storePin(username, fingerprint);
  } else if (pin.ikFingerprint !== fingerprint) {
    showKeyChangeWarning(username);
    throw new Error(`TOFU violation: key changed for ${username}`);
  }
  contacts.set(username, bundle);
  addContactToSidebar(username, fingerprint, isNew);
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

// ---------------------------------------------------------------------------
// Inbox polling
// ---------------------------------------------------------------------------

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
          const { SK } = await x3dhReceive(myPrivateKey, msg.x3dh_header, wrappingKey);
          session = await initSessionAsReceiver(SK, msg.x3dh_header.ik_a, myPublicKeyB64, wrappingKey);
        }

        if (!session) {
          console.warn("fetchInbox: no session for", sender, "— skipping");
          continue;
        }

        const plaintext = await ratchetDecrypt(
          session,
          { ciphertext: msg.ciphertext, nonce: msg.nonce, ratchet_pub: msg.ratchet_pub, pn: msg.pn, n: msg.n },
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
// Blockchain verification
// ---------------------------------------------------------------------------

async function verifyBlockchain(username) {
  const bundle = contacts.get(username);
  if (!bundle?.user_id) {
    const panel = document.getElementById("verify-result-panel");
    if (panel) { panel.textContent = "Re-add this contact to enable verification."; panel.style.display = "block"; }
    return;
  }

  const ids    = [currentUser.id, bundle.user_id].sort();
  const convId = ids[0] + "_" + ids[1];
  const panel  = document.getElementById("verify-result-panel");
  if (panel) { panel.textContent = "Verifying…"; panel.style.display = "block"; }

  try {
    const res = await fetch(`${API_BASE.replace("/api", "")}/public/verify/${encodeURIComponent(convId)}`, { credentials: "include" });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      if (panel) panel.textContent = "Verify failed: " + (err.detail || `HTTP ${res.status}`);
      return;
    }
    const data = await res.json();
    if (!panel) return;
    if (data.verified) {
      const ts = data.timestamp ? new Date(data.timestamp * 1000).toLocaleString() : "";
      // Validate URL scheme before injecting into href — escapeHtml does not strip javascript: URIs.
      const safeUrl = /^https:\/\//.test(data.etherscan_url ?? "") ? data.etherscan_url : "#";
      panel.innerHTML = `<span style="color:#34d399">&#10003; Chain verified</span> — digest matches on-chain record${ts ? " @ " + escapeHtml(ts) : ""}. ` +
        `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer" style="color:#818cf8">Etherscan</a>`;
    } else {
      panel.innerHTML = `<span style="color:#ef4444">&#10007; Mismatch</span> — on-chain: <code>${escapeHtml((data.on_chain_digest || "").slice(0, 18))}…</code> ` +
        `local: <code>${escapeHtml((data.local_digest || "").slice(0, 18))}…</code>`;
    }
  } catch (err) {
    if (panel) panel.textContent = "Verify error: " + err.message;
  }
}

// ---------------------------------------------------------------------------
// WebSocket — real-time delivery + heartbeat cover traffic
// ---------------------------------------------------------------------------

function connectWebSocket() {
  if (ws && ws.readyState <= WebSocket.OPEN) return;

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.addEventListener("open", () => {
    stopInboxPoller(); // WS handles real-time; keep polling as fallback on close
  });

  ws.addEventListener("message", (event) => {
    try {
      const frame = JSON.parse(event.data);
      if (frame.type === "new_message") {
        fetchInbox();
      }
      // heartbeat and unknown frame types are silently discarded
    } catch {
      // non-JSON frame — ignore
    }
  });

  ws.addEventListener("close", () => {
    ws = null;
    startInboxPoller(); // resume polling as fallback
    if (currentUser) {
      wsReconnectTimer = setTimeout(connectWebSocket, 5000);
    }
  });

  ws.addEventListener("error", () => {
    // error always followed by close — handled there
  });
}

function disconnectWebSocket() {
  clearTimeout(wsReconnectTimer);
  if (ws) { ws.close(); ws = null; }
}

// ---------------------------------------------------------------------------
// SPK rotation + OPK replenishment
// ---------------------------------------------------------------------------

const OPK_LOW_WATERMARK = 5;
const OPK_BATCH_SIZE    = 10;
const SPK_ROTATION_MS   = 7 * 24 * 60 * 60 * 1000; // 7 days

async function maybeReplenishPrekeys() {
  if (!wrappingKey) return; // old-format session — migration notice guides user to re-register

  const { opk_count } = await apiFetch("/auth/prekeys/count");
  const spkCreatedAt   = await loadPrivateKey("spk_created_at");
  const spkAgeMs       = spkCreatedAt != null ? Date.now() - spkCreatedAt : Infinity;

  if (spkAgeMs > SPK_ROTATION_MS) {
    await _rotateSpkAndTopUpOpks();
  } else if (opk_count < OPK_LOW_WATERMARK) {
    await _topUpOpks();
  }
}

async function _rotateSpkAndTopUpOpks() {
  const spkKP       = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const spkPubB64   = await exportPublicKey(spkKP.publicKey);
  const spkPubBytes = Uint8Array.from(atob(spkPubB64), c => c.charCodeAt(0));
  const spkSigB64   = await signMessage(spkPubBytes.buffer, mySigningKey);
  const opks        = await generateOPKs(OPK_BATCH_SIZE, wrappingKey);
  const keyId       = Math.floor(Date.now() / 1000);

  await storePrivateKey("spk",           await wrapPrivateKey(spkKP.privateKey, wrappingKey));
  await storePrivateKey("spk_pub_b64",   spkPubB64);
  await storePrivateKey("spk_created_at", Date.now());

  await apiFetch("/auth/prekeys", {
    method: "POST",
    body: JSON.stringify({
      signed_prekey:    { key_id: keyId, public_key: spkPubB64, signature: spkSigB64 },
      one_time_prekeys: await Promise.all(
        opks.map(async (kp, i) => ({
          key_id:     keyId * 100 + i,
          public_key: await exportPublicKey(kp.publicKey),
        }))
      ),
    }),
  });
}

async function _topUpOpks() {
  const opks  = await generateOPKs(OPK_BATCH_SIZE, wrappingKey);
  const keyId = Math.floor(Date.now() / 1000);

  await apiFetch("/auth/opks", {
    method: "POST",
    body: JSON.stringify({
      one_time_prekeys: await Promise.all(
        opks.map(async (kp, i) => ({
          key_id:     keyId * 100 + i,
          public_key: await exportPublicKey(kp.publicKey),
        }))
      ),
    }),
  });
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

  // Clear all credential fields so they are never visible after logout/back-nav.
  ["login-username", "login-password",
   "reg-username", "reg-email", "reg-password"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = "";
  });

  // Always land on the login form, not the register form.
  const loginForm    = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  if (loginForm)    loginForm.style.display    = "block";
  if (registerForm) registerForm.style.display = "none";
}

function showApp() {
  document.getElementById("auth-section").style.display = "none";
  document.getElementById("app-section").style.display  = "flex";
  connectWebSocket();
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
  document.getElementById("btn-login")?.addEventListener("click", login);
  document.getElementById("btn-register")?.addEventListener("click", register);
  document.getElementById("btn-logout")?.addEventListener("click", logout);
  document.getElementById("btn-send")?.addEventListener("click", sendMessage);

  // Auth form tab navigation
  document.getElementById("show-register")?.addEventListener("click", () => {
    document.getElementById("login-form").style.display    = "none";
    document.getElementById("register-form").style.display = "block";
  });
  document.getElementById("show-login")?.addEventListener("click", () => {
    document.getElementById("register-form").style.display = "none";
    document.getElementById("login-form").style.display    = "block";
  });

  // Clear field errors as the user types
  [
    ["login-username", "login-username-error"],
    ["login-password", "login-password-error"],
    ["reg-username",   "reg-username-error"],
    ["reg-email",      "reg-email-error"],
    ["reg-password",   "reg-password-error"],
  ].forEach(([inputId, errorId]) => {
    document.getElementById(inputId)?.addEventListener("input", () =>
      setFieldError(inputId, errorId, "")
    );
  });

  document.getElementById("btn-add-contact")?.addEventListener("click", async () => {
    const input    = document.getElementById("new-contact");
    const username = input.value.trim();
    if (!username) return;
    try {
      await fetchContactKeybundle(username); // also calls addContactToSidebar internally
      input.value = "";
    } catch (err) {
      alert(err.message);
    }
  });

  document.getElementById("btn-verify-chain")?.addEventListener("click", () => {
    if (activeRecipient) verifyBlockchain(activeRecipient);
  });

  // Allow Send on Enter (Shift+Enter for newline).
  document.getElementById("plaintext-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
}

function addContactToSidebar(username, fingerprintHex, isNew) {
  const list = document.getElementById("contact-list");
  if (!list) return;

  // If already in the list, update the fingerprint display and return.
  const existing = list.querySelector(`[data-username="${CSS.escape(username)}"]`);
  if (existing) {
    _updateContactFp(existing, fingerprintHex, isNew);
    return;
  }

  const li = document.createElement("li");
  li.dataset.username = username;
  li.style.cursor     = "pointer";

  const nameSpan = document.createElement("span");
  nameSpan.textContent = username;
  li.appendChild(nameSpan);

  if (fingerprintHex) _updateContactFp(li, fingerprintHex, isNew);

  li.addEventListener("click", () => {
    activeRecipient = username;
    document.getElementById("chat-recipient").textContent = username;
    document.getElementById("message-list").innerHTML = "";
    document.getElementById("verify-result-panel").style.display = "none";

    // Show fingerprint + verify button in chat header.
    const bundle = contacts.get(username);
    const fp = document.getElementById("chat-fp");
    if (fp && fingerprintHex) {
      fp.textContent = "Key: " + _formatFp(fingerprintHex);
    } else if (fp) {
      fp.textContent = "";
    }
    const verifyBtn = document.getElementById("btn-verify-chain");
    if (verifyBtn) verifyBtn.style.display = bundle?.user_id ? "inline-block" : "none";
  });

  list.appendChild(li);
}

function _formatFp(hex) {
  return hex.match(/.{1,8}/g).join(" ");
}

function _updateContactFp(li, fingerprintHex, isNew) {
  let fpEl = li.querySelector(".contact-fp");
  if (!fpEl) {
    fpEl = document.createElement("div");
    fpEl.className = "contact-fp";
    li.appendChild(fpEl);
  }
  const badgeClass = isNew ? "fp-new" : "fp-pinned";
  const badgeText  = isNew ? " ⚠ new" : " ✓";
  fpEl.innerHTML = escapeHtml(_formatFp(fingerprintHex)) +
    `<span class="${badgeClass}">${badgeText}</span>`;
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

  if (res.status === 204) return null;
  return res.json();
}
