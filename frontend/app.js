/**
 * app.js — Alphra web client
 *
 * Auth:  httpOnly JWT cookie (set by server on login) + double-submit CSRF token.
 *        All requests use credentials:'include' so the cookie is sent automatically.
 *        State-changing requests (POST/PUT/DELETE) echo the readable csrf_token
 *        cookie in the X-CSRF-Token header.
 *
 * Crypto: X3DH key agreement + Double Ratchet, implemented in crypto.js using
 *         only the Web Crypto API. Private keys are AES-256-GCM encrypted at rest
 *         in IndexedDB under keys derived from the user's password via PBKDF2→HKDF.
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
  deriveStorageKeys,
  wrapPrivateKey,
  unwrapPrivateKey,
  saveMessage,
  loadMessages,
  loadAllMessageIds,
} from "./crypto.js";

// Derive API base from the serving origin so the same build works on
// localhost:8000 (dev) and https://cryptmunks.theburkenator.com (prod).
// Set window.SECUREMSG_API_BASE before this script loads to override.
const API_BASE         = (window.SECUREMSG_API_BASE ?? window.location.origin) + "/api";
const POLL_INTERVAL_MS = 5000;
// Mirrors C++ client kPageSize — messages shown per contact on initial load;
// "Load older messages" reveals one more page per click.
const PAGE_SIZE        = 30;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

let currentUser    = null;  // { id, username }
let myPrivateKey   = null;  // X25519 CryptoKey — our identity private key
let mySigningKey   = null;  // Ed25519 CryptoKey — our signing private key
let myPublicKeyB64 = null;  // base64 X25519 IK public key (our own)
let wrappingKey    = null;  // AES-GCM key for wrapping CryptoKey objects; never persisted
let storageKey     = null;  // AES-GCM key for encrypting sessions + message history; never persisted
let ws             = null;  // WebSocket connection
let wsReconnectTimer = null;

const contacts       = new Map(); // username → KeyBundleResponse
const sessions       = new Map(); // username → Double Ratchet session
const messageCache   = new Map(); // convId   → [{ id, sender, plaintext, timestamp, blockchain_confirmed }]
const renderLimits   = new Map(); // username → number of messages to render
const seenMessageIds = new Set(); // server message IDs already processed this session

let activeRecipient = null;
let inboxPoller     = null;
let confirmPoller   = null;

// Message IDs rendered with ⏳ that haven't been confirmed on-chain yet.
const pendingConfirmations = new Set();

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  // Show "Account created" banner when redirected from register page.
  if (new URLSearchParams(location.search).get("registered") === "true") {
    const banner = document.getElementById("registered-banner");
    if (banner) banner.style.display = "block";
  }

  try {
    currentUser = await apiFetch("/auth/me");

    const storedIK = await loadPrivateKey("x25519");
    if (storedIK instanceof CryptoKey) {
      // Pre-wrapping session — keys are non-extractable CryptoKeys. Usable
      // directly but not encrypted at rest. Migration notice prompts re-register.
      myPrivateKey   = storedIK;
      mySigningKey   = await loadPrivateKey("ed25519");
      myPublicKeyB64 = await loadPrivateKey("my_ik_pub_b64");
      await _populateSeenIds();
      showApp();
      startInboxPoller();
    } else {
      // Wrapped keys — password needed to unwrap. Show login.
      showAuth();
    }
  } catch {
    showAuth();
  }

  attachEventListeners();
});

// Handle bfcache restore — the browser may show a frozen snapshot on back-nav
// without re-running DOMContentLoaded. Force re-authentication.
window.addEventListener("pageshow", (e) => {
  if (e.persisted) {
    disconnectWebSocket();
    showAuth();
  }
});

// Pre-populate seenMessageIds from IndexedDB so fetchInbox never tries to
// re-decrypt messages whose ratchet keys have already been consumed.
async function _populateSeenIds() {
  try {
    const ids = await loadAllMessageIds();
    ids.forEach(id => seenMessageIds.add(String(id)));
  } catch (err) {
    console.warn("_populateSeenIds: could not load message IDs", err);
  }
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

const USERNAME_RE = /^[a-zA-Z0-9_]{3,20}$/;
const EMAIL_RE    = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function setFieldError(inputId, errorId, message) {
  const input = document.getElementById(inputId);
  const span  = document.getElementById(errorId);
  if (!input || !span) return;
  span.textContent = message;
  input.classList.toggle("invalid", !!message);
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
  const username = document.getElementById("reg-username")?.value.trim() ?? "";
  const email    = document.getElementById("reg-email")?.value.trim()    ?? "";
  const password = document.getElementById("reg-password")?.value        ?? "";
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

  const username = document.getElementById("reg-username")?.value.trim();
  const email    = document.getElementById("reg-email")?.value.trim();
  const password = document.getElementById("reg-password")?.value;

  const registerBtn = document.getElementById("btn-register");
  try {
    const ikKeypair      = await generateKeyPair();
    const signingKeypair = await generateSigningPair();
    const ikPubB64       = await exportPublicKey(ikKeypair.publicKey);
    const signingPubB64  = await exportPublicKey(signingKeypair.publicKey);

    await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username,
        email,
        password,
        x25519_public_key:  ikPubB64,
        ed25519_public_key: signingPubB64,
        client_type:        "web",
      }),
    });

    // Generate the signed prekey (SPK).
    const spkKeypair  = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const spkPubB64   = await exportPublicKey(spkKeypair.publicKey);
    const spkPubBytes = Uint8Array.from(atob(spkPubB64), c => c.charCodeAt(0));
    const spkSigB64   = await signMessage(spkPubBytes.buffer, signingKeypair.privateKey);

    // Login to get the auth cookie before uploading prekeys (prekeys require auth).
    if (registerBtn) registerBtn.textContent = "Generating keys…";
    currentUser = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, client_type: "web" }),
    });

    // Derive both storage keys in a single PBKDF2 pass.
    const keySalt = crypto.getRandomValues(new Uint8Array(16));
    ({ wrappingKey, storageKey } = await deriveStorageKeys(password, keySalt));

    // Wrap all private keys before persisting to IndexedDB.
    await storePrivateKey("wrap_salt",      keySalt);
    await storePrivateKey("x25519",         await wrapPrivateKey(ikKeypair.privateKey,      wrappingKey));
    await storePrivateKey("ed25519",        await wrapPrivateKey(signingKeypair.privateKey, wrappingKey));
    await storePrivateKey("spk",            await wrapPrivateKey(spkKeypair.privateKey,      wrappingKey));
    await storePrivateKey("my_ik_pub_b64",  ikPubB64);
    await storePrivateKey("spk_pub_b64",    spkPubB64);
    await storePrivateKey("spk_created_at", Date.now());

    const opks  = await generateOPKs(10, wrappingKey);
    const keyId = Math.floor(Date.now() / 1000);

    await apiFetch("/auth/prekeys", {
      method: "POST",
      body: JSON.stringify({
        signed_prekey:    { key_id: keyId, public_key: spkPubB64, signature: spkSigB64 },
        one_time_prekeys: await Promise.all(
          opks.map(async (kp, i) => ({ key_id: keyId * 100 + i, public_key: await exportPublicKey(kp.publicKey) })),
        ),
      }),
    });

    myPrivateKey   = ikKeypair.privateKey;
    mySigningKey   = signingKeypair.privateKey;
    myPublicKeyB64 = ikPubB64;
    if (registerBtn) registerBtn.textContent = "Register & Generate Keys";
    showApp();
    await _populateSeenIds();
    startInboxPoller();
  } catch (err) {
    setFormError("reg-form-error", err.message);
    if (registerBtn) registerBtn.textContent = "Register & Generate Keys";
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

    const storedIK = await loadPrivateKey("x25519");
    if (storedIK instanceof CryptoKey) {
      // Pre-wrapping session — use keys directly and show a migration notice.
      myPrivateKey = storedIK;
      mySigningKey = await loadPrivateKey("ed25519");
      showMigrationNotice();
    } else if (storedIK?.wrapped) {
      const keySalt = await loadPrivateKey("wrap_salt");
      if (!keySalt) throw new Error("Corrupt key store — please re-register.");

      if (loginBtn) loginBtn.textContent = "Unlocking keys…";
      ({ wrappingKey, storageKey } = await deriveStorageKeys(password, keySalt));

      const storedSigningKey = await loadPrivateKey("ed25519");
      myPrivateKey = await unwrapPrivateKey(storedIK.ciphertext,        storedIK.nonce,        wrappingKey, { name: "X25519" },  ["deriveKey", "deriveBits"], true);
      mySigningKey = await unwrapPrivateKey(storedSigningKey.ciphertext, storedSigningKey.nonce, wrappingKey, { name: "Ed25519" }, ["sign"], true);
    } else {
      throw new Error("No keys found — please register.");
    }

    myPublicKeyB64 = await loadPrivateKey("my_ik_pub_b64");
    showApp();
    await _populateSeenIds();
    startInboxPoller();
    maybeReplenishPrekeys().catch(err => console.error("prekey replenishment failed:", err));
  } catch (err) {
    setFormError("login-form-error", err.message);
  } finally {
    if (loginBtn) loginBtn.textContent = "Enter";
  }
}

function showMigrationNotice() {
  const banner = document.createElement("div");
  banner.style.cssText = "position:fixed;top:0;left:0;right:0;background:#92400e;color:#fff;padding:12px 20px;font-size:14px;z-index:9999;text-align:center;";
  banner.textContent = "Your keys were stored without encryption. Re-register to enable at-rest key protection.";
  const btn = document.createElement("button");
  btn.textContent  = "Dismiss";
  btn.style.cssText = "margin-left:16px;padding:3px 12px;font-size:13px;cursor:pointer;";
  btn.onclick = () => banner.remove();
  banner.appendChild(btn);
  document.body.prepend(banner);
}

async function logout() {
  try {
    await apiFetch("/auth/logout", { method: "POST" });
  } finally {
    // Clear all session state so a subsequent login as a different user starts clean.
    currentUser    = null;
    myPrivateKey   = null;
    mySigningKey   = null;
    myPublicKeyB64 = null;
    wrappingKey    = null;
    storageKey     = null;
    activeRecipient = null;
    contacts.clear();
    sessions.clear();
    messageCache.clear();
    renderLimits.clear();
    seenMessageIds.clear();
    disconnectWebSocket();
    stopInboxPoller();
    showAuth();
  }
}

// ---------------------------------------------------------------------------
// TOFU key pinning
// ---------------------------------------------------------------------------

const TOFU_DB_NAME    = "tofu-store";
const TOFU_STORE_NAME = "pins";
// v2: scoped composite keys ("ownerUsername:contactUsername") prevent cross-account
// pin reuse on a shared device. v1 records are cleared on upgrade.
const TOFU_DB_VERSION = 2;

function openTofuDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(TOFU_DB_NAME, TOFU_DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      if (e.oldVersion < 2) {
        if (db.objectStoreNames.contains(TOFU_STORE_NAME)) {
          db.deleteObjectStore(TOFU_STORE_NAME);
        }
        db.createObjectStore(TOFU_STORE_NAME);
      }
    };
    req.onsuccess = (e) => resolve(e.target.result);
    req.onerror   = (e) => reject(e.target.error);
  });
}

function _tofuKey(contactUsername) {
  return `${currentUser.username}:${contactUsername}`;
}

async function getPin(contactUsername) {
  const db = await openTofuDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(TOFU_STORE_NAME).objectStore(TOFU_STORE_NAME).get(_tofuKey(contactUsername));
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror   = () => reject(req.error);
  });
}

async function storePin(contactUsername, fingerprint) {
  const db = await openTofuDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(TOFU_STORE_NAME, "readwrite");
    tx.objectStore(TOFU_STORE_NAME).put({ fingerprint, pinnedAt: new Date().toISOString() }, _tofuKey(contactUsername));
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
    "position:fixed", "top:0", "left:0", "right:0",
    "background:#c0392b", "color:#fff", "padding:16px 24px",
    "font-size:15px", "font-weight:bold", "z-index:9999", "text-align:center",
  ].join(";");
  banner.textContent = `⚠ Security warning: key changed for ${username}. Possible MITM attack. Contact blocked.`;
  const dismissBtn = document.createElement("button");
  dismissBtn.textContent = "Dismiss";
  dismissBtn.style.cssText = "margin-left:20px;padding:4px 14px;font-size:14px;cursor:pointer;";
  dismissBtn.onclick = () => banner.remove();
  banner.appendChild(dismissBtn);
  document.body.prepend(banner);
}

// Fetch a contact's key bundle and enforce TOFU pinning.
// First contact: pin the fingerprint. Subsequent: compare — mismatch blocks.
async function fetchContactKeybundle(username) {
  const bundle      = await apiFetch(`/auth/user/${username}/keybundle`);
  const fingerprint = await computeFingerprint(bundle.ik_x25519);
  const pin         = await getPin(username);
  const isFirstContact = pin === null;

  if (isFirstContact) {
    await storePin(username, fingerprint);
  } else if (pin.fingerprint !== fingerprint) {
    showKeyChangeWarning(username);
    throw new Error(`TOFU violation: key changed for ${username}`);
  }

  contacts.set(username, bundle);
  addContactToSidebar(username, fingerprint, isFirstContact);
  return bundle;
}

// ---------------------------------------------------------------------------
// Conversation ID helpers
// ---------------------------------------------------------------------------

// Local conversation ID — username pair sorted alphabetically.
function localConvId(usernameA, usernameB) {
  return [usernameA, usernameB].sort().join(":");
}

// Server-side conversation ID — UUID pair sorted lexicographically.
function serverConvId(uuid1, uuid2) {
  return [uuid1, uuid2].sort().join("_");
}

// ---------------------------------------------------------------------------
// Message persistence
// ---------------------------------------------------------------------------

// Encrypt and persist a message, keep the in-memory cache live.
// Silent no-op if storageKey is null (pre-wrapping session).
async function persistMessage(sender, recipient, plaintext, msgId, timestamp, blockchainConfirmed = false) {
  const convId = localConvId(sender, recipient);
  const entry  = {
    id:                   String(msgId),
    sender,
    plaintext,
    timestamp:            timestamp ?? Date.now(),
    blockchain_confirmed: blockchainConfirmed,
  };

  // Always keep the in-memory cache live, even without a storageKey.
  if (!messageCache.has(convId)) messageCache.set(convId, []);
  const msgs = messageCache.get(convId);
  if (!msgs.find(m => m.id === entry.id)) {
    msgs.push(entry);
    msgs.sort((a, b) => a.timestamp - b.timestamp);
  }

  if (!storageKey) return;
  try {
    await saveMessage(convId, entry, storageKey);
  } catch (err) {
    console.warn("persistMessage: storage failed", err);
  }
}

// ---------------------------------------------------------------------------
// Thread rendering
// ---------------------------------------------------------------------------

// Re-render the message list from the in-memory cache, showing only the last
// renderLimits[username] messages (default PAGE_SIZE).
function renderThread(username) {
  const list = document.getElementById("message-list");
  if (!list) return;
  list.innerHTML = "";

  const convId = localConvId(currentUser?.username ?? "", username);
  const all    = messageCache.get(convId) ?? [];
  const limit  = renderLimits.get(username) ?? PAGE_SIZE;
  const start  = Math.max(0, all.length - limit);

  for (let i = start; i < all.length; i++) {
    _appendBubble(list, all[i].sender, all[i].plaintext, {
      timestamp:            all[i].timestamp,
      blockchain_confirmed: all[i].blockchain_confirmed ?? false,
      id:                   all[i].id,
    });
  }

  const loadOlderBtn = document.getElementById("btn-load-older");
  if (loadOlderBtn) loadOlderBtn.style.display = start > 0 ? "flex" : "none";

  const wrapper = document.getElementById("messages-wrapper");
  if (wrapper) wrapper.scrollTop = wrapper.scrollHeight;
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
    let session = sessions.get(activeRecipient) ?? await loadSession(activeRecipient, storageKey);

    if (!session) {
      const bundle = contacts.get(activeRecipient) ?? await fetchContactKeybundle(activeRecipient);
      const { SK, ephemeralPubB64, usedOPKPub } = await x3dhSend(myPrivateKey, bundle);

      session = await initSessionAsSender(SK, bundle.spk.public_key, myPublicKeyB64, bundle.ik_x25519);
      session.x3dh_ephemeral_pub = ephemeralPubB64;
      session.x3dh_used_opk_pub  = usedOPKPub;
    }

    const encrypted = await ratchetEncrypt(session, plaintext);

    let x3dhHeader = null;
    if (!session.x3dh_header_sent) {
      x3dhHeader = {
        ik_a:         myPublicKeyB64,
        ek_a:         session.x3dh_ephemeral_pub,
        used_opk_pub: session.x3dh_used_opk_pub,
      };
      session.x3dh_header_sent = true;
    }

    sessions.set(activeRecipient, session);
    await saveSession(activeRecipient, session, storageKey);

    await apiFetch("/messages/send", {
      method: "POST",
      body: JSON.stringify({
        recipient_username: activeRecipient,
        ciphertext:  encrypted.ciphertext_b64,
        nonce:       encrypted.nonce_b64,
        ratchet_pub: encrypted.ratchet_pub_b64,
        pn:          encrypted.pn,
        n:           encrypted.n,
        x3dh_header: x3dhHeader,
      }),
    });

    const sentAt = Date.now();
    const sentId = "sent-" + sentAt + "-" + Math.random().toString(36).slice(2);
    await persistMessage(currentUser.username, activeRecipient, plaintext, sentId, sentAt, false);
    renderThread(activeRecipient);
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
        let session = sessions.get(sender) ?? await loadSession(sender, storageKey);

        if (!session && msg.x3dh_header) {
          // Validate ik_a against any existing TOFU pin before deriving the
          // session — a compromised server could substitute a malicious identity
          // key in the X3DH header to hijack the session silently.
          const existingPin = await getPin(sender);
          if (existingPin !== null) {
            const inboundFingerprint = await computeFingerprint(msg.x3dh_header.ik_a);
            if (inboundFingerprint !== existingPin.fingerprint) {
              console.error("fetchInbox: x3dh_header.ik_a does not match pinned key for", sender);
              showKeyChangeWarning(sender);
              continue;
            }
          }
          const { SK } = await x3dhReceive(myPrivateKey, msg.x3dh_header, wrappingKey);
          session = await initSessionAsReceiver(SK, msg.x3dh_header.ik_a, myPublicKeyB64, wrappingKey);
        }

        if (!session) {
          console.warn("fetchInbox: no session for", sender, "— skipping");
          continue;
        }

        const plaintext = await ratchetDecrypt(session, {
          ciphertext:  msg.ciphertext,
          nonce:       msg.nonce,
          ratchet_pub: msg.ratchet_pub,
          pn:          msg.pn,
          n:           msg.n,
        });

        sessions.set(sender, session);
        await saveSession(sender, session, storageKey);

        const receivedAt = msg.created_at ? Date.parse(msg.created_at) || Date.now() : Date.now();
        await persistMessage(sender, currentUser.username, plaintext, msg.id, receivedAt, msg.blockchain_confirmed ?? false);

        if (sender === activeRecipient) renderThread(sender);
      } catch (err) {
        console.error("fetchInbox: failed to decrypt message from", sender, err);
      }
    }
  } catch (err) {
    console.error("fetchInbox: request failed", err);
  }
}

// ---------------------------------------------------------------------------
// Blockchain verification
// ---------------------------------------------------------------------------

async function verifyBlockchain(username) {
  let bundle = contacts.get(username);
  if (!bundle?.user_id) {
    try {
      bundle = await fetchContactKeybundle(username);
    } catch (err) {
      const panel = document.getElementById("verify-result-panel");
      if (panel) { panel.textContent = "Verify failed: " + err.message; panel.style.display = "block"; }
      return;
    }
  }

  const convId = serverConvId(currentUser.id, bundle.user_id);
  const panel  = document.getElementById("verify-result-panel");
  if (panel) { panel.textContent = "Verifying…"; panel.style.display = "block"; }

  try {
    const res = await fetch(
      `${window.location.origin}/public/verify/${encodeURIComponent(convId)}`,
      { credentials: "include" },
    );
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      if (panel) panel.textContent = "Verify failed: " + (err.detail || `HTTP ${res.status}`);
      return;
    }
    const data = await res.json();
    if (!panel) return;
    if (data.verified) {
      const ts = data.timestamp ? new Date(data.timestamp * 1000).toLocaleString() : "";
      const safeUrl = /^https:\/\//.test(data.etherscan_url ?? "") ? data.etherscan_url : "#";
      panel.innerHTML =
        `<span style="color:#34d399">&#10003; Chain verified</span>` +
        ` — digest matches on-chain record${ts ? " @ " + escapeHtml(ts) : ""}. ` +
        `<a href="${escapeHtml(safeUrl)}" target="_blank" rel="noopener noreferrer" style="color:#818cf8">Etherscan</a>`;
    } else {
      panel.innerHTML =
        `<span style="color:#ef4444">&#10007; Mismatch</span>` +
        ` — on-chain: <code>${escapeHtml((data.on_chain_digest || "").slice(0, 18))}…</code>` +
        ` local: <code>${escapeHtml((data.local_digest || "").slice(0, 18))}…</code>`;
    }
  } catch (err) {
    if (panel) panel.textContent = "Verify error: " + err.message;
  }
}

// ---------------------------------------------------------------------------
// WebSocket — real-time delivery + cover-traffic heartbeats
// ---------------------------------------------------------------------------

function connectWebSocket() {
  if (ws && ws.readyState <= WebSocket.OPEN) return;

  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.addEventListener("open", () => {
    stopInboxPoller(); // WebSocket handles delivery; polling resumes if socket closes
  });

  ws.addEventListener("message", (event) => {
    try {
      const frame = JSON.parse(event.data);
      if (frame.type === "new_message") fetchInbox();
      // heartbeat frames are silently discarded
    } catch {
      // non-JSON frame — ignore
    }
  });

  ws.addEventListener("close", () => {
    ws = null;
    startInboxPoller(); // fall back to polling until reconnect
    if (currentUser) wsReconnectTimer = setTimeout(connectWebSocket, 5000);
  });

  ws.addEventListener("error", () => {
    // error is always followed by close — handled above
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
  if (!wrappingKey) return; // pre-wrapping session — migration notice handles this

  const { opk_count } = await apiFetch("/auth/prekeys/count");
  const spkCreatedAt  = await loadPrivateKey("spk_created_at");
  const spkAgeMs      = spkCreatedAt != null ? Date.now() - spkCreatedAt : Infinity;

  if (spkAgeMs > SPK_ROTATION_MS) {
    await _rotateSPK();
  } else if (opk_count < OPK_LOW_WATERMARK) {
    await _topUpOPKs();
  }
}

async function _rotateSPK() {
  const spkKeypair  = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const spkPubB64   = await exportPublicKey(spkKeypair.publicKey);
  const spkPubBytes = Uint8Array.from(atob(spkPubB64), c => c.charCodeAt(0));
  const spkSigB64   = await signMessage(spkPubBytes.buffer, mySigningKey);
  const opks        = await generateOPKs(OPK_BATCH_SIZE, wrappingKey);
  const keyId       = Math.floor(Date.now() / 1000);

  await storePrivateKey("spk",            await wrapPrivateKey(spkKeypair.privateKey, wrappingKey));
  await storePrivateKey("spk_pub_b64",    spkPubB64);
  await storePrivateKey("spk_created_at", Date.now());

  await apiFetch("/auth/prekeys", {
    method: "POST",
    body: JSON.stringify({
      signed_prekey:    { key_id: keyId, public_key: spkPubB64, signature: spkSigB64 },
      one_time_prekeys: await Promise.all(
        opks.map(async (kp, i) => ({ key_id: keyId * 100 + i, public_key: await exportPublicKey(kp.publicKey) })),
      ),
    }),
  });
}

async function _topUpOPKs() {
  const opks  = await generateOPKs(OPK_BATCH_SIZE, wrappingKey);
  const keyId = Math.floor(Date.now() / 1000);

  await apiFetch("/auth/opks", {
    method: "POST",
    body: JSON.stringify({
      one_time_prekeys: await Promise.all(
        opks.map(async (kp, i) => ({ key_id: keyId * 100 + i, public_key: await exportPublicKey(kp.publicKey) })),
      ),
    }),
  });
}

// ---------------------------------------------------------------------------
// Inbox poller
// ---------------------------------------------------------------------------

function startInboxPoller() {
  inboxPoller   = setInterval(fetchInbox, POLL_INTERVAL_MS);
  confirmPoller = setInterval(_checkPendingConfirmations, 15_000);
}

function stopInboxPoller() {
  clearInterval(inboxPoller);
  clearInterval(confirmPoller);
  inboxPoller   = null;
  confirmPoller = null;
}

async function _checkPendingConfirmations() {
  if (pendingConfirmations.size === 0) return;
  for (const msgId of [...pendingConfirmations]) {
    try {
      const msg = await apiFetch(`/messages/${msgId}`);
      if (!msg.blockchain_confirmed) continue;

      pendingConfirmations.delete(msgId);

      // Update the badge in every visible bubble with this message ID.
      document.querySelectorAll(`[data-message-id="${CSS.escape(msgId)}"]`).forEach(bubble => {
        const badge = bubble.querySelector(".badge-pending");
        if (badge) {
          badge.className = "badge-verified";
          badge.title     = "Blockchain verified";
          badge.textContent = "✓";
        }
      });

      // Keep in-memory caches in sync so re-renders show ✓ too.
      for (const entries of decryptedCache.values()) {
        const e = entries.find(x => x.meta?.id === msgId);
        if (e) e.meta.blockchain_confirmed = true;
      }
      for (const msgs of messageCache.values()) {
        const m = msgs.find(x => x.id === msgId);
        if (m) m.blockchain_confirmed = true;
      }
    } catch {
      pendingConfirmations.delete(msgId);
    }
  }
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

function showAuth() {
  document.getElementById("auth-section").style.display = "flex";
  document.getElementById("app-section").style.display  = "none";

  // Clear credentials so they are never visible after logout or back-navigation.
  ["login-username", "login-password", "reg-username", "reg-email", "reg-password"]
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ""; });

  // Clear the contact sidebar and chat area so a subsequent login starts clean.
  const contactList = document.getElementById("contact-list");
  if (contactList) contactList.innerHTML = "";
  const messageList = document.getElementById("message-list");
  if (messageList) messageList.innerHTML = "";
  const chatRecipient = document.getElementById("chat-recipient");
  if (chatRecipient) chatRecipient.textContent = "Select a conversation";
  const chatFp = document.getElementById("chat-fp");
  if (chatFp) chatFp.textContent = "";

  // Always land on the login form (no-op when register-form doesn't exist on this page).
  const loginForm    = document.getElementById("login-form");
  const registerForm = document.getElementById("register-form");
  if (loginForm)    loginForm.style.display    = "flex";
  if (registerForm) registerForm.style.display = "none";
}

function showApp() {
  document.getElementById("auth-section").style.display = "none";
  document.getElementById("app-section").style.display  = "flex";
  const display = document.getElementById("my-username-display");
  if (display && currentUser) display.textContent = currentUser.username;
  connectWebSocket();
  _applyBlockchainVisibility();
  _restoreContactList();
}

// Re-populate the sidebar from the TOFU store — every pinned contact is
// someone the user has explicitly added, so it's the right persistence source.
async function _restoreContactList() {
  if (!currentUser) return;
  try {
    const db     = await openTofuDb();
    const prefix = `${currentUser.username}:`;
    const tx     = db.transaction(TOFU_STORE_NAME);
    const store  = tx.objectStore(TOFU_STORE_NAME);

    const allKeys = await new Promise((resolve, reject) => {
      const req = store.getAllKeys();
      req.onsuccess = () => resolve(req.result ?? []);
      req.onerror   = () => reject(req.error);
    });

    const mine = allKeys.filter(k => String(k).startsWith(prefix));

    for (const key of mine) {
      const contactUsername = String(key).slice(prefix.length);
      const record = await new Promise((resolve, reject) => {
        const req = db.transaction(TOFU_STORE_NAME).objectStore(TOFU_STORE_NAME).get(key);
        req.onsuccess = () => resolve(req.result ?? {});
        req.onerror   = () => reject(req.error);
      });
      addContactToSidebar(contactUsername, record.fingerprint ?? null, false);
    }
  } catch (err) {
    console.warn("_restoreContactList:", err);
  }
}

let _blockchainConfigured = false;

async function _applyBlockchainVisibility() {
  try {
    const { configured } = await apiFetch("/blockchain/status");
    _blockchainConfigured = configured;
  } catch {
    _blockchainConfigured = false;
  }
}

// ---------------------------------------------------------------------------
// Bubble rendering
// ---------------------------------------------------------------------------

// Format a millisecond timestamp for display in a message bubble.
// Today → "2:34 PM"; this year → "Jan 15 · 2:34 PM"; older → "Jan 15 2024 · 2:34 PM".
function formatTimestamp(ms) {
  if (!ms) return "";
  const d       = new Date(ms);
  const now     = new Date();
  const timeStr = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  const sameDay = d.getDate()     === now.getDate()  &&
                  d.getMonth()    === now.getMonth()  &&
                  d.getFullYear() === now.getFullYear();
  if (sameDay) return timeStr;

  const dateStr = d.getFullYear() === now.getFullYear()
    ? d.toLocaleDateString([], { month: "short", day: "numeric" })
    : d.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });

  return `${dateStr} · ${timeStr}`;
}

function _appendBubble(list, senderUsername, plaintext, meta = {}) {
  const isMine = senderUsername === currentUser?.username;
  const bubble = document.createElement("div");
  bubble.className = `message-bubble ${isMine ? "sent" : "received"}`;
  if (meta.id) bubble.dataset.messageId = meta.id;

  // Accept either milliseconds (from messageCache) or ISO strings (from API).
  const tsMs    = typeof meta.timestamp === "number"
    ? meta.timestamp
    : (meta.timestamp ? Date.parse(meta.timestamp) : 0);
  const timeStr = formatTimestamp(tsMs);

  const badgeHtml = meta.blockchain_confirmed
    ? '<span class="badge-verified" title="Blockchain verified">✓</span>'
    : (tsMs ? '<span class="badge-pending" title="Pending blockchain confirmation">⏳</span>' : "");

  bubble.innerHTML =
    `<div class="bubble-text">${escapeHtml(plaintext)}</div>` +
    `<div class="bubble-meta">${escapeHtml(timeStr)}${badgeHtml}</div>`;

  list.appendChild(bubble);

  if (meta.id && !meta.blockchain_confirmed && meta.timestamp) {
    pendingConfirmations.add(meta.id);
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

// ---------------------------------------------------------------------------
// Event listeners
// ---------------------------------------------------------------------------

function attachEventListeners() {
  document.getElementById("btn-login")?.addEventListener("click", login);
  document.getElementById("btn-logout")?.addEventListener("click", logout);
  document.getElementById("btn-send")?.addEventListener("click", sendMessage);

  // Clear inline field errors as the user types.
  [
    ["login-username", "login-username-error"],
    ["login-password", "login-password-error"],
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
      await fetchContactKeybundle(username);
      input.value = "";
    } catch (err) {
      alert(err.message);
    }
  });

  // Allow adding a friend by pressing Enter in the new-contact field.
  document.getElementById("new-contact")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); document.getElementById("btn-add-contact")?.click(); }
  });

  // Client-side search: show/hide contact rows as user types.
  document.getElementById("search-conversations")?.addEventListener("input", (e) => {
    const q = e.target.value.trim().toLowerCase();
    document.getElementById("contact-list")?.querySelectorAll("li").forEach(li => {
      li.style.display = (!q || li.dataset.username.toLowerCase().includes(q)) ? "" : "none";
    });
  });

  // Inline blockchain verification.
  document.getElementById("btn-verify-chain")?.addEventListener("click", () => {
    if (activeRecipient) verifyBlockchain(activeRecipient);
  });

  // Load older messages — increases the render window by PAGE_SIZE and scrolls
  // to the top so the user sees the newly revealed messages.
  document.getElementById("btn-load-older")?.addEventListener("click", () => {
    if (!activeRecipient) return;
    renderLimits.set(activeRecipient, (renderLimits.get(activeRecipient) ?? PAGE_SIZE) + PAGE_SIZE);
    renderThread(activeRecipient);
    const msgList = document.getElementById("message-list");
    if (msgList) msgList.scrollTop = 0;
  });

  // Mobile: hamburger toggle for sidebar.
  document.getElementById("menu-toggle")?.addEventListener("click", () => {
    document.getElementById("sidebar")?.classList.toggle("open");
  });

  // Send on Enter (Shift+Enter for newline).
  document.getElementById("plaintext-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
}

// ---------------------------------------------------------------------------
// Contact sidebar
// ---------------------------------------------------------------------------

function addContactToSidebar(username, fingerprintHex, isFirstContact) {
  const list = document.getElementById("contact-list");
  if (!list) return;

  // Update fingerprint badge if contact already exists.
  const existing = list.querySelector(`[data-username="${CSS.escape(username)}"]`);
  if (existing) {
    return; // already shown — fingerprint stored, no UI update needed
  }

  const li = document.createElement("li");
  li.dataset.username = username;
  li.textContent      = username; // clean name only, fingerprint shown in header

  li.addEventListener("click", async () => {
    // Update active state in sidebar.
    list.querySelectorAll("li").forEach(el => el.classList.remove("active"));
    li.classList.add("active");

    activeRecipient = username;
    document.getElementById("chat-recipient").textContent = username;

    // Hide previous verify result.
    const verifyPanel = document.getElementById("verify-result-panel");
    if (verifyPanel) verifyPanel.style.display = "none";

    // Show key fingerprint in header and reveal the inline verify button.
    const chatFp = document.getElementById("chat-fp");
    if (chatFp) chatFp.textContent = fingerprintHex ? _formatFingerprint(fingerprintHex) : "";

    const verifyBtn = document.getElementById("btn-verify-chain");
    if (verifyBtn) verifyBtn.style.display = _blockchainConfigured ? "inline-flex" : "none";

    // Load and render history from encrypted IndexedDB store.
    renderLimits.set(username, PAGE_SIZE);
    if (storageKey && currentUser) {
      try {
        const convId  = localConvId(currentUser.username, username);
        const history = await loadMessages(convId, storageKey);
        messageCache.set(convId, history);
      } catch (err) {
        console.warn("Failed to load message history:", err);
      }
    }
    renderThread(username);

    // On mobile, close sidebar after selecting a conversation.
    document.getElementById("sidebar")?.classList.remove("open");
  });

  list.appendChild(li);
}

function _formatFingerprint(hex) {
  return hex.match(/.{1,8}/g).join(" ");
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

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: "include" });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const detail = err.detail;
    const message = Array.isArray(detail)
      ? detail.map(e => e.msg ?? String(e)).join(", ")
      : (detail || `HTTP ${res.status}`);
    throw new Error(message);
  }

  if (res.status === 204) return null;
  return res.json();
}
