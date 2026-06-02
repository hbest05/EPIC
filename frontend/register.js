/**
 * register.js — standalone registration page controller
 *
 * Reuses the same crypto functions as app.js.
 * On success redirects to /index.html?registered=true rather than auto-logging in,
 * so the login page can show the "Account created" confirmation banner.
 */

import {
  generateKeyPair,
  generateSigningPair,
  exportPublicKey,
  signMessage,
  storePrivateKey,
  generateOPKs,
  deriveStorageKeys,
  wrapPrivateKey,
} from "./crypto.js";

const API_BASE = (window.SECUREMSG_API_BASE ?? window.location.origin) + "/api";

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
    const detail = err.detail;
    const message = Array.isArray(detail)
      ? detail.map(e => e.msg ?? String(e)).join(", ")
      : (detail || `HTTP ${res.status}`);
    throw new Error(message);
  }

  if (res.status === 204) return null;
  const text = await res.text();
  return text ? JSON.parse(text) : null;
}

async function register() {
  const username = document.getElementById("reg-username").value.trim();
  const email    = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  const confirm  = document.getElementById("reg-confirm").value;
  const errorEl  = document.getElementById("reg-password-error");

  if (!username || !email || !password || !confirm) {
    alert("All fields are required.");
    return;
  }

  if (password !== confirm) {
    errorEl.style.display = "block";
    return;
  }
  errorEl.style.display = "none";

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

    // Login immediately after register — sets the httpOnly auth cookie
    // AND the readable csrf_token cookie required by all subsequent POSTs.
    await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, client_type: "web" }),
    });

    // Derive storage keys from password so private keys are encrypted at rest
    // in IndexedDB — same format app.js login() expects to unwrap.
    const keySalt = crypto.getRandomValues(new Uint8Array(16));
    const { wrappingKey } = await deriveStorageKeys(password, keySalt);

    // Wrap and persist all private keys after server confirms.
    await storePrivateKey("wrap_salt",      keySalt);
    await storePrivateKey("x25519",         await wrapPrivateKey(x25519Priv, wrappingKey));
    await storePrivateKey("ed25519",        await wrapPrivateKey(ed25519Priv, wrappingKey));
    await storePrivateKey("my_ik_pub_b64",  x25519PubB64);

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

    await storePrivateKey("spk",            await wrapPrivateKey(spkKP.privateKey, wrappingKey));
    await storePrivateKey("spk_pub_b64",    spkPubB64);
    await storePrivateKey("spk_created_at", Date.now());

    // Generate 10 OPKs with the wrapping key so they're encrypted at rest too.
    const opks = await generateOPKs(10, wrappingKey);

    // Upload prekeys.
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

    window.location.href = "index.html?registered=true";
  } catch (err) {
    alert(err.message);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("btn-register").addEventListener("click", register);

  // Live password-match feedback as user types confirm field.
  document.getElementById("reg-confirm").addEventListener("input", () => {
    const password = document.getElementById("reg-password").value;
    const confirm  = document.getElementById("reg-confirm").value;
    const errorEl  = document.getElementById("reg-password-error");
    errorEl.style.display = (confirm && password !== confirm) ? "block" : "none";
  });
});
