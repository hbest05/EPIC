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
} from "./crypto.js";

const API_BASE = "http://localhost:8000/api";

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

    await storePrivateKey("spk",         spkKP.privateKey);
    await storePrivateKey("spk_pub_b64", spkPubB64);

    // Generate 10 OPKs (private keys stored in IndexedDB by generateOPKs).
    const opks = await generateOPKs(10);

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

    window.location.href = "/index.html?registered=true";
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
