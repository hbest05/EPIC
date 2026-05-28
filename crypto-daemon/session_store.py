"""
session_store.py — at-rest encryption of Double Ratchet session state.

Each session is serialized to JSON, encrypted with AES-256-GCM under the
identity's wrap key, and written to <base>/sessions/<session_id>.json,
where <base> is identity.base_dir() — $SECUREMSG_HOME if set, else
~/.securemsg. Files are reloaded at daemon startup once the identity is unlocked.

OPK private keys live alongside sessions under <base>/opks/<hex_pub>.json
using the same encryption scheme. They are loaded at identity-unlock time
and unlinked the moment they are consumed in x3dh_receive, preserving the
one-time invariant across daemon restarts.

The current Signed Prekey (private + public + signature) is persisted as a
single file at <base>/spk.json, overwritten on each generate_prekeys. Only
the most-recent SPK is recoverable, matching the in-memory semantics.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from identity import base_dir

SESSION_AAD = b"securemsg-session-v1"
OPK_AAD = b"securemsg-opk-v1"
SPK_AAD = b"securemsg-spk-v1"
NONCE_LEN = 12


def sessions_dir() -> Path:
    return base_dir() / "sessions"


def opks_dir() -> Path:
    return base_dir() / "opks"


def _opk_filename(opk_pub_b64: str) -> str:
    """File name = hex of the raw 32-byte public — stable and filesystem-safe."""
    return base64.b64decode(opk_pub_b64, validate=True).hex() + ".json"


def save_session(session, wrap_key: bytes) -> None:
    """Encrypt + persist a Session. Atomic via os.replace."""
    d = sessions_dir()
    d.mkdir(parents=True, exist_ok=True)
    plaintext = json.dumps(session.to_dict()).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(wrap_key).encrypt(nonce, plaintext, SESSION_AAD)
    blob = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    path = d / f"{session.session_id}.json"
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(blob, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_all_sessions(wrap_key: bytes) -> Dict[str, "object"]:
    """Decrypt every session file with the given wrap key. Bad files are skipped."""
    from double_ratchet import Session  # local import to avoid cycle

    out: Dict[str, Session] = {}
    d = sessions_dir()
    if not d.exists():
        return out
    for path in d.glob("*.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            nonce = base64.b64decode(blob["nonce"])
            ct = base64.b64decode(blob["ct"])
            plaintext = AESGCM(wrap_key).decrypt(nonce, ct, SESSION_AAD)
            sess = Session.from_dict(json.loads(plaintext))
            if sess.session_id:
                out[sess.session_id] = sess
        except Exception:
            # Wrong wrap key or corrupt — skip silently; no key material in logs.
            continue
    return out


def save_opk(opk_pub_b64: str, opk_priv: X25519PrivateKey, wrap_key: bytes) -> None:
    """Encrypt + persist a single OPK private key. Atomic via os.replace."""
    from cryptography.hazmat.primitives import serialization

    d = opks_dir()
    d.mkdir(parents=True, exist_ok=True)
    priv_raw = opk_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    plaintext = json.dumps({
        "opk_pub_b64": opk_pub_b64,
        "opk_priv_b64": base64.b64encode(priv_raw).decode("ascii"),
    }).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(wrap_key).encrypt(nonce, plaintext, OPK_AAD)
    blob = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    path = d / _opk_filename(opk_pub_b64)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(blob, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_all_opks(wrap_key: bytes) -> Dict[str, X25519PrivateKey]:
    """Decrypt every OPK file with the given wrap key. Bad files are skipped.

    Returns {opk_pub_b64: X25519PrivateKey} — same shape as state.prekeys["opks"].
    """
    out: Dict[str, X25519PrivateKey] = {}
    d = opks_dir()
    if not d.exists():
        return out
    for path in d.glob("*.json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                blob = json.load(f)
            nonce = base64.b64decode(blob["nonce"])
            ct = base64.b64decode(blob["ct"])
            plaintext = AESGCM(wrap_key).decrypt(nonce, ct, OPK_AAD)
            rec = json.loads(plaintext)
            opk_pub_b64 = rec["opk_pub_b64"]
            priv = X25519PrivateKey.from_private_bytes(base64.b64decode(rec["opk_priv_b64"]))
            out[opk_pub_b64] = priv
        except Exception:
            # Wrong wrap key or corrupt — skip silently; no key material in logs.
            continue
    return out


def load_opk(opk_pub_b64: str, wrap_key: bytes) -> X25519PrivateKey | None:
    """Load and decrypt a single OPK private key by its public b64.

    Returns the X25519PrivateKey, or None if no file exists / wrong wrap key /
    corrupt. The on-disk keystore is the durable source of truth for which
    OPKs remain unconsumed, so this lets x3dh_receive resolve an OPK that is
    on disk but absent from the in-memory cache.
    """
    try:
        path = opks_dir() / _opk_filename(opk_pub_b64)
    except Exception:
        return None
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        nonce = base64.b64decode(blob["nonce"])
        ct = base64.b64decode(blob["ct"])
        plaintext = AESGCM(wrap_key).decrypt(nonce, ct, OPK_AAD)
        rec = json.loads(plaintext)
        return X25519PrivateKey.from_private_bytes(
            base64.b64decode(rec["opk_priv_b64"])
        )
    except Exception:
        # Wrong wrap key or corrupt — don't leak details.
        return None


def delete_opk(opk_pub_b64: str) -> None:
    """Unlink the on-disk OPK record. No-op if the file is already gone."""
    path = opks_dir() / _opk_filename(opk_pub_b64)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


def spk_path() -> Path:
    return base_dir() / "spk.json"


def save_spk(
    spk_priv: X25519PrivateKey,
    spk_pub_bytes: bytes,
    spk_sig: bytes,
    wrap_key: bytes,
) -> None:
    """Encrypt + persist the current SPK (priv + pub + signature). Atomic.

    Overwrites any previous SPK file — only the most recent SPK is kept,
    matching the in-memory state.prekeys behavior.
    """
    from cryptography.hazmat.primitives import serialization

    d = base_dir()
    d.mkdir(parents=True, exist_ok=True)
    priv_raw = spk_priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    plaintext = json.dumps({
        "spk_priv_b64": base64.b64encode(priv_raw).decode("ascii"),
        "spk_pub_b64": base64.b64encode(spk_pub_bytes).decode("ascii"),
        "spk_sig_b64": base64.b64encode(spk_sig).decode("ascii"),
    }).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(wrap_key).encrypt(nonce, plaintext, SPK_AAD)
    blob = {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    path = spk_path()
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(blob, f)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_spk(wrap_key: bytes) -> dict | None:
    """Decrypt and return {"spk_priv","spk_pub_bytes","spk_sig"} or None.

    Returns None if no SPK file exists, the wrap key is wrong, or the file is
    corrupt. The returned dict's keys match the in-memory state.prekeys layout
    used by handlers, so it can be merged in directly.
    """
    path = spk_path()
    if not path.exists():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        nonce = base64.b64decode(blob["nonce"])
        ct = base64.b64decode(blob["ct"])
        plaintext = AESGCM(wrap_key).decrypt(nonce, ct, SPK_AAD)
        rec = json.loads(plaintext)
        return {
            "spk_priv": X25519PrivateKey.from_private_bytes(
                base64.b64decode(rec["spk_priv_b64"])
            ),
            "spk_pub_bytes": base64.b64decode(rec["spk_pub_b64"]),
            "spk_sig": base64.b64decode(rec["spk_sig_b64"]),
        }
    except Exception:
        # Wrong wrap key or corrupt — don't leak details.
        return None
