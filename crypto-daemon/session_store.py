"""
session_store.py — at-rest encryption of Double Ratchet session state.

Each session is serialized to JSON, encrypted with AES-256-GCM under the
identity's wrap key, and written to ~/.securemsg/sessions/<session_id>.json.
Files are reloaded at daemon startup once the identity is unlocked.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SESSION_AAD = b"securemsg-session-v1"
NONCE_LEN = 12


def sessions_dir() -> Path:
    return Path.home() / ".securemsg" / "sessions"


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
