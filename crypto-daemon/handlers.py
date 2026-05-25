"""
handlers.py — request dispatch + per-op implementations.

Every public op takes (state, params) and either returns a dict (becomes
the "data" field of the response) or raises OpError. Unhandled exceptions
are caught at the dispatcher and surface as {status: error, code: internal}
WITHOUT exposing the underlying message, so internal state never leaks.
"""

from __future__ import annotations

import base64
import uuid
from typing import Callable, Dict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

import identity as identity_mod
import session_store
import x3dh as x3dh_mod
from double_ratchet import Session, _raw_pub


class OpError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class DaemonState:
    """In-memory state shared across all connections for the daemon lifetime."""

    def __init__(self):
        self.identity: identity_mod.Identity | None = None
        # Most recent batch of generated prekeys (responder side).
        # {'spk_priv': X25519PrivateKey, 'spk_pub_bytes': bytes,
        #  'spk_sig': bytes, 'opks': {opk_pub_b64: X25519PrivateKey}}
        self.prekeys: dict = {}
        self.sessions: Dict[str, Session] = {}

    def require_identity(self) -> identity_mod.Identity:
        if self.identity is None:
            raise OpError("not_loaded", "identity not loaded")
        return self.identity


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _ub64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def _require_str(params: dict, name: str) -> str:
    v = params.get(name)
    if not isinstance(v, str) or not v:
        raise OpError("bad_request", f"{name} required (string)")
    return v


def handle(state: DaemonState, req: dict) -> dict:
    if not isinstance(req, dict):
        return {"status": "error", "code": "bad_request", "message": "request must be object"}
    op = req.get("op")
    if not isinstance(op, str):
        return {"status": "error", "code": "bad_request", "message": "missing op"}
    params = req.get("params") or {}
    if not isinstance(params, dict):
        return {"status": "error", "code": "bad_request", "message": "params must be object"}
    fn = OPS.get(op)
    if fn is None:
        return {"status": "error", "code": "unknown_op", "message": f"unknown op: {op}"}
    try:
        data = fn(state, params)
        return {"status": "ok", "data": data or {}}
    except OpError as e:
        return {"status": "error", "code": e.code, "message": e.message}
    except Exception as e:
        # Hide details — type name only, never args (could include key bytes).
        return {"status": "error", "code": "internal", "message": type(e).__name__}


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

def op_generate_identity(state: DaemonState, params: dict) -> dict:
    pp = _require_str(params, "passphrase")
    ident = identity_mod.generate(pp)
    state.identity = ident
    # Fresh identity → no sessions yet.
    state.sessions = {}
    return {
        "ik_pub": ident.ik_pub_b64(),
        "sign_pub": ident.sign_pub_b64(),
    }


def op_load_identity(state: DaemonState, params: dict) -> dict:
    pp = _require_str(params, "passphrase")
    try:
        ident = identity_mod.load(pp)
    except FileNotFoundError:
        raise OpError("not_found", "no identity file present")
    except ValueError:
        raise OpError("bad_passphrase", "identity decryption failed")
    state.identity = ident
    state.sessions = session_store.load_all_sessions(ident.wrap_key)
    return {
        "ik_pub": ident.ik_pub_b64(),
        "sign_pub": ident.sign_pub_b64(),
        "sessions_loaded": len(state.sessions),
    }


def op_generate_prekeys(state: DaemonState, params: dict) -> dict:
    ident = state.require_identity()
    spk_priv = X25519PrivateKey.generate()
    spk_pub_bytes = _raw_pub(spk_priv.public_key())
    spk_sig = ident.sign_priv.sign(spk_pub_bytes)

    opks_b64 = []
    opk_map: Dict[str, X25519PrivateKey] = {}
    for _ in range(10):
        opk = X25519PrivateKey.generate()
        opk_pub_b64 = _b64(_raw_pub(opk.public_key()))
        opk_map[opk_pub_b64] = opk
        opks_b64.append(opk_pub_b64)

    state.prekeys = {
        "spk_priv": spk_priv,
        "spk_pub_bytes": spk_pub_bytes,
        "spk_sig": spk_sig,
        "opks": opk_map,
    }
    return {
        "spk_pub": _b64(spk_pub_bytes),
        "spk_sig": _b64(spk_sig),
        "opks": opks_b64,
    }


def op_x3dh_send(state: DaemonState, params: dict) -> dict:
    ident = state.require_identity()
    bundle = params.get("bundle")
    peer_user_id = _require_str(params, "peer_user_id")
    plaintext = params.get("plaintext")
    if not isinstance(bundle, dict):
        raise OpError("bad_request", "bundle required (object)")
    if not isinstance(plaintext, str):
        raise OpError("bad_request", "plaintext required (string)")

    try:
        sk, _ek_priv, ek_pub_bytes, used_opk_b64 = x3dh_mod.derive_sk_sender(
            ident.ik_priv, bundle
        )
    except x3dh_mod.InvalidBundleError as e:
        raise OpError("invalid_bundle", str(e))

    session_id = uuid.uuid4().hex
    ik_a_bytes = ident.ik_pub_bytes()
    ik_b_bytes = _ub64(bundle["ik_pub"])
    peer_spk_pub_bytes = _ub64(bundle["spk_pub"])

    session = Session.init_sender(
        session_id, sk, ik_a_bytes, ik_b_bytes, peer_spk_pub_bytes, peer_user_id
    )
    first = session.encrypt(plaintext)
    state.sessions[session_id] = session
    session_store.save_session(session, ident.wrap_key)

    return {
        "session_id": session_id,
        "ik_pub": _b64(ik_a_bytes),
        "ek_pub": _b64(ek_pub_bytes),
        "used_opk_pub": used_opk_b64,
        "message": first,
    }


def op_x3dh_receive(state: DaemonState, params: dict) -> dict:
    ident = state.require_identity()
    header = params.get("header")
    peer_user_id = _require_str(params, "peer_user_id")
    if not isinstance(header, dict):
        raise OpError("bad_request", "header required (object)")
    for k in ("ik_a", "ek_a"):
        if not isinstance(header.get(k), str):
            raise OpError("bad_request", f"header.{k} required (string)")
    try:
        peer_ik_pub_bytes = _ub64(header["ik_a"])
        peer_ek_pub_bytes = _ub64(header["ek_a"])
    except Exception:
        raise OpError("bad_request", "header values not valid base64")
    if len(peer_ik_pub_bytes) != 32 or len(peer_ek_pub_bytes) != 32:
        raise OpError("bad_request", "header key wrong length")

    if not state.prekeys:
        raise OpError("no_prekeys", "call generate_prekeys before x3dh_receive")

    my_opk_priv = None
    used_opk_b64 = header.get("used_opk_pub")
    if used_opk_b64:
        if not isinstance(used_opk_b64, str):
            raise OpError("bad_request", "used_opk_pub must be string")
        my_opk_priv = state.prekeys["opks"].pop(used_opk_b64, None)
        if my_opk_priv is None:
            raise OpError("unknown_opk", "requested OPK not in our keystore")

    try:
        sk = x3dh_mod.derive_sk_receiver(
            ident.ik_priv,
            state.prekeys["spk_priv"],
            my_opk_priv,
            peer_ik_pub_bytes,
            peer_ek_pub_bytes,
        )
    except x3dh_mod.InvalidBundleError as e:
        raise OpError("x3dh_failed", str(e))

    session_id = uuid.uuid4().hex
    ik_a_bytes = peer_ik_pub_bytes
    ik_b_bytes = ident.ik_pub_bytes()
    spk_priv_bytes = state.prekeys["spk_priv"].private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    session = Session.init_receiver(
        session_id, sk, ik_a_bytes, ik_b_bytes, spk_priv_bytes, peer_user_id
    )
    state.sessions[session_id] = session
    session_store.save_session(session, ident.wrap_key)
    return {"session_id": session_id}


def op_encrypt_message(state: DaemonState, params: dict) -> dict:
    ident = state.require_identity()
    sid = _require_str(params, "session_id")
    pt = params.get("plaintext")
    if not isinstance(pt, str):
        raise OpError("bad_request", "plaintext required (string)")
    sess = state.sessions.get(sid)
    if sess is None:
        raise OpError("no_session", "unknown session_id")
    try:
        msg = sess.encrypt(pt)
    except RuntimeError as e:
        raise OpError("no_send_chain", str(e))
    session_store.save_session(sess, ident.wrap_key)
    return msg


def op_decrypt_message(state: DaemonState, params: dict) -> dict:
    ident = state.require_identity()
    sid = _require_str(params, "session_id")
    sess = state.sessions.get(sid)
    if sess is None:
        raise OpError("no_session", "unknown session_id")
    for k in ("ciphertext", "nonce", "ratchet_pub", "pn", "n"):
        if k not in params:
            raise OpError("bad_request", f"{k} required")
    try:
        pt = sess.decrypt(
            params["ciphertext"],
            params["nonce"],
            params["ratchet_pub"],
            int(params["pn"]),
            int(params["n"]),
        )
    except ValueError as e:
        raise OpError("decrypt_failed", str(e))
    session_store.save_session(sess, ident.wrap_key)
    return {"plaintext": pt}


def op_dh_ratchet_step(state: DaemonState, params: dict) -> dict:
    ident = state.require_identity()
    sid = _require_str(params, "session_id")
    their_pub = _require_str(params, "their_ratchet_pub")
    sess = state.sessions.get(sid)
    if sess is None:
        raise OpError("no_session", "unknown session_id")
    try:
        sess.dh_ratchet_step(their_pub)
    except ValueError as e:
        raise OpError("bad_request", str(e))
    session_store.save_session(sess, ident.wrap_key)
    return {"ratchet_pub": _b64(sess.dhs_pub_bytes)}


OPS: Dict[str, Callable[[DaemonState, dict], dict]] = {
    "generate_identity": op_generate_identity,
    "load_identity": op_load_identity,
    "generate_prekeys": op_generate_prekeys,
    "x3dh_send": op_x3dh_send,
    "x3dh_receive": op_x3dh_receive,
    "encrypt_message": op_encrypt_message,
    "decrypt_message": op_decrypt_message,
    "dh_ratchet_step": op_dh_ratchet_step,
}
