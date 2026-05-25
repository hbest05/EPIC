"""
double_ratchet.py — Double Ratchet session state machine.

Per-message symmetric chain step:
    (CK_next, MK) = HKDF-SHA256(CK, salt=None, info='SecureMsg_MsgKey_v1') -> 64 bytes

DH ratchet step (when a new peer ratchet pub arrives):
    (RK_next, CK_x) = HKDF-SHA256(DH(our_priv, their_pub), salt=RK, info='SecureMsg_Ratchet_v1')

Each AES-256-GCM frame is encrypted under the per-message key MK with a
fresh 12-byte nonce. The AAD binds the IKs of both parties, the current
sender ratchet pub, and the message numbers (PN, N), so any header
tampering breaks the tag.

Plaintext is padded PKCS#7-style to a 256-byte boundary BEFORE encryption
to hide exact message length.
"""

from __future__ import annotations

import base64
import secrets
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RATCHET_INFO = b"SecureMsg_Ratchet_v1"
CHAIN_INFO = b"SecureMsg_MsgKey_v1"
PAD_BLOCK = 256
MAX_SKIPPED = 100
NONCE_LEN = 12


def _raw_priv(k: X25519PrivateKey) -> bytes:
    return k.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_pub(k: X25519PublicKey) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _hkdf(ikm: bytes, length: int, salt: Optional[bytes], info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def advance_chain(ck: bytes) -> Tuple[bytes, bytes]:
    """(CK_next, MK) = HKDF(CK, info=CHAIN_INFO) -> 64 bytes split 32/32."""
    out = _hkdf(ck, 64, None, CHAIN_INFO)
    return out[:32], out[32:]


def dh_ratchet_hkdf(rk: bytes, dh_out: bytes) -> Tuple[bytes, bytes]:
    """(RK_next, CK_x) = HKDF(DH, salt=RK, info=RATCHET_INFO) -> 64 bytes."""
    out = _hkdf(dh_out, 64, rk, RATCHET_INFO)
    return out[:32], out[32:]


def pad_message(pt: bytes) -> bytes:
    pad_len = PAD_BLOCK - (len(pt) % PAD_BLOCK)
    return pt + bytes([pad_len]) * pad_len


def unpad_message(padded: bytes) -> bytes:
    if not padded:
        raise ValueError("padding: empty data")
    pad_len = padded[-1]
    if pad_len == 0 or pad_len > PAD_BLOCK or pad_len > len(padded):
        raise ValueError("padding: bad length")
    if any(b != pad_len for b in padded[-pad_len:]):
        raise ValueError("padding: bad content")
    return padded[:-pad_len]


def _wipe(buf: bytearray) -> None:
    for i in range(len(buf)):
        buf[i] = 0


class Session:
    """Double Ratchet state for one conversation."""

    def __init__(self):
        self.session_id: Optional[str] = None
        self.peer_user_id: Optional[str] = None
        self.role: Optional[str] = None  # "initiator" or "responder"

        # IKs as recorded in AAD — these never change for the session.
        self.ik_a: Optional[bytes] = None  # initiator's IK pub
        self.ik_b: Optional[bytes] = None  # responder's IK pub

        # Ratchet state
        self.rk: Optional[bytes] = None
        self.ck_send: Optional[bytes] = None
        self.ck_recv: Optional[bytes] = None
        self.n_send: int = 0
        self.n_recv: int = 0
        self.pn: int = 0

        self.dhs_priv_bytes: Optional[bytes] = None
        self.dhs_pub_bytes: Optional[bytes] = None
        self.dhr_bytes: Optional[bytes] = None

        # Skipped message keys: {(their_pub_hex, n): MK}
        self.skipped: Dict[Tuple[str, int], bytes] = {}

    # ------------------------------------------------------------------ init

    @classmethod
    def init_sender(
        cls,
        session_id: str,
        sk: bytes,
        ik_a_bytes: bytes,
        ik_b_bytes: bytes,
        peer_spk_pub_bytes: bytes,
        peer_user_id: str,
    ) -> "Session":
        s = cls()
        s.session_id = session_id
        s.peer_user_id = peer_user_id
        s.role = "initiator"
        s.ik_a = ik_a_bytes
        s.ik_b = ik_b_bytes
        s.rk = sk

        # Fresh sender ratchet keypair; derive initial send chain via DH(DHs, SPK_B).
        dhs = X25519PrivateKey.generate()
        s.dhs_priv_bytes = _raw_priv(dhs)
        s.dhs_pub_bytes = _raw_pub(dhs.public_key())
        peer_spk = X25519PublicKey.from_public_bytes(peer_spk_pub_bytes)
        dh = dhs.exchange(peer_spk)
        s.rk, s.ck_send = dh_ratchet_hkdf(s.rk, dh)
        s.dhr_bytes = peer_spk_pub_bytes
        return s

    @classmethod
    def init_receiver(
        cls,
        session_id: str,
        sk: bytes,
        ik_a_bytes: bytes,
        ik_b_bytes: bytes,
        my_spk_priv_bytes: bytes,
        peer_user_id: str,
    ) -> "Session":
        s = cls()
        s.session_id = session_id
        s.peer_user_id = peer_user_id
        s.role = "responder"
        s.ik_a = ik_a_bytes
        s.ik_b = ik_b_bytes
        s.rk = sk
        # Responder's initial DHs is the SPK private — when the sender's first
        # message arrives, we'll DH(SPK_priv, sender_ratchet_pub) to derive
        # the receive chain. That matches the sender's send chain derivation.
        s.dhs_priv_bytes = my_spk_priv_bytes
        s.dhs_pub_bytes = _raw_pub(
            X25519PrivateKey.from_private_bytes(my_spk_priv_bytes).public_key()
        )
        s.dhr_bytes = None
        return s

    # ------------------------------------------------------------------ encrypt

    def _make_aad(self, ratchet_pub: bytes, pn: int, n: int) -> bytes:
        return (
            self.ik_a
            + self.ik_b
            + ratchet_pub
            + pn.to_bytes(4, "big")
            + n.to_bytes(4, "big")
        )

    def encrypt(self, plaintext: str) -> dict:
        if self.ck_send is None:
            raise RuntimeError("no sending chain; call dh_ratchet_step first")
        new_ck, mk = advance_chain(self.ck_send)
        mk_buf = bytearray(mk)
        try:
            self.ck_send = new_ck
            n = self.n_send
            self.n_send += 1

            padded = pad_message(plaintext.encode("utf-8"))
            nonce = secrets.token_bytes(NONCE_LEN)
            aad = self._make_aad(self.dhs_pub_bytes, self.pn, n)
            ct = AESGCM(bytes(mk_buf)).encrypt(nonce, padded, aad)
            return {
                "ciphertext": base64.b64encode(ct).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ratchet_pub": base64.b64encode(self.dhs_pub_bytes).decode("ascii"),
                "pn": self.pn,
                "n": n,
                "aad": base64.b64encode(aad).decode("ascii"),
            }
        finally:
            _wipe(mk_buf)

    # ------------------------------------------------------------------ decrypt

    def decrypt(
        self,
        ciphertext_b64: str,
        nonce_b64: str,
        ratchet_pub_b64: str,
        pn: int,
        n: int,
    ) -> str:
        try:
            ct = base64.b64decode(ciphertext_b64, validate=True)
            nonce = base64.b64decode(nonce_b64, validate=True)
            their_pub = base64.b64decode(ratchet_pub_b64, validate=True)
        except Exception as exc:
            raise ValueError("decrypt: bad base64") from exc
        if len(their_pub) != 32 or len(nonce) != NONCE_LEN:
            raise ValueError("decrypt: bad input length")

        # 1. Skipped-key cache hit.
        cache_key = (their_pub.hex(), n)
        if cache_key in self.skipped:
            mk = self.skipped.pop(cache_key)
            return self._open(ct, nonce, mk, their_pub, pn, n)

        # 2. New DH ratchet pub — advance state and skip any leftover keys.
        if self.dhr_bytes != their_pub:
            self._dh_ratchet_recv(their_pub, pn)

        # 3. Skip ahead in the current recv chain to reach n.
        if n < self.n_recv:
            raise ValueError("decrypt: message older than chain (not cached)")
        while self.n_recv < n:
            if len(self.skipped) >= MAX_SKIPPED:
                raise ValueError("decrypt: too many skipped keys")
            new_ck, mk_skip = advance_chain(self.ck_recv)
            self.ck_recv = new_ck
            self.skipped[(their_pub.hex(), self.n_recv)] = mk_skip
            self.n_recv += 1

        new_ck, mk = advance_chain(self.ck_recv)
        self.ck_recv = new_ck
        self.n_recv += 1
        return self._open(ct, nonce, mk, their_pub, pn, n)

    def _open(
        self,
        ct: bytes,
        nonce: bytes,
        mk: bytes,
        their_pub: bytes,
        pn: int,
        n: int,
    ) -> str:
        mk_buf = bytearray(mk)
        try:
            aad = self._make_aad(their_pub, pn, n)
            try:
                padded = AESGCM(bytes(mk_buf)).decrypt(nonce, ct, aad)
            except Exception as exc:
                # AAD mismatch or tag failure — never return partial plaintext.
                raise ValueError("decrypt: AEAD verification failed") from exc
            pt = unpad_message(padded)
            return pt.decode("utf-8")
        finally:
            _wipe(mk_buf)

    # ------------------------------------------------------------------ DH ratchet

    def _dh_ratchet_recv(self, their_new_pub: bytes, their_pn: int) -> None:
        # Drain the remaining keys of the OLD recv chain so out-of-order
        # messages from before the peer's ratchet are still decryptable.
        if self.ck_recv is not None and self.dhr_bytes is not None:
            while self.n_recv < their_pn:
                if len(self.skipped) >= MAX_SKIPPED:
                    raise ValueError("dh_ratchet: too many skipped keys")
                new_ck, mk_skip = advance_chain(self.ck_recv)
                self.ck_recv = new_ck
                self.skipped[(self.dhr_bytes.hex(), self.n_recv)] = mk_skip
                self.n_recv += 1

        self.dhr_bytes = their_new_pub
        their_pub_key = X25519PublicKey.from_public_bytes(their_new_pub)

        # Derive new RECV chain from current DHs + their new pub.
        my_priv = X25519PrivateKey.from_private_bytes(self.dhs_priv_bytes)
        dh = my_priv.exchange(their_pub_key)
        self.rk, self.ck_recv = dh_ratchet_hkdf(self.rk, dh)
        self.n_recv = 0

        # Generate fresh DHs and derive new SEND chain.
        new_dhs = X25519PrivateKey.generate()
        self.pn = self.n_send
        self.n_send = 0
        self.dhs_priv_bytes = _raw_priv(new_dhs)
        self.dhs_pub_bytes = _raw_pub(new_dhs.public_key())
        dh2 = new_dhs.exchange(their_pub_key)
        self.rk, self.ck_send = dh_ratchet_hkdf(self.rk, dh2)

    def dh_ratchet_step(self, their_new_pub_b64: str) -> None:
        try:
            their_pub = base64.b64decode(their_new_pub_b64, validate=True)
        except Exception as exc:
            raise ValueError("dh_ratchet_step: bad base64") from exc
        if len(their_pub) != 32:
            raise ValueError("dh_ratchet_step: bad key length")
        # Pass current n_recv as "their_pn" — no extra keys to skip.
        self._dh_ratchet_recv(their_pub, self.n_recv)

    # ------------------------------------------------------------------ serde

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "peer_user_id": self.peer_user_id,
            "role": self.role,
            "ik_a": base64.b64encode(self.ik_a).decode() if self.ik_a else None,
            "ik_b": base64.b64encode(self.ik_b).decode() if self.ik_b else None,
            "rk": base64.b64encode(self.rk).decode() if self.rk else None,
            "ck_send": base64.b64encode(self.ck_send).decode() if self.ck_send else None,
            "ck_recv": base64.b64encode(self.ck_recv).decode() if self.ck_recv else None,
            "n_send": self.n_send,
            "n_recv": self.n_recv,
            "pn": self.pn,
            "dhs_priv": base64.b64encode(self.dhs_priv_bytes).decode()
            if self.dhs_priv_bytes
            else None,
            "dhs_pub": base64.b64encode(self.dhs_pub_bytes).decode()
            if self.dhs_pub_bytes
            else None,
            "dhr": base64.b64encode(self.dhr_bytes).decode() if self.dhr_bytes else None,
            "skipped": [
                {"pub_hex": k[0], "n": k[1], "mk": base64.b64encode(v).decode()}
                for k, v in self.skipped.items()
            ],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Session":
        s = cls()
        s.session_id = d.get("session_id")
        s.peer_user_id = d.get("peer_user_id")
        s.role = d.get("role")
        s.ik_a = base64.b64decode(d["ik_a"]) if d.get("ik_a") else None
        s.ik_b = base64.b64decode(d["ik_b"]) if d.get("ik_b") else None
        s.rk = base64.b64decode(d["rk"]) if d.get("rk") else None
        s.ck_send = base64.b64decode(d["ck_send"]) if d.get("ck_send") else None
        s.ck_recv = base64.b64decode(d["ck_recv"]) if d.get("ck_recv") else None
        s.n_send = int(d.get("n_send", 0))
        s.n_recv = int(d.get("n_recv", 0))
        s.pn = int(d.get("pn", 0))
        s.dhs_priv_bytes = (
            base64.b64decode(d["dhs_priv"]) if d.get("dhs_priv") else None
        )
        s.dhs_pub_bytes = base64.b64decode(d["dhs_pub"]) if d.get("dhs_pub") else None
        s.dhr_bytes = base64.b64decode(d["dhr"]) if d.get("dhr") else None
        s.skipped = {
            (e["pub_hex"], int(e["n"])): base64.b64decode(e["mk"])
            for e in d.get("skipped", [])
        }
        return s
