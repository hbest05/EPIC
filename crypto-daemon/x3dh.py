"""
x3dh.py — Extended Triple Diffie-Hellman key agreement.

Sender computes:
    DH1 = X25519(IK_A, SPK_B)
    DH2 = X25519(EK_A, IK_B)
    DH3 = X25519(EK_A, SPK_B)
    DH4 = X25519(EK_A, OPK_B)        # optional
    SK  = HKDF-SHA256(DH1||DH2||DH3||DH4, salt=0x00*32, info='SecureMsg_X3DH_v1')

Receiver recomputes the same DHs with the swapped roles using its own
private SPK / OPK.

The SPK signature is verified BEFORE any DH happens; an invalid signature
aborts the operation.
"""

from __future__ import annotations

import base64
from typing import Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

X3DH_INFO = b"SecureMsg_X3DH_v1"
X3DH_SALT = b"\x00" * 32


class InvalidBundleError(Exception):
    """Raised when a peer's prekey bundle fails validation."""


def hkdf_sha256(ikm: bytes, length: int, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def _raw_pub_x(k: X25519PublicKey) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _validate_b64_key(s: str, name: str, expected_len: int = 32) -> bytes:
    try:
        b = base64.b64decode(s, validate=True)
    except Exception as exc:
        raise InvalidBundleError(f"{name}: not valid base64") from exc
    if len(b) != expected_len:
        raise InvalidBundleError(
            f"{name}: expected {expected_len} bytes, got {len(b)}"
        )
    return b


def derive_sk_sender(
    my_ik_priv: X25519PrivateKey, peer_bundle: dict
) -> Tuple[bytes, X25519PrivateKey, bytes, Optional[str]]:
    """Sender-side X3DH.

    Returns (sk, ephemeral_priv, ephemeral_pub_bytes, used_opk_pub_b64_or_None).
    """
    for k in ("ik_pub", "sign_pub", "spk_pub", "spk_sig"):
        if k not in peer_bundle or not isinstance(peer_bundle[k], str):
            raise InvalidBundleError(f"missing or non-string field: {k}")

    peer_ik_pub_bytes = _validate_b64_key(peer_bundle["ik_pub"], "ik_pub")
    peer_sign_pub_bytes = _validate_b64_key(peer_bundle["sign_pub"], "sign_pub")
    spk_pub_bytes = _validate_b64_key(peer_bundle["spk_pub"], "spk_pub")
    try:
        spk_sig = base64.b64decode(peer_bundle["spk_sig"], validate=True)
    except Exception as exc:
        raise InvalidBundleError("spk_sig: not valid base64") from exc
    if len(spk_sig) != 64:
        raise InvalidBundleError("spk_sig: expected 64 bytes")

    # Verify SPK signature BEFORE any DH operations.
    try:
        Ed25519PublicKey.from_public_bytes(peer_sign_pub_bytes).verify(
            spk_sig, spk_pub_bytes
        )
    except InvalidSignature as exc:
        raise InvalidBundleError("SPK signature verification failed") from exc

    peer_ik_pub = X25519PublicKey.from_public_bytes(peer_ik_pub_bytes)
    peer_spk_pub = X25519PublicKey.from_public_bytes(spk_pub_bytes)

    peer_opk_pub = None
    used_opk_b64 = None
    if peer_bundle.get("opk_pub"):
        opk_bytes = _validate_b64_key(peer_bundle["opk_pub"], "opk_pub")
        peer_opk_pub = X25519PublicKey.from_public_bytes(opk_bytes)
        used_opk_b64 = peer_bundle["opk_pub"]

    ek_priv = X25519PrivateKey.generate()
    ek_pub_bytes = _raw_pub_x(ek_priv.public_key())

    dh1 = my_ik_priv.exchange(peer_spk_pub)
    dh2 = ek_priv.exchange(peer_ik_pub)
    dh3 = ek_priv.exchange(peer_spk_pub)
    ikm = dh1 + dh2 + dh3
    if peer_opk_pub is not None:
        dh4 = ek_priv.exchange(peer_opk_pub)
        ikm += dh4

    sk = hkdf_sha256(ikm, 32, X3DH_SALT, X3DH_INFO)

    # Best-effort wipe of DH outputs.
    for buf in (dh1, dh2, dh3):
        _ = buf  # bytes are immutable; rely on GC. Caller does not retain ikm.
    return sk, ek_priv, ek_pub_bytes, used_opk_b64


def derive_sk_receiver(
    my_ik_priv: X25519PrivateKey,
    my_spk_priv: X25519PrivateKey,
    my_opk_priv: Optional[X25519PrivateKey],
    peer_ik_pub_bytes: bytes,
    peer_ek_pub_bytes: bytes,
) -> bytes:
    """Receiver-side X3DH — recomputes the same SK as the sender."""
    if len(peer_ik_pub_bytes) != 32 or len(peer_ek_pub_bytes) != 32:
        raise InvalidBundleError("peer key wrong length")
    peer_ik_pub = X25519PublicKey.from_public_bytes(peer_ik_pub_bytes)
    peer_ek_pub = X25519PublicKey.from_public_bytes(peer_ek_pub_bytes)

    dh1 = my_spk_priv.exchange(peer_ik_pub)
    dh2 = my_ik_priv.exchange(peer_ek_pub)
    dh3 = my_spk_priv.exchange(peer_ek_pub)
    ikm = dh1 + dh2 + dh3
    if my_opk_priv is not None:
        dh4 = my_opk_priv.exchange(peer_ek_pub)
        ikm += dh4

    return hkdf_sha256(ikm, 32, X3DH_SALT, X3DH_INFO)
