"""
identity.py — long-term identity keys, Argon2id-wrapped at rest.

Generates an X25519 identity key (IK, used for X3DH DH operations) and a
separate Ed25519 signing key (used to sign the Signed Prekey). The pair is
encrypted with AES-256-GCM under a key derived from the user's passphrase
via Argon2id, then written to <base>/identity.enc, where <base> is
$SECUREMSG_HOME if set, otherwise ~/.securemsg. Overriding the base lets
two daemons run side-by-side on one host with separate identities.

The wrap key derived from the passphrase is also returned so the daemon
can reuse it to encrypt session state at rest.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ARGON_TIME = 3
ARGON_MEM_KIB = 65536  # 64 MiB
ARGON_PAR = 1
SALT_LEN = 16
NONCE_LEN = 12
MAGIC = b"SMID"
VERSION = 1
IDENTITY_AAD = b"securemsg-identity-v1"


def _raw_priv_x(k: X25519PrivateKey) -> bytes:
    return k.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_pub_x(k: X25519PublicKey) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _raw_priv_ed(k: Ed25519PrivateKey) -> bytes:
    return k.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_pub_ed(k: Ed25519PublicKey) -> bytes:
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def derive_wrap_key(passphrase: str, salt: bytes) -> bytes:
    """Argon2id(passphrase, salt) → 32-byte symmetric wrap key."""
    return hash_secret_raw(
        passphrase.encode("utf-8"),
        salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEM_KIB,
        parallelism=ARGON_PAR,
        hash_len=32,
        type=Type.ID,
    )


def _secure_zero(b: bytearray) -> None:
    for i in range(len(b)):
        b[i] = 0


class Identity:
    """Loaded identity — private keys held in memory for the session."""

    def __init__(
        self,
        ik_priv: X25519PrivateKey,
        sign_priv: Ed25519PrivateKey,
        wrap_key: bytes,
    ):
        self.ik_priv = ik_priv
        self.ik_pub = ik_priv.public_key()
        self.sign_priv = sign_priv
        self.sign_pub = sign_priv.public_key()
        self.wrap_key = wrap_key

    def ik_pub_b64(self) -> str:
        return base64.b64encode(_raw_pub_x(self.ik_pub)).decode("ascii")

    def sign_pub_b64(self) -> str:
        return base64.b64encode(_raw_pub_ed(self.sign_pub)).decode("ascii")

    def ik_pub_bytes(self) -> bytes:
        return _raw_pub_x(self.ik_pub)


def base_dir() -> Path:
    """Base directory for daemon state. Overridable via $SECUREMSG_HOME so
    two daemons on one host can use separate identities and session stores."""
    override = os.environ.get("SECUREMSG_HOME")
    if override:
        return Path(override)
    return Path.home() / ".securemsg"


def identity_path() -> Path:
    return base_dir() / "identity.enc"


def generate(passphrase: str) -> Identity:
    """Generate fresh keypairs, encrypt with passphrase-derived key, persist."""
    ik_priv = X25519PrivateKey.generate()
    sign_priv = Ed25519PrivateKey.generate()

    salt = secrets.token_bytes(SALT_LEN)
    wrap_key = derive_wrap_key(passphrase, salt)

    blob_bytes = json.dumps(
        {
            "ik_priv": base64.b64encode(_raw_priv_x(ik_priv)).decode(),
            "sign_priv": base64.b64encode(_raw_priv_ed(sign_priv)).decode(),
        }
    ).encode("utf-8")
    nonce = secrets.token_bytes(NONCE_LEN)
    ct = AESGCM(wrap_key).encrypt(nonce, blob_bytes, IDENTITY_AAD)

    # Best-effort zero of the JSON buffer (the bytes object itself is immutable
    # but at least the bytearray copy we hold is wiped).
    buf = bytearray(blob_bytes)
    _secure_zero(buf)

    path = identity_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".enc.tmp")
    with open(tmp, "wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))
        f.write(salt)
        f.write(nonce)
        f.write(ct)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    return Identity(ik_priv, sign_priv, wrap_key)


def load(passphrase: str) -> Identity:
    """Read the identity file, derive wrap key, decrypt private keys."""
    path = identity_path()
    if not path.exists():
        raise FileNotFoundError("identity file not present")
    with open(path, "rb") as f:
        data = f.read()
    header_len = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN
    if len(data) < header_len:
        raise ValueError("identity file truncated")
    if data[: len(MAGIC)] != MAGIC:
        raise ValueError("bad magic")
    if data[len(MAGIC)] != VERSION:
        raise ValueError("unsupported identity file version")

    off = len(MAGIC) + 1
    salt = data[off : off + SALT_LEN]
    off += SALT_LEN
    nonce = data[off : off + NONCE_LEN]
    off += NONCE_LEN
    ct = data[off:]

    wrap_key = derive_wrap_key(passphrase, salt)
    try:
        plaintext = AESGCM(wrap_key).decrypt(nonce, ct, IDENTITY_AAD)
    except Exception:
        # Generic — don't reveal whether failure is bad password vs corruption.
        raise ValueError("identity decryption failed")

    blob = json.loads(plaintext)
    ik_priv = X25519PrivateKey.from_private_bytes(base64.b64decode(blob["ik_priv"]))
    sign_priv = Ed25519PrivateKey.from_private_bytes(
        base64.b64decode(blob["sign_priv"])
    )

    pt_buf = bytearray(plaintext)
    _secure_zero(pt_buf)

    return Identity(ik_priv, sign_priv, wrap_key)
