"""
Signal Protocol ORM models (X3DH + Double Ratchet).

Four tables live here:
  - SignedPrekey      weekly-rotated medium-term prekey per user
  - OneTimePrekey     single-use prekeys consumed during X3DH key agreement
  - RatchetSession    per-pair Double Ratchet chain state
  - SkippedMessageKey cached keys for out-of-order message delivery
"""

import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func

from app.database import Base


class SignedPrekey(Base):
    """
    Medium-term signed prekey (SPK) uploaded by a user.

    Rotated weekly. The server keeps the active SPK plus any recently expired
    ones needed to complete in-flight X3DH sessions. The signature is an
    Ed25519 signature over the public_key bytes, made with the user's identity
    key (users.ed25519_public_key), so recipients can verify authenticity.
    """

    __tablename__ = "signed_prekeys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key_id = Column(Integer, nullable=False)
    public_key = Column(String(512), nullable=False)   # base64 X25519 public key
    signature = Column(String(512), nullable=False)    # base64 Ed25519 sig over public_key
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_signed_prekeys_user_id_key_id", "user_id", "key_id"),
    )


class OneTimePrekey(Base):
    """
    One-time prekey (OPK) for X3DH key agreement.

    Each OPK is consumed exactly once: on the first keybundle fetch the server
    marks used=True and never serves it again. Application code must replenish
    the pool when it runs low (Signal recommends keeping ≥ 100 unused OPKs).
    Enforce MAX_SKIP and pool-size limits in application logic, not here.
    """

    __tablename__ = "one_time_prekeys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key_id = Column(Integer, nullable=False)
    public_key = Column(String(512), nullable=False)   # base64 X25519 public key
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        # Fetch path: WHERE user_id = ? AND used = false LIMIT 1
        Index("ix_one_time_prekeys_user_id_used", "user_id", "used"),
    )


class RatchetSession(Base):
    """
    Double Ratchet session state between an ordered pair of users.

    (local_user_id, remote_user_id) is unique — Alice→Bob and Bob→Alice each
    get their own row. Every ratchet step must UPDATE this row atomically.

    root_key and the chain keys are base64-encoded secrets. Consider adding
    column-level encryption or TDE at the infrastructure layer; the DB sees
    them plaintext by default.
    """

    __tablename__ = "ratchet_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    local_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    remote_user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    root_key = Column(String(512), nullable=False)                    # KDF root — rotate every DH ratchet step
    sending_chain_key = Column(String(512), nullable=True)            # CKs
    receiving_chain_key = Column(String(512), nullable=True)          # CKr
    sending_ratchet_public_key = Column(String(512), nullable=True)   # DHs public half
    receiving_ratchet_public_key = Column(String(512), nullable=True) # DHr

    sending_chain_index = Column(Integer, default=0, nullable=False)
    receiving_chain_index = Column(Integer, default=0, nullable=False)
    previous_sending_chain_length = Column(Integer, default=0, nullable=False)  # PN header field

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    # Must be updated on every ratchet step so consumers can detect stale reads
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        UniqueConstraint("local_user_id", "remote_user_id", name="uq_ratchet_sessions_local_remote"),
    )


class SkippedMessageKey(Base):
    """
    Cached message keys for out-of-order delivery (Double Ratchet §2.6).

    When a receiver skips ahead in a chain, the keys for skipped indices are
    stored here so earlier messages can be decrypted on late arrival.

    IMPORTANT: application logic MUST enforce MAX_SKIP (≤ 1000 per session)
    before inserting new rows. There is no DB-level guard against unbounded
    growth — that check belongs in the ratchet service layer.
    """

    __tablename__ = "skipped_message_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("ratchet_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    ratchet_public_key = Column(String(512), nullable=False)  # DH epoch identifier (base64)
    message_index = Column(Integer, nullable=False)           # N value within that epoch
    message_key = Column(String(512), nullable=False)         # base64 symmetric key
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "session_id",
            "ratchet_public_key",
            "message_index",
            name="uq_skipped_message_keys_session_ratchet_index",
        ),
        # Lookup path: WHERE session_id = ? AND ratchet_public_key = ? AND message_index = ?
        Index(
            "ix_skipped_message_keys_session_ratchet_index",
            "session_id",
            "ratchet_public_key",
            "message_index",
        ),
    )
