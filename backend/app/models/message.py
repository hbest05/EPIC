import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID, BYTEA
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.database import Base


class UserKey(Base):
    __tablename__ = "user_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    public_key = Column(BYTEA, nullable=False)
    key_fingerprint = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="key")


class Message(Base):
    __tablename__ = "messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    recipient_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    ciphertext = Column(BYTEA, nullable=False)
    nonce = Column(BYTEA, nullable=False)
    hpke_enc_blob = Column(BYTEA, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    blockchain_tx_hash = Column(String, nullable=True)

    # Double Ratchet header fields — populated by the sending ratchet service
    ratchet_public_key = Column(String(512), nullable=True)        # sender's DH ratchet key (base64)
    previous_chain_length = Column(Integer, nullable=True)         # PN: length of previous sending chain
    message_index = Column(Integer, nullable=True)                 # N: index within current sending chain
    session_id = Column(
        UUID(as_uuid=True),
        ForeignKey("ratchet_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")
    access_records = relationship("MessageAccess", back_populates="message", cascade="all, delete")


class MessageAccess(Base):
    __tablename__ = "message_access"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id = Column(UUID(as_uuid=True), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    granted_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    granted_at = Column(DateTime(timezone=True), server_default=func.now())
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    message = relationship("Message", back_populates="access_records")
    user = relationship("User", foreign_keys=[user_id], back_populates="access_records")