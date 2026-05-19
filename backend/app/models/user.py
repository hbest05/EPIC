"""
User ORM model.

Stores account credentials and public key material for end-to-end encryption.
Passwords are NEVER stored in plaintext — only the Argon2id hash is persisted.
The ed25519_public_key column holds the user's signing public key so recipients
can verify message authenticity without trusting the server.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, String, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)

    # Argon2id hash — see services/auth_service.py
    password_hash = Column(String(255), nullable=False)

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_seen_at = Column(DateTime, nullable=True)

    key = relationship("UserKey", back_populates="user", uselist=False)
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")
    access_records = relationship("MessageAccess", foreign_keys="MessageAccess.user_id", back_populates="user")
