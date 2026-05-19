"""
User ORM model.

Stores account credentials and public key material for end-to-end encryption.
Passwords are NEVER stored in plaintext — only the Argon2id hash is persisted.
The ed25519_public_key column holds the user's signing public key so recipients
can verify message authenticity without trusting the server.
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, String, Boolean
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)

    # Argon2id hash — see services/auth_service.py
    password_hash = Column(String(255), nullable=False)

    # X25519 public key (base64-encoded) for ECDH key exchange
    # TODO: Populate during registration when client generates key pair
    x25519_public_key = Column(String(512), nullable=True)

    # Ed25519 public key (base64-encoded) for message signature verification
    ed25519_public_key = Column(String(512), nullable=True)

    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, nullable=True)
