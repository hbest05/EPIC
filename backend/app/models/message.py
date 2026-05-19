"""
Message ORM model.

The server stores only ciphertext — plaintext is never transmitted unencrypted.
The keccak256_hash column mirrors what is written to the blockchain so the
integrity of a message can be independently verified on-chain.

Encryption scheme (to be implemented):
  - Sender generates an ephemeral X25519 keypair
  - ECDH with recipient's X25519 public key -> shared secret
  - XSalsa20-Poly1305 (libsodium box) encrypts the plaintext
  - Ciphertext + ephemeral public key stored here
"""

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, String, Text, Boolean
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class Message(Base):
    __tablename__ = "messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    recipient_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    # NaCl box ciphertext (base64-encoded)
    ciphertext = Column(Text, nullable=False)

    # Ephemeral X25519 public key used for this message (base64-encoded)
    ephemeral_public_key = Column(String(512), nullable=False)

    # Ed25519 signature of the ciphertext by sender (base64-encoded)
    signature = Column(String(512), nullable=True)

    # keccak256(ciphertext) — anchored to blockchain via MessageDigest contract
    keccak256_hash = Column(String(66), nullable=True)  # 0x + 64 hex chars

    # Set to True once the hash has been confirmed on-chain
    blockchain_confirmed = Column(Boolean, default=False, nullable=False)

    # Ethereum transaction hash of the on-chain submission
    tx_hash = Column(String(66), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    delivered_at = Column(DateTime, nullable=True)
