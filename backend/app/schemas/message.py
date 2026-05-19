"""
Pydantic schemas for message send/receive endpoints.

The server never sees plaintext — clients encrypt before sending and decrypt
after receiving. The API therefore deals exclusively with ciphertext blobs and
metadata.

HPKE Mode_Auth fields:
  ciphertext    — AES-128-GCM output
  hpke_enc_blob — KEM encapsulated key ("enc" in RFC 9180 terminology)
  nonce         — AEAD nonce
No separate signature field: Mode_Auth binds the sender's static X25519 key
into the KEM, providing authentication without a second key pair.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class SendMessageRequest(BaseModel):
    recipient_username: str
    ciphertext: str = Field(..., description="Base64-encoded AES-128-GCM ciphertext")
    hpke_enc_blob: str = Field(..., description="Base64-encoded HPKE encapsulated key (RFC 9180 enc)")
    nonce: str = Field(..., description="Base64-encoded AEAD nonce")


class MessageResponse(BaseModel):
    id: str
    sender_username: str
    ciphertext: str
    hpke_enc_blob: str
    nonce: str
    keccak256_hash: Optional[str] = None
    blockchain_confirmed: bool
    tx_hash: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class BlockchainStatusResponse(BaseModel):
    message_id: str
    keccak256_hash: Optional[str]
    blockchain_confirmed: bool
    tx_hash: Optional[str]
