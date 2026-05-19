"""
Pydantic schemas for message send/receive endpoints.

The server never sees plaintext — clients encrypt before sending and decrypt
after receiving. The API therefore deals exclusively with ciphertext blobs and
metadata.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class SendMessageRequest(BaseModel):
    recipient_username: str
    # All crypto material produced client-side
    ciphertext: str = Field(..., description="Base64-encoded NaCl box ciphertext")
    ephemeral_public_key: str = Field(..., description="Base64-encoded ephemeral X25519 pubkey")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature of ciphertext")


class MessageResponse(BaseModel):
    id: str
    sender_username: str
    ciphertext: str
    ephemeral_public_key: str
    signature: str
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
