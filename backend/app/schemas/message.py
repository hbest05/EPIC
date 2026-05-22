"""
Pydantic schemas for message and blockchain verification endpoints.

The server never sees plaintext — clients encrypt before sending and decrypt
after receiving.  The API deals exclusively with ciphertext blobs and metadata.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Send message
# ---------------------------------------------------------------------------

class SendMessageRequest(BaseModel):
    recipient_username: str
    ciphertext: str    = Field(..., description="Base64-encoded AES-128-GCM ciphertext")
    hpke_enc_blob: str = Field(..., description="Base64-encoded HPKE encapsulated key (RFC 9180 enc)")
    nonce: str         = Field(..., description="Base64-encoded AEAD nonce")


class SendMessageResponse(BaseModel):
    id: str
    blockchain_pending: bool = True


# ---------------------------------------------------------------------------
# Message responses
# ---------------------------------------------------------------------------

class MessageResponse(BaseModel):
    id: str
    sender_username: str
    ciphertext: str       # base64-encoded
    hpke_enc_blob: str    # base64-encoded
    nonce: str            # base64-encoded
    created_at: datetime
    blockchain_tx_hash: Optional[str]    = None
    blockchain_block_number: Optional[int] = None
    blockchain_record_index: Optional[int] = None
    blockchain_confirmed: bool           = False
    etherscan_url: Optional[str]         = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Blockchain verification
# ---------------------------------------------------------------------------

class BlockchainVerifyResponse(BaseModel):
    conversation_id: str
    record_index: int
    verified: bool
    on_chain_digest: str
    local_digest: str
    timestamp: int          # Unix seconds of the on-chain block timestamp
    etherscan_url: str
