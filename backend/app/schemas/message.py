"""
Pydantic schemas for message and blockchain verification endpoints.

The server never sees plaintext — clients encrypt before sending and decrypt
after receiving.  The API deals exclusively with ciphertext blobs and metadata.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Send message
# ---------------------------------------------------------------------------

class X3DHInitHeader(BaseModel):
    """Header carried on the first Double Ratchet message of a new session.

    Lets the recipient run x3dh_receive to derive the shared root key before
    decrypting. Absent on every subsequent message in the same session.
    """
    ik_a: str          = Field(..., description="Base64 sender X25519 identity public key")
    ek_a: str          = Field(..., description="Base64 sender X25519 ephemeral public key")
    used_opk_pub: Optional[str] = Field(None, description="Base64 of the recipient OPK consumed by this handshake, or null")


class SendMessageRequest(BaseModel):
    recipient_username: str
    ciphertext: str    = Field(..., description="Base64-encoded AEAD ciphertext")
    nonce: str         = Field(..., description="Base64-encoded AEAD nonce")
    # hpke_enc_blob remains for legacy HPKE flows; Double Ratchet senders omit it.
    hpke_enc_blob: Optional[str] = Field(None, description="Base64 HPKE encapsulated key (legacy HPKE flow only)")
    # Double Ratchet header — required on Double Ratchet ciphertexts.
    ratchet_pub: Optional[str]   = Field(None, description="Base64 sender DH ratchet public key")
    pn: Optional[int]            = Field(None, description="Previous sending-chain length")
    n: Optional[int]             = Field(None, description="Index within the current sending chain")
    # First message of a new session carries the X3DH initiator header so the
    # recipient can run x3dh_receive before decrypting.
    x3dh_header: Optional[X3DHInitHeader] = None


class SendMessageResponse(BaseModel):
    id: str
    blockchain_pending: bool = True


# ---------------------------------------------------------------------------
# Message responses
# ---------------------------------------------------------------------------

class MessageResponse(BaseModel):
    id: str
    sender_username: str
    recipient_username: Optional[str] = None  # populated by /sent so the client can thread by peer
    ciphertext: str                       # base64-encoded
    nonce: str                            # base64-encoded
    hpke_enc_blob: Optional[str] = None   # base64-encoded; null for Double Ratchet messages
    ratchet_pub: Optional[str]   = None
    pn: Optional[int]            = None
    n: Optional[int]             = None
    x3dh_header: Optional[X3DHInitHeader] = None
    created_at: datetime
    blockchain_tx_hash: Optional[str]    = None
    blockchain_block_number: Optional[int] = None
    blockchain_record_index: Optional[int] = None
    blockchain_batch_index: Optional[int]  = None
    blockchain_confirmed: bool           = False
    etherscan_url: Optional[str]         = None

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Message forwarding
# ---------------------------------------------------------------------------

class ForwardMessageRequest(BaseModel):
    target_user_id: UUID


class ForwardMessageResponse(BaseModel):
    id: UUID
    tx_hash: Optional[str] = None
    etherscan_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Access revocation
# ---------------------------------------------------------------------------

class RevokeAccessResponse(BaseModel):
    revoked_user_id: UUID
    conversation_id: str
    tx_hash: Optional[str] = None
    etherscan_url: Optional[str] = None
    revoked_at: datetime


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
