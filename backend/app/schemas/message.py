from datetime import datetime

from pydantic import BaseModel


class SendMessageRequest(BaseModel):
    recipient_username: str
    ciphertext: str
    nonce: str
    ratchet_public_key: str
    previous_chain_length: int
    message_index: int
    identity_key_pub: str | None = None
    ephemeral_key_pub: str | None = None


class MessageResponse(BaseModel):
    id: str
    sender_username: str
    ciphertext: str
    nonce: str
    ratchet_public_key: str | None
    previous_chain_length: int | None
    message_index: int | None
    identity_key_pub: str | None
    ephemeral_key_pub: str | None
    blockchain_confirmed: bool
    created_at: datetime
