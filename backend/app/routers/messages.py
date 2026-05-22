"""
Messages router — send, inbox, and fetch endpoints.

After each message is persisted, a BackgroundTask records a keccak256 digest
of the ciphertext on Ethereum Sepolia via web3.py.  The HTTP response is
returned immediately; the background task runs after the DB session commits,
then updates the message row once the Ethereum transaction is confirmed.
"""

import base64
import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, get_db
from app.models.message import Message
from app.models.user import User
from app.schemas.message import MessageResponse, SendMessageRequest, SendMessageResponse
from app.services.auth_service import get_current_user
from app.services.blockchain_service import is_configured, record_conversation_digest

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _conversation_id(user_a_id, user_b_id) -> str:
    """
    Deterministic conversation identifier for a user pair.

    Sorts UUID string representations lexicographically so
    conversation_id(A, B) == conversation_id(B, A).
    This string is used as the on-chain conversationId for the DigestRegistry.
    """
    a, b = str(user_a_id), str(user_b_id)
    return f"{min(a, b)}_{max(a, b)}"


def _to_response(msg: Message, sender_username: str) -> MessageResponse:
    """Convert a Message ORM object to a wire-safe MessageResponse."""
    tx_hash   = msg.blockchain_tx_hash
    etherscan = f"https://sepolia.etherscan.io/tx/{tx_hash}" if tx_hash else None
    return MessageResponse(
        id=str(msg.id),
        sender_username=sender_username,
        ciphertext=base64.b64encode(msg.ciphertext).decode(),
        hpke_enc_blob=base64.b64encode(msg.hpke_enc_blob).decode(),
        nonce=base64.b64encode(msg.nonce).decode(),
        created_at=msg.created_at,
        blockchain_tx_hash=tx_hash,
        blockchain_block_number=msg.blockchain_block_number,
        blockchain_record_index=msg.blockchain_record_index,
        blockchain_confirmed=tx_hash is not None,
        etherscan_url=etherscan,
    )


# ---------------------------------------------------------------------------
# Blockchain background task
# ---------------------------------------------------------------------------

async def _record_blockchain(
    message_id: str,
    conversation_id: str,
    conversation_text: str,
) -> None:
    """
    Record a keccak256 digest on-chain then update the message row.

    Scheduled via FastAPI BackgroundTasks so it runs after the HTTP response
    is sent — which is after get_db() has committed the INSERT.  Opens its
    own session so it is independent of the request session lifecycle.
    Never raises: errors are logged and the app continues normally.
    """
    if not is_configured():
        return
    try:
        result = await record_conversation_digest(conversation_id, conversation_text)
        async with AsyncSessionLocal() as session:
            await session.execute(
                update(Message)
                .where(Message.id == message_id)
                .values(
                    blockchain_tx_hash=result.get("tx_hash"),
                    blockchain_block_number=result.get("block_number"),
                    blockchain_record_index=result.get("record_index"),
                )
            )
            await session.commit()
        logger.info(
            "blockchain record confirmed | msg=%s tx=%s block=%s idx=%s",
            message_id,
            result.get("tx_hash"),
            result.get("block_number"),
            result.get("record_index"),
        )
    except Exception as exc:
        logger.error("blockchain record failed for message %s: %s", message_id, exc)


# ---------------------------------------------------------------------------
# POST /send
# ---------------------------------------------------------------------------

@router.post("/send", response_model=SendMessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    body: SendMessageRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession  = Depends(get_db),
):
    # Resolve recipient
    result = await db.execute(select(User).where(User.username == body.recipient_username))
    recipient = result.scalar_one_or_none()
    if recipient is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recipient not found")

    # Validate and decode ciphertext blobs
    try:
        ciphertext_bytes    = base64.b64decode(body.ciphertext, validate=True)
        hpke_enc_blob_bytes = base64.b64decode(body.hpke_enc_blob, validate=True)
        nonce_bytes         = base64.b64decode(body.nonce, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ciphertext, hpke_enc_blob, and nonce must be valid base64",
        )

    # Persist message — get_db() commits on success
    msg = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        ciphertext=ciphertext_bytes,
        hpke_enc_blob=hpke_enc_blob_bytes,
        nonce=nonce_bytes,
    )
    db.add(msg)
    await db.flush()  # populate msg.id before the task captures it

    conv_id = _conversation_id(current_user.id, recipient.id)
    # Schedule after response — BackgroundTasks run after get_db() commits,
    # so the INSERT is visible when _record_blockchain opens its own session.
    background_tasks.add_task(
        _record_blockchain,
        str(msg.id),
        conv_id,
        body.ciphertext,  # hash the base64 string; verify endpoint re-encodes the same way
    )

    return SendMessageResponse(id=str(msg.id))


# ---------------------------------------------------------------------------
# GET /inbox
# ---------------------------------------------------------------------------

@router.get("/inbox", response_model=list[MessageResponse])
async def get_inbox(
    current_user: User = Depends(get_current_user),
    db: AsyncSession  = Depends(get_db),
):
    result = await db.execute(
        select(Message, User.username)
        .join(User, User.id == Message.sender_id)
        .where(Message.recipient_id == current_user.id)
        .order_by(Message.created_at.desc())
    )
    rows = result.all()
    return [_to_response(msg, username) for msg, username in rows]


# ---------------------------------------------------------------------------
# GET /{message_id}
# ---------------------------------------------------------------------------

@router.get("/{message_id}", response_model=MessageResponse)
async def get_message(
    message_id: UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession  = Depends(get_db),
):
    result = await db.execute(
        select(Message, User.username)
        .join(User, User.id == Message.sender_id)
        .where(Message.id == message_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")

    msg, sender_username = row
    # Only the sender or recipient may read a message
    if msg.sender_id != current_user.id and msg.recipient_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    return _to_response(msg, sender_username)
