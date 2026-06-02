"""
Messages router — send, inbox, and fetch endpoints.

After each message is persisted, a BackgroundTask pushes a batch entry to
Redis. When the batch accumulator for a conversation hits BATCH_SIZE (10),
flush_batch_if_ready() fires a single recordBatch() tx on-chain, covering
all 10 messages in one Ethereum transaction.
"""

import base64
import json
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder
from sqlalchemy import select, tuple_, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, get_db
from app.models.message import Message
from app.models.user import User
from app.schemas.message import (
    ForwardMessageRequest,
    ForwardMessageResponse,
    MessageResponse,
    SendMessageRequest,
    SendMessageResponse,
    X3DHInitHeader,
)
from app.services.auth_service import get_current_user
from app.services.blockchain_service import (
    compute_content_hash,
    is_configured,
    flush_batch_if_ready,
    push_to_batch,
    record_event_triggered_digest,
)
from app.services.redis_service import get_redis
from app.services.ws_manager import manager

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bucket_timestamp(dt: datetime, bucket_minutes: int = 15) -> datetime:
    """Floor dt to the nearest bucket_minutes boundary (UTC).

    Stored in the DB so an observer with read access sees only bucketed
    timestamps, degrading timing-correlation attacks. The exact send time
    is inside the AEAD ciphertext (server-opaque) and on Sepolia (blockchain).
    """
    bucket_seconds = bucket_minutes * 60
    epoch = int(dt.timestamp())
    return datetime.fromtimestamp((epoch // bucket_seconds) * bucket_seconds, tz=timezone.utc)


def _conversation_id(user_a_id, user_b_id) -> str:
    """
    Deterministic conversation identifier for a user pair.

    Sorts UUID string representations lexicographically so
    conversation_id(A, B) == conversation_id(B, A).
    This string is used as the on-chain conversationId for the DigestRegistry.
    """
    a, b = str(user_a_id), str(user_b_id)
    return f"{min(a, b)}_{max(a, b)}"


def _to_response(
    msg: Message,
    sender_username: str,
    recipient_username: Optional[str] = None,
) -> MessageResponse:
    """Convert a Message ORM object to a wire-safe MessageResponse.

    The `hpke_enc_blob` column is overloaded: under the legacy HPKE flow it
    holds the RFC 9180 encapsulated key; under the Double Ratchet flow it
    holds a UTF-8 JSON serialisation of the X3DHInitHeader (or empty bytes
    after the first message in the session). We disambiguate by trying to
    parse JSON first.
    """
    tx_hash   = msg.blockchain_tx_hash
    etherscan = f"https://sepolia.etherscan.io/tx/{tx_hash}" if tx_hash else None

    hpke_enc_b64: Optional[str] = None
    x3dh_hdr: Optional[X3DHInitHeader] = None
    raw = msg.hpke_enc_blob or b""
    if raw:
        try:
            obj = json.loads(raw.decode("utf-8"))
            if isinstance(obj, dict) and "ik_a" in obj and "ek_a" in obj:
                x3dh_hdr = X3DHInitHeader(**obj)
            else:
                hpke_enc_b64 = base64.b64encode(raw).decode()
        except (UnicodeDecodeError, json.JSONDecodeError):
            hpke_enc_b64 = base64.b64encode(raw).decode()

    return MessageResponse(
        id=str(msg.id),
        sender_username=sender_username,
        recipient_username=recipient_username,
        ciphertext=base64.b64encode(msg.ciphertext).decode(),
        nonce=base64.b64encode(msg.nonce).decode(),
        hpke_enc_blob=hpke_enc_b64,
        ratchet_pub=msg.ratchet_public_key,
        pn=msg.previous_chain_length,
        n=msg.message_index,
        x3dh_header=x3dh_hdr,
        created_at=msg.created_at,
        blockchain_tx_hash=tx_hash,
        blockchain_block_number=msg.blockchain_block_number,
        blockchain_record_index=msg.blockchain_record_index,
        blockchain_batch_index=msg.blockchain_batch_index,
        blockchain_confirmed=tx_hash is not None,
        etherscan_url=etherscan,
    )


# ---------------------------------------------------------------------------
# Blockchain background task (Tier 1 — batch accumulator)
# ---------------------------------------------------------------------------

async def _push_to_batch_and_maybe_flush(
    message_id: str,
    conversation_id: str,
    sender_id: str,
    timestamp: str,
    content_hash: str,
) -> None:
    """
    Push this message into the per-conversation Redis batch list.
    If the list has reached BATCH_SIZE, flush_batch_if_ready() fires
    a single recordBatch() tx covering all accumulated messages.

    Scheduled via FastAPI BackgroundTasks so it runs after the HTTP response
    is sent — guaranteeing the INSERT is committed before we do any UPDATE.
    Never raises: errors are logged and the app continues normally.
    """
    if not is_configured():
        return
    try:
        new_length = await push_to_batch(
            conversation_id,
            message_id,
            sender_id,
            timestamp,
            content_hash,
        )
        await flush_batch_if_ready(conversation_id, new_length)
    except Exception as exc:
        logger.error("batch push failed for message %s: %s", message_id, exc)


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
        ciphertext_bytes = base64.b64decode(body.ciphertext, validate=True)
        nonce_bytes      = base64.b64decode(body.nonce, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="ciphertext and nonce must be valid base64",
        )

    # Decide what to store in the (NOT NULL) hpke_enc_blob column.
    #   1. Double Ratchet first-message: serialise the X3DH initiator header.
    #   2. Double Ratchet follow-up:     empty bytes.
    #   3. Legacy HPKE:                  decoded HPKE encapsulated key.
    if body.x3dh_header is not None:
        hpke_enc_blob_bytes = json.dumps(
            body.x3dh_header.model_dump(), separators=(",", ":")
        ).encode("utf-8")
    elif body.hpke_enc_blob:
        try:
            hpke_enc_blob_bytes = base64.b64decode(body.hpke_enc_blob, validate=True)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="hpke_enc_blob must be valid base64",
            )
    else:
        hpke_enc_blob_bytes = b""

    # Persist message — created_at is bucketed to 15-min intervals so the
    # server's metadata log reveals only coarse timing to a DB-level attacker.
    # Exact send time lives inside the AEAD ciphertext (server-opaque).
    msg = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        ciphertext=ciphertext_bytes,
        hpke_enc_blob=hpke_enc_blob_bytes,
        nonce=nonce_bytes,
        ratchet_public_key=body.ratchet_pub,
        previous_chain_length=body.pn,
        message_index=body.n,
        created_at=_bucket_timestamp(datetime.now(timezone.utc)),
    )
    db.add(msg)
    await db.flush()  # populate msg.id before the task captures it

    # Real-time delivery: push the full message to the recipient's WebSocket if
    # connected. Scheduled as a BackgroundTask so it fires after get_db() commits
    # the INSERT — the payload is self-contained, so the recipient never needs to
    # refetch and there's no read-before-commit race.
    #
    # Best-effort only: building the payload (db.refresh to load the
    # server-default created_at, MessageResponse serialisation) runs in the
    # request path, so any failure here MUST NOT abort the send. The message is
    # already persisted; a missed push just means the recipient picks it up on
    # their next poll/reconnect. Mirrors the blockchain task's never-raise rule.
    try:
        await db.refresh(msg)  # load created_at (server_default func.now())
        push_payload = {
            "type": "new_message",
            "message": jsonable_encoder(
                _to_response(msg, current_user.username, recipient.username)
            ),
        }
        background_tasks.add_task(manager.send_to_user, str(recipient.id), push_payload)
    except Exception as exc:
        logger.error("ws push scheduling failed for message %s: %s", msg.id, exc)

    conv_id      = _conversation_id(current_user.id, recipient.id)
    timestamp    = datetime.now(timezone.utc).isoformat()
    content_hash = compute_content_hash(body.ciphertext)

    # Tier 1: push to batch accumulator; flush when BATCH_SIZE is reached.
    # BackgroundTasks run after get_db() commits so the INSERT is visible.
    background_tasks.add_task(
        _push_to_batch_and_maybe_flush,
        str(msg.id),
        conv_id,
        str(current_user.id),
        timestamp,
        content_hash,
    )

    return SendMessageResponse(id=str(msg.id))


# ---------------------------------------------------------------------------
# POST /{message_id}/forward
# ---------------------------------------------------------------------------

@router.post("/{message_id}/forward", response_model=ForwardMessageResponse, status_code=status.HTTP_201_CREATED)
async def forward_message(
    message_id: UUID,
    body: ForwardMessageRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession  = Depends(get_db),
):
    # 1. Fetch original message
    result = await db.execute(select(Message).where(Message.id == message_id))
    original = result.scalar_one_or_none()
    if original is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")

    # 2. Caller must be sender or recipient of the original message
    if original.sender_id != current_user.id and original.recipient_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    # 3. Target user must exist
    result = await db.execute(select(User).where(User.id == body.target_user_id))
    target_user = result.scalar_one_or_none()
    if target_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found")

    # 4. Persist the forwarded message in its own session so the INSERT is
    #    committed before record_event_triggered_digest opens its own session
    #    to back-fill the tx_hash — without a prior commit the UPDATE would
    #    target an invisible row.
    async with AsyncSessionLocal() as session:
        new_msg = Message(
            sender_id=current_user.id,
            recipient_id=body.target_user_id,
            ciphertext=original.ciphertext,
            hpke_enc_blob=original.hpke_enc_blob,
            nonce=original.nonce,
            forwarded_from_id=original.id,
        )
        session.add(new_msg)
        await session.flush()
        new_msg_id = str(new_msg.id)
        await session.commit()

    # 5. Tier 2: await blockchain recording directly — timestamp is legally significant
    conv_id   = _conversation_id(original.sender_id, original.recipient_id)
    b64_ctext = base64.b64encode(original.ciphertext).decode()
    blockchain_result = await record_event_triggered_digest(conv_id, new_msg_id, b64_ctext)

    tx_hash   = blockchain_result.get("tx_hash") if blockchain_result else None
    etherscan = f"https://sepolia.etherscan.io/tx/{tx_hash}" if tx_hash else None

    return ForwardMessageResponse(
        id=UUID(new_msg_id),
        tx_hash=tx_hash,
        etherscan_url=etherscan,
    )


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------

async def _cursor_position(db: AsyncSession, message_id: UUID):
    """Return (created_at, id) of a cursor message, or None if it doesn't exist.

    Paging uses the composite (created_at, id) key so the cursor is stable even
    when several messages share a created_at timestamp.
    """
    result = await db.execute(
        select(Message.created_at, Message.id).where(Message.id == message_id)
    )
    return result.one_or_none()


async def _resolve_peer_id(db: AsyncSession, username: str):
    """Resolve a username to its user id, or None if no such user."""
    result = await db.execute(select(User.id).where(User.username == username))
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# GET /inbox
# ---------------------------------------------------------------------------

@router.get("/inbox", response_model=list[MessageResponse])
async def get_inbox(
    limit: int = Query(30, ge=1, le=100),
    before: Optional[UUID] = Query(None, description="Return messages older than this id"),
    after: Optional[UUID] = Query(None, description="Return messages newer than this id"),
    with_user: Optional[str] = Query(None, description="Restrict to messages from this sender"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession  = Depends(get_db),
):
    stmt = (
        select(Message, User.username)
        .join(User, User.id == Message.sender_id)
        .where(Message.recipient_id == current_user.id)
    )

    if with_user is not None:
        peer_id = await _resolve_peer_id(db, with_user)
        if peer_id is None:
            return []
        stmt = stmt.where(Message.sender_id == peer_id)

    if before is not None:
        cur = await _cursor_position(db, before)
        if cur is None:
            return []
        stmt = stmt.where(tuple_(Message.created_at, Message.id) < tuple_(cur.created_at, cur.id))

    if after is not None:
        cur = await _cursor_position(db, after)
        if cur is None:
            return []
        stmt = stmt.where(tuple_(Message.created_at, Message.id) > tuple_(cur.created_at, cur.id))

    stmt = stmt.order_by(Message.created_at.desc(), Message.id.desc()).limit(limit)
    rows = (await db.execute(stmt)).all()
    return [_to_response(msg, username) for msg, username in rows]


# ---------------------------------------------------------------------------
# GET /sent
# ---------------------------------------------------------------------------

@router.get("/sent", response_model=list[MessageResponse])
async def get_sent(
    limit: int = Query(30, ge=1, le=100),
    before: Optional[UUID] = Query(None, description="Return messages older than this id"),
    with_user: Optional[str] = Query(None, description="Restrict to messages to this recipient"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession  = Depends(get_db),
):
    stmt = (
        select(Message, User.username)
        .join(User, User.id == Message.recipient_id)
        .where(Message.sender_id == current_user.id)
    )

    if with_user is not None:
        peer_id = await _resolve_peer_id(db, with_user)
        if peer_id is None:
            return []
        stmt = stmt.where(Message.recipient_id == peer_id)

    if before is not None:
        cur = await _cursor_position(db, before)
        if cur is None:
            return []
        stmt = stmt.where(tuple_(Message.created_at, Message.id) < tuple_(cur.created_at, cur.id))

    stmt = stmt.order_by(Message.created_at.desc(), Message.id.desc()).limit(limit)
    rows = (await db.execute(stmt)).all()
    return [
        _to_response(msg, current_user.username, recipient_username=recipient_username)
        for msg, recipient_username in rows
    ]


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
