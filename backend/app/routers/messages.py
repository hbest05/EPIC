import base64
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.database import get_db
from app.models.message import Message
from app.models.user import User
from app.schemas.message import MessageResponse, SendMessageRequest
from app.services.auth_service import get_current_user

router = APIRouter()


def _to_response(msg: Message, sender_username: str) -> MessageResponse:
    return MessageResponse(
        id=str(msg.id),
        sender_username=sender_username,
        ciphertext=base64.b64encode(bytes(msg.ciphertext)).decode(),
        nonce=base64.b64encode(bytes(msg.nonce)).decode(),
        ratchet_public_key=msg.ratchet_public_key,
        previous_chain_length=msg.previous_chain_length,
        message_index=msg.message_index,
        identity_key_pub=None,
        ephemeral_key_pub=None,
        blockchain_confirmed=False,
        created_at=msg.created_at,
    )


@router.post("/send")
async def send_message(
    body: SendMessageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(User).where(User.username == body.recipient_username))
    recipient = result.scalar_one_or_none()
    if recipient is None:
        raise HTTPException(status_code=404, detail="Recipient not found")

    msg = Message(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        ciphertext=base64.b64decode(body.ciphertext),
        nonce=base64.b64decode(body.nonce),
        hpke_enc_blob=b"",
        ratchet_public_key=body.ratchet_public_key,
        previous_chain_length=body.previous_chain_length,
        message_index=body.message_index,
    )
    db.add(msg)
    await db.flush()
    return {"message_id": str(msg.id)}


@router.get("/inbox")
async def inbox(
    since: Optional[datetime] = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    SenderUser = aliased(User)
    stmt = (
        select(Message, SenderUser.username)
        .join(SenderUser, Message.sender_id == SenderUser.id)
        .where(Message.recipient_id == current_user.id)
    )
    if since is not None:
        stmt = stmt.where(Message.created_at > since)
    stmt = stmt.order_by(Message.created_at.asc())

    result = await db.execute(stmt)
    return [_to_response(msg, sender_username) for msg, sender_username in result.all()]


@router.get("/{message_id}")
async def get_message(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        msg_uuid = uuid.UUID(message_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Message not found")

    SenderUser = aliased(User)
    result = await db.execute(
        select(Message, SenderUser.username)
        .join(SenderUser, Message.sender_id == SenderUser.id)
        .where(Message.id == msg_uuid)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Message not found")

    msg, sender_username = row
    if msg.sender_id != current_user.id and msg.recipient_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    return _to_response(msg, sender_username)
