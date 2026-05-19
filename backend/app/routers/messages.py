"""
Messages router — send and receive encrypted messages.

All message bodies are ciphertext from the client's perspective. The server
stores and forwards ciphertext blobs without ever seeing plaintext.

Endpoints:
  POST /api/messages/send      -> store ciphertext, queue hash for blockchain
  GET  /api/messages/inbox     -> return messages addressed to current user
  GET  /api/messages/{id}      -> return a specific message by ID
  DELETE /api/messages/{id}    -> soft-delete a message (marks as deleted, keeps hash)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.message import MessageResponse, SendMessageRequest
from app.services import auth_service, redis_service

router = APIRouter()


@router.post("/send", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    payload: SendMessageRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(auth_service.get_current_user),
):
    """
    TODO:
    - Lookup recipient by username
    - Persist Message record (ciphertext, ephemeral key, signature)
    - Compute keccak256(ciphertext) and store on Message
    - Enqueue hash onto Redis stream for blockchain worker
    - Return created message
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/inbox", response_model=list[MessageResponse])
async def get_inbox(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(auth_service.get_current_user),
):
    """
    TODO:
    - Query messages where recipient_id = current_user.id
    - Order by created_at DESC
    - Paginate (add limit/offset query params)
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/{message_id}", response_model=MessageResponse)
async def get_message(
    message_id: str,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(auth_service.get_current_user),
):
    """Return a single message — only accessible by sender or recipient."""
    raise HTTPException(status_code=501, detail="Not implemented yet")
