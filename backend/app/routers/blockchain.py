"""
Blockchain router — tamper-evidence verification endpoint.

GET /api/verify/{conversation_id}
  Fetches the most recently confirmed message in a conversation, performs an
  eth_call against MessageDigestRegistry via web3.py, and returns a comparison
  of the local and on-chain digests.

The conversation_id path parameter must be in the canonical format produced
by the messages router: "{min_uuid}_{max_uuid}" (lexicographically sorted
string representations of the two participants' user UUIDs).
"""

import base64
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal, get_db
from app.models.message import Message
from app.schemas.message import BlockchainVerifyResponse
from app.services.auth_service import get_current_user
from app.services.rate_limit import limiter
from app.services.blockchain_service import (
    blockchain_configured,
    record_final_digest,
    verify_on_chain,
)
from app.models.user import User

logger = logging.getLogger(__name__)

# Three routers from this module:
#   router               — mounted at /api/blockchain  (existing prefix)
#   verify_router        — mounted at /api/verify      (task-spec path)
#   conversations_router — mounted at /api/conversations (Tier 3 close endpoint)
router               = APIRouter()
verify_router        = APIRouter()
conversations_router = APIRouter()
public_router        = APIRouter()   # no auth — used by the standalone verify page


# ---------------------------------------------------------------------------
# Shared verification logic
# ---------------------------------------------------------------------------

async def _do_verify(
    conversation_id: str,
    text: Optional[str],
    db: AsyncSession,
    caller_id: uuid.UUID,
) -> BlockchainVerifyResponse:
    if not blockchain_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blockchain integration is not configured on this server.",
        )

    # Parse conversationId → two user UUIDs.  Validation happens first so a
    # malformed ID gets a 422 (not a 403) before any participant check runs,
    # avoiding an information leak about the caller's identity.
    parts = conversation_id.split("_", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="conversation_id must be in the format {uuid1}_{uuid2}",
        )

    try:
        uid_a = uuid.UUID(parts[0])
        uid_b = uuid.UUID(parts[1])
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="conversation_id must be in the format {uuid1}_{uuid2}",
        )

    # Participant check — enforced on every route (public and authenticated).
    # Prevents any authenticated user from probing conversation existence or
    # retrieving on-chain metadata for conversations they are not party to.
    # Runs after UUID parsing so the comparison is always against valid UUIDs.
    if caller_id not in (uid_a, uid_b):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a participant in this conversation",
        )

    # Fetch the most recently confirmed message in this conversation
    result = await db.execute(
        select(Message)
        .where(
            Message.blockchain_record_index.isnot(None),
            (
                (Message.sender_id == uid_a) & (Message.recipient_id == uid_b)
            ) | (
                (Message.sender_id == uid_b) & (Message.recipient_id == uid_a)
            ),
        )
        .order_by(Message.created_at.desc())
        .limit(1)
    )
    msg = result.scalar_one_or_none()
    if msg is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No blockchain-confirmed messages found for this conversation. "
                "Either the conversation does not exist or the on-chain recording "
                "has not completed yet."
            ),
        )

    # Resolve the conversation text to verify:
    #   - If ?text=... is provided, use that directly.
    #   - Otherwise, reconstruct from the stored ciphertext (base64-encode it,
    #     matching what the send endpoint passed to recordConversationDigest).
    if text is not None:
        conversation_text = text
    else:
        conversation_text = base64.b64encode(msg.ciphertext).decode()

    # eth_call via web3.py — awaited (view call, typically < 2 s on Sepolia)
    try:
        result_data = await verify_on_chain(
            conversation_id=conversation_id,
            record_index=msg.blockchain_record_index,
            conversation_text=conversation_text,
        )
    except TimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Blockchain RPC timed out: {exc}",
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Blockchain verification failed: {exc}",
        )

    tx_hash = msg.blockchain_tx_hash or ""
    return BlockchainVerifyResponse(
        conversation_id=conversation_id,
        record_index=msg.blockchain_record_index,
        verified=result_data["verified"],
        on_chain_digest=result_data["onChainDigest"],
        local_digest=result_data["localDigest"],
        timestamp=result_data["timestamp"],
        etherscan_url=f"https://sepolia.etherscan.io/tx/{tx_hash}",
    )


# ---------------------------------------------------------------------------
# Route registered under /api/blockchain (existing API structure)
# ---------------------------------------------------------------------------

@router.get("/verify/{conversation_id}", response_model=BlockchainVerifyResponse)
async def verify_blockchain(
    conversation_id: str,
    text: Optional[str] = Query(default=None, max_length=65536,
                                description="Conversation text to verify. "
                                "If omitted, the stored ciphertext is used."),
    current_user: User = Depends(get_current_user),
    db: AsyncSession   = Depends(get_db),
):
    return await _do_verify(conversation_id, text, db, caller_id=current_user.id)


# ---------------------------------------------------------------------------
# Route registered under /api/verify (task-spec path: /api/verify/:conversationId)
# ---------------------------------------------------------------------------

@verify_router.get("/{conversation_id}", response_model=BlockchainVerifyResponse)
async def verify_blockchain_alias(
    conversation_id: str,
    text: Optional[str] = Query(default=None, max_length=65536,
                                description="Conversation text to verify. "
                                "If omitted, the stored ciphertext is used."),
    current_user: User = Depends(get_current_user),
    db: AsyncSession   = Depends(get_db),
):
    return await _do_verify(conversation_id, text, db, caller_id=current_user.id)


# ---------------------------------------------------------------------------
# GET /public/verify/{conversation_id}
#
# Requires authentication. The participant check is enforced inside _do_verify
# (shared with all three verify routes) so it cannot be bypassed regardless of
# which route is called or how the conversation_id is shaped.
# ---------------------------------------------------------------------------

@public_router.get("/{conversation_id}", response_model=BlockchainVerifyResponse)
@limiter.limit("30/minute")
async def verify_blockchain_public(
    request: Request,
    conversation_id: str,
    text: Optional[str] = Query(default=None, max_length=65536,
                                description="Conversation text to verify. "
                                "If omitted, the stored ciphertext is used."),
    current_user: User = Depends(get_current_user),
    db: AsyncSession   = Depends(get_db),
):
    return await _do_verify(conversation_id, text, db, caller_id=current_user.id)


# ---------------------------------------------------------------------------
# POST /api/conversations/{conversation_id}/close  (Tier 3 — final digest)
# ---------------------------------------------------------------------------

@conversations_router.post("/{conversation_id}/close")
async def close_conversation(
    conversation_id: str,
    current_user: User = Depends(get_current_user),
):
    """
    Tier 3 — conversation close.

    Flushes any remaining sub-batch messages from Redis then records a final
    closing digest on-chain that hashes all confirmed tx_hashes for the
    conversation. This gives an auditable "end-of-conversation" anchor that
    proves the complete message sequence existed at a specific block.

    The caller must be one of the two participants in the conversation
    (validated by the conversation_id format check below).
    """
    if not blockchain_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blockchain integration is not configured on this server.",
        )

    # Validate conversation_id format and ensure caller is a participant.
    parts = conversation_id.split("_", 1)
    if len(parts) != 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="conversation_id must be in the format {uuid1}_{uuid2}",
        )
    try:
        uid_a = uuid.UUID(parts[0])
        uid_b = uuid.UUID(parts[1])
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="conversation_id must be in the format {uuid1}_{uuid2}",
        )

    if current_user.id not in (uid_a, uid_b):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a participant in this conversation.",
        )

    try:
        result = await record_final_digest(conversation_id)
    except TimeoutError as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Blockchain RPC timed out: {exc}",
        )
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Final digest recording failed: {exc}",
        )

    return result
