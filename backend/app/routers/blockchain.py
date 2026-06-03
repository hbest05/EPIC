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

from datetime import datetime, timezone

from app.database import AsyncSessionLocal, get_db
from app.models.message import Message
from app.models.revocation import ConversationRevocation
from app.schemas.message import BlockchainVerifyResponse, RevokeAccessResponse
from app.services.auth_service import get_current_user
from app.services.rate_limit import limiter
from app.services.blockchain_service import (
    blockchain_configured,
    record_event_triggered_digest,
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


@router.get("/status")
async def blockchain_status():
    """Returns whether blockchain integration is configured on this server."""
    return {"configured": blockchain_configured()}


# ---------------------------------------------------------------------------
# Shared verification logic
# ---------------------------------------------------------------------------

async def _do_verify(
    conversation_id: str,
    text: Optional[str],
    db: AsyncSession,
    caller_id: Optional[uuid.UUID] = None,
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

    # Participant check — only enforced for authenticated callers.
    # The public verify route passes caller_id=None and skips this check
    # so the standalone verify page works without a session.
    if caller_id is not None and caller_id not in (uid_a, uid_b):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a participant in this conversation",
        )

    # Fetch the most recently confirmed message in this conversation
    result = await db.execute(
        select(Message)
        .where(
            Message.blockchain_tx_hash.isnot(None),
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
            conversation_text=conversation_text,
            record_index=msg.blockchain_record_index,
            batch_index=msg.blockchain_batch_index,
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

    tx_hash   = msg.blockchain_tx_hash or ""
    idx       = msg.blockchain_record_index if msg.blockchain_record_index is not None else msg.blockchain_batch_index
    return BlockchainVerifyResponse(
        conversation_id=conversation_id,
        record_index=idx if idx is not None else 0,
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
# GET /api/verify-public/by-users?user_a=alice&user_b=bob
#
# Username-pair lookup — resolves two usernames to their UUIDs, constructs
# the canonical conversation_id, then delegates to _do_verify.
# No authentication required; rate-limited to 30 req/min per IP.
# MUST be defined before /{conversation_id} so FastAPI matches it first.
# ---------------------------------------------------------------------------

@public_router.get("/by-users", response_model=BlockchainVerifyResponse)
@limiter.limit("30/minute")
async def verify_blockchain_by_users(
    request: Request,
    user_a: str = Query(..., max_length=64, description="First participant's username"),
    user_b: str = Query(..., max_length=64, description="Second participant's username"),
    text: Optional[str] = Query(default=None, max_length=65536),
    db: AsyncSession = Depends(get_db),
):
    if user_a.lower() == user_b.lower():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="user_a and user_b must be different users",
        )

    result_a = await db.execute(select(User).where(User.username == user_a))
    result_b = await db.execute(select(User).where(User.username == user_b))
    ua = result_a.scalar_one_or_none()
    ub = result_b.scalar_one_or_none()

    if ua is None or ub is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No blockchain record found for this conversation.",
        )

    a, b = str(ua.id), str(ub.id)
    conversation_id = f"{min(a, b)}_{max(a, b)}"
    return await _do_verify(conversation_id, text, db)


# ---------------------------------------------------------------------------
# GET /api/verify-public/{conversation_id}
#
# No authentication required — used by the standalone verify.html page.
# The participant check is skipped; rate-limited to 30 req/min per IP.
# ---------------------------------------------------------------------------

@public_router.get("/{conversation_id}", response_model=BlockchainVerifyResponse)
@limiter.limit("30/minute")
async def verify_blockchain_public(
    request: Request,
    conversation_id: str,
    text: Optional[str] = Query(default=None, max_length=65536,
                                description="Conversation text to verify. "
                                "If omitted, the stored ciphertext is used."),
    db: AsyncSession = Depends(get_db),
):
    return await _do_verify(conversation_id, text, db)


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


# ---------------------------------------------------------------------------
# POST /api/conversations/{conversation_id}/revoke/{user_id}  (Tier 2)
# ---------------------------------------------------------------------------

@conversations_router.post("/{conversation_id}/revoke/{user_id}", response_model=RevokeAccessResponse)
async def revoke_access(
    conversation_id: str,
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession   = Depends(get_db),
):
    """
    Tier 2 — revoke a participant's access to a conversation.

    Persists a ConversationRevocation row regardless of blockchain availability,
    then records the revocation immediately on-chain via recordDigest() so the
    timestamp of the revocation act is provably anchored.

    Blocks: self-revocation; non-participant caller; non-participant target.
    """
    # Validate conversation_id and participant membership.
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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="You are not a participant in this conversation.")

    if user_id not in (uid_a, uid_b):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Target user is not a participant in this conversation.")

    if user_id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="You cannot revoke your own access.")

    revoked_at = datetime.now(timezone.utc)

    # Persist revocation regardless of blockchain availability — dedicated
    # session with explicit commit so the row is visible to the back-fill UPDATE.
    async with AsyncSessionLocal() as session:
        revocation = ConversationRevocation(
            conversation_id=conversation_id,
            revoked_user_id=user_id,
            revoked_by_id=current_user.id,
            revoked_at=revoked_at,
        )
        session.add(revocation)
        await session.commit()
        await session.refresh(revocation)
        revocation_id = str(revocation.id)

    # Tier 2 — record revocation event on-chain immediately.
    blockchain_result = await record_event_triggered_digest(
        conversation_id=conversation_id,
        message_id=revocation_id,
        conversation_text=f"revoke:{user_id}:{revoked_at.isoformat()}",
    )

    tx_hash   = blockchain_result.get("tx_hash") if blockchain_result else None
    etherscan = f"https://sepolia.etherscan.io/tx/{tx_hash}" if tx_hash else None

    return RevokeAccessResponse(
        revoked_user_id=str(user_id),
        conversation_id=conversation_id,
        tx_hash=tx_hash,
        etherscan_url=etherscan,
        revoked_at=revoked_at,
    )
