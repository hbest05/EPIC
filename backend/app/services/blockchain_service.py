"""
blockchain_service.py — Native Python web3.py implementation of the
MessageDigestRegistry integration.

Replaces the previous Python → Node.js subprocess bridge entirely.
All Ethereum calls are made directly from Python using AsyncWeb3 so
no Node.js runtime is required in the backend container.

Provider pattern (REQUIRED — do not change):
    from web3 import AsyncWeb3
    from web3.providers import AsyncHTTPProvider
    w3 = AsyncWeb3(AsyncHTTPProvider(RPC_URL))

Recording is fire-and-forget: the HTTP response is returned before
Ethereum confirms the transaction.  A background coroutine updates
the message row once the receipt arrives.  All errors are caught and
logged — the app stays functional even when Sepolia is unreachable.

Verification is awaited: getRecord() is an eth_call (view function)
and typically resolves in < 2 s on a public RPC endpoint.

Public interface (unchanged — routers require zero modifications):
    is_configured() / blockchain_configured()  → bool
    verify_on_chain(conversation_id, record_index, conversation_text) → dict
"""

import asyncio
import json
import logging
import pathlib
import uuid as _uuid_mod
from datetime import datetime, timezone
from typing import Optional

from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

from sqlalchemy import and_, or_, select, update

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.message import Message
from app.services.redis_service import get_redis

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ABI loading
#
# The ABI is copied into the Docker image at /abi/MessageDigestRegistryABI.json
# (outside /app so the dev hot-reload volume mount does not shadow it).
# For local development without Docker the file is resolved relative to the
# repo root's blockchain/ directory.
# ---------------------------------------------------------------------------

_ABI_CANDIDATES = [
    pathlib.Path("/abi/MessageDigestRegistryABI.json"),  # Docker image path (COPY'd at build time)
    # Local dev: blockchain_service.py lives at backend/app/services/; four levels up → repo root
    pathlib.Path(__file__).parent.parent.parent.parent / "blockchain" / "MessageDigestRegistryABI.json",
]


def _load_abi() -> list:
    for candidate in _ABI_CANDIDATES:
        if candidate.exists():
            return json.loads(candidate.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        "MessageDigestRegistryABI.json not found. "
        f"Searched: {[str(p) for p in _ABI_CANDIDATES]}"
    )


# Load eagerly — if the file is missing it is a misconfiguration and we want
# to know at startup, not on the first blockchain call.
try:
    _ABI: Optional[list] = _load_abi()
except FileNotFoundError as _abi_err:
    _ABI = None
    logger.warning("ABI not found at startup (%s) — blockchain calls will fail", _abi_err)

# ---------------------------------------------------------------------------
# Lazy-initialised Web3 context
#
# AsyncWeb3(AsyncHTTPProvider(...)) does NOT open a connection at init time;
# the first network call triggers the actual TCP connection.  This means we
# can initialise the objects synchronously here even though w3 is async.
# ---------------------------------------------------------------------------

_w3:       Optional[AsyncWeb3] = None
_contract: Optional[object]   = None
_account:  Optional[object]   = None


def _ctx() -> tuple:
    """
    Return (w3, contract, account) initialised from settings.
    Raises RuntimeError if configuration is missing.
    """
    global _w3, _contract, _account

    if _w3 is None:
        rpc_url          = settings.rpc_url or settings.eth_rpc_url
        private_key      = settings.private_key or settings.eth_private_key
        contract_address = settings.contract_address

        if not (rpc_url and private_key and contract_address):
            raise RuntimeError(
                "Blockchain not configured. Set RPC_URL, PRIVATE_KEY, and "
                "CONTRACT_ADDRESS environment variables."
            )
        if _ABI is None:
            raise RuntimeError(
                "Contract ABI not loaded. Ensure MessageDigestRegistryABI.json "
                "is accessible (see _ABI_CANDIDATES in blockchain_service.py)."
            )

        _w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url, request_kwargs={"timeout": 60}))
        # from_key() is synchronous — derives the account address from the key.
        # PRIVATE_KEY is never logged; the account object only exposes the address.
        _account  = _w3.eth.account.from_key(private_key)
        _contract = _w3.eth.contract(
            address=AsyncWeb3.to_checksum_address(contract_address),
            abi=_ABI,
        )

    return _w3, _contract, _account


# ---------------------------------------------------------------------------
# Configuration check
# ---------------------------------------------------------------------------

def is_configured() -> bool:
    """
    Return True if all three required env vars are present and the ABI loaded.
    Logs a warning (once) when False so operators can diagnose missing config.
    """
    pk  = settings.private_key or settings.eth_private_key
    rpc = settings.rpc_url     or settings.eth_rpc_url
    ca  = settings.contract_address
    ok  = bool(pk and rpc and ca and _ABI)
    if not ok:
        missing = [n for n, v in [("PRIVATE_KEY", pk), ("RPC_URL", rpc), ("CONTRACT_ADDRESS", ca)] if not v]
        if missing:
            logger.warning("Blockchain not configured — missing: %s", ", ".join(missing))
        elif _ABI is None:
            logger.warning("Blockchain not configured — ABI file not found")
    return ok


# Alias used by both routers (imported by exact name — do not rename).
blockchain_configured = is_configured


def compute_content_hash(ciphertext_b64: str) -> str:
    """
    Compute keccak256 of the ciphertext string.
    Used to pre-hash content before storing in the Redis batch accumulator,
    keeping the stored value compact and consistent with what goes on-chain.
    """
    w3 = _w3 if _w3 is not None else AsyncWeb3()
    return w3.keccak(text=ciphertext_b64).hex()


# ---------------------------------------------------------------------------
# Core async functions
# ---------------------------------------------------------------------------

async def record_conversation_digest(
    conversation_id: str,
    conversation_text: str,
) -> dict:
    """
    Hash conversation_text with keccak256 and record the digest on-chain.

    Steps:
      1. Compute digest = keccak256(UTF-8 bytes of conversation_text)
      2. Fetch nonce, gas price, chain id from the RPC node
      3. Build the recordDigest(...) transaction
      4. Sign with the server wallet's private key
      5. Broadcast and wait for 1 confirmation
      6. Parse the DigestRecorded event to extract recordIndex

    Returns:
        {"tx_hash": str, "block_number": int, "record_index": int | None}

    Raises on any RPC or signing error — caller must catch.
    """
    w3, contract, account = _ctx()

    # 1. keccak256(utf-8 bytes) — identical to JS ethers.keccak256(ethers.toUtf8Bytes(...))
    digest: bytes = w3.keccak(text=conversation_text)  # 32-byte HexBytes

    # 2. Chain parameters — fetched in parallel to minimise RPC round-trips
    nonce, gas_price, chain_id = await asyncio.gather(
        w3.eth.get_transaction_count(account.address),
        w3.eth.gas_price,
        w3.eth.chain_id,
    )

    fn = contract.functions.recordDigest(conversation_id, digest)

    # 3. Estimate gas with a 20 % safety buffer
    gas_estimate = await fn.estimate_gas({"from": account.address})

    # 4. Build the transaction (legacy gas pricing — works on all EVM networks)
    tx = await fn.build_transaction({
        "from":     account.address,
        "nonce":    nonce,
        "gas":      int(gas_estimate * 1.2),
        "gasPrice": int(gas_price * 1.1),  # 10 % above current to help priority
        "chainId":  chain_id,
    })

    # 5. Sign (synchronous — no network call) and broadcast
    signed  = account.sign_transaction(tx)
    tx_hash = await w3.eth.send_raw_transaction(signed.raw_transaction)

    # 6. Wait for 1 block confirmation (timeout matches ~2 Sepolia block times)
    receipt = await w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    # 7. Parse DigestRecorded event to extract the recordIndex
    #    recordIndex is uint256 indexed — process_receipt decodes it correctly.
    record_index: Optional[int] = None
    try:
        events = contract.events.DigestRecorded().process_receipt(receipt)
        if events:
            record_index = int(events[0]["args"]["recordIndex"])
    except Exception as exc:
        logger.warning("Could not parse DigestRecorded event: %s", exc)

    return {
        "tx_hash":      receipt["transactionHash"].hex(),
        "block_number": receipt["blockNumber"],
        "record_index": record_index,
    }


async def verify_digest(
    conversation_id: str,
    conversation_text: str,
    record_index: int,
) -> dict:
    """
    Verify a conversation segment against its on-chain digest.

    Recomputes the keccak256 hash locally and compares it to the value stored
    at record_index in the contract.  getRecord() is a view call (eth_call) —
    gas-free and requires no signing.

    Returns a dict with camelCase keys matching the old verifyDigestCli.js
    output so blockchain.py router requires zero changes:
        {
            "verified":              bool,
            "onChainDigest":         "0x...",
            "localDigest":           "0x...",
            "timestamp":             int,       # Unix seconds
            "recorder":              "0x...",   # submitting wallet address
            "onChainConversationId": str,
        }

    Raises on RPC error — caller handles HTTP error response.
    """
    w3, contract, _ = _ctx()

    # Recompute hash locally — same algorithm used in record_conversation_digest
    local_digest: bytes = w3.keccak(text=conversation_text)

    # eth_call — no gas, no signing, typically < 1 s
    on_chain_digest, timestamp, recorder, on_chain_conv_id = (
        await contract.functions.getRecord(record_index).call()
    )

    verified = local_digest == on_chain_digest

    return {
        "verified":              verified,
        "onChainDigest":         "0x" + on_chain_digest.hex(),   # camelCase — matches blockchain.py
        "localDigest":           "0x" + local_digest.hex(),      # camelCase — matches blockchain.py
        "timestamp":             timestamp,
        "recorder":              recorder,
        "onChainConversationId": on_chain_conv_id,
    }


async def get_on_chain_record(record_index: int) -> dict:
    """
    Fetch a single record from the contract by index.

    Returns:
        {"digest": "0x...", "timestamp": int, "recorder": "0x...", "conversation_id": str}

    Raises on RPC error or out-of-bounds index (contract reverts with panic 0x32).
    """
    w3, contract, _ = _ctx()

    digest_bytes, timestamp, recorder, conversation_id = (
        await contract.functions.getRecord(record_index).call()
    )

    return {
        "digest":          "0x" + digest_bytes.hex(),
        "timestamp":       timestamp,
        "recorder":        recorder,
        "conversation_id": conversation_id,
    }


# ---------------------------------------------------------------------------
# Background recording (fire-and-forget)
# ---------------------------------------------------------------------------

async def _record_and_update(
    message_id: str,
    conversation_id: str,
    conversation_text: str,
) -> None:
    """
    Record digest on-chain then update the message row with the result.
    Never raises — errors are logged so callers are unaffected.
    """
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
        # Never propagate — the app must function when Sepolia is unreachable.
        logger.error("blockchain record failed for message %s: %s", message_id, exc)


# ---------------------------------------------------------------------------
# Batch accumulator (Tier 1)
#
# Each message is pushed to a Redis List keyed per conversation.
# When the list length hits BATCH_SIZE the Lua script atomically pops all
# entries, computes a deterministic JSON digest, and submits one tx.
# ---------------------------------------------------------------------------

BATCH_SIZE = 10
_REDIS_BATCH_KEY_PREFIX = "blockchain:batch:"

# Atomic LRANGE + DEL — returns all items then removes the key in one round-trip.
# Returns empty list if the key does not exist (safe to call unconditionally).
_LUA_POP_ALL = """
local items = redis.call('LRANGE', KEYS[1], 0, -1)
redis.call('DEL', KEYS[1])
return items
"""


def _batch_key(conversation_id: str) -> str:
    return f"{_REDIS_BATCH_KEY_PREFIX}{conversation_id}"


def _build_batch_payload(entries: list[dict]) -> str:
    """
    Deterministic JSON encoding of a list of message dicts.
    Sorted by message_id so the hash is stable regardless of arrival order.
    """
    sorted_entries = sorted(entries, key=lambda e: e["message_id"])
    return json.dumps(sorted_entries, sort_keys=True, separators=(",", ":"))


async def push_to_batch(
    conversation_id: str,
    message_id: str,
    sender_id: str,
    timestamp: str,
    content_hash: str,
) -> int:
    """
    Push one message entry to the per-conversation Redis batch list.
    Returns the new list length (used by flush_batch_if_ready).
    """
    redis = get_redis()
    entry = json.dumps({
        "message_id":  message_id,
        "sender_id":   sender_id,
        "timestamp":   timestamp,
        "content_hash": content_hash,
    }, sort_keys=True, separators=(",", ":"))
    length = await redis.rpush(_batch_key(conversation_id), entry)
    length = int(length)
    logger.warning("BATCH push conv=%s msg=%s list_length=%d/%d",
                   conversation_id[:16], message_id[:8], length, BATCH_SIZE)
    return length


async def flush_batch(conversation_id: str) -> Optional[dict]:
    """
    Atomically pop all entries for a conversation, hash them, and record
    a single recordBatch() tx on-chain.

    Returns the tx result dict or None if the list was empty or blockchain
    is not configured.  Never raises — errors are logged.
    """
    if not is_configured():
        return None

    redis = get_redis()
    raw_items: list[str] = await redis.eval(
        _LUA_POP_ALL, 1, _batch_key(conversation_id)
    )
    if not raw_items:
        return None

    entries = [json.loads(item) for item in raw_items]
    payload = _build_batch_payload(entries)
    logger.warning("BATCH popped %d entries from Redis, building tx", len(entries))

    w3, contract, account = _ctx()
    digest: bytes = w3.keccak(text=payload)
    logger.warning("BATCH digest=%s account=%s — fetching nonce/gas", digest.hex()[:16], account.address)

    nonce, gas_price, chain_id = await asyncio.gather(
        w3.eth.get_transaction_count(account.address),
        w3.eth.gas_price,
        w3.eth.chain_id,
    )

    fn = contract.functions.recordBatch(conversation_id, digest, len(entries))
    gas_estimate = await fn.estimate_gas({"from": account.address})

    tx = await fn.build_transaction({
        "from":     account.address,
        "nonce":    nonce,
        "gas":      int(gas_estimate * 1.2),
        "gasPrice": int(gas_price * 1.1),
        "chainId":  chain_id,
    })

    signed  = account.sign_transaction(tx)
    tx_hash = await w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = await w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    batch_index: Optional[int] = None
    try:
        events = contract.events.BatchDigestRecorded().process_receipt(receipt)
        if events:
            batch_index = int(events[0]["args"]["batchIndex"])
    except Exception as exc:
        logger.warning("Could not parse BatchDigestRecorded event: %s", exc)

    result = {
        "tx_hash":      receipt["transactionHash"].hex(),
        "block_number": receipt["blockNumber"],
        "batch_index":  batch_index,
        "message_count": len(entries),
        "message_ids":  [e["message_id"] for e in entries],
    }

    # Back-fill blockchain_batch_index on all messages in this batch.
    try:
        async with AsyncSessionLocal() as session:
            for entry in entries:
                await session.execute(
                    update(Message)
                    .where(Message.id == entry["message_id"])
                    .values(
                        blockchain_tx_hash=result["tx_hash"],
                        blockchain_block_number=result["block_number"],
                        blockchain_batch_index=batch_index,
                    )
                )
            await session.commit()
    except Exception as exc:
        logger.error("Failed to back-fill batch blockchain fields: %s", exc)

    logger.info(
        "batch blockchain record confirmed | conv=%s tx=%s block=%s idx=%s msgs=%d",
        conversation_id,
        result["tx_hash"],
        result["block_number"],
        batch_index,
        len(entries),
    )
    return result


async def flush_batch_if_ready(conversation_id: str, current_length: int) -> None:
    """
    Flush the batch only when it has reached BATCH_SIZE.
    Runs flush_batch as an independent event-loop task so it is not cancelled
    when the HTTP request context closes before the RPC calls complete.
    """
    if current_length < BATCH_SIZE:
        logger.warning("BATCH not ready conv=%s length=%d/%d",
                       conversation_id[:16], current_length, BATCH_SIZE)
        return
    logger.warning("BATCH threshold reached conv=%s — scheduling flush", conversation_id[:16])
    asyncio.ensure_future(_flush_batch_guarded(conversation_id))


async def _flush_batch_guarded(conversation_id: str) -> None:
    logger.warning("BATCH flush starting conv=%s", conversation_id[:16])
    try:
        result = await flush_batch(conversation_id)
        if result:
            logger.warning("BATCH flush SUCCESS conv=%s tx=%s block=%s",
                           conversation_id[:16], result.get("tx_hash","?")[:16], result.get("block_number","?"))
        else:
            logger.warning("BATCH flush returned None conv=%s", conversation_id[:16])
    except Exception as exc:
        logger.error("BATCH flush FAILED conv=%s: %s", conversation_id[:16], exc, exc_info=True)


# ---------------------------------------------------------------------------
# Event-triggered single digest (Tier 2)
# ---------------------------------------------------------------------------

async def record_event_triggered_digest(
    conversation_id: str,
    message_id: str,
    conversation_text: str,
) -> Optional[dict]:
    """
    Record a single-message digest immediately on-chain using recordDigest().
    Uses a composite conversationId of the form '<conv_id>:event:<msg_id>'
    so event-triggered records are distinguishable from batch records in the
    contract's indexes without conflicting with the batch accumulator key.

    Returns {"tx_hash": str, "block_number": int, "record_index": int | None}
    on success, or None if blockchain is not configured or an error occurs.
    Never raises — errors are logged.
    """
    if not is_configured():
        return None
    composite_id = f"{conversation_id}:event:{message_id}"
    try:
        result = await record_conversation_digest(composite_id, conversation_text)
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
            "event-triggered record confirmed | msg=%s tx=%s",
            message_id, result.get("tx_hash"),
        )
        return result
    except Exception as exc:
        logger.error("event-triggered record failed for msg=%s: %s", message_id, exc)
        return None


# ---------------------------------------------------------------------------
# Final digest on conversation close (Tier 3)
# ---------------------------------------------------------------------------

async def record_final_digest(conversation_id: str) -> dict:
    """
    Flush any remaining queued messages then record a closing digest that
    hashes all confirmed tx_hashes for the conversation.

    Steps:
      1. Flush any sub-BATCH_SIZE remainder from the Redis list.
      2. Query all blockchain_tx_hash values for the conversation from DB.
      3. Hash the sorted list of tx_hashes with keccak256.
      4. Record via recordDigest() with conversationId '<conv_id>:final'.

    Returns a summary dict.  Raises on RPC/DB errors — caller maps to HTTP.
    """
    # Flush remaining batch entries (may be 0–9 messages).
    flush_result = None
    try:
        flush_result = await flush_batch(conversation_id)
    except Exception as exc:
        logger.warning("flush_batch during close failed for conv=%s: %s", conversation_id, exc)

    # Parse conversation_id into the two participant UUIDs so we can filter
    # the query to only messages that belong to this conversation.
    # Format guaranteed by the close endpoint: '<min_uuid>_<max_uuid>'.
    _parts = conversation_id.split("_", 1)
    uid_a = _uuid_mod.UUID(_parts[0])
    uid_b = _uuid_mod.UUID(_parts[1])

    # Collect confirmed tx_hashes for this conversation only.
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            select(Message.blockchain_tx_hash)
            .where(
                Message.blockchain_tx_hash.isnot(None),
                or_(
                    and_(Message.sender_id == uid_a, Message.recipient_id == uid_b),
                    and_(Message.sender_id == uid_b, Message.recipient_id == uid_a),
                ),
            )
            .order_by(Message.created_at.asc())
        )
        tx_hashes = [row[0] for row in result.all() if row[0]]

    if not tx_hashes:
        return {"status": "no_confirmed_transactions", "flush": flush_result}

    sorted_hashes = sorted(tx_hashes)
    final_text = json.dumps(sorted_hashes, separators=(",", ":"))

    final_conv_id = f"{conversation_id}:final"
    record_result = await record_conversation_digest(final_conv_id, final_text)

    logger.info(
        "final digest recorded | conv=%s tx=%s tx_count=%d",
        conversation_id, record_result.get("tx_hash"), len(tx_hashes),
    )
    return {
        "status":        "ok",
        "tx_hash":       record_result.get("tx_hash"),
        "block_number":  record_result.get("block_number"),
        "record_index":  record_result.get("record_index"),
        "tx_hash_count": len(tx_hashes),
        "flush":         flush_result,
    }


async def verify_batch_digest(
    conversation_id: str,
    conversation_text: str,  # unused — kept for API compat; payload rebuilt from DB
    batch_index: int,
) -> dict:
    """
    Verify a batch record via getBatch(batch_index).
    Reconstructs the original batch payload from the DB so the local digest
    matches exactly what was submitted on-chain.
    """
    import base64 as _b64
    from app.database import AsyncSessionLocal
    from app.models.message import Message as _Msg

    # Fetch all messages that belong to this batch.
    async with AsyncSessionLocal() as session:
        rows = (await session.execute(
            select(_Msg)
            .where(_Msg.blockchain_batch_index == batch_index)
            .order_by(_Msg.created_at)
        )).scalars().all()

    entries = [
        {
            "message_id":   str(row.id),
            "sender_id":    str(row.sender_id),
            "timestamp":    row.created_at.isoformat(),
            "content_hash": compute_content_hash(_b64.b64encode(row.ciphertext).decode()),
        }
        for row in rows
    ]

    w3, contract, _ = _ctx()
    local_payload = _build_batch_payload(entries)
    local_digest: bytes = w3.keccak(text=local_payload)

    digest, timestamp, _, on_chain_conv_id, _ = (
        await contract.functions.getBatch(batch_index).call()
    )

    verified = local_digest == digest
    if not verified:
        logger.warning(
            "VERIFY mismatch batch_index=%s entries=%d local_payload_prefix=%.80s",
            batch_index, len(entries), local_payload
        )

    return {
        "verified":        verified,
        "onChainDigest":   "0x" + digest.hex(),
        "localDigest":     "0x" + local_digest.hex(),
        "timestamp":       timestamp,
        "conversationId":  on_chain_conv_id,
    }


async def verify_on_chain(
    conversation_id: str,
    conversation_text: str,
    record_index: Optional[int] = None,
    batch_index: Optional[int] = None,
) -> dict:
    """
    Verify a conversation segment against its on-chain digest.

    Uses getBatch() for batch-confirmed messages (batch_index set) or
    getRecord() for single-digest messages (record_index set).
    Raises RuntimeError / TimeoutError — caller maps these to HTTP errors.
    """
    if batch_index is not None:
        return await verify_batch_digest(conversation_id, conversation_text, batch_index)
    return await verify_digest(conversation_id, conversation_text, record_index)
