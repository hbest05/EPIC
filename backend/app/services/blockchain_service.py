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
    fire_and_forget(message_id, conversation_id, conversation_text)
    verify_on_chain(conversation_id, record_index, conversation_text) → dict
"""

import asyncio
import json
import logging
import pathlib
from typing import Optional

from web3 import AsyncWeb3
from web3.providers import AsyncHTTPProvider

from sqlalchemy import update

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.message import Message

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

        _w3 = AsyncWeb3(AsyncHTTPProvider(rpc_url))
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
# Public API (imported by exact name in routers — do not rename)
# ---------------------------------------------------------------------------

def fire_and_forget(
    message_id: str,
    conversation_id: str,
    conversation_text: str,
) -> None:
    """
    Schedule on-chain digest recording as a background asyncio task.

    Returns immediately — the HTTP 201 response is not delayed.
    Logs a warning and skips scheduling if blockchain is not configured.
    """
    if not is_configured():
        return  # warning already logged by is_configured()

    # create_task runs the coroutine on the running event loop without blocking
    # the current request.  Exceptions inside the coroutine are caught in
    # _record_and_update so the task never causes an unhandled exception.
    asyncio.create_task(
        _record_and_update(message_id, conversation_id, conversation_text)
    )


async def verify_on_chain(
    conversation_id: str,
    record_index: int,
    conversation_text: str,
) -> dict:
    """
    Verify a conversation segment against its on-chain digest.

    Thin wrapper around verify_digest() that preserves the interface expected
    by blockchain.py router.  Returns camelCase keys.

    Raises RuntimeError / TimeoutError — caller maps these to HTTP errors.
    """
    return await verify_digest(conversation_id, conversation_text, record_index)
