"""
Redis service — async connection pool and blockchain write queue.

Uses Redis Streams as a durable queue: the backend pushes keccak256 hashes
via push_hash_to_queue(); a worker (TODO below) reads from the stream and
submits them to the MessageDigest smart contract on Ethereum.
"""

import redis.asyncio as aioredis

from app.config import settings

# ---------------------------------------------------------------------------
# Module-level connection pool — initialised on app startup
# ---------------------------------------------------------------------------

_pool: aioredis.Redis | None = None

BLOCKCHAIN_STREAM = "blockchain:hashes"


async def init_redis() -> None:
    global _pool
    _pool = await aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
    )


async def close_redis() -> None:
    global _pool
    if _pool:
        await _pool.aclose()
        _pool = None


def get_redis() -> aioredis.Redis:
    if _pool is None:
        raise RuntimeError("Redis pool not initialised — call init_redis() first")
    return _pool


# ---------------------------------------------------------------------------
# Blockchain write queue
# ---------------------------------------------------------------------------

async def push_hash_to_queue(message_id: str, keccak_hash: str) -> str:
    """
    Add a message hash to the blockchain write stream.

    Returns the Redis stream entry ID assigned to this record.
    """
    redis = get_redis()
    entry_id = await redis.xadd(
        BLOCKCHAIN_STREAM,
        {"message_id": message_id, "hash": keccak_hash},
    )
    return entry_id


# ---------------------------------------------------------------------------
# Auth failure tracking — application-layer equivalent of fail2ban
# ---------------------------------------------------------------------------

_AUTH_FAIL_PREFIX = "auth:fail:"
_AUTH_WINDOW_SEC = 600    # 10-minute window before counter resets
_AUTH_LOCKOUT_SEC = 3600  # 1-hour lockout once threshold is reached
AUTH_MAX_FAILURES = 5     # exported — used in auth router to reject before DB work


async def record_auth_failure(ip: str) -> None:
    """
    Increment the failed-login counter for an IP.

    TTL logic:
      - First failure: starts a 10-min window (key expires, counter resets).
      - 5th failure: extends TTL to 1 hour (lockout begins).
    """
    redis = get_redis()
    key = f"{_AUTH_FAIL_PREFIX}{ip}"
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, _AUTH_WINDOW_SEC)
    elif count >= AUTH_MAX_FAILURES:
        await redis.expire(key, _AUTH_LOCKOUT_SEC)


async def get_auth_failure_count(ip: str) -> int:
    """Return current failure count for an IP (0 if no record)."""
    val = await get_redis().get(f"{_AUTH_FAIL_PREFIX}{ip}")
    return int(val) if val else 0


async def clear_auth_failures(ip: str) -> None:
    """Delete the failure counter on a successful login."""
    await get_redis().delete(f"{_AUTH_FAIL_PREFIX}{ip}")


# ---------------------------------------------------------------------------
# TODO: Blockchain consumer loop
#
# Implement a background worker that:
#   1. Calls XREADGROUP on BLOCKCHAIN_STREAM using a consumer group so that
#      multiple workers can share the load and crashed entries are retried.
#   2. Batches entries up to a configurable size (e.g. 10) and submits them
#      to the smart contract via storeHashBatch() to save gas.
#   3. ACKs each entry (XACK) only after the Ethereum transaction is confirmed.
#   4. Handles pending entry recovery (XPENDING / XCLAIM) for entries that
#      were read but never ACK'd due to a crash.
#   5. Runs as an asyncio task launched from main.py on startup, cancelled
#      cleanly on shutdown.
# ---------------------------------------------------------------------------
