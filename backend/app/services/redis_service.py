"""
Redis service — blockchain write queue.

Messages are stored in PostgreSQL immediately on send. Their keccak256 hashes
are then pushed onto a Redis stream (`blockchain:queue`) so an async worker
can batch-submit them to the Ethereum Sepolia testnet via the MessageDigest
smart contract.

This decoupling means:
  - Message delivery is not blocked by Ethereum's ~12s block time
  - Failed on-chain submissions can be retried from the stream
  - The worker can batch multiple hashes into a single transaction to save gas

Stream key: "blockchain:queue"
Consumer group: "blockchain:workers"
"""

import json
from typing import Optional

import aioredis

from app.config import settings

_redis: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """Return the shared async Redis client, creating it on first call."""
    global _redis
    if _redis is None:
        _redis = await aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


async def enqueue_hash(message_id: str, keccak256_hash: str) -> str:
    """
    Push a message hash onto the Redis stream for async on-chain submission.

    Returns the Redis stream entry ID (used to ACK after successful submission).

    TODO:
    - Ensure the consumer group exists (XGROUP CREATE … MKSTREAM)
    - XADD with message_id and hash fields
    """
    r = await get_redis()
    entry_id = await r.xadd(
        "blockchain:queue",
        {"message_id": message_id, "hash": keccak256_hash},
    )
    return entry_id


async def close():
    """Gracefully close the Redis connection pool."""
    global _redis
    if _redis:
        await _redis.close()
        _redis = None
