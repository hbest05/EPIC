"""
Redis service — async connection pool and auth failure tracking.

Blockchain recording is handled directly by blockchain_service.py via the
three-tier model (batch accumulator, event-triggered, final digest).
Redis is used here only for connection pooling and auth failure tracking.
"""

import redis.asyncio as aioredis

from app.config import settings

# ---------------------------------------------------------------------------
# Module-level connection pool — initialised on app startup
# ---------------------------------------------------------------------------

_pool: aioredis.Redis | None = None


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
