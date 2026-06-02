"""
Authentication service — password hashing, JWT lifecycle, and request dependencies.

Password hashing: Argon2id (m=65536, t=3, p=4) via passlib.
JWT: HS256, short-lived (see config for expiry). Token is carried in an httpOnly
cookie — never returned in a response body or read by JavaScript.
CSRF: double-submit cookie pattern. A separate readable csrf_token cookie is set
on login; every state-changing request must echo it in the X-CSRF-Token header.
"""

import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt  # PyJWT — replaces python-jose (PYSEC-2024-232, PYSEC-2024-233)
from fastapi import Depends, HTTPException, Request, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db

# ---------------------------------------------------------------------------
# Password hashing — Argon2id
# ---------------------------------------------------------------------------

pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,  # 64 MiB
    argon2__time_cost=3,
    argon2__parallelism=4,
)


def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------

def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT with `sub` set to the user's UUID string."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    return jwt.encode(
        {"sub": subject, "exp": expire},
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

def generate_csrf_token() -> str:
    return secrets.token_hex(32)


async def verify_csrf(request: Request) -> None:
    """
    Dependency — validate the double-submit CSRF token on state-changing requests.
    Raises 403 if the X-CSRF-Token header does not match the csrf_token cookie.
    """
    cookie = request.cookies.get("csrf_token")
    header = request.headers.get("X-CSRF-Token")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="CSRF validation failed")


# ---------------------------------------------------------------------------
# Current-user dependency
# ---------------------------------------------------------------------------

_credentials_exception = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
)


async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    FastAPI dependency — reads the access_token httpOnly cookie, validates the JWT,
    and returns the User ORM object. Raises 401 on any failure.
    """
    from app.models.user import User  # local import avoids circular dependency at module load

    token = request.cookies.get("access_token")
    if not token:
        raise _credentials_exception

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        user_id: str = payload.get("sub")
        if not user_id:
            raise _credentials_exception
    except jwt.PyJWTError:
        raise _credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise _credentials_exception

    return user
