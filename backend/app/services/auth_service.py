"""
Authentication service — password hashing and JWT lifecycle.

Password hashing strategy: Argon2id (winner of the Password Hashing Competition).
  - Memory: 64 MiB  (resist GPU cracking)
  - Iterations: 3
  - Parallelism: 4
  These parameters should be tuned to ~500ms on the production server.

JWT strategy:
  - Short-lived access tokens (30 min) signed with HS256
  - TODO: Add refresh token rotation with Redis blocklist for revocation
"""

from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

# Argon2id via passlib
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,   # 64 MiB
    argon2__time_cost=3,
    argon2__parallelism=4,
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password with Argon2id. Returns the full encoded hash."""
    # TODO: Validate password entropy before hashing (zxcvbn or similar)
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True if plain_password matches the stored Argon2id hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(subject: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a signed JWT with `sub` set to the user's UUID string.
    The token carries no sensitive data — only the user ID.
    """
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=settings.jwt_access_token_expire_minutes)
    )
    payload = {"sub": subject, "exp": expire}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    FastAPI dependency — decode and validate the bearer JWT, return the user.

    TODO:
    - Decode JWT
    - Check Redis blocklist for revoked tokens
    - Fetch and return User from DB by ID in `sub` claim
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # TODO: Fetch user from DB and return
    raise HTTPException(status_code=501, detail="DB lookup not yet implemented")
