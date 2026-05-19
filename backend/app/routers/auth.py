"""
Authentication router — registration, login, and token refresh.

Flow:
  POST /api/auth/register  -> hash password with Argon2id, store user + public keys
  POST /api/auth/login     -> verify password hash, issue JWT access token
  POST /api/auth/refresh   -> validate refresh token, issue new access token
  GET  /api/auth/me        -> return profile of the authenticated user
  GET  /api/auth/user/{username}/pubkeys -> return a user's public keys so the
                              caller can perform ECDH key exchange before sending
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.auth import LoginRequest, RegisterRequest, TokenResponse, UserPublicProfile
from app.services import auth_service

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db: AsyncSession = Depends(get_db)):
    """
    TODO:
    - Check username/email uniqueness
    - Hash password with Argon2id via auth_service.hash_password()
    - Persist User record with public keys
    - Return 201 on success
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
    """
    TODO:
    - Fetch user by username
    - Verify password with auth_service.verify_password()
    - Generate JWT via auth_service.create_access_token()
    - Return token
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/me", response_model=UserPublicProfile)
async def get_me(current_user=Depends(auth_service.get_current_user)):
    """Return the authenticated user's profile."""
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/user/{username}/pubkeys", response_model=UserPublicProfile)
async def get_user_pubkeys(username: str, db: AsyncSession = Depends(get_db)):
    """
    Return another user's public keys so the caller can perform ECDH before
    sending an encrypted message. Does not require authentication so clients
    can fetch keys before logging in (e.g. during key-exchange setup).
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")
