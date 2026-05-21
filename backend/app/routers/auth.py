import base64
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.message import UserKey
from app.models.user import User
from app.schemas.auth import LoginRequest, LoginResponse, RegisterRequest, UserPublicProfile
from app.services.auth_service import (
    create_access_token,
    generate_csrf_token,
    get_current_user,
    hash_password,
    pwd_context,
    verify_csrf,
    verify_password,
)

router = APIRouter()

# True when running under HTTPS — False for http://localhost in development
_SECURE_COOKIE = settings.app_env != "development"
_COOKIE_MAX_AGE = settings.jwt_access_token_expire_minutes * 60


@router.post("/register", response_model=UserPublicProfile, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Uniqueness checks
    taken = await db.execute(select(User).where(User.username == body.username))
    if taken.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already taken")

    taken = await db.execute(select(User).where(User.email == body.email))
    if taken.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    # Validate and decode both public keys
    try:
        x25519_bytes = base64.b64decode(body.x25519_public_key, validate=True)
        ed25519_bytes = base64.b64decode(body.ed25519_public_key, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Public keys must be valid base64",
        )

    # Create user — password hashed with Argon2id (m=65536, t=3, p=4)
    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    await db.flush()  # get user.id before inserting UserKey rows

    # Store both identity keys with SHA-256 fingerprints for TOFU lookup
    for key_type, key_bytes in (("x25519", x25519_bytes), ("ed25519", ed25519_bytes)):
        db.add(UserKey(
            user_id=user.id,
            key_type=key_type,
            public_key=key_bytes,
            key_fingerprint=hashlib.sha256(key_bytes).hexdigest(),
        ))

    # get_db commits all three inserts together on success
    return UserPublicProfile(
        id=str(user.id),
        username=user.username,
        x25519_public_key=body.x25519_public_key,
        ed25519_public_key=body.ed25519_public_key,
    )


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    # Always run verify_password even when user is not found to prevent
    # timing-based username enumeration attacks
    if user is None:
        pwd_context.dummy_verify()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(str(user.id))
    csrf_token = generate_csrf_token()

    # httpOnly — inaccessible to JavaScript, not vulnerable to XSS token theft
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=_SECURE_COOKIE,
        samesite="strict",
        max_age=_COOKIE_MAX_AGE,
    )
    # Not httpOnly — JavaScript must read this and echo it in X-CSRF-Token header
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=_SECURE_COOKIE,
        samesite="strict",
        max_age=_COOKIE_MAX_AGE,
    )

    return LoginResponse(id=str(user.id), username=user.username)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("csrf_token")
    return {"message": "Logged out"}


@router.get("/me", response_model=LoginResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return LoginResponse(id=str(current_user.id), username=current_user.username)


# TODO: POST /prekeys  — upload signed prekey + batch of one-time prekeys
# TODO: GET  /user/{username}/keybundle — fetch full X3DH key bundle for a user
