import base64
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.message import UserKey
from app.models.signal import OneTimePrekey, SignedPrekey
from app.models.user import User
from app.schemas.auth import (
    KeyBundleResponse,
    LoginRequest,
    LoginResponse,
    OPKBundle,
    RegisterRequest,
    SPKBundle,
    UploadPrekeysRequest,
    UserPublicProfile,
)
from app.services.auth_service import (
    create_access_token,
    generate_csrf_token,
    get_current_user,
    hash_password,
    pwd_context,
    verify_password,
)
from app.services.rate_limit import limiter
from app.services.redis_service import (
    AUTH_MAX_FAILURES,
    clear_auth_failures,
    get_auth_failure_count,
    record_auth_failure,
)

router = APIRouter()

# True when running under HTTPS — False for http://localhost in development
_SECURE_COOKIE = settings.app_env != "development"
_COOKIE_MAX_AGE = settings.jwt_access_token_expire_minutes * 60


@router.post("/register", response_model=UserPublicProfile, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register(request: Request, body: RegisterRequest, db: AsyncSession = Depends(get_db)):
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
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    ip = request.client.host

    # Reject immediately if this IP has hit the failure threshold — no DB work needed
    if await get_auth_failure_count(ip) >= AUTH_MAX_FAILURES:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
        )

    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    # Always run verify_password even when user is not found to prevent
    # timing-based username enumeration attacks
    if user is None:
        pwd_context.dummy_verify()
        await record_auth_failure(ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not verify_password(body.password, user.password_hash):
        await record_auth_failure(ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        await record_auth_failure(ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    await clear_auth_failures(ip)
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


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("csrf_token")
    return {"message": "Logged out"}


@router.get("/me", response_model=LoginResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return LoginResponse(id=str(current_user.id), username=current_user.username)


@router.post(
    "/prekeys",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def upload_prekeys(
    body: UploadPrekeysRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Validate both fields are legal base64 before touching the DB
    try:
        spk_pub_bytes = base64.b64decode(body.signed_prekey.public_key, validate=True)
        spk_sig_bytes = base64.b64decode(body.signed_prekey.signature, validate=True)
        for opk in body.one_time_prekeys:
            base64.b64decode(opk.public_key, validate=True)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="All public_key and signature fields must be valid base64",
        )

    # Verify SPK signature against the user's registered Ed25519 identity key.
    # This catches cross-client identity races before bad data reaches the DB.
    ed_key_result = await db.execute(
        select(UserKey).where(
            UserKey.user_id == current_user.id,
            UserKey.key_type == "ed25519",
        )
    )
    ed_key_row = ed_key_result.scalar_one_or_none()
    if ed_key_row is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="identity keys not registered; register before uploading prekeys",
        )
    try:
        Ed25519PublicKey.from_public_bytes(ed_key_row.public_key).verify(
            spk_sig_bytes, spk_pub_bytes
        )
    except InvalidSignature:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SPK signature does not verify under your registered Ed25519 identity key",
        )

    # Insert new SPK — old ones are kept for in-flight X3DH sessions until they expire
    db.add(SignedPrekey(
        user_id=current_user.id,
        key_id=body.signed_prekey.key_id,
        public_key=body.signed_prekey.public_key,
        signature=body.signed_prekey.signature,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    ))

    # Insert OPK batch — duplicates will be rejected by the DB unique index
    for opk in body.one_time_prekeys:
        db.add(OneTimePrekey(
            user_id=current_user.id,
            key_id=opk.key_id,
            public_key=opk.public_key,
        ))

    # get_db commits all inserts on success; returns 204 No Content


@router.get("/user/{username}/keybundle", response_model=KeyBundleResponse)
async def get_keybundle(
    username: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Resolve target user
    result = await db.execute(select(User).where(User.username == username))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Fetch both identity keys (X25519 + Ed25519)
    keys_result = await db.execute(
        select(UserKey).where(UserKey.user_id == target.id)
    )
    user_keys = keys_result.scalars().all()
    ik_x25519 = next((k for k in user_keys if k.key_type == "x25519"), None)
    ik_ed25519 = next((k for k in user_keys if k.key_type == "ed25519"), None)

    if not ik_x25519 or not ik_ed25519:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="prekeys not uploaded",
        )

    # Fetch most recent active SPK
    spk_result = await db.execute(
        select(SignedPrekey)
        .where(SignedPrekey.user_id == target.id)
        .order_by(SignedPrekey.created_at.desc())
        .limit(1)
    )
    spk = spk_result.scalar_one_or_none()
    if spk is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="prekeys not uploaded",
        )

    # Consume one OPK atomically — mark used before commit so it is never served twice
    opk_result = await db.execute(
        select(OneTimePrekey)
        .where(
            OneTimePrekey.user_id == target.id,
            OneTimePrekey.used.is_(False),
        )
        .limit(1)
    )
    opk = opk_result.scalar_one_or_none()
    opk_bundle = None
    if opk:
        opk.used = True
        await db.flush()
        opk_bundle = OPKBundle(key_id=opk.key_id, public_key=opk.public_key)

    # UserKey.public_key is BYTEA — encode to base64 for the wire
    return KeyBundleResponse(
        username=target.username,
        ik_x25519=base64.b64encode(ik_x25519.public_key).decode(),
        ik_ed25519=base64.b64encode(ik_ed25519.public_key).decode(),
        ik_fingerprint=ik_x25519.key_fingerprint,
        spk=SPKBundle(
            key_id=spk.key_id,
            public_key=spk.public_key,
            signature=spk.signature,
        ),
        opk=opk_bundle,
    )
