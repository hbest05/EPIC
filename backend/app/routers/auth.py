from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.user import User
from app.models.signal import SignedPrekey, OneTimePrekey as OTPModel
from app.schemas.auth import (
    RegisterRequest,
    LoginRequest,
    TokenResponse,
    UploadPrekeysRequest,
)
from app.services.auth_service import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
)

router = APIRouter()


@router.post("/register", response_model=TokenResponse)
async def register(request: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == request.username))
    if result.scalar_one_or_none() is not None:
        raise HTTPException(status_code=400, detail="Username already taken")

    result = await db.execute(select(User).where(User.email == request.email))
    if result.scalar_one_or_none() is not None:
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=request.username,
        email=request.email,
        password_hash=hash_password(request.password),
        identity_key=request.identity_key,
        ed25519_public_key=request.ed25519_public_key,
    )
    db.add(user)
    await db.flush()

    db.add(SignedPrekey(
        user_id=user.id,
        key_id=request.signed_prekey_id,
        public_key=request.signed_prekey_public,
        signature=request.signed_prekey_sig,
    ))

    for opk in request.one_time_prekeys:
        db.add(OTPModel(
            user_id=user.id,
            key_id=opk.id,
            public_key=opk.public_key,
        ))

    token = create_access_token(subject=str(user.id))
    return TokenResponse(access_token=token, token_type="bearer", expires_in=1800)


@router.post("/login", response_model=TokenResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == request.username))
    user = result.scalar_one_or_none()

    if user is None or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    token = create_access_token(subject=str(user.id))
    return TokenResponse(access_token=token, token_type="bearer", expires_in=1800)


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "email": current_user.email,
        "identity_key": current_user.identity_key,
        "ed25519_public_key": current_user.ed25519_public_key,
    }


@router.get("/user/{username}/keybundle")
async def get_keybundle(
    username: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(User).where(User.username == username))
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")

    result = await db.execute(
        select(SignedPrekey)
        .where(SignedPrekey.user_id == target.id)
        .order_by(SignedPrekey.created_at.desc())
        .limit(1)
    )
    spk = result.scalar_one_or_none()
    if spk is None:
        raise HTTPException(status_code=404, detail="No signed prekey on file for user")

    # SELECT FOR UPDATE SKIP LOCKED ensures concurrent requests never consume the same OPK
    result = await db.execute(
        select(OTPModel)
        .where(OTPModel.user_id == target.id, OTPModel.used == False)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    opk = result.scalar_one_or_none()
    opk_payload = None
    if opk is not None:
        opk.used = True
        await db.flush()
        opk_payload = {"id": opk.key_id, "public_key": opk.public_key}

    return {
        "username": target.username,
        "identity_key": target.identity_key,
        "ed25519_public_key": target.ed25519_public_key,
        "signed_prekey_id": spk.key_id,
        "signed_prekey_public": spk.public_key,
        "signed_prekey_sig": spk.signature,
        "one_time_prekey": opk_payload,
    }


@router.post("/prekeys")
async def upload_prekeys(
    body: UploadPrekeysRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    for opk in body.one_time_prekeys:
        db.add(OTPModel(
            user_id=current_user.id,
            key_id=opk.id,
            public_key=opk.public_key,
        ))
    await db.flush()
    return {"uploaded": len(body.one_time_prekeys)}
