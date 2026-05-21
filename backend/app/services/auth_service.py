#import cryptcontext forrrr argon2! which is the chosen hash for our passwords
#cryptcontext setup with specifications, chosen from documentation
#functions use imported hash and verify functions, no wheel reinventing here ahahhahahh


from passlib.context import CryptContext

pwd_context = CryptContext (
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,
    argon2__time_cost=3,
    argon2__parallelism=4
)

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed:str) -> bool:
    return pwd_context.verify(plain, hashed)

#okay, now that we can sign up a user, and we can verify a user signin...
#gotsta give them a JWT! so they can use the service with a nice temporary verification badge basically

#import jwt & also need datetime (and config sure why not)

from datetime import datetime, timedelta, timezone
from jose import jwt
from app.config import settings

#build up a jwt with an expiry and a payload with the field names jwt needs
#reutrning the dictionary payload, uses .env secret key from config.py

def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": subject,
        "exp": expire
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm = settings.jwt_algorithm)

#time for get_current_user func using a lot of fastapi built in stuff
#receives jwt string, validates, returns user object.

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.models.user import User

#auth2passwordbearer reads Authorization: Bearer <token> header from inc req
#it gives a raw token string

oauth2_scheme = OAuth2PasswordBearer(tockeUrl="/api/auth/login")

async def get_current_user(
        token: str = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_db)
) -> User:
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    #jwt.decode takes str, verifies against sk, and returns payload if valid
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        user_id: str = payload.get("sub")
        #checks it is valid AND still exists!!
        if user_id is None:
            raise invalid
    except JWTError:
        raise invalid
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise invalid
    return user

