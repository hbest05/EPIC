"""
Pydantic request/response schemas for authentication endpoints.

These schemas define the API contract — they are separate from ORM models
intentionally so the database representation can evolve independently of the
public API surface.

Key design: HPKE Mode_Auth requires only one key pair per user (X25519).
The sender's static private key is bound into the KEM encapsulation, so no
separate Ed25519 signing key is needed.
"""

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=12, description="Min 12 chars; will be hashed with Argon2id")
    public_key: str = Field(..., description="Base64-encoded X25519 public key (used for HPKE Mode_Auth KEM)")


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class UserPublicProfile(BaseModel):
    id: str
    username: str
    public_key: str  # Base64-encoded X25519 public key

    class Config:
        from_attributes = True
