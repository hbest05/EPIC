"""
Pydantic request/response schemas for authentication endpoints.

These schemas define the API contract — they are separate from ORM models
intentionally so the database representation can evolve independently of the
public API surface.
"""

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=12, description="Min 12 chars; will be hashed with Argon2id")
    x25519_public_key: str = Field(..., description="Base64-encoded X25519 identity key — used in X3DH DH operations")
    ed25519_public_key: str = Field(..., description="Base64-encoded Ed25519 signing key — used to sign the SPK")


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    id: str
    username: str


class UserPublicProfile(BaseModel):
    id: str
    username: str
    x25519_public_key: str
    ed25519_public_key: str

    class Config:
        from_attributes = True
