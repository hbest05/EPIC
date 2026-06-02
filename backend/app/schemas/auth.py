"""
Pydantic request/response schemas for authentication endpoints.

These schemas define the API contract — they are separate from ORM models
intentionally so the database representation can evolve independently of the
public API surface.
"""

from pydantic import BaseModel, EmailStr, Field


_VALID_CLIENT_TYPES = {"web", "cpp"}


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=12, description="Min 12 chars; will be hashed with Argon2id")
    x25519_public_key: str = Field(..., description="Base64-encoded X25519 identity key — used in X3DH DH operations")
    ed25519_public_key: str = Field(..., description="Base64-encoded Ed25519 signing key — used to sign the SPK")
    client_type: str = Field(..., description="Client type: 'web' or 'cpp'")


class LoginRequest(BaseModel):
    username: str
    password: str
    client_type: str = Field(..., description="Client type: 'web' or 'cpp'")


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


# ---------------------------------------------------------------------------
# Prekey upload
# ---------------------------------------------------------------------------

class SignedPrekeyUpload(BaseModel):
    key_id: int
    public_key: str = Field(..., description="Base64-encoded X25519 SPK public key")
    signature: str = Field(..., description="Base64-encoded Ed25519 signature over public_key, made with the user's IK")


class OneTimePrekeyUpload(BaseModel):
    key_id: int
    public_key: str = Field(..., description="Base64-encoded X25519 OPK public key")


class UploadPrekeysRequest(BaseModel):
    signed_prekey: SignedPrekeyUpload
    one_time_prekeys: list[OneTimePrekeyUpload] = Field(..., min_length=1, max_length=100)


class UploadOPKsRequest(BaseModel):
    one_time_prekeys: list[OneTimePrekeyUpload] = Field(..., min_length=1, max_length=100)


class OPKCountResponse(BaseModel):
    opk_count: int


# ---------------------------------------------------------------------------
# Key bundle response
# ---------------------------------------------------------------------------

class SPKBundle(BaseModel):
    key_id: int
    public_key: str  # base64 X25519
    signature: str   # base64 Ed25519 signature by IK


class OPKBundle(BaseModel):
    key_id: int
    public_key: str  # base64 X25519


class KeyBundleResponse(BaseModel):
    username: str
    user_id: str          # UUID of the user — used by clients to construct conversation_id for blockchain verify
    # Long-term identity keys
    ik_x25519: str       # base64 raw X25519 — used in X3DH DH operations
    ik_ed25519: str      # base64 raw Ed25519 — verifies SPK signature
    ik_fingerprint: str  # SHA-256 hex of raw X25519 IK bytes — use for TOFU pinning
    # Signed prekey
    spk: SPKBundle
    # One-time prekey — absent if pool exhausted; client must fall back to 3DH
    opk: OPKBundle | None = None
