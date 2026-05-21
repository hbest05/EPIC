from pydantic import BaseModel, EmailStr, Field


class OneTimePrekey(BaseModel):
    id: int
    public_key: str


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=12)
    identity_key: str
    ed25519_public_key: str
    signed_prekey_id: int
    signed_prekey_public: str
    signed_prekey_sig: str
    one_time_prekeys: list[OneTimePrekey]


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserPublicProfile(BaseModel):
    id: str
    username: str
    identity_key: str
    ed25519_public_key: str


class UploadPrekeysRequest(BaseModel):
    one_time_prekeys: list[OneTimePrekey]
