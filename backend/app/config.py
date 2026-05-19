"""
Application configuration loaded from environment variables.

All secrets (DB URL, JWT secret, Redis URL) must be supplied via .env or
environment injection — never hardcoded. Pydantic-settings validates types
and raises at startup if required values are missing.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # PostgreSQL
    database_url: str = "postgresql+asyncpg://user:password@db:5432/securemsg"

    # Redis
    redis_url: str = "redis://redis:6379/0"

    # JWT
    jwt_secret_key: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # Blockchain / Ethereum
    # TODO: Set to Sepolia RPC endpoint (e.g. Infura/Alchemy URL)
    eth_rpc_url: str = ""
    # TODO: Deployed MessageDigest contract address on Sepolia
    contract_address: str = ""
    # TODO: Private key of the signing wallet (use secrets manager in prod)
    eth_private_key: str = ""

    class Config:
        env_file = ".env"


settings = Settings()
