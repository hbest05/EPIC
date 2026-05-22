"""
Application configuration — loads all settings from environment variables.

In development, copy .env.example to .env and fill in your values.
pydantic-settings reads .env automatically when it exists.

In production, export the variables directly (12-factor style) and never
commit .env to version control — it contains secrets.

Usage anywhere in the codebase:
    from app.config import settings

    print(settings.database_url)
    print(settings.jwt_secret_key)

Every field maps 1-to-1 with a variable name from .env.example.
"""

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Single source of truth for runtime configuration.

    Field names match the environment variable names (case-insensitive).
    Default values make the app start in a local Docker-Compose environment
    without a .env file, but MUST be overridden in production.
    """

    # ------------------------------------------------------------------
    # Database
    # ------------------------------------------------------------------
    # SQLAlchemy requires the "postgresql+asyncpg://" scheme prefix so it
    # selects the async driver.  This same URL is used by both the app
    # engine (app.database) and the Alembic migration runner (alembic/env.py),
    # keeping them in sync by construction.
    database_url: str = Field(
        default="postgresql+asyncpg://securemsg:securemsg@db:5432/securemsg",
        description="Async SQLAlchemy URL — must use the asyncpg driver scheme",
    )

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------
    # Used by the blockchain write-queue (Redis Streams).  The redis-py
    # client accepts this URL format directly.
    redis_url: str = Field(
        default="redis://:alphaandthecryptmunks@redis:6379/0",
        description="Redis connection URL used by the blockchain write queue",
    )

    app_env: str = Field(
        default="production",
        description="Runtime environment — set to 'development' to disable secure cookie flag for localhost",
    )

    # ------------------------------------------------------------------
    # JWT
    # ------------------------------------------------------------------
    # jwt_secret_key signs every access token with HMAC-SHA256.
    # Generate a safe value with: python -c "import secrets; print(secrets.token_hex(32))"
    # Keep this secret — anyone who has it can forge valid tokens.
    jwt_secret_key: str = Field(
        default="CHANGE_ME_TO_A_RANDOM_256_BIT_SECRET",
        description="HMAC-SHA256 signing key for JWTs — must be cryptographically random in prod",
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm (keep HS256 unless you switch to RS256)",
    )
    jwt_access_token_expire_minutes: int = Field(
        default=30,
        description="Access token lifetime in minutes before the client must re-authenticate",
    )

    # ------------------------------------------------------------------
    # Blockchain (optional — web3.py / MessageDigestRegistry)
    # ------------------------------------------------------------------
    # Leave all three empty during development if you haven't deployed the
    # contract yet.  The app starts and runs normally without them; on-chain
    # recording calls are skipped with a logged warning.
    #
    # Canonical env var names (set these in .env or docker-compose):
    #   PRIVATE_KEY       — server wallet private key (0x-prefixed 64 hex chars)
    #   RPC_URL           — Sepolia JSON-RPC endpoint
    #   CONTRACT_ADDRESS  — deployed MessageDigestRegistry address
    #
    # The eth_* aliases are kept for backward compatibility with existing .env
    # files that used the original variable names.
    private_key: str = Field(
        default="",
        description="Server wallet private key — SENSITIVE, never logged (PRIVATE_KEY env var)",
    )
    rpc_url: str = Field(
        default="",
        description="Sepolia JSON-RPC endpoint (RPC_URL env var)",
    )
    contract_address: str = Field(
        default="",
        description="Deployed MessageDigestRegistry contract address on Sepolia",
    )

    # Backward-compatible aliases for pre-existing .env files
    eth_rpc_url: str = Field(
        default="",
        description="Alias for RPC_URL — prefer RPC_URL in new deployments",
    )
    eth_private_key: str = Field(
        default="",
        description="Alias for PRIVATE_KEY — prefer PRIVATE_KEY in new deployments",
    )

    model_config = SettingsConfigDict(
        # Load from a .env file if present; silently skip if it doesn't exist
        env_file=".env",
        env_file_encoding="utf-8",
        # Allow DATABASE_URL and database_url to both match the same field
        case_sensitive=False,
        # Ignore extra env vars that don't correspond to any field
        extra="ignore",
    )


# ---------------------------------------------------------------------------
# Module-level singleton — import this object everywhere, never instantiate
# Settings() yourself.  Having one instance ensures .env is only parsed once
# and that all code sees the same configuration values.
# ---------------------------------------------------------------------------
settings = Settings()
