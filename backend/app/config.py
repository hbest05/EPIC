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
    # Blockchain (optional)
    # ------------------------------------------------------------------
    # These are only required when the blockchain write-queue worker is
    # running.  Leave them empty during development if you haven't deployed
    # the smart contract yet — the app will still start.
    eth_rpc_url: str = Field(
        default="",
        description="Ethereum JSON-RPC endpoint (e.g. Alchemy/Infura Sepolia URL)",
    )
    contract_address: str = Field(
        default="",
        description="Deployed MessageDigest.sol contract address on Sepolia",
    )
    eth_private_key: str = Field(
        default="",
        description="Private key for the on-chain submitter account — use a secrets manager in prod",
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
