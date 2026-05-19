"""
SQLAlchemy async engine and session factory.

Uses asyncpg under the hood. All database interactions should go through
`get_db()` as a FastAPI dependency so sessions are properly scoped to each
request and cleaned up on completion or error.
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=False,  # Set True to log SQL in development
    pool_pre_ping=True,
)

AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Shared declarative base for all ORM models."""
    pass


async def get_db():
    """FastAPI dependency that yields a per-request DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
