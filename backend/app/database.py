"""
Database connection layer — engine, session factory, declarative Base, and
the get_db() FastAPI dependency.

This module is the single place where SQLAlchemy is configured.  Everything
else that needs database access imports from here.

What lives here
---------------
Base               DeclarativeBase that every ORM model inherits from.
                   Alembic reads Base.metadata to autogenerate migrations.

engine             Async engine backed by asyncpg.  Imported by:
                     - main.py  (startup health-check)
                     - alembic/env.py  (migration runner creates its own engine
                       but shares the same URL via settings)

AsyncSessionLocal  Async session factory.  Produces AsyncSession instances.
                   Used internally by get_db(); rarely needed elsewhere.

get_db()           FastAPI dependency.  Injects an AsyncSession into route
                   handlers, commits on success, rolls back on any exception,
                   and always closes the session when the request is done.

Async / asyncpg notes
---------------------
asyncpg is a pure-async PostgreSQL driver — it has no synchronous interface.
SQLAlchemy's async layer wraps asyncpg and adds connection pooling.

The URL scheme "postgresql+asyncpg://..." tells SQLAlchemy which driver to
use.  If you see "MissingGreenlet" errors it usually means synchronous ORM
operations (lazy loads, implicit I/O) are leaking into async code — use
expire_on_commit=False and eager-load all relationships.
"""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings


# ---------------------------------------------------------------------------
# Declarative Base
#
# Every ORM model (User, Message, SignedPrekey, …) must inherit from Base.
# SQLAlchemy registers each model class in Base.metadata when the class body
# is executed (i.e. when the module is imported).  Alembic compares
# Base.metadata against the live schema to generate migration scripts.
#
# Rule: never instantiate Base directly; only subclass it.
# ---------------------------------------------------------------------------
class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Async engine
#
# create_async_engine wraps asyncpg in SQLAlchemy's connection pool.
#
# pool_pre_ping=True
#   Before handing a pooled connection to the caller, SQLAlchemy sends a
#   lightweight "SELECT 1" to verify the connection is still alive.  This
#   silently recycles connections that went stale (e.g. after a Postgres
#   restart, an idle-timeout disconnect, or a load-balancer reset).
#   Slight per-request overhead (~0.1 ms) is worth the reliability.
#
# echo=False
#   Set to True or "debug" locally to log every SQL statement SQLAlchemy
#   emits.  Never enable in production — logs contain query parameters.
# ---------------------------------------------------------------------------
engine = create_async_engine(
    settings.database_url,
    pool_pre_ping=True,
    echo=False,
)


# ---------------------------------------------------------------------------
# Async session factory
#
# async_sessionmaker is the SQLAlchemy 2.x replacement for sessionmaker for
# async sessions.  Each call to AsyncSessionLocal() produces a new AsyncSession
# bound to the shared engine pool.
#
# expire_on_commit=False
#   After session.commit(), SQLAlchemy would normally expire all ORM objects,
#   meaning the next attribute access triggers a lazy SELECT to refresh them.
#   In an async context that lazy SELECT runs synchronously inside asyncpg and
#   raises MissingGreenlet.  Disabling expiry means objects keep their
#   in-memory state after the commit — caller must re-query if freshness
#   matters (e.g. after a server-side default is applied).
# ---------------------------------------------------------------------------
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ---------------------------------------------------------------------------
# FastAPI database dependency
#
# Inject this into any route or service that needs database access:
#
#   from app.database import get_db
#   from sqlalchemy.ext.asyncio import AsyncSession
#
#   @router.get("/example")
#   async def example(db: AsyncSession = Depends(get_db)):
#       result = await db.execute(select(User))
#       return result.scalars().all()
#
# The session lifecycle for each HTTP request:
#   1. AsyncSessionLocal() opens a connection from the pool.
#   2. yield hands the session to the route handler.
#   3. If the handler returns normally → commit() persists all changes.
#   4. If the handler raises an exception → rollback() discards all changes.
#   5. The async context manager (async with) always closes the session,
#      returning the connection to the pool.
#
# NOTE: Do not call db.commit() manually inside a route — this dependency
# does it for you.  If you need fine-grained transaction control (e.g.
# savepoints) acquire the session from AsyncSessionLocal() directly.
# ---------------------------------------------------------------------------
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
