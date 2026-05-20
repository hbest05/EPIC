"""
Alembic async migration environment.

This file is executed by every `alembic` CLI command.  It has two jobs:

  1. Supply the database URL and Base.metadata to Alembic so it knows what
     schema to manage and where the database lives.

  2. Bridge Alembic's synchronous migration API into the asyncpg async driver,
     because asyncpg has no synchronous interface.

Common commands
---------------
  alembic upgrade head                       # apply all unapplied migrations
  alembic downgrade -1                       # roll back one migration
  alembic revision --autogenerate -m "..."   # generate migration from ORM diff
  alembic current                            # show current DB revision
  alembic history                            # list all revisions

Why asyncpg needs special handling
-----------------------------------
Standard Alembic uses psycopg2, which is synchronous.  Our app uses asyncpg,
which is purely async.  The trick: we create an async engine, open a real
async connection, then call `connection.run_sync(callback)` which gives Alembic
a synchronous proxy it can drive normally.  asyncio.run() provides the event
loop that drives it all.

URL precedence
--------------
The database URL comes from app.config.settings (i.e. the DATABASE_URL
environment variable / .env file), NOT from alembic.ini.  The ini value is a
placeholder kept for IDE plugins that inspect the file statically.  This ensures
the app and migration runner always use the same connection string.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

# ---------------------------------------------------------------------------
# Import Base so Alembic has the full metadata object to diff against.
# Import app.models for its side-effect: each model module registers its
# Table objects in Base.metadata when it is imported.  Without this import
# autogenerate would see an empty schema and try to drop everything.
# ---------------------------------------------------------------------------
from app.database import Base
import app.models  # noqa: F401 — side-effect populates Base.metadata
from app.config import settings

# ---------------------------------------------------------------------------
# Alembic's standard logging setup (reads [loggers] from alembic.ini)
# ---------------------------------------------------------------------------
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------------------
# target_metadata tells autogenerate which ORM tables to compare.
# This must be set after all model modules have been imported above.
# ---------------------------------------------------------------------------
target_metadata = Base.metadata


# ---------------------------------------------------------------------------
# OFFLINE MIGRATIONS
#
# Run with: alembic upgrade head --sql
#
# Offline mode generates SQL statements without connecting to the database.
# Useful for:
#   - Code review of migration SQL before applying
#   - Environments where the migration runner can't reach the database
#   - Generating SQL to hand off to a DBA
#
# In offline mode Alembic renders SQL using the dialect alone (no real
# connection), so literal_binds=True is needed to inline parameter values
# instead of leaving "?" placeholders.
# ---------------------------------------------------------------------------
def run_migrations_offline() -> None:
    """Generate migration SQL without a live database connection."""
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Detect column type changes (e.g. String(256) → String(512))
        compare_type=True,
        # Detect server_default additions/removals
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# ONLINE MIGRATIONS — async bridge
#
# Alembic's migration runner is synchronous: it calls context.run_migrations()
# which iterates upgrade/downgrade functions line by line.  asyncpg is
# async-only: every database call must be awaited.
#
# The bridge pattern:
#   1. create_async_engine()  — standard async SQLAlchemy engine
#   2. async with engine.connect() as conn  — real asyncpg connection
#   3. await conn.run_sync(do_run_migrations)
#      run_sync() runs a synchronous callback inside the event loop, handing
#      it a synchronous "proxy" connection object.  Alembic drives migrations
#      through this proxy without knowing it is async underneath.
#   4. asyncio.run(run_async_migrations())  — provides the event loop
#
# We create a fresh engine here (not reusing app.database.engine) because
# Alembic is often run as a standalone process (CI, migration-only container)
# and we don't want to share pool state with the application server.
# ---------------------------------------------------------------------------
def do_run_migrations(connection) -> None:
    """
    Configure Alembic context and execute pending migrations.

    Called by run_sync(), so `connection` is a synchronous proxy even though
    the underlying transport is async.
    """
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """
    Create an async engine, connect to the database, and run migrations.

    Disposes the engine when done so no connections are leaked — important
    when this runs in a short-lived migration container or CI job.
    """
    connectable = create_async_engine(settings.database_url, pool_pre_ping=True)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for online migrations — drives the async bridge."""
    asyncio.run(run_async_migrations())


# ---------------------------------------------------------------------------
# Dispatch — Alembic sets is_offline_mode() based on whether --sql was passed.
# ---------------------------------------------------------------------------
if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
