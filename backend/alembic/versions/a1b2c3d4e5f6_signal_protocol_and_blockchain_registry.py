"""signal protocol tables and blockchain registry columns

Revision ID: a1b2c3d4e5f6
Revises: e32ea88cfd28
Create Date: 2026-05-22

Adds everything the initial migration missed:
  - user_keys.key_type  (auth.py already writes this; was absent from initial migration)
  - signed_prekeys, one_time_prekeys, ratchet_sessions, skipped_message_keys tables
  - Signal Protocol columns on messages (ratchet_public_key, previous_chain_length,
    message_index, session_id)
  - Blockchain registry columns on messages (blockchain_block_number,
    blockchain_record_index) — tx_hash was already in the initial migration

Also fixes the user_keys unique constraint: the initial migration had
UniqueConstraint('user_id') which prevents a user from having both an X25519
and an Ed25519 key. This migration drops it and adds a correct composite index
on (user_id, key_type).
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "e32ea88cfd28"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # -------------------------------------------------------------------------
    # user_keys — add key_type; fix broken unique constraint
    # -------------------------------------------------------------------------
    # The initial migration put UniqueConstraint('user_id') on user_keys, which
    # prevents a user from uploading both an X25519 and an Ed25519 key pair.
    # auth.py inserts two rows per user, so this constraint must be dropped.
    op.drop_constraint("user_keys_user_id_key", "user_keys", type_="unique")

    # Add key_type — use a temporary default so existing rows satisfy NOT NULL.
    conn.execute(sa.text(
        "ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS key_type VARCHAR(16)"
    ))
    op.execute("UPDATE user_keys SET key_type = 'x25519' WHERE key_type IS NULL")
    op.alter_column("user_keys", "key_type", nullable=False)

    # Composite index replaces the dropped unique constraint.
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_user_keys_user_id_key_type"
        " ON user_keys (user_id, key_type)"
    ))

    # -------------------------------------------------------------------------
    # ratchet_sessions — must exist before messages.session_id FK can be added
    # -------------------------------------------------------------------------
    if not conn.dialect.has_table(conn, "ratchet_sessions"):
        op.create_table(
            "ratchet_sessions",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("local_user_id", sa.UUID(), nullable=False),
            sa.Column("remote_user_id", sa.UUID(), nullable=False),
            sa.Column("root_key", sa.String(512), nullable=False),
            sa.Column("sending_chain_key", sa.String(512), nullable=True),
            sa.Column("receiving_chain_key", sa.String(512), nullable=True),
            sa.Column("sending_ratchet_public_key", sa.String(512), nullable=True),
            sa.Column("receiving_ratchet_public_key", sa.String(512), nullable=True),
            sa.Column("sending_chain_index", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("receiving_chain_index", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("previous_sending_chain_length", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["local_user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["remote_user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "local_user_id", "remote_user_id",
                name="uq_ratchet_sessions_local_remote",
            ),
        )
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_ratchet_sessions_local_user_id"
        " ON ratchet_sessions (local_user_id)"
    ))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_ratchet_sessions_remote_user_id"
        " ON ratchet_sessions (remote_user_id)"
    ))

    # -------------------------------------------------------------------------
    # signed_prekeys
    # -------------------------------------------------------------------------
    if not conn.dialect.has_table(conn, "signed_prekeys"):
        op.create_table(
            "signed_prekeys",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("user_id", sa.UUID(), nullable=False),
            sa.Column("key_id", sa.Integer(), nullable=False),
            sa.Column("public_key", sa.String(512), nullable=False),
            sa.Column("signature", sa.String(512), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_signed_prekeys_user_id_key_id"
        " ON signed_prekeys (user_id, key_id)"
    ))

    # -------------------------------------------------------------------------
    # one_time_prekeys
    # -------------------------------------------------------------------------
    if not conn.dialect.has_table(conn, "one_time_prekeys"):
        op.create_table(
            "one_time_prekeys",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("user_id", sa.UUID(), nullable=False),
            sa.Column("key_id", sa.Integer(), nullable=False),
            sa.Column("public_key", sa.String(512), nullable=False),
            sa.Column("used", sa.Boolean(), nullable=False, server_default="false"),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_one_time_prekeys_user_id_used"
        " ON one_time_prekeys (user_id, used)"
    ))

    # -------------------------------------------------------------------------
    # skipped_message_keys
    # -------------------------------------------------------------------------
    if not conn.dialect.has_table(conn, "skipped_message_keys"):
        op.create_table(
            "skipped_message_keys",
            sa.Column("id", sa.UUID(), nullable=False),
            sa.Column("session_id", sa.UUID(), nullable=False),
            sa.Column("ratchet_public_key", sa.String(512), nullable=False),
            sa.Column("message_index", sa.Integer(), nullable=False),
            sa.Column("message_key", sa.String(512), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(["session_id"], ["ratchet_sessions.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "session_id", "ratchet_public_key", "message_index",
                name="uq_skipped_message_keys_session_ratchet_index",
            ),
        )
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_skipped_message_keys_session_id"
        " ON skipped_message_keys (session_id)"
    ))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_skipped_message_keys_session_ratchet_index"
        " ON skipped_message_keys (session_id, ratchet_public_key, message_index)"
    ))

    # -------------------------------------------------------------------------
    # messages — Signal Protocol columns
    # -------------------------------------------------------------------------
    conn.execute(sa.text(
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS ratchet_public_key VARCHAR(512)"
    ))
    conn.execute(sa.text(
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS previous_chain_length INTEGER"
    ))
    conn.execute(sa.text(
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS message_index INTEGER"
    ))
    conn.execute(sa.text(
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS"
        " session_id UUID REFERENCES ratchet_sessions(id) ON DELETE SET NULL"
    ))
    conn.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_messages_session_id"
        " ON messages (session_id)"
    ))

    # -------------------------------------------------------------------------
    # messages — blockchain registry columns (the main goal of this PR)
    # -------------------------------------------------------------------------
    conn.execute(sa.text(
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS blockchain_block_number INTEGER"
    ))
    conn.execute(sa.text(
        "ALTER TABLE messages ADD COLUMN IF NOT EXISTS blockchain_record_index INTEGER"
    ))


def downgrade() -> None:
    conn = op.get_bind()

    # Blockchain registry columns
    conn.execute(sa.text("ALTER TABLE messages DROP COLUMN IF EXISTS blockchain_record_index"))
    conn.execute(sa.text("ALTER TABLE messages DROP COLUMN IF EXISTS blockchain_block_number"))

    # Signal Protocol columns
    conn.execute(sa.text("DROP INDEX IF EXISTS ix_messages_session_id"))
    conn.execute(sa.text("ALTER TABLE messages DROP COLUMN IF EXISTS session_id"))
    conn.execute(sa.text("ALTER TABLE messages DROP COLUMN IF EXISTS message_index"))
    conn.execute(sa.text("ALTER TABLE messages DROP COLUMN IF EXISTS previous_chain_length"))
    conn.execute(sa.text("ALTER TABLE messages DROP COLUMN IF EXISTS ratchet_public_key"))

    # Signal Protocol tables (reverse creation order — FK dependencies)
    conn.execute(sa.text("DROP INDEX IF EXISTS ix_skipped_message_keys_session_ratchet_index"))
    conn.execute(sa.text("DROP INDEX IF EXISTS ix_skipped_message_keys_session_id"))
    if conn.dialect.has_table(conn, "skipped_message_keys"):
        op.drop_table("skipped_message_keys")

    conn.execute(sa.text("DROP INDEX IF EXISTS ix_one_time_prekeys_user_id_used"))
    if conn.dialect.has_table(conn, "one_time_prekeys"):
        op.drop_table("one_time_prekeys")

    conn.execute(sa.text("DROP INDEX IF EXISTS ix_signed_prekeys_user_id_key_id"))
    if conn.dialect.has_table(conn, "signed_prekeys"):
        op.drop_table("signed_prekeys")

    conn.execute(sa.text("DROP INDEX IF EXISTS ix_ratchet_sessions_remote_user_id"))
    conn.execute(sa.text("DROP INDEX IF EXISTS ix_ratchet_sessions_local_user_id"))
    if conn.dialect.has_table(conn, "ratchet_sessions"):
        op.drop_table("ratchet_sessions")

    # user_keys — restore original (broken) state
    conn.execute(sa.text("DROP INDEX IF EXISTS ix_user_keys_user_id_key_type"))
    conn.execute(sa.text("ALTER TABLE user_keys DROP COLUMN IF EXISTS key_type"))
    op.create_unique_constraint("user_keys_user_id_key", "user_keys", ["user_id"])
