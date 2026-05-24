"""add_forwarding_and_revocation

Revision ID: d1e2f3a4b5c6
Revises: c8d9e0f1a2b3
Create Date: 2026-05-24 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = 'd1e2f3a4b5c6'
down_revision = 'c8d9e0f1a2b3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'messages',
        sa.Column('forwarded_from_id', sa.UUID(), nullable=True),
    )
    op.create_table(
        'conversation_revocations',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('conversation_id', sa.String(), nullable=False),
        sa.Column('revoked_user_id', sa.UUID(), nullable=False),
        sa.Column('revoked_by_id', sa.UUID(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['revoked_by_id'], ['users.id']),
        sa.ForeignKeyConstraint(['revoked_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_conversation_revocations_conversation_id',
        'conversation_revocations',
        ['conversation_id'],
    )


def downgrade() -> None:
    op.drop_index('ix_conversation_revocations_conversation_id', table_name='conversation_revocations')
    op.drop_table('conversation_revocations')
    op.drop_column('messages', 'forwarded_from_id')
