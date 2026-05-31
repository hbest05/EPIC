"""replace conversation_revocations with messages.deleted_for_recipient

Revision ID: f4a5b6c7d8e9
Revises: a7b8c9d0e1f2
Create Date: 2026-05-31 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = 'f4a5b6c7d8e9'
down_revision = 'a7b8c9d0e1f2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'messages',
        sa.Column(
            'deleted_for_recipient',
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.drop_index('ix_conversation_revocations_conversation_id', table_name='conversation_revocations')
    op.drop_table('conversation_revocations')


def downgrade() -> None:
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
    op.drop_column('messages', 'deleted_for_recipient')
