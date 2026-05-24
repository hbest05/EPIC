"""add blockchain_batch_index to messages

Revision ID: c8d9e0f1a2b3
Revises: a1b2c3d4e5f6
Create Date: 2026-05-24 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c8d9e0f1a2b3'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'messages',
        sa.Column('blockchain_batch_index', sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('messages', 'blockchain_batch_index')
