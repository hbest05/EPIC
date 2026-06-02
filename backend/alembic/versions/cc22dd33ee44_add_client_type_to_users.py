"""add client_type to users

Revision ID: cc22dd33ee44
Revises: a7b8c9d0e1f2
Create Date: 2026-05-31

Adds a nullable client_type column to users. Values are 'web' or 'cpp'.
NULL means a legacy account with no client restriction.
New registrations always set this field, and login enforces it.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "cc22dd33ee44"
down_revision: Union[str, None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("client_type", sa.String(16), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "client_type")
