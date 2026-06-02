"""merge migration heads

Revision ID: ffff00000000
Revises: 8662fc698943, d1e2f3a4b5c6
Create Date: 2026-05-25
"""

from typing import Sequence, Union

revision: str = 'ffff00000000'
down_revision: Union[str, Sequence[str], None] = ('8662fc698943', 'd1e2f3a4b5c6')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
