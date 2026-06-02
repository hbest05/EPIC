"""merge feat/improvedfrontend and main heads

Revision ID: aaaa00000001
Revises: cc22dd33ee44, f4a5b6c7d8e9
Create Date: 2026-06-02
"""

from typing import Sequence, Union

revision: str = 'aaaa00000001'
down_revision: Union[str, Sequence[str], None] = ('cc22dd33ee44', 'f4a5b6c7d8e9')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
