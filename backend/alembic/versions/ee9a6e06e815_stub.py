"""stub for ee9a6e06e815 — applied directly to DB on main branch

Revision ID: ee9a6e06e815
Revises: e32ea88cfd28
Create Date: 2026-05-25

This revision was applied directly to the database on the main branch
and has no corresponding migration file in any branch of the repository.
The stub exists so that Alembic can resolve the revision graph when
building the DAG from files — without it, ffff00000000_merge_migration_heads.py
causes a CommandError on any fresh deploy.
"""

from typing import Sequence, Union

revision: str = 'ee9a6e06e815'
down_revision: Union[str, None] = 'e32ea88cfd28'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
