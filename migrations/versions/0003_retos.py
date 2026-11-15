"""Retos de corrección: un intento es un proyecto marcado con el reto

Revision ID: 3b8f1d6e2c47
Revises: 7d1e4c2a9b30
Create Date: 2026-11-15 18:00:00

"""
from alembic import op
import sqlalchemy as sa

revision = "3b8f1d6e2c47"
down_revision = "7d1e4c2a9b30"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("challenge_id", sa.String(length=80), nullable=True))
        batch.add_column(sa.Column("challenge_solved_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index(batch.f("ix_projects_challenge_id"), ["challenge_id"], unique=False)


def downgrade():
    with op.batch_alter_table("projects") as batch:
        batch.drop_index(batch.f("ix_projects_challenge_id"))
        batch.drop_column("challenge_solved_at")
        batch.drop_column("challenge_id")
