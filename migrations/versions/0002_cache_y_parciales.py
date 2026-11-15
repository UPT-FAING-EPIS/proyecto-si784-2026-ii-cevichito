"""Caché de resultados por contenido y marcas de escaneo parcial o reutilizado

Revision ID: 7d1e4c2a9b30
Revises: f2c59aa0bbb5
Create Date: 2026-11-14 19:00:00

"""
from alembic import op
import sqlalchemy as sa

revision = "7d1e4c2a9b30"
down_revision = "f2c59aa0bbb5"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "scan_result_cache",
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hits", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("key", name=op.f("pk_scan_result_cache")),
    )
    op.create_index(op.f("ix_scan_result_cache_created_at"), "scan_result_cache", ["created_at"], unique=False)
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("partial", sa.Boolean(), server_default=sa.false(), nullable=False))
        batch.add_column(sa.Column("result_reused", sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade():
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("result_reused")
        batch.drop_column("partial")
    op.drop_index(op.f("ix_scan_result_cache_created_at"), table_name="scan_result_cache")
    op.drop_table("scan_result_cache")
