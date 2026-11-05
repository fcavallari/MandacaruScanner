"""scan_jobs.kind: url or site

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-05

"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The default backfills existing rows as "url". IF NOT EXISTS keeps this compatible with
    # Base.metadata.create_all (API startup), which creates the column on a fresh database.
    op.execute("ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS kind VARCHAR NOT NULL DEFAULT 'url'")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_jobs DROP COLUMN IF EXISTS kind")
