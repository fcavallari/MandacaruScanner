"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-11-03

"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # IF NOT EXISTS keeps this compatible with Base.metadata.create_all (API startup).
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_jobs (
            id VARCHAR NOT NULL,
            target_url VARCHAR NOT NULL,
            profile VARCHAR DEFAULT 'default',
            status VARCHAR,
            error TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
            updated_at TIMESTAMP WITH TIME ZONE,
            PRIMARY KEY (id)
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_scan_jobs_status ON scan_jobs (status)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_results (
            id VARCHAR NOT NULL,
            job_id VARCHAR REFERENCES scan_jobs (id),
            target_url VARCHAR NOT NULL,
            malicious_score FLOAT DEFAULT 0.0,
            final_url VARCHAR,
            is_redirect_chain_detected BOOLEAN DEFAULT FALSE,
            metadata_json JSONB,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
            PRIMARY KEY (id)
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_scan_results_job_id ON scan_results (job_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_scan_results_job_id")
    op.execute("DROP TABLE IF EXISTS scan_results")
    op.execute("DROP INDEX IF EXISTS ix_scan_jobs_status")
    op.execute("DROP TABLE IF EXISTS scan_jobs")
