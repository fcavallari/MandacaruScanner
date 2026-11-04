import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Dev fallback; docker-compose (and any deployment) injects the real URL via env.
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://pnakotic_admin:dark-matter-password@db:5432/pnakotic_memory",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def init_db():
    """Create any missing tables (idempotent, checkfirst).

    Alembic remains the source of truth for schema evolution; this is a
    convenience so `docker compose up` works without a manual migration step.
    """
    from . import models  # noqa: F401 - ensure models are registered on Base.metadata

    Base.metadata.create_all(bind=engine)
