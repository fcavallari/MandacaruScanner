import datetime

from sqlalchemy import Column, String, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from .session import Base


def utcnow() -> datetime.datetime:
    """Timezone-aware UTC now (datetime.utcnow is deprecated as of Python 3.12)."""
    return datetime.datetime.now(datetime.timezone.utc)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True)  # UUID
    target_url = Column(String, nullable=False)
    profile = Column(String, default="default")
    status = Column(String, index=True)  # queued, running, completed, failed
    error = Column(Text, nullable=True)  # populated when status == "failed"
    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    results = relationship("ScanResult", back_populates="job", uselist=False, cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True)
    job_id = Column(String, ForeignKey("scan_jobs.id"), index=True)
    target_url = Column(String, nullable=False)
    malicious_score = Column(Float, default=0.0)
    final_url = Column(String)
    is_redirect_chain_detected = Column(Boolean, default=False)
    # JSONB (queryable on Postgres); named metadata_json to avoid clashing with Base.metadata
    metadata_json = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    job = relationship("ScanJob", back_populates="results")


# For Alembic
__all__ = ["Base", "ScanJob", "ScanResult"]
