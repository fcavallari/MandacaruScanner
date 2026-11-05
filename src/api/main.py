import asyncio
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse

import uuid

from fastapi import FastAPI, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import joinedload

from ..database.session import SessionLocal, init_db
from ..database import models
from ..scanner.artifacts import task_folder_for
from ..scanner.netguard import url_is_allowed
from ..scanner.profiles import PROFILES
from ..workers.celery_app import run_scan_worker  # The Celery task

# Handlers that touch the DB or the broker are plain `def`, so FastAPI runs them in its
# threadpool instead of blocking the event loop (SQLAlchemy and Celery's publish are sync).

# CORS: open by default for the PoC; restrict via env in production,
# e.g. CORS_ORIGINS="https://a.example,https://b.example"
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]

# Jobs stuck in "running" longer than this are considered dead (worker crash / lost message).
STUCK_JOB_TIMEOUT = timedelta(minutes=int(os.getenv("STUCK_JOB_TIMEOUT_MINUTES", "15")))
# Jobs still "queued" this long were never picked up (message lost, no worker running).
# Longer than the running timeout: a busy queue legitimately holds jobs for a while.
QUEUED_JOB_TIMEOUT = timedelta(minutes=int(os.getenv("QUEUED_JOB_TIMEOUT_MINUTES", "60")))
SWEEP_INTERVAL_SECONDS = int(os.getenv("SWEEP_INTERVAL_SECONDS", "60"))

# Set once create_all has succeeded; until then each sweep retries it (DB came up late).
_db_ready = False


class ScanRequest(BaseModel):
    url: str = Field(..., pattern=r"^https?://")  # [P2] Validated input
    profile: str = "default"
    # Also load the URL in every other browser profile and compare landings (cloaking).
    compare_profiles: bool = True

    @field_validator("profile")
    @classmethod
    def _known_profile(cls, v: str) -> str:
        # An unknown name used to scan silently as "default", which reports the wrong persona.
        if v not in PROFILES:
            raise ValueError(f"unknown profile; one of: {', '.join(PROFILES)}")
        return v


async def _assert_public_host(url: str) -> None:
    """Fast-fail SSRF check: reject targets whose host resolves to a non-public address.

    This is only the early 400; the engine re-checks every browser request (including
    redirect hops) because a public URL can still redirect inward. See scanner/netguard.py.
    """
    if not await url_is_allowed(url):
        host = urlparse(url).hostname or url
        raise HTTPException(status_code=400, detail=f"Host {host} is not a public address")


def _ensure_db() -> None:
    global _db_ready
    if not _db_ready:
        init_db()  # idempotent table creation; alembic is the source of truth for evolution
        _db_ready = True


def sweep_stale_jobs(now: Optional[datetime] = None) -> int:
    """Mark jobs that no worker is going to finish as failed. Returns how many.

    * running too long: worker crash or wedged browser (acks_late re-queues the message
      on a clean worker loss; this is the fallback when nothing re-runs it).
    * queued too long: the message was lost or no worker is consuming.

    Each rule is one conditional UPDATE, so a worker that flips a job to running/completed
    between "find" and "write" can't be overwritten with a stale failure.
    """
    now = now or datetime.now(timezone.utc)
    rules = (
        ("running", STUCK_JOB_TIMEOUT, "timed out: no worker update within timeout"),
        ("queued", QUEUED_JOB_TIMEOUT, "timed out: never picked up by a worker"),
    )
    db = SessionLocal()
    try:
        _ensure_db()
        swept = 0
        for status, timeout, reason in rules:
            swept += (
                db.query(models.ScanJob)
                .filter(models.ScanJob.status == status, models.ScanJob.updated_at < now - timeout)
                .update({"status": "failed", "error": reason, "updated_at": now}, synchronize_session=False)
            )
        db.commit()
        return swept
    finally:
        db.close()


async def _sweep_loop():
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)
        try:
            await run_in_threadpool(sweep_stale_jobs)
        except Exception as exc:  # never let the sweeper die
            print(f"[sweeper] error: {exc}")


@asynccontextmanager
async def lifespan(_app):
    try:
        await run_in_threadpool(_ensure_db)
    except Exception as exc:
        print(f"[startup] could not initialize DB (will retry via sweeper): {exc}")
    sweep_task = asyncio.create_task(_sweep_loop())
    yield
    sweep_task.cancel()


app = FastAPI(title="Pnakotic API", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])


def serialize_result(res: models.ScanResult) -> dict:
    """The one `result` shape shared by /tasks and /tasks/{id}/results
    (mirrored by ScanResultData in frontend/src/lib/api.ts)."""
    meta = res.metadata_json or {}  # None-safe
    return {
        "final_url": res.final_url,
        "malicious_score": res.malicious_score,
        "is_redirect_chain_detected": res.is_redirect_chain_detected,
        "hops": meta.get("hops", []),
        "artifacts": meta.get("artifact_manifest", {}),
        "findings": meta.get("scoring_findings", []),
        "decisive": meta.get("decisive_findings", []),  # also at the head of findings
        "variants": meta.get("variants", []),  # the other profiles, when compared
        "cloaking": meta.get("cloaking"),
        "yara": meta.get("yara"),  # None when the worker had no YARA_RULES_DIR
        "raw_error": meta.get("raw_error"),
    }


def _create_and_dispatch(req: ScanRequest) -> dict:
    job_id = str(uuid.uuid4())
    db = SessionLocal()
    try:
        # 1. Persist Intent to DB first (Reliability)
        new_job = models.ScanJob(
            id=job_id,
            target_url=req.url,
            profile=req.profile,
            status="queued",
        )
        db.add(new_job)
        db.commit()

        # 2. Dispatch to Celery. The worker derives the artifact folder from ARTIFACTS_DIR.
        try:
            run_scan_worker.delay(job_id, req.url, req.profile, None, req.compare_profiles)
        except Exception as exc:  # broker down etc. - don't leave a phantom "queued" job
            new_job.status = "failed"
            new_job.error = f"Could not dispatch scan: {exc}"[:500]
            db.commit()
            raise HTTPException(status_code=503, detail="Task queue unavailable; scan not started")

        return {"task_id": job_id, "status": "queued", "artifact_dir": task_folder_for(job_id)}
    finally:
        db.close()


@app.post("/scan", status_code=201)
async def start_ritual(req: ScanRequest):
    await _assert_public_host(req.url)  # async DNS lookup
    return await run_in_threadpool(_create_and_dispatch, req)  # sync DB + broker publish


@app.get("/tasks/{task_id}/status")
def get_job_status(task_id: str):
    db = SessionLocal()
    try:
        job = db.query(models.ScanJob).filter_by(id=task_id).first()
        if not job:
            raise HTTPException(404, "Ritual trace lost")
        return {"task_id": job.id, "status": job.status, "error": job.error}
    finally:
        db.close()


@app.get("/tasks/{task_id}/results")
def get_ritual_results(task_id: str):
    db = SessionLocal()
    try:
        res = db.query(models.ScanResult).filter_by(job_id=task_id).first()
        if not res:
            raise HTTPException(404, "No results found for this ritual")
        return {
            "job_id": task_id,
            "target": res.target_url,
            "timestamp": str(res.created_at) if res.created_at else None,
            "result": serialize_result(res),
        }
    finally:
        db.close()


@app.get("/tasks")
def list_recent_tasks(limit: int = Query(20, ge=1, le=100)):
    """Most recent jobs (newest first), with results attached where available."""
    db = SessionLocal()
    try:
        jobs = (
            db.query(models.ScanJob)
            .options(joinedload(models.ScanJob.results))  # one query, not one per job
            .order_by(models.ScanJob.created_at.desc())
            .limit(limit)
            .all()
        )
        out = []
        for job in jobs:
            entry = {
                "task_id": job.id,
                "status": job.status,
                "target_url": job.target_url,
                "profile": job.profile,
                "error": job.error,
                "created_at": str(job.created_at) if job.created_at else None,
            }
            if job.results is not None:  # one-to-one relationship
                entry["result"] = serialize_result(job.results)
            out.append(entry)
        return {"tasks": out}
    finally:
        db.close()


@app.get("/tasks/{task_id}/artifacts/{file_path:path}")
def get_artifact(task_id: str, file_path: str):
    """Serve a single artifact (e.g. screenshots/landing_*.png) for a task."""
    try:
        base = task_folder_for(task_id)  # validated + traversal-safe
    except (ValueError, PermissionError):
        raise HTTPException(404, "Artifact not found")
    full = os.path.abspath(os.path.join(base, file_path))
    if not full.startswith(base + os.sep) or not os.path.isfile(full):
        raise HTTPException(404, "Artifact not found")
    return FileResponse(full)


@app.get("/health")
async def health():
    return {"status": "alive"}
