import asyncio
import os
import traceback
from typing import Optional

from celery import Celery

# Initialize Redis Connection
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery("pnakotic", broker=REDIS_URL, backend=REDIS_URL)
celery_app.conf.update(
    # A scan takes tens of seconds; don't ack until it's done so a dead worker re-queues it.
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Hard cap so a wedged browser can't pin a worker forever.
    task_time_limit=300,
    task_soft_time_limit=240,
    # Site quick checks open many browser contexts at once, so they get their own queue and a
    # dedicated single-concurrency worker. Everything else stays on the default "celery" queue.
    task_routes={"pnakotic.site_scan": {"queue": "site"}},
)


def run_async(coro):
    """Runs an async coroutine in a dedicated event loop for the worker process."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(name="pnakotic.scan")
def run_scan_worker(job_id: str, url: str, profile: str, task_folder: Optional[str] = None,
                    compare: bool = False):
    """The actual scan execution logic called by the API.

    `task_folder` is ignored. It is kept only so messages queued by an older API
    (which passed it) still deserialize; the engine resolves the folder from ARTIFACTS_DIR.
    `compare` also loads the URL in every other browser profile to catch cloaking; it
    defaults to off so those older messages keep their meaning.
    """
    # Import INSIDE task to prevent serialization errors in Celery workers
    from pnakotic.src.scanner.engine import PnakoticEngine
    from pnakotic.src.database.session import SessionLocal
    from pnakotic.src.database import models, ScanResult
    from pnakotic.src.database.models import utcnow

    db = SessionLocal()
    job = None
    try:
        job = db.query(models.ScanJob).filter_by(id=job_id).first()
        if not job:
            return f"Job {job_id} not found in DB"

        if job.status == "completed":
            # Re-queued message after a lost ack: the scan already succeeded.
            # Skip it so a completed job doesn't flip back to "running" (and re-scan).
            return f"Already completed: {job_id}"

        # Always write, even if the row already says "running" (a re-delivered message):
        # updated_at is the sweeper's clock, and it must start from *this* attempt.
        # Set explicitly because onupdate only fires when some column changed.
        job.status = "running"
        job.updated_at = utcnow()
        db.commit()

        engine = PnakoticEngine(task_id=job_id)  # artifacts land in ARTIFACTS_DIR/<job_id>

        # EXECUTION: Bridge Sync Celery -> Async Playwright
        result = run_async(engine.scan(url, profile, compare=bool(compare)))

        # DATABASE WRITE: Map Pydantic ScanResult to SQLAlchemy models.
        # Delete any stale row first so a re-queued message (acks_late) can't collide on the PK.
        db.query(ScanResult).filter_by(job_id=job.id).delete()
        res_entry = ScanResult(
            id=f"res_{job_id}",  # Unique ID for result record
            job_id=job.id,
            target_url=result.target_url,
            malicious_score=result.malicious_score,
            final_url=result.final_url,
            is_redirect_chain_detected=result.is_redirect_chain_detected,
            metadata_json={  # Fix key mapping for JSONB field in SQL
                "hops": [h.model_dump(mode="json") for h in result.hops],
                "artifact_manifest": result.metadata.get("artifact_manifest", {}),
                "scoring_findings": result.metadata.get("scoring_findings", []),
                "decisive_findings": result.metadata.get("decisive_findings", []),
                "variants": result.metadata.get("variants", []),
                "cloaking": result.metadata.get("cloaking"),
                "yara": result.metadata.get("yara"),  # rule count and what was scanned; None = off
                "raw_error": result.metadata.get("raw_error"),
                "redirect_loop": result.metadata.get("redirect_loop", False),
                "blocked_hosts": result.metadata.get("blocked_hosts", []),
                "scan_time": str(result.end_time) if result.end_time else None,
            }
        )
        db.add(res_entry)

        job.status = "completed"
        job.error = None
        db.commit()
        return f"Success: {job_id}"

    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"Worker Failure [JOB:{job_id}]: {e}\n{error_trace}")
        try:
            if job is not None:
                job.status = "failed"
                job.error = str(e)[:500]
                db.commit()
        except Exception:
            db.rollback()  # Don't mask the original error with a DB failure
        return f"Failed: {str(e)}"
    finally:
        db.close()


@celery_app.task(name="pnakotic.site_scan", soft_time_limit=240, time_limit=300)
def run_site_scan_worker(job_id: str, homepage_url: str):
    """Quick-check a whole site from its homepage; same lifecycle and idempotency as run_scan_worker."""
    # Import INSIDE task to prevent serialization errors in Celery workers
    from pnakotic.src.scanner.engine import PnakoticEngine
    from pnakotic.src.scanner.site_engine import SiteScanner
    from pnakotic.src.database.session import SessionLocal
    from pnakotic.src.database import models, ScanResult
    from pnakotic.src.database.models import utcnow

    db = SessionLocal()
    job = None
    try:
        job = db.query(models.ScanJob).filter_by(id=job_id).first()
        if not job:
            return f"Job {job_id} not found in DB"

        if job.status == "completed":
            return f"Already completed: {job_id}"

        # Always write, even if the row already says "running" (see run_scan_worker).
        job.status = "running"
        job.updated_at = utcnow()
        db.commit()

        engine = PnakoticEngine(task_id=job_id)  # artifacts land in ARTIFACTS_DIR/<job_id>
        outcome = run_async(SiteScanner(engine).scan(homepage_url))

        # Delete any stale row first so a re-queued message (acks_late) can't collide on the PK.
        db.query(ScanResult).filter_by(job_id=job.id).delete()
        db.add(ScanResult(
            id=f"res_{job_id}",
            job_id=job.id,
            target_url=homepage_url,
            malicious_score=outcome.worst_score,
            final_url=outcome.final_url,
            is_redirect_chain_detected=outcome.redirect_chain,
            metadata_json={
                "kind": "site",
                "site": outcome.report,
                "artifact_manifest": outcome.artifact_manifest,
                "raw_error": outcome.raw_error,
                "blocked_hosts": outcome.report.get("blocked_hosts", []),
                "scan_time": utcnow().isoformat(),
            },
        ))

        job.status = "completed"
        job.error = None
        db.commit()
        return f"Success: {job_id}"

    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"Site worker failure [JOB:{job_id}]: {e}\n{error_trace}")
        try:
            if job is not None:
                job.status = "failed"
                job.error = str(e)[:500]
                db.commit()
        except Exception:
            db.rollback()  # Don't mask the original error with a DB failure
        return f"Failed: {str(e)}"
    finally:
        db.close()
