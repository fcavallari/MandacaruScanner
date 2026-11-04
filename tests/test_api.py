"""API, sweeper and worker tests against a throwaway SQLite database (no Postgres/Redis)."""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker


@compiles(JSONB, "sqlite")
def _jsonb_as_json_on_sqlite(_type, _compiler, **_kw):
    return "JSON"


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Point the API module and the worker's session import at a fresh SQLite DB."""
    from pnakotic.src.api import main
    from pnakotic.src.database import session as db_session
    from pnakotic.src.database.session import Base

    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    monkeypatch.setattr(main, "SessionLocal", Session)
    monkeypatch.setattr(db_session, "SessionLocal", Session)  # the worker imports it at call time
    monkeypatch.setattr(main, "_db_ready", True)
    monkeypatch.setenv("ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    yield engine, Session
    engine.dispose()


def _add_job(Session, job_id, status, updated_at=None, created_at=None):
    from pnakotic.src.database import models

    s = Session()
    s.add(models.ScanJob(id=job_id, target_url=f"https://{job_id}.example/", status=status,
                         created_at=created_at or updated_at, updated_at=updated_at))
    s.commit()
    s.close()


def _job(Session, job_id):
    from pnakotic.src.database import models

    s = Session()
    try:
        return s.query(models.ScanJob).filter_by(id=job_id).one()
    finally:
        s.close()


def _as_utc(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # SQLite drops tzinfo


# ---------- sweeper ----------

def test_sweeper_fails_stale_running_and_queued_jobs(db):
    from pnakotic.src.api.main import sweep_stale_jobs

    _engine, Session = db
    now = datetime.now(timezone.utc)
    _add_job(Session, "run-old", "running", now - timedelta(minutes=20))
    _add_job(Session, "run-fresh", "running", now - timedelta(minutes=1))
    _add_job(Session, "queued-old", "queued", now - timedelta(hours=2))
    _add_job(Session, "queued-fresh", "queued", now - timedelta(minutes=5))
    _add_job(Session, "done-old", "completed", now - timedelta(days=1))

    assert sweep_stale_jobs(now) == 2
    assert _job(Session, "run-old").status == "failed"
    assert "no worker update" in _job(Session, "run-old").error
    assert _job(Session, "queued-old").status == "failed"
    assert "never picked up" in _job(Session, "queued-old").error
    assert _job(Session, "run-fresh").status == "running"
    assert _job(Session, "queued-fresh").status == "queued"
    assert _job(Session, "done-old").status == "completed"


# ---------- worker ----------

class _FakeEngine:
    """Stands in for PnakoticEngine; `behaviour` decides what scan() does."""
    behaviour = None
    calls = []

    def __init__(self, **kwargs):
        _FakeEngine.calls.append(kwargs)

    async def scan(self, url, profile):
        return _FakeEngine.behaviour(url, profile)


@pytest.fixture
def fake_engine(monkeypatch):
    from pnakotic.src.scanner import engine as engine_mod

    _FakeEngine.calls = []
    monkeypatch.setattr(engine_mod, "PnakoticEngine", _FakeEngine)
    return _FakeEngine


def test_worker_redelivery_refreshes_updated_at(db, fake_engine):
    from pnakotic.src.workers.celery_app import run_scan_worker

    _engine, Session = db
    long_ago = datetime.now(timezone.utc) - timedelta(minutes=14)
    _add_job(Session, "redeliv", "running", long_ago)  # row left "running" by a dead worker
    seen = {}

    def scan(_url, _profile):
        seen["updated_at"] = _as_utc(_job(Session, "redeliv").updated_at)
        raise RuntimeError("boom")

    fake_engine.behaviour = scan
    # Old-API message shape (4 args, incl. the now-ignored task_folder) still runs.
    run_scan_worker("redeliv", "https://redeliv.example/", "default", "/old/artifacts/redeliv")

    assert seen["updated_at"] > datetime.now(timezone.utc) - timedelta(minutes=1)
    assert fake_engine.calls == [{"task_id": "redeliv"}]  # no base_dir patching
    job = _job(Session, "redeliv")
    assert (job.status, job.error) == ("failed", "boom")


def test_worker_success_writes_result_and_replaces_stale_row(db, fake_engine):
    from pnakotic.src.database import models
    from pnakotic.src.scanner.models import RedirectHop, ScanResult
    from pnakotic.src.workers.celery_app import run_scan_worker

    _engine, Session = db
    _add_job(Session, "ok", "queued", datetime.now(timezone.utc))
    s = Session()
    s.add(models.ScanResult(id="res_ok", job_id="ok", target_url="stale"))  # from an earlier attempt
    s.commit()
    s.close()

    def scan(url, _profile):
        r = ScanResult(target_url=url, final_url="https://landing.example/", malicious_score=0.25)
        r.hops = [RedirectHop(url=url, status_code=302, mechanism="http_3xx")]
        r.is_redirect_chain_detected = True
        r.metadata = {"scoring_findings": ["x"], "blocked_hosts": ["db"]}
        return r

    fake_engine.behaviour = scan
    assert run_scan_worker("ok", "https://ok.example/", "default") == "Success: ok"

    s = Session()
    res = s.query(models.ScanResult).filter_by(job_id="ok").one()
    assert res.target_url == "https://ok.example/"
    assert res.metadata_json["blocked_hosts"] == ["db"]
    assert s.query(models.ScanJob).filter_by(id="ok").one().status == "completed"
    s.close()


# ---------- HTTP endpoints ----------

@pytest.fixture
def client(db):
    from fastapi.testclient import TestClient
    from pnakotic.src.api import main

    return TestClient(main.app)  # no `with`: skip lifespan (real DB init + sweeper)


def test_scan_dispatches_without_task_folder(client, monkeypatch):
    from pnakotic.src.api import main

    sent = []

    class FakeTask:
        @staticmethod
        def delay(*args):
            sent.append(args)

    monkeypatch.setattr(main, "run_scan_worker", FakeTask)
    resp = client.post("/scan", json={"url": "http://8.8.8.8/", "profile": "mobile-ios"})
    assert resp.status_code == 201
    task_id = resp.json()["task_id"]
    assert sent == [(task_id, "http://8.8.8.8/", "mobile-ios")]
    assert resp.json()["artifact_dir"].endswith(task_id)


def test_scan_rejects_internal_host(client):
    resp = client.post("/scan", json={"url": "http://localhost:8000/"})
    assert resp.status_code == 400


def test_task_list_is_one_query_and_matches_results_shape(client, db):
    from pnakotic.src.database import models

    engine, Session = db
    now = datetime.now(timezone.utc)
    s = Session()
    for i in range(3):
        s.add(models.ScanJob(id=f"j{i}", target_url=f"https://j{i}.example/", status="completed",
                             created_at=now - timedelta(minutes=i), updated_at=now))
        s.add(models.ScanResult(id=f"res_j{i}", job_id=f"j{i}", target_url=f"https://j{i}.example/",
                                final_url="https://end.example/", malicious_score=0.1 * i,
                                metadata_json={"hops": [], "scoring_findings": [f"f{i}"]}))
    s.commit()
    s.close()

    selects = []

    def count(_conn, _cursor, statement, *_args):
        if statement.lstrip().upper().startswith("SELECT"):
            selects.append(statement)

    event.listen(engine, "before_cursor_execute", count)
    try:
        listed = client.get("/tasks").json()["tasks"]
    finally:
        event.remove(engine, "before_cursor_execute", count)

    assert [t["task_id"] for t in listed] == ["j0", "j1", "j2"]
    assert len(selects) == 1
    detail = client.get("/tasks/j1/results").json()["result"]
    assert listed[1]["result"] == detail
    assert detail["findings"] == ["f1"]


# ---------- artifacts ----------

def test_artifact_paths_share_one_validator(tmp_path):
    from pnakotic.src.scanner.artifacts import ArtifactManager, resolve_task_folder

    am = ArtifactManager(base_dir=str(tmp_path))
    with pytest.raises(ValueError):
        am.create_task_folder("")
    assert am.get_task_manifest("../etc") == {"artifacts": []}
    assert am.create_task_folder("abc-1") == resolve_task_folder(str(tmp_path), "abc-1")


def test_scan_rejects_unknown_profile(client):
    # Used to fall back to "default" silently, reporting a persona that never ran.
    resp = client.post("/scan", json={"url": "http://8.8.8.8/", "profile": "no-such-persona"})
    assert resp.status_code == 422
