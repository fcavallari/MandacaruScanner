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


def _add_job(Session, job_id, status, updated_at=None, created_at=None, kind="url"):
    from pnakotic.src.database import models

    s = Session()
    s.add(models.ScanJob(id=job_id, target_url=f"https://{job_id}.example/", status=status,
                         created_at=created_at or updated_at, updated_at=updated_at, kind=kind))
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
    compared = []

    def __init__(self, **kwargs):
        _FakeEngine.calls.append(kwargs)

    async def scan(self, url, profile, compare=False):
        _FakeEngine.compared.append(compare)
        return _FakeEngine.behaviour(url, profile)


@pytest.fixture
def fake_engine(monkeypatch):
    from pnakotic.src.scanner import engine as engine_mod

    _FakeEngine.calls = []
    _FakeEngine.compared = []
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
    assert fake_engine.compared == [False]  # old messages carry no compare flag
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
        r.metadata = {"scoring_findings": ["x"], "blocked_hosts": ["db"],
                      "variants": [{"profile": "mobile-ios", "final_url": "https://x.example/"}],
                      "cloaking": {"common": "landing.example"}}
        return r

    fake_engine.behaviour = scan
    assert run_scan_worker("ok", "https://ok.example/", "default", None, True) == "Success: ok"
    assert fake_engine.compared == [True]

    s = Session()
    res = s.query(models.ScanResult).filter_by(job_id="ok").one()
    assert res.target_url == "https://ok.example/"
    assert res.metadata_json["blocked_hosts"] == ["db"]
    assert res.metadata_json["variants"][0]["profile"] == "mobile-ios"
    assert res.metadata_json["cloaking"] == {"common": "landing.example"}
    assert s.query(models.ScanJob).filter_by(id="ok").one().status == "completed"
    s.close()


@pytest.fixture
def fake_site_scanner(monkeypatch):
    from pnakotic.src.scanner import engine as engine_mod
    from pnakotic.src.scanner import site_engine
    from pnakotic.src.scanner.site_engine import SiteOutcome

    class _FakeSiteScanner:
        behaviour = None
        engines = []

        def __init__(self, engine, *args, **kwargs):
            _FakeSiteScanner.engines.append(engine)

        async def scan(self, url):
            if _FakeSiteScanner.behaviour is not None:
                return _FakeSiteScanner.behaviour(url)
            return SiteOutcome(report={"verdict": {"verdict": "clean"}, "blocked_hosts": ["db"]},
                               homepage_url=url, final_url=url, worst_score=0.0,
                               redirect_chain=False, artifact_manifest={}, raw_error=None)

    _FakeSiteScanner.behaviour = None
    _FakeSiteScanner.engines = []
    monkeypatch.setattr(site_engine, "SiteScanner", _FakeSiteScanner)
    monkeypatch.setattr(engine_mod, "PnakoticEngine", _FakeEngine)
    _FakeEngine.calls = []
    return _FakeSiteScanner


def test_site_worker_writes_report_and_is_idempotent(db, fake_site_scanner):
    from pnakotic.src.database import models
    from pnakotic.src.workers.celery_app import run_site_scan_worker

    _engine, Session = db
    _add_job(Session, "s1", "queued", kind="site")
    s = Session()
    s.add(models.ScanResult(id="res_s1", job_id="s1", target_url="stale"))  # from an earlier attempt
    s.commit()
    s.close()

    assert run_site_scan_worker("s1", "https://s.com/") == "Success: s1"
    assert _FakeEngine.calls == [{"task_id": "s1"}]
    s = Session()
    row = s.query(models.ScanResult).filter_by(job_id="s1").one()
    s.close()
    assert row.target_url == "https://s.com/" and row.final_url == "https://s.com/"
    assert row.malicious_score == 0.0 and row.is_redirect_chain_detected is False
    assert row.metadata_json["kind"] == "site" and row.metadata_json["site"]["verdict"]["verdict"] == "clean"
    assert row.metadata_json["blocked_hosts"] == ["db"]
    assert row.metadata_json["scan_time"]
    assert _job(Session, "s1").status == "completed"
    assert run_site_scan_worker("s1", "https://s.com/").startswith("Already completed")


def test_site_worker_failure_marks_job_failed_with_truncated_error(db, fake_site_scanner):
    from pnakotic.src.workers.celery_app import run_site_scan_worker

    _engine, Session = db
    long_ago = datetime.now(timezone.utc) - timedelta(minutes=14)
    _add_job(Session, "s2", "running", long_ago, kind="site")

    def boom(_url):
        raise RuntimeError("x" * 900)

    fake_site_scanner.behaviour = boom
    assert run_site_scan_worker("s2", "https://s.com/").startswith("Failed:")
    job = _job(Session, "s2")
    assert job.status == "failed" and job.error == "x" * 500


def test_site_task_is_routed_to_site_queue():
    from pnakotic.src.workers.celery_app import celery_app

    assert celery_app.conf.task_routes["pnakotic.site_scan"] == {"queue": "site"}


def test_scan_job_kind_defaults_to_url(db):
    from pnakotic.src.database import models

    _engine, Session = db
    s = Session()
    s.add(models.ScanJob(id="k1", target_url="https://k1.example/", status="queued"))
    s.commit()
    assert s.query(models.ScanJob).filter_by(id="k1").one().kind == "url"
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
    assert sent == [(task_id, "http://8.8.8.8/", "mobile-ios", None, True)]  # compares by default
    assert resp.json()["artifact_dir"].endswith(task_id)
    client.post("/scan", json={"url": "http://8.8.8.8/", "compare_profiles": False})
    assert sent[1][1:] == ("http://8.8.8.8/", "default", None, False)


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


# ---------- site quick check ----------

def test_site_scan_dispatches_and_lists_kind(client, monkeypatch):
    from pnakotic.src.api import main

    sent = []

    class FakeTask:
        @staticmethod
        def delay(*args):
            sent.append(args)

    monkeypatch.setattr(main, "run_site_scan_worker", FakeTask)

    async def _noop_async(*a, **k):
        return None

    monkeypatch.setattr(main, "_assert_public_host", _noop_async)
    resp = client.post("/site-scan", json={"site": "Example.COM/blog"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "queued" and body["artifact_dir"].endswith(body["task_id"])
    assert sent == [(body["task_id"], "https://example.com/")]
    listed = client.get("/tasks").json()["tasks"][0]
    assert listed["kind"] == "site" and listed["profile"] == "default"
    assert listed["target_url"] == "https://example.com/"


def test_site_scan_rejects_bad_input_and_internal_host(client):
    assert client.post("/site-scan", json={"site": "ftp://x"}).status_code == 422
    assert client.post("/site-scan", json={"site": ""}).status_code == 422
    assert client.post("/site-scan", json={"site": "x" * 2049}).status_code == 422
    assert client.post("/site-scan", json={"site": "127.0.0.1"}).status_code == 400


def test_site_scan_marks_job_failed_when_dispatch_fails(client, db, monkeypatch):
    from pnakotic.src.api import main

    class BrokenTask:
        @staticmethod
        def delay(*args):
            raise RuntimeError("broker down")

    monkeypatch.setattr(main, "run_site_scan_worker", BrokenTask)

    async def _noop_async(*a, **k):
        return None

    monkeypatch.setattr(main, "_assert_public_host", _noop_async)
    resp = client.post("/site-scan", json={"site": "example.com"})
    assert resp.status_code == 503
    job = client.get("/tasks").json()["tasks"][0]
    assert job["status"] == "failed" and "broker down" in job["error"]


def test_tasks_lists_url_jobs_as_kind_url(client, db):
    _engine, Session = db
    _add_job(Session, "u1", "queued")
    assert client.get("/tasks").json()["tasks"][0]["kind"] == "url"


def test_serialize_result_site_fields(monkeypatch):
    from pnakotic.src.api import main
    from pnakotic.src.database import models

    monkeypatch.setenv("CLEANUP_URL", "https://clean.example/")
    row = models.ScanResult(id="r", job_id="j", target_url="https://s.com/",
                            metadata_json={"kind": "site", "site": {"verdict": {}}})
    out = main.serialize_result(row)
    assert out["kind"] == "site" and out["site"] == {"verdict": {}}
    assert out["cleanup_url"] == "https://clean.example/"
    url_out = main.serialize_result(models.ScanResult(id="r2", job_id="j2", target_url="x", metadata_json={}))
    assert url_out["kind"] == "url" and "site" not in url_out and "cleanup_url" not in url_out


def test_serialize_result_site_cleanup_url_defaults(monkeypatch):
    from pnakotic.src.api import main
    from pnakotic.src.database import models

    monkeypatch.delenv("CLEANUP_URL", raising=False)
    row = models.ScanResult(id="r", job_id="j", target_url="https://s.com/",
                            metadata_json={"kind": "site", "site": None})
    assert main.serialize_result(row)["cleanup_url"] == "https://elderward.space.fast"


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
