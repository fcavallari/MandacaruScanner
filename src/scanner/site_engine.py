"""The site quick check, end to end (spec §4): the homepage in four profiles, page picking,
budgeted stage-2 loads, site-mode scoring and the report.

One browser and one egress proxy serve every load; each load gets a fresh context. The site
budget runs from the start of stage 1: once it is spent no load starts, loads still running
get ``grace_s`` more and are then cancelled, and every load that didn't run is recorded as
not checked for lack of time.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from .engine import BROWSER_ERRORS, LoadOptions, PnakoticEngine
from .models import ScanResult
from .page_picker import pick_pages, probe_url
from .site_findings import Load
from .site_identity import on_site, resolve_site_host
from .site_report import build_report, classify_load

HOMEPAGE_PROFILES = ("default", "mobile-ios", "googlebot", "search-clicker")
PAGE_PROFILES = ("default", "mobile-ios", "googlebot")

NOTE_HTTP = "Checked over http"
NOTE_OFFSITE = "No pages could be picked because the homepage left the site"

MAX_ERROR_CHARS = 256
# After cancelling the loads still running at the deadline, how long to wait for their
# contexts to close before the browser is closed under them.
CANCEL_WAIT_S = 5.0

_Job = Tuple[int, str, str]  # (page index, url, profile)
_Outcome = Tuple[Optional[ScanResult], Optional[str], Optional[str]]  # (result, error, screenshot)


@dataclass
class SiteOutcome:
    report: dict
    homepage_url: str
    final_url: str
    worst_score: float
    redirect_chain: bool
    artifact_manifest: dict
    raw_error: Optional[str]


def _host(url: Optional[str]) -> str:
    """The URL's lower-case hostname without a trailing dot; '' when there is none."""
    try:
        return (urlsplit(url or "").hostname or "").rstrip(".")
    except ValueError:
        return ""


def _netloc(host: str, port: Optional[int]) -> str:
    host = "[{}]".format(host) if ":" in host else host
    return host if port is None else "{}:{}".format(host, port)


def _root(base_url: str, fallback_url: str, site_host: str) -> str:
    """``<scheme>://<site_host>[:port]/``, with the scheme and port of ``base_url`` (a landing,
    page-supplied), or of ``fallback_url`` when ``base_url``'s port doesn't parse."""
    try:
        parts = urlsplit(base_url)
        port = parts.port
    except ValueError:
        parts = urlsplit(fallback_url)
        port = parts.port
    return urlunsplit((parts.scheme, _netloc(site_host, port), "/", "", ""))


def _error(e: BaseException) -> str:
    return str(e).replace("\x00", "").strip()[:MAX_ERROR_CHARS]


def _shot(task_folder: str, shot_dir: str, since: float) -> Optional[str]:
    """The newest landing screenshot written into shot_dir since ``since``, relative to the task folder."""
    folder = os.path.join(task_folder, shot_dir)
    try:
        names = os.listdir(folder)
    except OSError:
        return None
    best = None  # type: Optional[Tuple[float, str]]
    for name in names:
        if not (name.startswith("landing_") and name.endswith(".png")):
            continue
        try:
            mtime = os.stat(os.path.join(folder, name)).st_mtime
        except OSError:
            continue
        if mtime >= since and (best is None or (mtime, name) > best):
            best = (mtime, name)
    return os.path.join(shot_dir, best[1]) if best else None


def _raise_bugs(tasks) -> None:
    """Re-raise what a finished load raised: browser errors are caught in the load itself,
    so anything here is a bug or Celery's SoftTimeLimitExceeded."""
    for task in tasks:
        if task.done() and not task.cancelled() and task.exception() is not None:
            raise task.exception()


class SiteScanner:
    def __init__(self, engine: PnakoticEngine, budget_s: float = 150.0, concurrency: int = 6,
                 grace_s: float = 10.0, page_limit: int = 5):
        self.engine = engine
        self.budget_s = budget_s
        self.concurrency = concurrency
        self.grace_s = grace_s
        self.page_limit = page_limit

    async def _load(self, browser, task_folder: str, job: _Job, sem: asyncio.Semaphore,
                    deadline: float) -> _Outcome:
        index, url, profile = job
        async with sem:
            if time.monotonic() >= deadline:
                return None, "budget", None
            shot_dir = os.path.join("pages", str(index), profile)
            options = LoadOptions(site=True, shot_dir=shot_dir, full_page=(index == 0 and profile == "default"))
            since = time.time()
            try:
                result = await self.engine._scan_in_context(browser, url, profile, task_folder,
                                                            primary=False, options=options)
            except BROWSER_ERRORS as e:
                return None, _error(e) or "load_failed", _shot(task_folder, shot_dir, since)
            return result, None, _shot(task_folder, shot_dir, since)

    async def _run(self, browser, task_folder: str, jobs: List[_Job], sem: asyncio.Semaphore,
                   deadline: float) -> List[_Outcome]:
        """Run the jobs under the semaphore until the deadline, then the grace period, then cancel."""
        if not jobs:
            return []
        tasks = [asyncio.ensure_future(self._load(browser, task_folder, job, sem, deadline)) for job in jobs]
        cut = set()  # type: set
        try:
            _, pending = await asyncio.wait(tasks, timeout=max(0.0, deadline - time.monotonic()),
                                            return_when=asyncio.FIRST_EXCEPTION)
            _raise_bugs(tasks)
            if pending:
                _, pending = await asyncio.wait(pending, timeout=self.grace_s, return_when=asyncio.FIRST_EXCEPTION)
                _raise_bugs(tasks)
            cut = set(pending)
            for task in cut:
                task.cancel()
            if cut:
                # Let each cancelled load close its context before the browser goes away.
                await asyncio.wait(cut, timeout=CANCEL_WAIT_S)
                _raise_bugs(cut)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
        return [(None, "budget", None) if task in cut or task.cancelled() else task.result() for task in tasks]

    async def scan(self, homepage_url: str) -> SiteOutcome:
        engine = self.engine
        task_folder = engine.artifacts.create_task_folder(engine.task_id)
        deadline = time.monotonic() + self.budget_s
        sem = asyncio.Semaphore(self.concurrency)
        notes = []  # type: List[str]
        blocked = []  # type: List[str]

        async with engine.browser_session() as (browser, proxy):
            # Stage 1: the homepage in every homepage profile at once.
            home_jobs = [(0, homepage_url, p) for p in HOMEPAGE_PROFILES]
            home = await self._run(browser, task_folder, home_jobs, sem, deadline)
            default = home[0][0]
            if (default is not None and default.metadata.get("navigation_failed")
                    and "net::ERR_" in str(default.metadata.get("raw_error") or "")
                    and urlsplit(homepage_url).scheme == "https"):
                # A network-level failure over https: try http once, and keep only that set.
                # The discarded loads' screenshots go first (before the rerun can write a
                # same-named file), so the manifest lists only loads in the report.
                for _, _, shot in home:
                    if shot:
                        try:
                            os.remove(os.path.join(task_folder, shot))
                        except OSError:
                            pass
                homepage_url = urlunsplit(("http",) + tuple(urlsplit(homepage_url))[1:])
                home_jobs = [(0, homepage_url, p) for p in HOMEPAGE_PROFILES]
                home = await self._run(browser, task_folder, home_jobs, sem, deadline)
                default = home[0][0]
                notes.append(NOTE_HTTP)

            entered_host = _host(homepage_url)
            landing = default.final_url if default is not None else None
            landing_host = _host(landing)
            site_host, offsite_domain = resolve_site_host(
                entered_host, "http://{}/".format(_netloc(landing_host, None)) if landing_host else "")
            states = [classify_load(result, error) for result, error, _ in home]

            # Links come from the first homepage landing that stayed on the site.
            links = None  # type: Optional[List[str]]
            checked_any = False
            for (result, _, _), (state, _) in zip(home, states):
                if state == "not_checked" or result is None:
                    continue
                checked_any = True
                if on_site(_host(result.final_url), site_host):
                    links = [u for u in result.metadata.get("links") or [] if isinstance(u, str)]
                    break
            root = _root(landing if landing and _host(landing) == site_host else homepage_url,
                         homepage_url, site_host)
            picked = []  # type: List[str]
            if links is None:
                if checked_any:
                    notes.append(NOTE_OFFSITE)
            else:
                for url in pick_pages(links, site_host, root, limit=self.page_limit):
                    if await engine.host_allowed(_host(url)):
                        picked.append(url)
            urls = picked + [probe_url(root, secrets.token_hex(6))]

            # Stage 2: every picked page and the 404 probe, in every page profile.
            page_jobs = [(i, url, p) for i, url in enumerate(urls, start=1) for p in PAGE_PROFILES]
            pages = await self._run(browser, task_folder, page_jobs, sem, deadline)
            blocked += proxy.blocked_hosts

        jobs = home_jobs + page_jobs
        outcomes = home + pages
        loads = []  # type: List[Load]
        for (index, url, profile), (result, error, shot) in zip(jobs, outcomes):
            if result is not None:
                own_blocked = result.metadata.pop("guard_blocked_hosts", [])
                if own_blocked:
                    result.metadata["blocked_hosts"] = own_blocked
                    blocked += own_blocked
                engine.scorer.score(result, site_host=site_host)
            state, reason = classify_load(result, error)
            loads.append(Load(page_index=index, page_url=url, profile=profile, state=state,
                              reason=reason, result=result, shot=shot))

        # Fold each page's other checked profiles into its default load (cloaking, worst score).
        by_page = {}  # type: Dict[int, List[Load]]
        for load in loads:
            if load.state != "not_checked" and load.result is not None:
                by_page.setdefault(load.page_index, []).append(load)
        worst = 0.0
        for page_loads in by_page.values():
            first = page_loads[0]
            if first.profile == "default":
                variants = {l.profile: l.result for l in page_loads[1:]}
                engine.scorer.combine(first.result, "default", variants)
            worst = max([worst] + [l.result.malicious_score for l in page_loads])

        rules = engine.yara_rules
        report = build_report(entered_host, site_host, offsite_domain, loads,
                              rules.count if rules else 0, blocked, notes)
        default_error = home[0][1]
        if default is not None:
            raw_error = default.metadata.get("raw_error")
        else:
            raw_error = default_error if default_error != "budget" else None
        return SiteOutcome(
            report=report,
            homepage_url=homepage_url,
            final_url=landing or homepage_url,
            worst_score=worst,
            redirect_chain=any(l.result.is_redirect_chain_detected for l in loads if l.result is not None),
            artifact_manifest=engine.artifacts.get_task_manifest(engine.task_id),
            raw_error=raw_error,
        )
