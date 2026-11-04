import asyncio
import base64
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, CDPSession, Response
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from .models import RedirectHop, ScanResult, REDIRECT_MECHANISMS
from ..intelligence.scorer import PnakoticScorer
from .profiles import PROFILES
from .static_analyzer import StaticAnalyst, SIGNATURE_MECHANISMS
from .artifacts import ArtifactManager
from .behavior import BehaviorRecorder
from .yara_scan import YARA_MECHANISM, ScriptCollector, load_rules, scan_buffers, MAX_FRAMES
from .egress_proxy import EgressProxy
from .netguard import HostCheck, host_is_public, url_is_allowed

# --block-new-web-contents: window.open / popups would load in a new target that the
# page's CDP session does not intercept, so forbid them outright.
# WebRTC never uses the proxy; this policy disables its direct UDP paths.
CHROMIUM_ARGS = [
    "--block-new-web-contents",
    "--webrtc-ip-handling-policy=disable_non_proxied_udp",
    "--force-webrtc-ip-handling-policy",
]


# After `load`, how long to wait for the network to go quiet before analysing anyway.
SETTLE_MS = 3000
# Cap on the landing-page screenshot so one stuck paint can't eat the whole job.
SCREENSHOT_TIMEOUT_MS = 10000

# Browser-call failures that are expected on hostile pages: log and carry on. Anything else
# (a bug, Celery's SoftTimeLimitExceeded) must propagate out of scan().
BROWSER_ERRORS = (PlaywrightError, asyncio.TimeoutError)


def launch_options(proxy_port: int) -> dict:
    """Keyword arguments for chromium.launch().

    BROWSER_CHANNEL selects the browser. Empty (default): Playwright's bundled Chromium,
    which is cut ahead of Chrome's release and only re-patched when Playwright itself
    releases. "chrome" (or "msedge"): the branded stable channel installed on the machine
    (`playwright install chrome`), which gets Chrome's security builds the day Google
    ships them. The Docker image sets it; local development usually leaves it unset.
    """
    opts = dict(
        headless=True, args=CHROMIUM_ARGS, chromium_sandbox=True,
        proxy={"server": f"socks5://127.0.0.1:{proxy_port}"},
    )
    channel = os.environ.get("BROWSER_CHANNEL", "").strip()
    if channel:
        opts["channel"] = channel
    return opts


_browser_logged = False


def _log_browser_once(browser) -> None:
    """One line per worker process saying which build is actually scanning (see V9 in the review)."""
    global _browser_logged
    if not _browser_logged:
        _browser_logged = True
        channel = os.environ.get("BROWSER_CHANNEL", "").strip() or "bundled chromium"
        print(f"[engine] browser: {browser.version} ({channel})")

# CDP Page.frameRequestedNavigation `reason` -> hop mechanism. The first three are
# redirects; every other reason (anchorClick, formSubmission*, reload, other, ...) is an
# informational "client_navigation".
NAVIGATION_MECHANISMS = {
    "scriptInitiated": "js_location",
    "metaTagRefresh": "meta_refresh",
    "httpHeaderRefresh": "meta_refresh",
}


class EgressGuard:
    """Second egress layer: fails HTTP requests whose host isn't public, including redirect hops.

    Playwright's page.route() is not re-invoked for redirects, so this uses CDP
    Fetch interception at the request stage, which pauses each hop (and iframe and
    worker requests) individually. WebSockets and SharedWorkers are invisible to it;
    EgressProxy covers those. See netguard.py for the policy.
    """

    def __init__(self, cdp: CDPSession, host_allowed: HostCheck):
        self.cdp = cdp
        self.host_allowed = host_allowed
        self.blocked_hosts: List[str] = []
        self._verdicts: Dict[str, "asyncio.Future[bool]"] = {}
        self._tasks: Set[asyncio.Task] = set()  # strong refs; asyncio only keeps weak ones

    async def start(self) -> None:
        self.cdp.on("Fetch.requestPaused", self._on_paused)
        await self.cdp.send("Fetch.enable", {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]})

    def _on_paused(self, event: dict) -> None:
        task = asyncio.ensure_future(self._handle(event))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _cached_host_allowed(self, host: str) -> bool:
        if host not in self._verdicts:  # one lookup per host per scan, shared by concurrent requests
            self._verdicts[host] = asyncio.ensure_future(self.host_allowed(host))
        return await self._verdicts[host]

    async def _handle(self, event: dict) -> None:
        request_id = event["requestId"]
        url = event.get("request", {}).get("url", "")
        try:
            allowed = await url_is_allowed(url, self._cached_host_allowed)
        except Exception as exc:  # never leave a request paused (it would hang until timeout)
            print(f"[egress-guard] check failed for {url[:200]!r}, blocking: {exc}")
            allowed = False
        try:
            if allowed:
                await self.cdp.send("Fetch.continueRequest", {"requestId": request_id})
            else:
                await self.cdp.send("Fetch.failRequest", {"requestId": request_id, "errorReason": "BlockedByClient"})
                host = urlparse(url).hostname or url[:100]  # record only a block that happened
                if host not in self.blocked_hosts:
                    self.blocked_hosts.append(host)
        except Exception as exc:  # page / session already closed
            print(f"[egress-guard] could not settle paused request {url[:200]!r}: {exc}")


class PnakoticEngine:
    def __init__(self, max_hops=10, timeout_ms=30000, task_id="default",
                 host_allowed: Optional[HostCheck] = None):
        self.max_hops = max_hops
        self.timeout_ms = timeout_ms
        self.scorer = PnakoticScorer()
        self.analyst = StaticAnalyst()
        self.artifacts = ArtifactManager()
        # Root artifact folder injected via task_id in constructor or runner
        self.task_id = task_id
        # Egress policy for every browser request; injectable so tests can allow a local server.
        self.host_allowed: HostCheck = host_allowed or host_is_public
        self.yara_rules = None  # set per scan from YARA_RULES_DIR (yara_scan.load_rules)

    async def scan(self, target_url: str, profile_name="default", compare: bool = False) -> ScanResult:
        """Scan target_url in the requested profile and return its scored result.

        With compare=True every other profile loads the URL too, each in its own browser
        context (own cookies and storage) in the same browser, all in parallel so the job
        takes about as long as one scan. The scorer then compares where each profile landed
        (cloaking, see PnakoticScorer.combine). The requested profile stays the job's chain;
        the others are summarized in metadata["variants"]. Contexts share one egress IP, so
        only user-agent, viewport and referrer cloaking can show up, not IP or geo cloaking.
        """
        if profile_name not in PROFILES:
            profile_name = "default"
        task_folder = self.artifacts.create_task_folder(self.task_id)
        names = [profile_name] + ([n for n in PROFILES if n != profile_name] if compare else [])
        # Compiled once per worker process; None when YARA_RULES_DIR is unset (scanning off).
        self.yara_rules = await asyncio.to_thread(load_rules)

        async with async_playwright() as p:
            # Launch-level SOCKS5 proxy: Playwright then maps every hostname to NOTFOUND in
            # Chromium's own resolver, so names reach the proxy, which resolves and pins them.
            proxy = EgressProxy(self.host_allowed)
            proxy_port = await proxy.start()
            try:
                browser = await p.chromium.launch(**launch_options(proxy_port))
            except BaseException:
                await proxy.stop()
                raise
            _log_browser_once(browser)
            try:
                outcomes = await asyncio.gather(
                    *(self._scan_in_context(browser, target_url, name, task_folder, primary=(i == 0))
                      for i, name in enumerate(names)),
                    return_exceptions=True,
                )
            finally:
                try:
                    await browser.close()
                finally:
                    await proxy.stop()

        # The requested profile is the job: any error there fails it. A comparison profile may
        # fail on a hostile page (browser errors only); anything else (a bug, Celery's
        # SoftTimeLimitExceeded) still propagates.
        for outcome in outcomes:
            if isinstance(outcome, BaseException) and not isinstance(outcome, BROWSER_ERRORS):
                raise outcome
        if isinstance(outcomes[0], BaseException):
            raise outcomes[0]

        result = outcomes[0]
        # The proxy is shared, so its blocks can't be told apart per profile; they go on the job.
        blocked = list(dict.fromkeys(result.metadata.pop("guard_blocked_hosts", []) + proxy.blocked_hosts))
        if blocked:
            result.metadata["blocked_hosts"] = blocked
        result.metadata["artifact_manifest"] = self.artifacts.get_task_manifest(self.task_id)
        self.scorer.score(result)
        if compare:
            variants: Dict[str, object] = {}
            for name, outcome in zip(names[1:], outcomes[1:]):
                if isinstance(outcome, BaseException):
                    variants[name] = str(outcome).replace("\x00", "").strip()[:256]
                    continue
                own_blocked = outcome.metadata.pop("guard_blocked_hosts", [])
                if own_blocked:
                    outcome.metadata["blocked_hosts"] = own_blocked
                self.scorer.score(outcome)
                variants[name] = outcome
            self.scorer.combine(result, profile_name, variants)
        return result

    async def _scan_in_context(self, browser, target_url: str, profile_name: str,
                               task_folder: str, primary: bool) -> ScanResult:
        """Load target_url once in a fresh context for one profile. Unscored; scan() scores.

        The requested profile's screenshot goes to screenshots/ (the dashboard's landing
        shot); comparison profiles write to profiles/<name>/.
        """
        profile = PROFILES[profile_name]
        result = ScanResult(target_url=target_url)
        result.metadata["profile"] = profile_name
        intercepted: List[RedirectHop] = []
        shot_dir = os.path.join(task_folder, "screenshots" if primary else os.path.join("profiles", profile_name))
        os.makedirs(shot_dir, exist_ok=True)

        final_url = target_url
        redirect_count = 0

        # Set viewport and mobile emulation from profile
        ctx = await browser.new_context(
            user_agent=profile.user_agent,
            viewport=profile.viewport,
            extra_http_headers=profile.extra_headers,
            is_mobile=profile.is_mobile,
            has_touch=profile.has_touch,
            service_workers="block",  # SW fetches would run outside the guarded page
        )
        guard: Optional[EgressGuard] = None
        behavior = BehaviorRecorder()
        rules = getattr(self, "yara_rules", None)
        scripts = ScriptCollector() if rules else None
        documents: List[tuple] = []  # (source, url, html) for YARA: the landing page and its frames
        try:
            await behavior.attach(ctx)  # before new_page: hooks must precede every page script
            page = await ctx.new_page()
            behavior.watch(page)
            guard = EgressGuard(await ctx.new_cdp_session(page), self.host_allowed)
            await guard.start()  # before goto: the first navigation is checked too

            tasks: Set[asyncio.Task] = set()  # strong refs; asyncio only keeps weak ones

            def note_redirect() -> None:
                """Count one redirect (3xx or client-side); past max_hops, flag a loop and stop the page."""
                nonlocal redirect_count
                redirect_count += 1
                if redirect_count >= self.max_hops:
                    result.metadata["redirect_loop"] = True
                    task = asyncio.ensure_future(page.close())
                    tasks.add(task)
                    task.add_done_callback(tasks.discard)
                    task.add_done_callback(lambda t: t.cancelled() or t.exception())  # page already gone

            async def on_resp(r: Response):
                nonlocal final_url
                try:  # [P4] Sanitize header extraction from bad response
                    if not (300 <= r.status < 400):
                        return
                    # Only the page's own navigation is the chain. Subresources
                    # (pixels, CDN assets, XHR) and iframes redirect all the time.
                    if not (r.request.is_navigation_request() and r.request.frame == page.main_frame):
                        return
                    note_redirect()
                    # Resolve relative Location headers (e.g. "/next") against the
                    # current URL so final_url is always absolute.
                    location = r.headers.get("location")
                    if location:
                        final_url = str(urljoin(str(r.url), location))
                    intercepted.append(RedirectHop(
                        url=str(r.url),
                        status_code=r.status,
                        headers={k: v for k, v in r.headers.items() if isinstance(v, str)},
                        mechanism="http_3xx",
                    ))
                except Exception:
                    pass  # Ignore malformed headers (e.g., binary payloads)

            # Client-side navigations (JS, meta refresh, ...) leave the page before any
            # regex sees them, so watch them through CDP. frameRequestedNavigation does not
            # fire for the initial goto or for HTTP 3xx, so these never double-count with
            # on_resp. The hop's url is the page that issued the navigation (the last
            # committed main-frame URL), the destination goes in evidence["to"].
            cdp = guard.cdp
            await cdp.send("Page.enable")
            tree = await cdp.send("Page.getFrameTree")
            main_frame_id = tree["frameTree"]["frame"]["id"]
            current_url = target_url

            def on_frame_navigated(event: dict) -> None:
                nonlocal current_url
                frame = event.get("frame") or {}
                if frame.get("id") == main_frame_id and frame.get("url"):
                    current_url = frame["url"]

            def on_requested_navigation(event: dict) -> None:
                nonlocal final_url
                if event.get("frameId") != main_frame_id:
                    return
                if redirect_count >= self.max_hops:
                    return  # loop already flagged; events queued behind the close are noise
                reason = event.get("reason") or "other"
                mechanism = NAVIGATION_MECHANISMS.get(reason, "client_navigation")
                destination = event.get("url") or ""
                if mechanism in REDIRECT_MECHANISMS:
                    note_redirect()
                    if destination:
                        final_url = destination
                intercepted.append(RedirectHop(
                    url=current_url,
                    mechanism=mechanism,
                    evidence=json.dumps({
                        "id": mechanism,
                        "reason": reason,
                        "disposition": event.get("disposition"),
                        "to": destination,
                    }),
                ))

            cdp.on("Page.frameNavigated", on_frame_navigated)
            cdp.on("Page.frameRequestedNavigation", on_requested_navigation)

            page.on("response", on_resp)
            if scripts:
                scripts.watch(page)

            # 1. Navigate. `load` (not networkidle): one slow subresource must not sink the scan.
            try:
                await page.goto(target_url, wait_until="load", timeout=self.timeout_ms)
            except BROWSER_ERRORS as e:
                # [P4] Sanitize error string for Metadata Injection Protection
                result.metadata["raw_error"] = str(e).replace("\x00", "").strip()[:256]

            # 2. Bounded settle so late client-side redirects and lazy content can show up.
            if not page.is_closed():
                try:
                    await page.wait_for_load_state("networkidle", timeout=SETTLE_MS)
                except (PlaywrightTimeoutError, asyncio.TimeoutError):
                    result.metadata["settle_timed_out"] = True
                except PlaywrightError as e:
                    print(f"[engine] settle failed: {str(e)[:200]}")

            # 3. Analysis half. Each step stands alone; a closed page (redirect loop) skips them.
            # Only a real http(s) page counts: a refused/failed/download navigation leaves
            # about:blank or chrome-error://, and the tracked URL is the better answer then.
            if not page.is_closed() and page.url.startswith(("http://", "https://")):
                final_url = page.url
            content = ""
            if not page.is_closed():
                try:
                    content = await page.content()
                except BROWSER_ERRORS as e:
                    print(f"[engine] page.content() failed: {str(e)[:200]}")
            if rules:
                if content:
                    documents.append(("page", page.url, content))
                # Ad slots are iframes, often cross-origin: their documents are where injected
                # code tends to be. Bounded count; a frame that's gone is skipped.
                for frame in (page.frames[1:MAX_FRAMES + 1] if not page.is_closed() else []):
                    try:
                        documents.append(("frame", frame.url, await frame.content()))
                    except BROWSER_ERRORS:
                        pass
            if content:
                # No try/except here on purpose: a bug (or SoftTimeLimitExceeded) must fail the job.
                findings = self.analyst.analyze_content(content)
                for finding in findings:
                    # One hop per signature with its real mechanism. Regex hits are
                    # "code present" signals; redirects that fire come from CDP above.
                    intercepted.append(RedirectHop(
                        url=page.url,
                        mechanism=SIGNATURE_MECHANISMS.get(finding["id"], "static_analysis"),
                        evidence=json.dumps(finding),  # [P4] JSON-serializable evidence
                    ))
            if not page.is_closed():
                shot_path = os.path.join(
                    shot_dir, f"landing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
                try:
                    await page.screenshot(path=shot_path, full_page=True, timeout=SCREENSHOT_TIMEOUT_MS)
                except (PlaywrightTimeoutError, asyncio.TimeoutError) as e:
                    # Playwright waits for document.fonts.ready, which never resolves while the
                    # document is still loading (the slow-subresource case). Take a plain viewport
                    # capture straight from CDP instead of leaving the scan without a screenshot.
                    print(f"[engine] screenshot timed out ({str(e)[:80]!r}), falling back to CDP capture")
                    try:
                        shot = await asyncio.wait_for(
                            cdp.send("Page.captureScreenshot", {"format": "png"}), SCREENSHOT_TIMEOUT_MS / 1000)
                        with open(shot_path, "wb") as fh:
                            fh.write(base64.b64decode(shot["data"]))
                    except BROWSER_ERRORS as e2:
                        print(f"[engine] CDP screenshot failed: {str(e2)[:200]}")
                except PlaywrightError as e:
                    print(f"[engine] screenshot failed: {str(e)[:200]}")
            if scripts:
                await scripts.drain()  # bodies can only be read while the context is open
        finally:
            try:
                await ctx.close()
            except BROWSER_ERRORS:
                pass  # browser already gone
            if guard and guard.blocked_hosts:
                result.metadata["guard_blocked_hosts"] = list(guard.blocked_hosts)

        if rules:
            buffers = [(src, url, html.encode("utf-8", "replace")) for src, url, html in documents]
            buffers += [("script", url, body) for url, body in scripts.scripts]
            matches, stats = await scan_buffers(rules, buffers)
            stats["scripts_dropped"] = scripts.dropped
            result.metadata["yara"] = stats
            for match in matches:
                intercepted.append(RedirectHop(url=match["url"], mechanism=YARA_MECHANISM, evidence=json.dumps(match)))

        # What the page tried to do to the visitor, after the context is gone (no late events).
        result.hops = intercepted + behavior.hops()
        result.final_url = final_url
        result.end_time = datetime.now()
        # A "chain" means at least one actual redirect mechanism was observed;
        # passive static findings (e.g. a base64 blob) don't count on their own.
        result.is_redirect_chain_detected = any(
            h.mechanism in REDIRECT_MECHANISMS for h in intercepted
        )
        return result
