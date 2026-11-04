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

    async def scan(self, target_url: str, profile_name="default") -> ScanResult:
        profile = PROFILES.get(profile_name, PROFILES["default"])
        result = ScanResult(target_url=target_url)
        intercepted: List[RedirectHop] = []
        task_folder = self.artifacts.create_task_folder(self.task_id)
        os.makedirs(os.path.join(task_folder, "screenshots"), exist_ok=True)

        final_url = target_url
        redirect_count = 0

        async with async_playwright() as p:
            # Launch-level SOCKS5 proxy: Playwright then maps every hostname to NOTFOUND in
            # Chromium's own resolver, so names reach the proxy, which resolves and pins them.
            proxy = EgressProxy(self.host_allowed)
            proxy_port = await proxy.start()
            try:
                browser = await p.chromium.launch(
                    headless=True, args=CHROMIUM_ARGS, chromium_sandbox=True,
                    proxy={"server": f"socks5://127.0.0.1:{proxy_port}"},
                )
            except BaseException:
                await proxy.stop()
                raise
            guard: Optional[EgressGuard] = None
            try:
                # Set viewport and mobile emulation from profile
                ctx = await browser.new_context(
                    user_agent=profile.user_agent,
                    viewport=profile.viewport,
                    extra_http_headers=profile.extra_headers,
                    is_mobile=profile.is_mobile,
                    has_touch=profile.has_touch,
                    service_workers="block",  # SW fetches would run outside the guarded page
                )
                page = await ctx.new_page()
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
                        task_folder, "screenshots",
                        f"landing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png",
                    )
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
            finally:
                try:
                    await browser.close()
                finally:
                    await proxy.stop()
                blocked = list(dict.fromkeys((guard.blocked_hosts if guard else []) + proxy.blocked_hosts))
                if blocked:
                    result.metadata["blocked_hosts"] = blocked

        result.hops = intercepted
        result.final_url = final_url
        result.end_time = datetime.now()
        # A "chain" means at least one actual redirect mechanism was observed;
        # passive static findings (e.g. a base64 blob) don't count on their own.
        result.is_redirect_chain_detected = any(
            h.mechanism in REDIRECT_MECHANISMS for h in intercepted
        )
        result.metadata["artifact_manifest"] = self.artifacts.get_task_manifest(self.task_id)
        self.scorer.score(result)
        return result
