import asyncio
import base64
import json
import html as htmllib
import os
import re
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import AsyncIterator, Dict, List, Optional, Set, Tuple
from urllib.parse import urldefrag, urljoin, urlparse

from playwright.async_api import async_playwright, Browser, CDPSession, Response
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from .models import RedirectHop, ScanResult, REDIRECT_MECHANISMS
from ..intelligence.scorer import PnakoticScorer
from .profiles import PROFILES
from .static_analyzer import StaticAnalyst, SIGNATURE_MECHANISMS, MAX_CONTENT_CHARS
from .artifacts import ArtifactManager
from .behavior import BehaviorRecorder
from .yara_scan import YARA_MECHANISM, ScriptCollector, load_rules, scan_buffers, MAX_BUFFER_BYTES, MAX_FRAMES
from .egress_proxy import EgressProxy
from .netguard import HostCheck, host_is_public, url_is_allowed
from .script_trace import ScriptTracer, find_injections
from .page_picker import extract_links
from .challenge import challenge_vendor, looks_like_challenge

# --block-new-web-contents: window.open / popups would load in a new target that the
# page's CDP session does not intercept, so forbid them outright. Chrome still reports each
# attempt as Page.windowOpen, which is how popups are recorded (see "popup_open" below).
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
# Site mode: how long to wait for the served main document's body (as ScriptCollector.drain).
SERVED_BODY_TIMEOUT_S = 5.0
# After the landing is analysed, one click on an empty spot of the page: popunder scripts
# open their ad on the visitor's first click, which a load-only scan never sees.
CLICK_SETTLE_MS = 1500
# A page can call window.open in a loop; keep the first few, count the rest.
MAX_POPUP_HOPS = 10
# Stored URLs from the page are attacker-controlled; bound them.
MAX_EVIDENCE_URL = 2048

# Finds a point to click that is not a link or control, so the click only reaches
# document-level listeners (where popunder and click-hijack scripts sit). Returns null if
# every candidate lands on something interactive. Runs in the page, so a hostile page can
# lie; the worst case is a click on a link, which is then recorded like any navigation.
# Coordinates are the page's CSS pixels, the space page.mouse.click uses; on a mobile page
# with no viewport meta that is the ~980px layout width, wider than the device viewport.
NEUTRAL_POINT_JS = """() => {
  const W = innerWidth, H = innerHeight;
  const sel = 'a,button,input,select,textarea,label,summary,iframe,video,audio,[onclick],[role=button],[role=link],[contenteditable]';
  const pts = [[.5,.5],[.5,.25],[.25,.5],[.75,.5],[.5,.75],[.1,.9],[.9,.1],[.05,.05]];
  for (const [fx, fy] of pts) {
    const x = Math.round(W * fx), y = Math.round(H * fy);
    const el = document.elementFromPoint(x, y);
    if (el && !el.closest(sel)) return [x, y, W, H];
  }
  return null;
}"""

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


# Page-content signals for the scorer. The page is attacker-controlled: every quantifier is bounded
# and the input is capped at MAX_CONTENT_CHARS.
_TITLE_RE = re.compile(r"<title\b[^>]{0,200}>([^<]{0,1000})", re.IGNORECASE)
_PASSWORD_INPUT_RE = re.compile(r"<input[^>]{0,500}type\s*=\s*['\"]?password", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b", re.IGNORECASE)
HTML_CONTENT_TYPES = ("text/html", "application/xhtml")


def extract_page_signals(content: str) -> dict:
    """Title, password-input count and form count of a captured HTML document."""
    content = content[:MAX_CONTENT_CHARS]
    m = _TITLE_RE.search(content)
    title = " ".join(htmllib.unescape(m.group(1)).split())[:200] if m else ""
    return {
        "title": title,
        "password_inputs": len(_PASSWORD_INPUT_RE.findall(content)),
        "forms": len(_FORM_RE.findall(content)),
    }


@dataclass
class LoadOptions:
    """How _scan_in_context() loads one page. Without options it is the URL probe's load.

    shot_dir: screenshot folder relative to the task folder (default: screenshots/ or
    profiles/<name>/). full_page: full-page screenshot, else the viewport. site: also
    capture what the site check needs (served HTML, links, script initiators, per-buffer
    YARA, challenge detection).
    """
    shot_dir: Optional[str] = None
    full_page: bool = True
    site: bool = False


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


async def _served_body(resp: Response) -> Optional[bytes]:
    """The HTML body of a main-frame navigation response, capped; None when it isn't HTML,
    is too large to pull, or the browser can't give it any more."""
    headers = resp.headers
    raw_type = (headers.get("content-type") or "").split(";")[0].strip().lower()
    if raw_type and not raw_type.startswith(HTML_CONTENT_TYPES):
        return None
    try:
        length = int(headers.get("content-length") or 0)
    except ValueError:
        length = 0
    if length > MAX_BUFFER_BYTES * 4:  # don't pull a huge body just to truncate it
        return None
    try:
        # Bounded: a document that streams forever never finishes its body.
        return (await asyncio.wait_for(resp.body(), SERVED_BODY_TIMEOUT_S))[:MAX_BUFFER_BYTES]
    except BROWSER_ERRORS as e:
        print(f"[engine] served body unavailable: {str(e)[:200]}")
        return None


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

        async with self.browser_session() as (browser, proxy):
            outcomes = await asyncio.gather(
                *(self._scan_in_context(browser, target_url, name, task_folder, primary=(i == 0))
                  for i, name in enumerate(names)),
                return_exceptions=True,
            )

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

    @asynccontextmanager
    async def browser_session(self) -> AsyncIterator[Tuple[Browser, EgressProxy]]:
        """One browser behind its own egress proxy, closed (browser, then proxy) on exit.

        Also loads the YARA rules into self.yara_rules for the loads run in the session.
        """
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
                yield browser, proxy
            finally:
                try:
                    await browser.close()
                finally:
                    await proxy.stop()

    async def _scan_in_context(self, browser, target_url: str, profile_name: str,
                               task_folder: str, primary: bool,
                               options: Optional[LoadOptions] = None) -> ScanResult:
        """Load target_url once in a fresh context for one profile. Unscored; scan() scores.

        The requested profile's screenshot goes to screenshots/ (the dashboard's landing
        shot); comparison profiles write to profiles/<name>/; options.shot_dir overrides
        both. Every load collects script bodies and traces script initiators: metadata gets
        "injections" (find_injections) and, when any, "flagged_scripts" (the script responses
        the CDN refused as malware, yara_scan.ScriptCollector.flagged). With options.site,
        metadata also gets main_status, served_bytes, links, script_requests and challenge,
        and YARA keeps one finding per buffer (the served HTML first, as source "served").
        """
        profile = PROFILES[profile_name]
        result = ScanResult(target_url=target_url)
        result.metadata["profile"] = profile_name
        intercepted: List[RedirectHop] = []
        site = bool(options and options.site)
        if options is not None and options.shot_dir:
            shot_dir = os.path.join(task_folder, options.shot_dir)
        else:
            shot_dir = os.path.join(task_folder, "screenshots" if primary else os.path.join("profiles", profile_name))
        full_page = options.full_page if options is not None else True
        os.makedirs(shot_dir, exist_ok=True)

        final_url = target_url
        redirect_count = 0
        content_type = ""  # Content-Type of the main frame's last 2xx navigation response
        main_status: Optional[int] = None  # site mode: the last main-frame navigation status
        served_resp: Optional[Response] = None  # site mode: the last non-3xx one
        served: Optional[bytes] = None  # its body (capped)
        tracer: Optional[ScriptTracer] = None
        links: List[str] = []

        # Set viewport and mobile emulation from profile
        ctx = await browser.new_context(
            user_agent=profile.user_agent_for(browser.version),
            viewport=profile.viewport,
            extra_http_headers=profile.extra_headers,
            is_mobile=profile.is_mobile,
            has_touch=profile.has_touch,
            service_workers="block",  # SW fetches would run outside the guarded page
        )
        guard: Optional[EgressGuard] = None
        behavior = BehaviorRecorder()
        rules = getattr(self, "yara_rules", None)
        # Script bodies are kept in every mode (bounded, yara_scan.py): YARA matches them, and the
        # scorer reads the injection evidence (body_markers) and the CDN-blocked scripts.
        scripts: Optional[ScriptCollector] = ScriptCollector()
        documents: List[tuple] = []  # (source, url, html) for YARA: the landing page and its frames
        try:
            await behavior.attach(ctx)  # before new_page: hooks must precede every page script
            page = await ctx.new_page()
            behavior.watch(page)
            guard = EgressGuard(await ctx.new_cdp_session(page), self.host_allowed)
            await guard.start()  # before goto: the first navigation is checked too
            # The UA string alone is not enough: client hints would still say HeadlessChrome.
            try:
                await guard.cdp.send("Emulation.setUserAgentOverride", {
                    "userAgent": profile.user_agent_for(browser.version),
                    "userAgentMetadata": profile.user_agent_metadata(browser.version),
                })
            except PlaywrightError as e:
                print(f"[engine] client-hint override failed: {str(e)[:200]}")

            tasks: Set[asyncio.Task] = set()  # strong refs; asyncio only keeps weak ones
            # "load" until the landing is analysed, then "click" for the click probe. What
            # happens after the click is recorded as evidence but never moves final_url.
            phase = "load"
            popups_seen = 0

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
                nonlocal final_url, content_type, main_status, served_resp
                try:  # [P4] Sanitize header extraction from bad response
                    if phase == "click":
                        # Responses to our own click probe: a click-hijack's 3xx hops (its
                        # click_hijack hop is the record) and its landing page must not
                        # replace the content_type that page_signals was built from.
                        return
                    if site and r.request.is_navigation_request() and r.request.frame == page.main_frame:
                        main_status = r.status
                        if not (300 <= r.status < 400):
                            served_resp = r
                    if r.status < 300:
                        # Last main-frame navigation response wins: it is the landing document.
                        if r.request.is_navigation_request() and r.request.frame == page.main_frame:
                            raw = r.headers.get("content-type") or ""
                            content_type = raw.split(";")[0].strip().lower()
                        return
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
            tracer = ScriptTracer()  # who started each script request; the scorer and site report read it
            await tracer.attach(cdp, main_frame_id)
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
                destination = (event.get("url") or "")[:MAX_EVIDENCE_URL]
                if phase == "click":
                    # Our click hit no link, yet the page left: a script hijacked the click.
                    intercepted.append(RedirectHop(
                        url=current_url,
                        mechanism="click_hijack",
                        evidence=json.dumps({
                            "id": "click_hijack", "reason": reason, "trigger": "click", "to": destination,
                        }),
                    ))
                    return
                mechanism = NAVIGATION_MECHANISMS.get(reason, "client_navigation")
                # A page reloading itself (location.href = location.href, a refresh timer
                # without url=) goes nowhere: record it, but not as a redirect. It still
                # counts toward max_hops so a reload loop stops.
                self_nav = (mechanism in REDIRECT_MECHANISMS and bool(destination)
                            and urldefrag(destination)[0] == urldefrag(current_url)[0])
                if self_nav:
                    mechanism = "client_navigation"
                    note_redirect()
                elif mechanism in REDIRECT_MECHANISMS:
                    note_redirect()
                    if destination:
                        final_url = destination
                evidence = {
                    "id": mechanism,
                    "reason": reason,
                    "disposition": event.get("disposition"),
                    "to": destination,
                }
                if self_nav:
                    evidence["self"] = True
                intercepted.append(RedirectHop(
                    url=current_url,
                    mechanism=mechanism,
                    evidence=json.dumps(evidence),
                ))

            def on_window_open(event: dict) -> None:
                # window.open, target=_blank, ... Blocked by --block-new-web-contents, so
                # nothing loads; the attempt itself is the evidence. Not a redirect: the
                # visitor's own tab stays where it is.
                nonlocal popups_seen
                popups_seen += 1
                if popups_seen > MAX_POPUP_HOPS:
                    result.metadata["popups_dropped"] = popups_seen - MAX_POPUP_HOPS
                    return
                intercepted.append(RedirectHop(
                    url=current_url,
                    mechanism="popup_open",
                    evidence=json.dumps({
                        "id": "popup_open",
                        "to": (event.get("url") or "")[:MAX_EVIDENCE_URL],
                        "trigger": phase,
                        "user_gesture": bool(event.get("userGesture")),
                    }),
                ))

            cdp.on("Page.frameNavigated", on_frame_navigated)
            cdp.on("Page.frameRequestedNavigation", on_requested_navigation)
            cdp.on("Page.windowOpen", on_window_open)

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
            # A failed navigation leaves Chrome's own error page, and a non-HTML landing document
            # (audio, PDF, ...) is wrapped in Chrome's markup: neither is the site's HTML.
            error_page = (not page.is_closed()) and page.url.startswith("chrome-error://")
            if error_page:
                result.metadata["navigation_failed"] = final_url
            is_html = not content_type or content_type.startswith(HTML_CONTENT_TYPES)
            content = ""
            if not page.is_closed() and not error_page and is_html:
                try:
                    content = await page.content()
                except BROWSER_ERRORS as e:
                    print(f"[engine] page.content() failed: {str(e)[:200]}")
            if served_resp is not None:
                served = await _served_body(served_resp)
            if site and content:
                links = extract_links(content, final_url, limit=2000)
            signals = extract_page_signals(content) if content else {"title": "", "password_inputs": 0, "forms": 0}
            signals["content_type"] = content_type
            signals["error_page"] = error_page
            result.metadata["page_signals"] = signals
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
                    await page.screenshot(path=shot_path, full_page=full_page, timeout=SCREENSHOT_TIMEOUT_MS)
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

            # 4. Click probe, after everything above has captured the landing as loaded.
            if not page.is_closed():
                point = None
                try:
                    raw = await page.evaluate(NEUTRAL_POINT_JS)
                    # The page computed this: accept only [x, y, W, H] numbers with the
                    # point inside a sane layout viewport.
                    if (isinstance(raw, list) and len(raw) == 4
                            and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in raw)
                            and 0 < raw[2] <= 20000 and 0 < raw[3] <= 20000
                            and 0 <= raw[0] < raw[2] and 0 <= raw[1] < raw[3]):
                        point = (float(raw[0]), float(raw[1]))
                except BROWSER_ERRORS as e:
                    print(f"[engine] click probe: no point ({str(e)[:200]})")
                if point is None:
                    result.metadata["click_probe"] = "skipped"
                else:
                    phase = "click"  # before the click: its events can arrive before click() returns
                    behavior.trigger = "click"  # behaviors from here on followed our click
                    try:
                        await asyncio.wait_for(page.mouse.click(*point), CLICK_SETTLE_MS / 1000 * 3)
                        result.metadata["click_probe"] = "clicked"
                        await asyncio.sleep(CLICK_SETTLE_MS / 1000)
                    except BROWSER_ERRORS as e:
                        result.metadata["click_probe"] = "failed"
                        print(f"[engine] click probe failed: {str(e)[:200]}")
            if scripts:
                await scripts.drain()  # bodies can only be read while the context is open
        finally:
            try:
                await ctx.close()
            except BROWSER_ERRORS:
                pass  # browser already gone
            if guard and guard.blocked_hosts:
                result.metadata["guard_blocked_hosts"] = list(guard.blocked_hosts)

        served_url = str(served_resp.url) if served_resp is not None else final_url
        if scripts and scripts.flagged:
            # Scripts the CDN refused as malware on the visitor's behalf (no body to scan).
            result.metadata["flagged_scripts"] = list(scripts.flagged)
        # Cross-site scripts started by script, with the obfuscation of the loader and of what it
        # loaded. The URL probe has no served HTML, so its inline injections carry no block.
        result.metadata["injections"] = find_injections(tracer.records if tracer else [], served_url, served,
                                                        dict(scripts.scripts) if scripts else {})
        if site:
            served_text = served.decode("utf-8", "replace") if served is not None else content
            result.metadata.update({
                "main_status": main_status,
                "served_bytes": len(served) if served is not None else 0,
                "links": links,
                "script_requests": list(tracer.records) if tracer else [],
                "challenge": looks_like_challenge(main_status, signals["title"], served_text),
            })
            if result.metadata["challenge"]:
                result.metadata["challenge_vendor"] = challenge_vendor(signals["title"], served_text)

        if rules:
            buffers = [("served", served_url, served)] if site and served is not None else []
            buffers += [(src, url, html.encode("utf-8", "replace")) for src, url, html in documents]
            buffers += [("script", url, body) for url, body in scripts.scripts]
            matches, stats = await scan_buffers(rules, buffers, per_buffer=site)
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
