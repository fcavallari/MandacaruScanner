# Pnakotic security review

Date: 2026-11-04. Scope: everything under `pnakotic/` (about 950 lines of Python, the React dashboard, Docker files). Method: full source read, the existing test suite (57 passed, Chromium present), three probe scripts run against local HTTP servers through the real `PnakoticEngine`. Probe scripts and raw output live in the session scratchpad:

- `/private/tmp/claude-501/-Users-fioa8c-WORK-Pnakotic/9c1adb93-699b-48c6-b110-03baebefc8d8/scratchpad/egress_probe.py` (egress guard vs. iframes, WebSockets, beacons, bot fingerprint)
- `/private/tmp/claude-501/-Users-fioa8c-WORK-Pnakotic/9c1adb93-699b-48c6-b110-03baebefc8d8/scratchpad/probe2.py` (workers, never-idle page, direct JS / meta redirects, CDP navigation reasons)
- `/private/tmp/claude-501/-Users-fioa8c-WORK-Pnakotic/9c1adb93-699b-48c6-b110-03baebefc8d8/scratchpad/redirect_probe.py` (JS, meta, delayed, click-gated redirects, downloads)
- the static-analyzer timing and evasion checks were run inline (see Part 1, D3 and Part 2, V3)

In the probes, the policy allowed only `127.0.0.1` (and `localhost` where noted); a second server bound to `[::1]` stood in for an internal host. Any request that reached the `::1` server bypassed the guard.

## Summary

**As a detector of malicious or suspicious code on a website, the tool is weak.** It is a reliable recorder of HTTP 3xx chains and little else. Client-side redirects that actually fire (JS, meta refresh) are not recorded. A page that keeps one connection open defeats the static analysis and the screenshot entirely. The regex analysis only sees the final page's serialized DOM, never external scripts or iframe content, and every one of ten trivial rewrites evaded it. Ordinary minified code can score 0.8 ("Malicious"). The browser announces itself as automation (`navigator.webdriver = true`), so any cloaked campaign will serve it clean content.

**As a piece of software exposed to hostile pages, it has two high-severity problems.** The Chromium sandbox is always disabled and the container runs as root, so a renderer exploit on a scanned page gives root inside a container that holds the database credentials and the task broker. And the egress guard, which the README says checks "every browser request, including each redirect hop, iframes and web-worker fetches", is bypassed by WebSockets (from the main frame, iframes and workers) and by SharedWorker fetches, while the UI reports the host as blocked.

Severity counts: 2 High, 3 Medium, 3 Low, plus hygiene items. The artifact path handling, the ORM usage, the task idempotency and the frontend rendering were reviewed and found sound.


## Status (2026-11-04, after fixes)

**V1 (sandbox/root): fixed, build not yet verified.** `engine.py` launches with `chromium_sandbox=True`; the Dockerfile runs as uid 1001 with browsers in `/ms-playwright`; compose adds `cap_drop: ALL`, `no-new-privileges`, `init`, a 1 GB `/dev/shm` for the worker, and `seccomp_profile.json` (Docker's default profile plus `chroot`, `clone`, `setns`, `unshare`, which the user-namespace sandbox needs; Microsoft's Playwright profile crashes current runc on arm64 because it predates `openat2`/`faccessat2`/`close_range`). Verified on a stand-in image with the exact compose flags: uid 1001, sandboxed launch and screenshot OK, and a negative control (default seccomp profile) fails with "Chromium sandboxing failed!", so the sandbox is really enforced. Not verified: `docker compose build` and a full `compose up`, because containers on this host could not reach PyPI during the session. An existing root-owned `artifacts_data` volume needs a one-time chown (see README).

**V2 (egress bypass): fixed and verified.** New `src/scanner/egress_proxy.py` is a per-scan SOCKS5 allow-listing proxy; Chromium is launched through it with local DNS disabled, so every TCP connection (HTTP, WebSocket, SharedWorker, iframe, redirect hop) is checked by hostname, resolved once, and connected to a checked address (closes DNS rebinding, V7, as well). WebRTC direct UDP is disabled by flag. The CDP guard remains as a second layer and now records a host as blocked only after the block succeeded. Six regression tests added (main-frame and worker WebSocket, SharedWorker fetch, allowed-WebSocket control, raw SOCKS5 handshake, `resolve_public_addrs`); 63 tests pass; both probe scripts now report that nothing reached the internal host.

**V3 (regex DoS): fixed and verified.** `js_atob` is now `atob\(\s*['"][^'"]{0,4096}['"]\s*\)` and `meta_refresh` bounds both `[^>]` runs to 2000 characters; `analyze_content` caps its input at `MAX_CONTENT_CHARS` (2,000,000) and appends a `content_truncated` finding when it does. The two 2.0 MB adversarial inputs that took 24.6 s and 12.4 s now take about 0.08 s each. The review's third suggestion, a separate analyzer timeout, was deliberately not implemented: Python's `re` cannot be interrupted without signals, `signal.alarm` would collide with Celery's soft-time-limit handling, and a thread-based timeout cannot stop the regex, so it would leave a runaway thread in a reused prefork worker. Bounded quantifiers plus the input cap make the worst case small and linear instead. Six tests in `tests/test_static_analyzer.py`, including the two adversarial inputs under a 1 s budget.

**D1 (client-side redirects) and D2 (analysis skipped on timeout): fixed and verified.** The engine now subscribes to CDP `Page.frameRequestedNavigation` on the main frame and records each client-side navigation as a hop with its real reason (`scriptInitiated` → `js_location`, `metaTagRefresh`/`httpHeaderRefresh` → `meta_refresh`, form submissions and anchor clicks → informational `client_navigation`); the event does not fire for the initial `goto` or for HTTP 3xx, so there is no double counting, and hash/`pushState` changes produce nothing. Client-side hops count toward `max_hops`, so a JS redirect loop is stopped. The landing-page regexes are now a secondary signal: `meta_refresh_code` (0.1) and `js_location_code` (0.15) instead of the observed-redirect weights, so the `/delayed` probe drops from 0.9 to the IP-landing baseline plus 0.15 and is no longer a "chain". Navigation is `goto(wait_until="load")` plus a 3 s bounded settle; `final_url`, `content()`, analysis and the screenshot each run in their own step with Playwright-only exception handling (a CDP `Page.captureScreenshot` fallback covers the case where Playwright's screenshot waits on fonts that never settle). The analysis path no longer swallows arbitrary exceptions, so Celery's `SoftTimeLimitExceeded` now fails the job instead of marking it completed. Probe results: `/js`, `/js-var`, `/meta` record the client-side hop plus the 302 with chain detected; `/never-idle` now yields static findings and a screenshot. Seven tests added in `tests/test_engine.py`; the frontend labels the new mechanisms and `npm run build` passes. 76 tests pass.

**V9 (browser freshness): fixed and verified.** Scans run in Google Chrome stable when `BROWSER_CHANNEL=chrome` (`launch_options()` in `engine.py`; the Dockerfile installs it with `playwright install chrome --with-deps` and sets the variable), and the worker logs the running build once per process. `playwright` is pinned to 1.64.1 (1.60.0 on Python 3.9). Verified: the amd64 image, built with the new Dockerfile and run under the exact compose hardening flags (seccomp profile, `cap_drop ALL`, `no-new-privileges`, `init`, 1 GB shm) as uid 1001, scanned `https://example.com` in **Chrome 157.0.8103.38**, the 3 Nov 2026 stable build, with the sandbox on and a screenshot written; the arm64 image with `BROWSER_CHANNEL=chromium` did the same in the bundled 156.0.8078.4. This also closes the `docker compose build` gap left open under V1. The local suite passes against this Mac's Chrome 156.0.8078.81 (`BROWSER_CHANNEL=chrome`). Caveats: Google ships no Linux arm64 Chrome, so Apple-silicon Docker must build with `BROWSER_CHANNEL=chromium` and stays on Playwright's cadence; the amd64 verification here ran under CPU emulation, not on native hardware; and branded Chrome contacts `accounts.google.com`, `clients2.google.com`, `update.googleapis.com`, `www.google.com` and `www.gstatic.com` at startup regardless of Playwright's quieting flags (the extra `--disable-sync`, `--no-pings`, `--disable-domain-reliability`, `--disable-component-update` made no difference). Those connections go through the egress proxy and are allowed by the public-host policy, so they are egress noise and a mild fingerprint, not a hole; they show up as `blocked_hosts` only under a loopback-only test policy. Not done from the V9 fix list: moving the Postgres password out of `docker-compose.yml`.

Open: V4 to V8, and D3 to D9 in Part 1.

---

## Part 1: How well does it find malicious or suspicious code?

### What was run and what came back

| Probe page | What a good scanner should record | What Pnakotic recorded |
|---|---|---|
| `/js-direct`: `window.location='/target'` | a JS redirect hop, chain detected | `hops=[]`, `chain_detected=False`, `final_url=/target` |
| `/meta`: `<meta http-equiv=refresh content="0;url=/target">` | a meta-refresh hop | `hops=[]`, `chain_detected=False`, `final_url=/target` |
| `/meta-dom`: same meta tag created by script | a meta-refresh hop | `hops=[]`, `chain_detected=False` |
| `/js` and `/meta` followed by a 302 | JS/meta hop plus the 302 | only the 302 (`http_3xx`); the client-side hop is missing |
| `/delayed`: `setTimeout(() => location.replace(...), 2500)` (never fires in the scan) | nothing, or "delayed redirect code present" | `js_location` hop, `chain_detected=True`, score 0.9 "Malicious", `final_url` unchanged |
| `/clickgate`: redirect on click | missed is acceptable, but should be flagged as untested | `hops=[]`, nothing reported |
| `/never-idle`: normal page plus one `<img>` whose response takes 40s; page also contains `atob('...')` and `String.fromCharCode` | static findings, screenshot | `raw_error: Timeout`, **no static analysis, no screenshot**, score from IP landing only |
| `/download`: `Content-Disposition: attachment; filename=update.exe` | a drive-by-download finding and the sample kept | `raw_error: Download is starting`, no finding, file discarded |
| fingerprint report from the page | `navigator.webdriver` false, plausible UA | `webdriver=true`, `plugins=0`, UA claims Chrome/120 while the real Chromium is 148.0.7778.96 |
| benign minified snippet `String.fromCharCode(0x2f); location.replace(e)` | low or zero | `js_fromCharCode` + `js_location_assignment`, score 0.8 "Malicious" |
| inline base64 PNG on a benign page | nothing | `b64_payload` finding (informational, unweighted) |

The CDP event `Page.frameRequestedNavigation` fired with `reason=scriptInitiated` for `/js-direct` and `reason=metaTagRefresh` for both meta cases, so the browser knows exactly how it moved; the engine just does not listen.

### Findings

**D1. Client-side redirects that fire are invisible; ones that do not fire are scored.**
*Fixed on 2026-11-04; see the Status section above. The text below describes the state as found.*
`engine.py` records hops only from HTTP 3xx responses (`on_resp`, lines 111 to 140) and from regexes run over the *landing* page (lines 147 to 157). A JS or meta redirect that works leaves the page before the regex ever sees it, so `hops` stays empty and `is_redirect_chain_detected` is false even though `final_url` changed. The regex therefore only ever fires on pages that *contain* redirect code but did not redirect, which is why `/delayed` scored 0.9 while `/js-direct` scored only the IP-landing weight. The "meta refresh" and "JS location" mechanisms described in the README never represent an observed redirect.
Fix: subscribe to `Page.frameRequestedNavigation` and `Page.frameNavigated` (or Playwright's `framenavigated`) on the main frame and record each client-side navigation as a hop with its real reason (`scriptInitiated`, `metaTagRefresh`, `httpHeaderRefresh`, `formSubmissionGet/Post`, `anchorClick`). Keep the regexes as a secondary "redirect code present but did not fire" signal with a lower weight.

**D2. One slow request defeats the analysis half of the tool.**
*Fixed on 2026-11-04; see the Status section above. The text below describes the state as found.*
`page.goto(..., wait_until="networkidle")` raises on timeout, and `content()`, `analyze_content()` and `screenshot()` all sit inside that `try` (engine.py lines 144 to 167), so a timeout skips all three. A single `<img src=/slow>`, a long-polling beacon or an open WebSocket held past the navigation timeout (30 s by default; the probe used 8 s) is enough. Malvertising pages routinely hold connections open, so this is the common case, not an edge case.
Fix: wait for `load` (or `domcontentloaded`) with a bounded settle time, then always run the analysis and screenshot in a path that executes even when the wait timed out.

**D3. Static analysis sees too little and is trivially evaded.**
It runs on `page.content()` of the final main frame only: no external `<script src>` bodies, no iframe documents, no intermediate pages, no network responses. The patterns in `static_analyzer.py` require a string literal right after `window|document|top.location =` and a literal inside `atob(`. All of these went undetected when fed to the analyzer:
`var u='…'; window.location=u` · `location.href='…'` (no prefix) · `location='…'` · `window['loc'+'ation']='…'` · `self.location` / `parent.location` · `atob(b)` with a variable · `eval(unescape(...))`, `new Function(...)` · `form.submit()` · `window.open(...)` · `<script src="https://cdn.evil/payload.js">`.
(The DOM-created meta tag case would appear in `page.content()` if it did not navigate, but as D1 shows it navigates first and is then never seen.)
Fix: capture script responses via `Network.responseReceived` / `Network.getResponseBody` (or Playwright `response.body()`) for every JS resource and analyze them too; analyze each frame's content; widen the patterns or move to a tokenizer-based check; treat "navigation happened" (D1) as the primary signal and code patterns as secondary.

**D4. False positives are high enough to make the score unusable as a verdict.**
`String.fromCharCode(` appears in most minified bundles and `location.replace(` in ordinary navigation code. Together they are 0.8 under `scorer.py` weights, which the dashboard labels "Malicious" (threshold 0.75 in `format.ts`). The repo's own `test_benign_scan` tolerates google.com scoring up to 0.6 ("Suspicious"). The `b64_payload` filter still fires on any inline base64 image or font.
Fix: do not weight obfuscation helpers unless they co-occur with an observed navigation or with `eval`/`Function`; score `js_location` only when the redirect was observed (D1); exclude `data:` URIs before the base64 scan.

**D5. The scanner is trivially fingerprinted as a bot, so cloaked campaigns will never show it the payload.**
Observed from inside a scanned page: `navigator.webdriver=true`, `navigator.plugins.length=0`, and a user agent claiming "Chrome/120.0.0.0" while `browser.version` reports 148.0.7778.96. A 28-major-version gap between the advertised and real engine is the kind of inconsistency feature-detection scripts look for; client-hint exposure (`navigator.userAgentData`) was not verified, it returned null on the probe's `data:` page. Headless shell, no proxy support, so the egress IP is a datacenter address. Every mainstream malvertising cloaker checks at least the first of these.
Fix: `--disable-blink-features=AutomationControlled`, set the UA to match the actual Chromium build (or drop the custom UA), add an init script to patch `webdriver`/plugins/languages, support `--proxy-server` for residential egress, and consider the `playwright-stealth` family of patches. Treat this as an arms race, not a one-time fix.

**D6. Timing- and interaction-gated redirects are missed.**
Anything that fires after the ~500 ms network-idle window (`/delayed`) or on a user gesture (`/clickgate`) is not observed. Forced redirects on click, scroll or after a timer are standard in the malvertising playbook.
Fix: after load, dwell for a configurable period (e.g. 5 to 10 s), scroll, and dispatch a synthetic click on the body; record any navigation that results via D1's events.

**D7. Popups and downloads produce no finding.**
`--block-new-web-contents` silently drops `window.open`, so a popup-based redirect (the most common forced-redirect vector in ads) leaves no trace. A drive-by download ends the scan with `raw_error: "Download is starting"` and the file is thrown away.
Fix: listen for `Page.windowOpen` (CDP) or Playwright's `popup` event and record the target URL as a hop/finding; register `page.on("download")`, record filename, MIME type and size as a weighted finding, and save the sample under the task's artifacts.

**D8. The scoring model is thin and partly misdirected.**
Six suspicious TLDs; `_apex()` takes the last two labels, so `google.co.uk` is `co.uk`; the "high-value landing after redirect" rule rewards the ordinary `google.com → www.google.com` 301 (the repo's own test expects a chain there). No URL/domain reputation, domain age, certificate checks, or landing-page content classification (fake AV, tech-support scams, push-notification prompts, brand impersonation), which is where most of today's malvertising lands.
Fix: use a public-suffix list for apex; replace the brand allowlist with a redirect-into-different-registrable-domain rule; add at least one reputation feed; add content heuristics for the scam landing types above.

**D9. Iframe content is out of scope by design, but ad payloads live in iframes.**
Hops inside iframes are intentionally ignored (correctly, for noise), but the iframe documents are also never analyzed, so an ad frame that does `top.location = …` is only seen if it results in a 3xx.
Fix: with D1 in place the resulting top-frame navigation will be recorded; additionally analyze each frame's content and attribute findings to the frame's origin.

---

## Part 2: Vulnerabilities in the tool itself

### V1. HIGH: Chromium sandbox disabled, browser runs as root in the container

*Fixed on 2026-11-04; see the Status section above. The text below describes the state as found.*

Evidence:
- Playwright 1.60 `driver/package/lib/coreBundle.js` lines 41681 to 41682: `if (options2.chromiumSandbox !== true) chromeArguments.push("--no-sandbox");` The flag is added on every platform unless the caller opts in.
- `src/scanner/engine.py:95` launches with `p.chromium.launch(headless=True, args=CHROMIUM_ARGS)` and never passes `chromium_sandbox=True`.
- `Dockerfile` has no `USER` directive; `docker-compose.yml` gives the worker the database URL with its password in the environment and mounts the shared artifacts volume.

Impact: the tool's purpose is to open pages chosen by attackers, and exploit kits are exactly what malvertising delivers. A renderer compromise on a scanned page runs as root in the worker container with no OS sandbox between it and the process: it can read `DATABASE_URL`, reach Postgres and Redis on the compose network (Redis has no auth; a client can enqueue arbitrary `pnakotic.scan` tasks), and write to the artifacts volume the API serves from.

Fix (verify by actually launching; this is not a one-line change):
1. `p.chromium.launch(..., chromium_sandbox=True)`.
2. Add a non-root `USER` to the Dockerfile. Chromium's sandbox needs unprivileged user namespaces, which Docker's default seccomp profile blocks; either run with a seccomp profile that allows `clone`/`unshare` with `CLONE_NEWUSER` (Playwright publishes one with its official image) or base the worker on `mcr.microsoft.com/playwright/python` and keep its `pwuser`.
3. Drop capabilities (`cap_drop: [ALL]`), `no-new-privileges`, read-only root filesystem with a writable tmp, and put workers on a network with no route to `db`/`redis` beyond what they need.
4. Longer term, run the browser in gVisor or a microVM; treat the worker as disposable per scan.

### V2. HIGH: Egress guard bypassed by WebSockets and SharedWorker fetches; UI reports the host as blocked

*Fixed on 2026-11-04; see the Status section above. The text below describes the state as found.*

Evidence (policy: only `127.0.0.1` and `localhost` allowed; `[::1]` is the stand-in internal host):

```
--- requests that reached the servers ---
('v6-INTERNAL', '[::1]:64775', '/leak-main-ws',  'websocket')   # WebSocket from the main frame
('v6-INTERNAL', '[::1]:64775', '/leak-oopif-ws', 'websocket')   # WebSocket from a cross-site iframe
=== INTERNAL host reached by: ['/leak-main-ws', '/leak-oopif-ws']
blocked_hosts: ['::1']

# probe2.py
=== INTERNAL host reached by: [('/leak-shared-worker', ''), ('/leak-worker-ws', 'websocket')]
blocked_hosts : ['::1']
```

HTTP `fetch`, `<img>` and `sendBeacon` from the main frame, from a same-site iframe, from a cross-site iframe and from a dedicated worker were all correctly blocked (the dedicated worker demonstrably ran, since its WebSocket got through). No request from the blob worker reached the internal host. What got through: every WebSocket (main frame, cross-site iframe, dedicated worker) and the plain `fetch()` from a `SharedWorker`. In each case `blocked_hosts` still listed `::1`, so the dashboard shows "Blocked request(s) to non-public host: ::1" for a host that was in fact reached.

Why: CDP `Fetch` interception only covers HTTP(S) requests dispatched through the intercepted target's URL loader. WebSocket handshakes do not go through `Fetch` at all. SharedWorkers are separate targets with their own session, and the engine only enables `Fetch` on the page's session (`ctx.new_cdp_session(page)`). The README's "Every browser request is checked, including each redirect hop, iframes and web-worker fetches" is therefore not true for WebSockets or shared workers. WebRTC (`RTCPeerConnection` with a STUN/TURN server at an internal address) was not tested and is almost certainly also uncovered.

Impact: a scanned page can open TCP connections from the worker to anything the worker can route to: compose services (`db:5432`, `redis:6379`), cloud metadata (`169.254.169.254`), or other internal hosts. The WebSocket handshake delivers a real `GET` with `Upgrade` headers to internal HTTP services (side effects of GET), and `onopen`/`onerror` timing gives a reliable port-and-host reachability oracle the page can exfiltrate to any public host. A SharedWorker `fetch()` is a full no-cors GET (response unreadable cross-origin, but side effects and timing leak). Combined with DNS rebinding, which is already acknowledged, the guard is best treated as a convenience filter rather than a boundary.

Fix:
1. Enforce egress at the network layer, not in CDP. Options: (a) `--proxy-server=http://127.0.0.1:PORT` pointing at a small local allow-listing proxy; Chromium tunnels WebSockets through the HTTP proxy with `CONNECT`, so the proxy sees and can refuse every TCP destination, and resolving in the proxy also closes DNS rebinding; or (b) run workers in a network namespace with no route to RFC 1918, link-local, loopback-aliases or the compose service network, with only the broker/DB reachable through explicit rules.
2. If CDP interception is kept as defense in depth, use `Target.setAutoAttach` with `flatten: true` and enable `Fetch` on every attached target (iframes, dedicated, shared and service workers), and document that WebSocket/WebRTC are not covered by it.
3. Only add a host to `blocked_hosts` when `Fetch.failRequest` succeeded, so the UI never claims a block that did not happen.
4. Update the README's security notes to describe what the guard actually covers.

### V3. MEDIUM: Quadratic regexes let one page pin a worker for minutes

*Fixed on 2026-11-04; see the Status section above. The text below describes the state as found.*

Evidence (inline timing against `StaticAnalyst().analyze_content`):

| Input | Size | Time |
|---|---|---|
| 4000 × `atob('` with no closing quote | 2.0 MB | 24.6 s |
| 4000 × `<meta ` with no closing `>` | 2.0 MB | 12.4 s |

`js_atob` is `atob\(\s*['"].*?['"]\s*\)` with `DOTALL`: every unmatched opener lazily scans to end of input, so cost is O(openers × length). `meta_refresh` has two `[^>]*` runs with the same shape. Cost grows quadratically, so a 10 MB page (well within what Chromium holds) is several minutes. The Celery soft time limit does interrupt a running match (verified: a SIGALRM handler fired inside the match at 2.0 s), so the ceiling is the 240 s soft limit, not the 300 s hard kill. Note that `SoftTimeLimitExceeded` is an ordinary `Exception`, and the analyzer runs inside the engine's `try` (engine.py lines 144 to 167), so the engine swallows it into `raw_error`, scores, and the worker marks the job **completed**; the poisoned scans do not even show up as failures. With two workers and no authentication or rate limiting (V4), a handful of requests takes the service down.

Fix: bound the quantifiers (`atob\(\s*['"][^'"]{0,4096}['"]`, `<meta[^>]{0,2000}`), cap the content passed to the analyzer (e.g. 2 MB, then truncate with a finding), and run the analyzer under its own short timeout.

### V4. MEDIUM: Unauthenticated, unlimited API with open CORS

Documented as a PoC limitation in the README, but worth stating the concrete abuse because the fixes are cheap: anyone who can reach port 8000 can (a) use the workers as an anonymous headless-browser proxy against any public host, with the deployment's IP as the source; (b) flood the queue (no rate limit, no per-client quota, no max queue depth); (c) list every scan, target URL, result and screenshot ever submitted via `GET /tasks`. `allow_origins=["*"]` lets any web page a staff member visits do all of this from their browser.

Fix: API key or SSO in front of every route except `/health`, per-client rate limit on `POST /scan`, a queue-depth cap, a specific `CORS_ORIGINS`, and per-owner scoping of `/tasks`.

### V5. MEDIUM: Unbounded resource use from attacker-controlled pages

- `page.screenshot(full_page=True)` on a page that sets `document.body.style.height = '200000px'` renders a huge bitmap in Chromium and writes a very large PNG to the shared volume (not benchmarked here; Chromium itself may fail the capture, which is also a lost screenshot).
- No retention or size limit on `ARTIFACTS_DIR`; the volume is shared with the API, so filling it degrades both services.
- Hop `headers` are stored in full and unbounded; `target_url` and `profile` have no length limits (`ScanRequest`), and an unknown profile string is silently accepted and stored.

Fix: cap screenshot dimensions (`clip` or a max page height), set a retention job and a per-task size cap, truncate stored headers, add `max_length` to the request model and reject unknown profiles with 422.

### V6. LOW: IPv6 transition addresses pass the public-IP check

On the image's Python (3.11.18, verified in `python:3.11-slim`):

```
64:ff9b::7f00:1  is_global= True   # NAT64 well-known prefix embedding 127.0.0.1
::7f00:1         is_global= True   # deprecated IPv4-compatible form of 127.0.0.1
2002:7f00:1::1   is_global= False  # 6to4: handled
```

`is_public_ip()` in `netguard.py` only unwraps `::ffff:` mapped addresses. This matters only where the worker's network has NAT64 or legacy IPv4-compatible routing, hence Low.
Fix: explicitly deny `64:ff9b::/96`, `64:ff9b:1::/48` and `::/96` (and extract the embedded IPv4 for NAT64 and check it), or move to Python 3.13 where `is_global` handles more transition forms, and keep the explicit NAT64 check either way.

### V7. LOW: DNS rebinding window widened by per-scan verdict caching

Acknowledged in the README. One detail makes it slightly worse: `EgressGuard._cached_host_allowed` pins the first verdict for a host for the whole scan (up to the 30 s navigation timeout plus settle), so an attacker needs only one public answer at first contact. The network-layer fix in V2 (resolve in the proxy and connect to the resolved address) closes this too.

### V8. LOW: Hygiene

- The Postgres password is hard-coded in `docker-compose.yml`, `src/database/session.py` and `alembic/env.py`.
- `POST /scan` returns `artifact_dir`, an absolute server-side path.
- `resolve_task_folder` uses `str.isalnum()`, which accepts non-ASCII letters and digits; harmless today (traversal is still blocked) but tighten to ASCII.
- `GET /tasks/{id}/artifacts/{path}` is correct (shared validator, `base + os.sep` prefix check, `isfile`), but for defense in depth given V1: allowlist `.png`, send `X-Content-Type-Options: nosniff`, and compare with `os.path.realpath` so a symlink dropped on the volume cannot redirect it.
- `build-essential` remains in the runtime image; use a build stage.
- Errors and guard decisions go to `print`; use logging with a redaction step for URLs.

### Reviewed and found sound

- Task-ID to path resolution (`artifacts.py`) and both call sites; tests cover traversal.
- Database access is ORM-parameterized; no raw SQL with user input.
- Celery uses JSON serialization; the worker re-validates `job_id` through the same path resolver, so a malicious broker message cannot escape `ARTIFACTS_DIR`.
- Idempotent task handling and the sweeper's conditional UPDATEs.
- The dashboard renders all server data through React text nodes; the only `href`s point at `artifactUrl()`; no `dangerouslySetInnerHTML`. No XSS found.
- Postgres and Redis are not published to the host.

### V9. MEDIUM: The bundled Chromium lags Chrome's security fixes, and nothing in the project tracks it

*Fixed on 2026-11-04; see the Status section above. The text below describes the state as found.*

Added 2026-11-04 after a public warning about Playwright's bundled Chromium. Verified facts:

| What | Version | Source |
|---|---|---|
| Chrome stable, 27 Oct 2026 | 156.0.8078.73, 4 Critical CVEs (use-after-free in FileSystem, FileAPI, Layout; integer overflow in Skia) | chromereleases.googleblog.com |
| Chrome stable, 29 Oct 2026 | 156.0.8078.79, 1 Critical (use-after-free in MediaStream) | same |
| Chrome stable, 3 Nov 2026 | 157.0.8103.38, 7 Critical | same |
| Newest Playwright for Python (1.64.1, 22 Oct 2026, needs Python 3.10+) | bundles Chromium **156.0.8078.4** | `browsers.json` at tag v1.64.1 |
| This machine (Python 3.9.6, so pip stops at Playwright 1.60) | Chromium **148.0.7778.96** | `browser.version` |
| Docker image (`python:3.11-slim`, `playwright>=1.40.0` unpinned) | whatever was current at build time; a fresh build today gets 1.64.1 / 156.0.8078.4 | Dockerfile, requirements.txt |

Playwright's Chromium is cut from the open-source project ahead of the branded release, so it is a *newer major* but an *earlier build* than Chrome stable: 156.0.8078.4 predates the .73 and .79 security builds of the same branch, and Playwright only moves when it releases. A scanner points this browser at hostile pages by design, so the renderer will eventually meet an exploit for a published bug.

What limits the blast radius here: since the V1 fix the renderer runs inside Chromium's own sandbox (`chromium_sandbox=True`), as uid 1001, with all capabilities dropped, `no-new-privileges`, and a seccomp profile, so a renderer bug alone is not enough; the attacker also needs a sandbox escape. What an escape would reach: the worker container holds `DATABASE_URL` with the Postgres password (hard-coded in `docker-compose.yml` as `dark-matter-password`), `REDIS_URL` (the Celery broker, so job injection), and the shared `artifacts_data` volume. It holds no host secrets.

Fix: (1) run scans in Google Chrome stable instead of the bundled build: `playwright install chrome --with-deps` in the Dockerfile and `chromium.launch(channel="chrome", ...)`, selectable by an environment variable so local development can keep the bundled browser; Chrome stable receives the security builds the day Google ships them, and the image then only needs rebuilding on Chrome's cadence (weekly is adequate). (2) Pin `playwright==1.64.1` and bump deliberately, and log `browser.version` at worker start so the running build is visible. (3) Move the Postgres password out of `docker-compose.yml` into an untracked `.env`. (4) For local development, move to Python 3.10 or newer so Playwright can be current, and never scan untrusted URLs from a laptop that holds real credentials; the test suite only touches `127.0.0.1` and `google.com`.

---

## Suggested order of work

Items 1 to 4 were completed on 2026-11-04 (see the Status section); V7 was closed by the V2 proxy's pinned resolution. The list is kept as written for the record.

1. V1: sandbox on, non-root, verified launch under a permissive-enough seccomp profile.
2. V2: network-layer egress control (allow-listing proxy or network namespace); fix the false "blocked" report; correct the README.
3. D1 + D2: record client-side navigations from CDP events; always analyze and screenshot even on timeout. These two changes turn the tool from "3xx logger" into something that sees the redirects it was built to find.
4. V3: bound the regexes and cap content size.
5. D5 + D6 + D7: anti-fingerprinting, dwell/interaction, popup and download capture.
6. V4 + V5: auth, rate limits, retention and size caps.
7. D3, D4, D8, D9: broaden analysis to scripts and frames, retune scoring, add reputation.
8. V6, V7, V8.
