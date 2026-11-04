# Pnakotic

Pnakotic follows a URL to see where it really goes. It opens the URL in headless Chromium, records every redirect on the way, checks the landing page for redirect and obfuscation tricks, and gives the result a malvertising risk score from 0 to 1, with a screenshot of where the browser ended up.

It is a proof of concept: a FastAPI service, Celery workers running Playwright, PostgreSQL, Redis, and a React dashboard.

## Quick start

```bash
docker compose up --build
```

| Service   | URL                     |
|-----------|-------------------------|
| Dashboard | http://localhost:5173   |
| API       | http://localhost:8000   |
| API docs  | http://localhost:8000/docs |

The stack runs PostgreSQL, Redis, the API (which applies Alembic migrations on start), two scan workers and the dashboard. The database credentials in `docker-compose.yml` are development defaults; change them before exposing the stack anywhere.

The scan workers run Google Chrome stable by default, so the browser gets Chrome's security builds the day Google ships them; rebuild the image on that cadence (weekly is adequate). Google publishes no Linux arm64 Chrome, so on Apple-silicon Docker build with Playwright's bundled Chromium instead:

```bash
BROWSER_CHANNEL=chromium docker compose up --build
```

(or put `BROWSER_CHANNEL=chromium` in a `.env` file next to `docker-compose.yml`). That build is only re-patched when Playwright releases, so prefer an amd64 host for anything beyond development.

The API and worker containers run as a non-root user (uid 1001). If you have an `artifacts_data` volume created by an earlier root-based image, give it to that user once before starting:

```bash
docker run --rm -v pnakotic_artifacts_data:/a alpine chown -R 1001:1001 /a
```

Start a scan from the dashboard, or with curl:

```bash
curl -s -X POST localhost:8000/scan -H 'content-type: application/json' -d '{"url": "http://google.com", "profile": "mobile-ios"}'
```

## How a scan works

1. `POST /scan` checks the URL and creates a job in `queued`. It rejects any host that resolves to a private, loopback, link-local or other non-public address.
2. A worker picks the job up, sets it to `running`, and opens the URL in Chromium with the chosen browser profile.
3. Every main-frame redirect is recorded as a hop: HTTP 3xx responses, and client-side navigations the browser reports through CDP (`window.location` assignments as `js_location`, meta refresh as `meta_refresh`, form submissions and anchor clicks as informational `client_navigation`). Redirects on images, scripts and iframes are ignored, and scanning stops after 10 redirects (a likely loop).
4. The page is loaded with a bounded settle period, then the HTML is checked for redirect code that did not fire (`meta_refresh_code`, `js_location_code`), `atob` / `String.fromCharCode` obfuscation, long base64 payloads and ClickFix lure text ("press Win+R … Ctrl+V") (input capped at 2 MB). A full-page screenshot is saved. A slow subresource that keeps the page from settling no longer skips the analysis or the screenshot.
5. While the page runs, hooks record what it tries to do to the visitor (`page_behavior` hops): clipboard writes (flagged when the text is a shell command, the ClickFix pattern), downloads it starts on its own (cancelled, never kept), alert/confirm/prompt dialogs, fullscreen and keyboard-lock requests, `beforeunload` handlers, `pushState` floods, notification-permission prompts and `window.open` attempts. The engine never clicks, so only what a page does by itself shows up.
6. If YARA rules are configured, the rendered HTML, up to 10 subframe documents and the bodies of up to 60 scripts the page loaded are matched against them (`yara_match` hops; see [YARA rules](#yara-rules)).
7. Unless the request turns it off, the URL is also loaded in every other browser profile, each in its own context, in parallel. Where each profile landed is compared (see [Scoring](#scoring)).
8. The result is scored and stored, and the job becomes `completed`.

If a worker dies, the job is retried. A background sweeper fails jobs left in `running` for 15 minutes or in `queued` for 60.

### Browser profiles

| Profile          | Emulates |
|------------------|----------|
| `default`        | Desktop Chrome on Linux, 1920×1080 |
| `mobile-ios`     | iPhone Safari, 390×844, touch |
| `mobile-android` | Pixel 8 Chrome, 412×915, touch |
| `search-clicker` | Desktop Chrome arriving from `https://www.google.com/` |

Malvertising often fires only for some visitors, so by default every scan loads the URL in all four profiles (`compare_profiles`, on by default). The requested profile's chain is the one shown and stored as the job's hops; the others are summarized in `variants`, with their screenshots under `profiles/<profile>/`. All profiles leave from the same IP, so this catches user-agent, viewport and referrer cloaking, not IP or geo cloaking.

### Scoring

**Decisive indicators** settle the verdict alone: the score becomes 1.0 and they lead the findings (and are listed in `decisive`):

- the page wrote a shell command to the clipboard (`powershell`, `mshta`, `cmd /c`, `curl … | sh`, …): ClickFix
- a download of an executable, script, installer, app package or disk image started without a click
- two or more browser-lock behaviors together: fullscreen, keyboard lock, `beforeunload` handler, `pushState` flood, 3+ dialogs (the tech-support-scam lock)
- a production YARA rule of severity 4 or 5 matched the page, a frame or a script
- cloaking: profiles landed on different sites and at least one profile's own page scored Suspicious (≥ 0.4) or worse

Everything else adds up, capped at 1.0. With profiles compared, the job's score is the worst profile's score plus the cloaking weight:

| Signal | Weight |
|--------|--------|
| Lands on a raw IP address | 0.5 |
| Observed JS redirect (`location` assignment / `replace()` / `assign()` that fired) | 0.4 |
| JS obfuscation helpers (`atob`, `String.fromCharCode`), counted once | 0.4 |
| Suspicious TLD (`.xyz`, `.top`, `.icu`, `.gq`, `.tk`, `.ml`) | 0.3 |
| Observed meta refresh | 0.25 |
| More than 5 redirects | 0.2 |
| Lands on a high-value brand domain (Google, X/Twitter, Apple, Microsoft) after a redirect | 0.2 |
| JS `location` code present in the page but it did not fire, counted once | 0.15 |
| Meta refresh tag present in the page but it did not fire, counted once | 0.1 |
| Download started without a click (not an executable, e.g. an archive) | 0.4 |
| YARA: exploratory rule of severity 4–5, or production rule of severity 3, once | 0.4 |
| Profiles land on different sites (cloaking), none of them suspicious | 0.35 |
| ClickFix lure text (Win+R and Ctrl+V instructions on one page) | 0.3 |
| Notification-permission prompt on load | 0.2 |
| Clipboard write without a click (not a command) | 0.15 |
| Each browser-lock behavior on its own, except a lone `beforeunload` handler (0) | 0.15 |
| YARA: any other match, once | 0.15 |
| `window.open` attempt | 0.1 |
| A JavaScript dialog | 0.1 |

A result counts as a redirect chain only if at least one real redirect was observed (HTTP 3xx, meta refresh or JS location). Redirect code that did not fire, obfuscation and base64 findings are reported but don't make a chain on their own. The weights are hand-tuned heuristics, not a trained model.

## API

| Method & path | Description |
|---------------|-------------|
| `POST /scan` | Body `{"url": "https://…", "profile": "default", "compare_profiles": true}`. Returns `201` with `task_id`. `400` for a non-public host, `422` for a non-http(s) URL, `503` if the queue is unavailable. |
| `GET /tasks?limit=20` | Most recent jobs (newest first, `limit` 1–100), with results where available. |
| `GET /tasks/{id}/status` | `queued`, `running`, `completed` or `failed`, plus `error`. |
| `GET /tasks/{id}/results` | Final URL, score, hops, findings and artifact list. `404` until the scan has a result. |
| `GET /tasks/{id}/artifacts/{path}` | A stored artifact, e.g. `screenshots/landing_20261104_101500.png`. |
| `GET /health` | Liveness check. |

`/tasks` and `/tasks/{id}/results` return the same `result` object: `final_url`, `malicious_score`, `is_redirect_chain_detected`, `hops`, `artifacts`, `findings`, `decisive`, `variants` (each profile's landing, redirect count and own score, the requested one first), `cloaking` (landing per profile, or `null`), `yara` (rules loaded and what was scanned, or `null` when YARA is off) and `raw_error`.

## Configuration

| Variable | Default | Used by |
|----------|---------|---------|
| `DATABASE_URL` | `postgresql+psycopg2://pnakotic_admin:…@db:5432/pnakotic_memory` | API, worker, Alembic |
| `REDIS_URL` | `redis://localhost:6379/0` | API, worker |
| `ARTIFACTS_DIR` | `./artifacts` | API, worker (must be shared between them) |
| `CORS_ORIGINS` | `*` | API (comma-separated list) |
| `STUCK_JOB_TIMEOUT_MINUTES` | `15` | API sweeper |
| `QUEUED_JOB_TIMEOUT_MINUTES` | `60` | API sweeper |
| `SWEEP_INTERVAL_SECONDS` | `60` | API sweeper |
| `VITE_API_BASE` | `http://localhost:8000` | Frontend, set at build time (`--build-arg`) |
| `YARA_RULES_DIR` | unset (YARA off) | Worker; `/app/yara-rules` in compose |
| `YARA_RULES_HOST_DIR` | `./yara-rules` | Compose only: the host directory mounted read-only at `/app/yara-rules` |

### YARA rules

No rules ship with Pnakotic. Point the worker at a rules directory and it compiles them once per process:

```bash
echo 'YARA_RULES_HOST_DIR=/path/to/your/yara/rules' >> .env
docker compose up -d --build
```

For a rules tree split by target (`html/`, `raw/`, `php/`, …) the worker uses every `html/` rule plus the `raw/` rules whose file name starts with `js` or `html`; PHP rules target server files. Any other directory is used whole (`*.yar`, `*.yara`). Each file gets its own namespace and the `filename` external, and a file that fails to compile is skipped and logged. The worker logs `[yara] N rule files from …` at its first scan. Matching uses yara-python (libyara) with a 5 s timeout per buffer, 2 MB per buffer, 12 MB per page and a 20 s budget per page. Rule metadata `severity` (1–5), the `production` / `exploratory` tag, `signatureId` and `description` are read for scoring and display.

## Development

The Python code is imported as the package `pnakotic.src…`, so this folder must be named `pnakotic`. Run the API and worker from its **parent** folder:

```bash
pip install -r pnakotic/requirements-dev.txt
```

```bash
playwright install chromium
```

```bash
uvicorn pnakotic.src.api.main:app --reload
```

```bash
celery -A pnakotic.src.workers.celery_app worker --loglevel=info
```

Both need PostgreSQL and Redis. `docker-compose.yml` doesn't publish their ports to the host, so outside Docker use local instances (or add `ports:` to those services), and point `DATABASE_URL` and `REDIS_URL` at `localhost`.

Apply migrations with:

```bash
alembic -c pnakotic/alembic.ini upgrade head
```

The dashboard lives in `frontend/`:

```bash
cd frontend && npm install && npm run dev
```

`npm run build` type-checks with `tsc` and builds into `frontend/dist`.

### Tests

Run from this folder:

```bash
python3 -m pytest
```

Most tests need nothing installed beyond the Python requirements. The API and worker tests use a temporary SQLite database and a fake engine. Browser tests use Chromium against a local server and are skipped if Chromium isn't installed. YARA tests write synthetic rules to a temporary folder (no real rules are needed or committed) and are skipped without yara-python. Two of them scan the real `google.com` and need network access.

Run a single test:

```bash
python3 -m pytest tests/test_engine.py::test_redirect_to_internal_host_is_blocked
```

## Project layout

```
src/api/            FastAPI app: endpoints, sweeper
src/workers/        Celery app and the scan task
src/scanner/        Playwright engine, browser profiles, static analysis,
                    page-behavior hooks (behavior.py), YARA (yara_scan.py),
                    egress guard (netguard.py), artifact storage
src/intelligence/   Scoring
src/database/       SQLAlchemy models and session
alembic/            Migrations
frontend/           React + Vite + Tailwind dashboard
tests/              pytest suite
```

## Security notes

Pnakotic opens untrusted URLs in a real browser, so the scanner limits what that browser can reach:

- Chromium is launched with a per-scan local SOCKS5 proxy (`src/scanner/egress_proxy.py`) as its only route out, and its own DNS is disabled, so every connection it opens (HTTP, WebSocket, workers, iframes, redirect hops) reaches the proxy by hostname. The proxy resolves the name once, allows it only if every resolved address is public, and connects to one of those checked addresses, so a host cannot swap to a private address after the check (DNS rebinding).
- CDP request interception (`EgressGuard`) runs as well, for precise per-URL blocking and `ERR_BLOCKED_BY_CLIENT` errors. Hosts blocked by either layer show up in the scan's findings.
- Popups and service workers are disabled; WebRTC's direct UDP paths are turned off.
- Chromium runs with its sandbox enabled (`chromium_sandbox=True`), and in Docker as a non-root user under the seccomp profile in `seccomp_profile.json`, which allows the user namespaces the sandbox needs.
- Which browser scans run in is chosen by `BROWSER_CHANNEL` (`chrome` in the Docker image, empty for Playwright's bundled Chromium locally). Playwright's bundled Chromium is cut ahead of Chrome's release and only re-patched when Playwright itself releases, so it can lag Chrome stable's security fixes by weeks; the Chrome channel does not. The worker logs the build it is running at its first scan. Branded Chrome also contacts a few Google hosts at startup (accounts, component updates, gstatic); they pass through the egress proxy like any public host. `playwright` is pinned in `requirements.txt` so browser bumps are deliberate.
- Locally, don't scan untrusted URLs on a laptop that holds real credentials unless `BROWSER_CHANNEL=chrome` points at an up-to-date Chrome; the test suite only touches `127.0.0.1` and `google.com`.
- CORS is open (`*`) by default and the API has no authentication. Don't expose it publicly as-is.
- Downloads a page starts are cancelled as soon as they begin; the file is never kept. Everything the page-behavior hooks report is treated as attacker input (known event ids only, strings truncated, at most 100 events), so a page faking events can only raise its own score. The hooks report through a randomly named binding that is removed from `window`, and wrapped functions keep their native `toString()`. A determined page can still detect instrumentation (and headless Chromium in general), so a clean scan is not proof that a URL is benign.
- YARA rule sets can be private: they are mounted read-only into the worker and never copied into the image or the repository (`yara-rules/` is git- and docker-ignored).
