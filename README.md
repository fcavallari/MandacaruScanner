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
4. Popups and new tabs are blocked, but each attempt is recorded as a `popup_open` hop with its destination. Nothing is loaded.
5. The page is loaded with a bounded settle period, then the HTML is checked for redirect code that did not fire (`meta_refresh_code`, `js_location_code`), `atob` / `String.fromCharCode` obfuscation and long base64 payloads (input capped at 2 MB). A full-page screenshot is saved. A slow subresource that keeps the page from settling no longer skips the analysis or the screenshot.
6. After the landing is captured, the scan clicks once on an empty part of the page (not a link or control) and waits 1.5 s. A popup that opens then is recorded with `trigger: click` (a popunder). If the tab navigates away, that is a `click_hijack` hop. Neither changes the recorded landing.
7. The result is scored and stored, and the job becomes `completed`.

If a worker dies, the job is retried. A background sweeper fails jobs left in `running` for 15 minutes or in `queued` for 60.

### Browser profiles

| Profile          | Emulates |
|------------------|----------|
| `default`        | Desktop Chrome on Linux, 1920×1080 |
| `mobile-ios`     | iPhone Safari, 390×844, touch |
| `mobile-android` | Pixel 8 Chrome, 412×915, touch |
| `search-clicker` | Desktop Chrome arriving from `https://www.google.com/` (what a click on a Google result sends) |
| `facebook-android` | A link tapped in the Facebook app on Android: the in-app WebView, `Referer: https://l.facebook.com/`, `X-Requested-With: com.facebook.katana` |
| `googlebot` | Googlebot Smartphone. Catches cloaking that checks the user agent; a site that verifies Googlebot by reverse DNS still sees a datacenter IP |

Malvertising often only fires for some visitors, so scanning one URL under several profiles is useful. Chrome user agents carry the real version of the browser doing the scan, and each profile's client hints (`sec-ch-ua*`) match it, so no request names `HeadlessChrome`. The iOS profile sends an empty `sec-ch-ua`, where real Safari sends none. `POST /scan` rejects an unknown profile name with `422`.

### Scoring

Signals add up and the total is capped at 1.0:

| Signal | Weight |
|--------|--------|
| Lands on a raw IP address | 0.5 |
| Observed JS redirect (`location` assignment / `replace()` / `assign()` that fired) to another registrable domain; same-site navigations, including a page reloading itself, are not scored | 0.4 |
| JS obfuscation helpers (`atob`, `String.fromCharCode`), counted once, only together with a cross-site redirect, a brand-name hostname or a credential form | 0.4 |
| Brand name in the hostname that is not the brand's own domain (`zoom` in `us05web-zoom-...pages.dev`), counted once; exempt when the scan lands on the brand's own domain, which makes the hostname the brand's redirector (`googleplay.com` → `play.google.com`) | 0.4 |
| Credential form: a password input on a page that names a brand (title or hostname) it does not belong to | 0.4 |
| Click hijack: the click probe hit no link, yet the page went to another site, counted once | 0.4 |
| Popup or new tab to another site (on load or on the click probe), counted once; same-site popups are not scored | 0.3 |
| Suspicious TLD (`.xyz`, `.top`, `.icu`, `.gq`, `.tk`, `.ml`, `.sbs`, `.click`, ... see `scorer.py`) | 0.3 |
| Observed meta refresh to another registrable domain (a refresh without `url=` is a reload timer and is ignored) | 0.25 |
| More than 5 redirects | 0.2 |
| Redirected to a different registrable domain than the one submitted (unless it is a high-value domain) | 0.2 |
| Lands on a high-value brand domain (Google, X/Twitter, Apple, Microsoft) after a redirect | 0.2 |
| JS `location` code present in the page but it did not fire, counted once | 0.15 |
| Page title that leads with a brand name (first three words) on a host that is not the brand's, unless a credential form already fired | 0.2 |
| Hosted on a free or disposable platform (`pages.dev`, `workers.dev`, `netlify.app`, `github.io`, ...) | 0.15 |
| Abuse-prone TLD (`.pro`, `.online`, `.shop`, `.site`, `.store`, `.live`, `.fun`, `.work`, `.website`, `.space`) | 0.15 |
| Meta refresh tag present in the page but it did not fire, counted once | 0.1 |
| JS obfuscation helpers with no cross-site redirect and no brand signal, counted once (replaces the 0.4 row) | 0.1 |

A result counts as a redirect chain only if at least one real redirect was observed (HTTP 3xx, meta refresh or JS location). Redirect code that did not fire, obfuscation and base64 findings are reported but don't make a chain on their own. Phishing pages usually don't redirect, so the brand, hosting and TLD rules work from the hostname and from the page itself (title, password inputs). Two findings are reported without a weight: navigation to an unreachable host, and a landing document that is not HTML. Brand tokens of six or more letters match inside a hostname label (`googleplay`); shorter ones only as a whole label (`pineapple.com` is not Apple). Base64 inside `data:` URIs is not reported as a payload. The brand, throwaway-hosting and TLD lists are module constants in `src/intelligence/scorer.py`. The weights are hand-tuned heuristics, not a trained model.

## API

| Method & path | Description |
|---------------|-------------|
| `POST /scan` | Body `{"url": "https://…", "profile": "default"}`. Returns `201` with `task_id`. `400` for a non-public host, `422` for a non-http(s) URL or an unknown profile, `503` if the queue is unavailable. |
| `GET /tasks?limit=20` | Most recent jobs (newest first, `limit` 1–100), with results where available. |
| `GET /tasks/{id}/status` | `queued`, `running`, `completed` or `failed`, plus `error`. |
| `GET /tasks/{id}/results` | Final URL, score, hops, findings and artifact list. `404` until the scan has a result. |
| `GET /tasks/{id}/artifacts/{path}` | A stored artifact, e.g. `screenshots/landing_20261104_101500.png`. |
| `GET /health` | Liveness check. |

`/tasks` and `/tasks/{id}/results` return the same `result` object.

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

Most tests need nothing installed beyond the Python requirements. The API and worker tests use a temporary SQLite database and a fake engine. Browser tests use Chromium against a local server and are skipped if Chromium isn't installed. Two of them scan the real `google.com` and need network access.

Run a single test:

```bash
python3 -m pytest tests/test_engine.py::test_redirect_to_internal_host_is_blocked
```

## Project layout

```
src/api/            FastAPI app: endpoints, sweeper
src/workers/        Celery app and the scan task
src/scanner/        Playwright engine, browser profiles, static analysis,
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
