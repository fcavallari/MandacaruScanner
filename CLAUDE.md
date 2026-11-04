# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Pnakotic is a redirect-chain / malvertising scanner (proof of concept). A URL is submitted to a FastAPI service, a Celery worker opens it in headless Chromium (Playwright) under a chosen browser profile, records every redirect hop, runs regex static analysis on the landing page, takes a screenshot, and assigns a heuristic `malicious_score` (0–1). A React dashboard (`frontend/`) submits scans and visualizes the chain.

## Commands

Backend (run from this directory — the repo root):

```bash
pip install -r requirements-dev.txt && playwright install chromium
python3 -m pytest                                   # all tests
python3 -m pytest tests/test_engine.py::test_scoring_ip_landing   # single test
python3 -m pytest -k "scoring or static or artifact"              # offline unit tests only
```

Full stack (Postgres, Redis, API on :8000, 2 workers, frontend on :5173):

```bash
docker compose up --build
```

The `api` container runs `alembic -c pnakotic/alembic.ini upgrade head` before uvicorn. Running the API or worker outside Docker must be done from the **parent** directory (see import path below), e.g. `uvicorn pnakotic.src.api.main:app` and `celery -A pnakotic.src.workers.celery_app worker`, with `DATABASE_URL` / `REDIS_URL` set (the defaults point at the compose hostnames `db` / `localhost`).

Frontend (`frontend/`): `npm run dev`, `npm run build` (runs `tsc` then `vite build` — this is the only type check; there is no lint or test script). API base URL comes from `VITE_API_BASE` (default `http://localhost:8000`), baked in at build time.

## Import path (important)

All code is imported as the package `pnakotic.src...`, so this directory must be named `pnakotic` and its **parent** must be on `sys.path`. `conftest.py` and `alembic/env.py` insert the parent; the Dockerfile copies the repo to `/app/pnakotic`. Inside `src/`, modules use relative imports, except `workers/celery_app.py`, which imports `pnakotic.src...` absolutely inside the task body. Tests import inside each test function.

## Architecture

Request flow:

1. `POST /scan` (`src/api/main.py`) validates the URL (`^https?://`, plus `_assert_public_host`, which resolves the host and rejects any non-public address as an early 400), writes a `ScanJob` row with status `queued`, then calls `run_scan_worker.delay(...)`. If dispatch fails, the job is marked `failed` and the endpoint returns 503.
2. `run_scan_worker` (`src/workers/celery_app.py`) sets the job to `running` and refreshes `updated_at` (also on re-delivery; that column is the sweeper's clock), runs the async `PnakoticEngine.scan()` in a fresh event loop, replaces any existing result row, writes a DB `ScanResult`, and sets `completed` (or `failed` with a truncated error). Celery uses `task_acks_late` + `task_reject_on_worker_lost`, so tasks **must stay idempotent**: completed jobs are skipped, and stale result rows are deleted before insert.
3. `PnakoticEngine.scan()` (`src/scanner/engine.py`) applies a `BrowserProfile` (`profiles.py`: `default`, `mobile-ios`, `mobile-android`, `search-clicker`). It records two kinds of main-frame redirect (not subresources or iframes): each navigation 3xx as an `http_3xx` hop (`on_resp`), and each client-side navigation reported by CDP `Page.frameRequestedNavigation` (`scriptInitiated` → `js_location`, `metaTagRefresh`/`httpHeaderRefresh` → `meta_refresh`, anything else → informational `client_navigation`; mapping in `NAVIGATION_MECHANISMS`). A client-side hop's `url` is the page that issued it and the destination is `evidence["to"]`. Both kinds go through `note_redirect()`, which stops the page at `max_hops`. Navigation is `goto(wait_until="load")` followed by a bounded `networkidle` settle (`SETTLE_MS`); then `final_url`, `page.content()`, `StaticAnalyst`, and the screenshot (with `SCREENSHOT_TIMEOUT_MS` and a CDP `Page.captureScreenshot` fallback) each run in their own step, so a timeout in one does not skip the others. Only Playwright errors are caught on that path; anything else (including Celery's `SoftTimeLimitExceeded`) propagates so the worker marks the job `failed`. Each static signature becomes a hop with the mechanism from `SIGNATURE_MECHANISMS`; the analyzer caps its input at `MAX_CONTENT_CHARS` and its regexes use bounded quantifiers (attacker-controlled input). It then calls `PnakoticScorer.score()`.
4. A background sweeper in the API `lifespan` (`sweep_stale_jobs`) marks as `failed` any job stuck in `running` longer than `STUCK_JOB_TIMEOUT_MINUTES` (default 15) or in `queued` longer than `QUEUED_JOB_TIMEOUT_MINUTES` (default 60). Each rule is a single conditional UPDATE, so it can't overwrite a job a worker just picked up.

Endpoints that touch the DB or the broker are plain `def`, so FastAPI runs them in its threadpool. `POST /scan` is `async` only for the DNS check, and runs its DB/dispatch part through `run_in_threadpool`. Keep blocking calls out of `async def` handlers.

Key concepts that span files:

- **Egress guard (SSRF).** `src/scanner/netguard.py` is the single policy: a host is allowed only if every address it resolves to is globally routable. The API uses it for the early 400. The engine enforces it in two layers. (1) `src/scanner/egress_proxy.py` is a per-scan local SOCKS5 proxy; the browser is launched with it at launch level, so Playwright also maps every hostname to NOTFOUND in Chromium's resolver and the proxy receives names, resolves them once, checks every address and connects to one of those checked addresses (pinned, so DNS rebinding is closed). This is the layer that covers WebSockets, SharedWorkers and anything else CDP can't see. (2) `EgressGuard` in `engine.py` keeps CDP `Fetch` interception for precise per-URL blocking and `ERR_BLOCKED_BY_CLIENT` errors. Popups are disabled (`--block-new-web-contents`), service workers are blocked, and WebRTC's direct UDP paths are disabled by flag. Blocked hosts from both layers are merged into `metadata["blocked_hosts"]` (only after a block actually happened) and an unweighted scoring finding. The browser launches with `chromium_sandbox=True` via `launch_options()`, which also reads `BROWSER_CHANNEL` (`chrome` in the Docker image, so scans run in Google Chrome stable, which gets security builds on Chrome's schedule; empty locally for the bundled Chromium, which lags stable). `playwright` is pinned in `requirements.txt`; the Dockerfile's `BROWSER_CHANNEL` build arg must be `chromium` on arm64, where Chrome has no Linux build. Tests that scan a local server must pass `host_allowed=` to `PnakoticEngine`; both layers use the same injected policy.
- **Two different `ScanResult` classes.** `src/scanner/models.py` has the Pydantic engine output; `src/database/models.py` has the SQLAlchemy row. The worker maps one onto the other. Hops, artifact manifest, scoring findings, `raw_error` and `redirect_loop` are stored in the DB row's `metadata_json` (JSONB, Postgres-only; named that way to avoid clashing with `Base.metadata`).
- **Redirect vs. passive mechanisms.** `REDIRECT_MECHANISMS = {http_3xx, meta_refresh, js_location}` are redirects the browser actually performed. Only these make `is_redirect_chain_detected` true and count toward the scorer's `deep_chain` and "high-value landing after redirect" rules. Regex hits on the landing page are weaker "code present but did not fire" signals: `meta_refresh_code` (0.1) and `js_location_code` (0.15), each applied once. `js_obfuscation` hops (`atob`, `String.fromCharCode`) score once but aren't redirects; `client_navigation` (form submit, anchor click) and `static_analysis` hops (for example `b64_payload`, `content_truncated`) are informational. `frontend/src/lib/format.ts` mirrors `REDIRECT_MECHANISMS` and labels every mechanism in `MECHANISM_LABELS`, so adding a mechanism means updating both. Adding a new signature means updating `StaticAnalyst.SIGNATURES` and `SIGNATURE_MECHANISMS`; if it should score, also update the scorer's `WEIGHTS`.
- **Artifacts.** The root is `ARTIFACTS_DIR` (default `./artifacts`, relative to the cwd; `/app/artifacts` is a shared volume between API and worker in compose). `resolve_task_folder()` is the single place a task ID becomes a path: it validates the ID (alphanumerics, `-` and `_`) and blocks traversal. `task_folder_for()` (API) and `ArtifactManager` (engine) both go through it. The worker doesn't pass a folder; the engine derives `<root>/<job_id>` itself. The task's optional fourth `task_folder` argument is ignored and kept only so messages from older APIs still run. Manifest `rel_path`s are served by `GET /tasks/{id}/artifacts/{path}`.
- **API response shape.** `/tasks` and `/tasks/{id}/results` share `serialize_result()` in `main.py` (`final_url`, `malicious_score`, `is_redirect_chain_detected`, `hops`, `artifacts`, `findings`, `raw_error`). `frontend/src/lib/api.ts` (`ScanResultData`) mirrors it by hand, so change both together. `/tasks` eager-loads results with `joinedload` (one query).
- **Schema.** Alembic (`alembic/versions/`) is the source of truth. `init_db()` (`create_all`) also runs at API startup and in the sweeper as a convenience, so a model change still needs a matching migration.

## Tests

`tests/test_netguard.py` unit-tests the egress policy. `tests/test_static_analyzer.py` covers the analyzer's regexes, the 2 MB input cap and two adversarial inputs under a 1 s budget. `tests/test_api.py` covers the endpoints, sweeper and worker against a temporary SQLite DB: its `db` fixture patches `SessionLocal` in both `main` and `database.session`, and compiles JSONB as JSON. The worker tests swap in a fake engine, so no Postgres, Redis or browser is needed. `tests/test_engine.py` contains offline unit tests (scorer weights, static-analyzer regexes, artifact safety), engine tests against a local `127.0.0.1` server (the `local_site` fixture), and two live tests that scan the real `google.com`. Browser tests are skipped automatically when Chromium can't launch. The google.com tests write screenshots to `./artifacts/test-job/` under the cwd. Scorer tests assert exact weight sums, so changing `WEIGHTS` means updating them.

## Frontend design

The dashboard follows a deliberate design system documented in `.taste-skill/notes.md`. It uses the "data-terminal" app-screen style with an abyssal green-black ground and one phosphor-teal accent. Public Sans is used for text, IBM Plex Mono for every figure, ID and URL, and Chakra Petch for the wordmark only. Selection is shown as a 1px accent line, with no glow, glass or entrance animations. Colors are CSS variables in `src/index.css`, exposed as Tailwind tokens (`ground`, `surface`, `raised`, `ink`, `accent`, `line`, …) in `tailwind.config.js`; use the tokens, not raw colors. Each token is wrapped in `color-mix(... <alpha-value> ...)` so opacity modifiers like `bg-accent/60` compile; a plain `var(--x)` token would silently drop them. Hop counts in the UI count only redirect mechanisms (`redirectCount` in `src/lib/format.ts`, mirroring `REDIRECT_MECHANISMS`). The vocabulary is "ritual/abyss": the screen is the "Observatory", a scan is a "probe" in every label and message, the chain is the "Descent" (each node a depth), and form errors open with a phrase in the voice ("The gate is sealed.") followed by the API's real reason. Data labels and verdicts (Benign / Watch / Suspicious / Malicious) stay literal. Keys: `/` focuses the URL prompt (`#probe-target`), j / k move through the probe list. The mark (`Mark.tsx`, `public/favicon.svg`) is the Pnakotic sigil: a point-down pentagon holding a redirect path from a hollow origin node to a solid landing node. The root `SKILL.md` is a vendored copy of the `design-taste-frontend` skill used for that redesign, not project documentation.
