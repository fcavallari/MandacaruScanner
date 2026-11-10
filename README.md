# Pnakotic

Pnakotic follows a URL to see where it really goes. It opens the URL in headless Chromium, records every redirect on the way, checks the landing page for redirect and obfuscation tricks, and gives the result a malvertising risk score from 0 to 1, with a screenshot of where the browser ended up.

It has a second mode for site owners, the [site survey](#site-survey): type a domain and Pnakotic loads a handful of its pages as several kinds of visitor and reports where on the site any compromise lives, with the URL and a code snippet.

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

The stack runs PostgreSQL, Redis, the API (which applies Alembic migrations on start), two scan workers, one site-check worker (`site-worker`) and the dashboard. The database credentials in `docker-compose.yml` are development defaults; change them before exposing the stack anywhere.

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

or check a whole site:

```bash
curl -s -X POST localhost:8000/site-scan -H 'content-type: application/json' -d '{"site": "example.com"}'
```

## How a scan works

1. `POST /scan` checks the URL and creates a job in `queued`. It rejects any host that resolves to a private, loopback, link-local or other non-public address.
2. A worker picks the job up, sets it to `running`, and opens the URL in Chromium with the chosen browser profile.
3. Every main-frame redirect is recorded as a hop: HTTP 3xx responses, and client-side navigations the browser reports through CDP (`window.location` assignments as `js_location`, meta refresh as `meta_refresh`, form submissions and anchor clicks as informational `client_navigation`). Redirects on images, scripts and iframes are ignored, and scanning stops after 10 redirects (a likely loop).
4. Popups and new tabs are blocked, but each attempt is recorded as a `popup_open` hop with its destination. Nothing is loaded.
5. The page is loaded with a bounded settle period, then the HTML is checked for redirect code that did not fire (`meta_refresh_code`, `js_location_code`), `atob` / `String.fromCharCode` obfuscation, long base64 payloads and ClickFix lure text ("press Win+R … Ctrl+V") (input capped at 2 MB). A full-page screenshot is saved. A slow subresource that keeps the page from settling no longer skips the analysis or the screenshot.
6. While the page runs, hooks record what it tries to do to the visitor (`page_behavior` hops): clipboard writes (flagged when the text is a shell command, the ClickFix pattern), downloads it starts on its own (cancelled, never kept), alert/confirm/prompt dialogs, fullscreen and keyboard-lock requests, `beforeunload` handlers, `pushState` floods and notification-permission prompts. Events after the click probe (next step) carry `trigger: click`; before it, the page acted on its own. Popups are recorded by the browser itself (`popup_open`, above), not by a page hook.
7. After the landing is captured, the scan clicks once on an empty part of the page (not a link or control) and waits 1.5 s. A popup that opens then is recorded with `trigger: click` (a popunder). If the tab navigates away, that is a `click_hijack` hop. Neither changes the recorded landing.
8. If YARA rules are configured, the rendered HTML, up to 10 subframe documents and the bodies of up to 60 scripts the page loaded are matched against them (`yara_match` hops; see [YARA rules](#yara-rules)). Code the page builds at runtime (`eval`, `new Function`, a script inserted by script) is captured too, up to 20 pieces of 200 000 characters, and matched the same way as a script; with or without rules, each piece is also checked for obfuscator.io markers. With or without rules, scripts loaded from another site are checked for obfuscator.io markers (in the loader and in the loaded body), and a cross-site script whose host answered with Cloudflare's "Suspected Malware" page is recorded; Chromium drops such a response before any event, so that URL is fetched once more through the same egress proxy to read the refusal.
9. Unless the request turns it off, the URL is also loaded in every other browser profile, each in its own context, in parallel. Where each profile landed is compared (see [Scoring](#scoring)).
10. The result is scored and stored, and the job becomes `completed`.

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

Malvertising often fires only for some visitors, so by default every scan loads the URL in all six profiles (`compare_profiles`, on by default). The requested profile's chain is the one shown and stored as the job's hops; the others are summarized in `variants`, with their screenshots under `profiles/<profile>/`. All profiles leave from the same IP, so this catches user-agent, viewport and referrer cloaking, not IP or geo cloaking.

Malvertising often only fires for some visitors, so scanning one URL under several profiles is useful. Chrome user agents carry the real version of the browser doing the scan, and each profile's client hints (`sec-ch-ua*`) match it, so no request names `HeadlessChrome`. The iOS profile sends an empty `sec-ch-ua`, where real Safari sends none. `POST /scan` rejects an unknown profile name with `422`.

### Scoring

**Decisive indicators** settle the verdict alone: the score becomes 1.0 and they lead the findings (and are listed in `decisive`):

- the page wrote a shell command to the clipboard (`powershell`, `mshta`, `cmd /c`, `curl … | sh`, …): ClickFix
- a download of an executable, script, installer, app package or disk image that the page started (on load, or after the click probe on an empty spot)
- two or more browser-lock behaviors together: fullscreen, keyboard lock, `beforeunload` handler, `pushState` flood, 3+ dialogs (the tech-support-scam lock)
- a production YARA rule of severity 4 or 5 matched the page, a frame or a script
- cloaking: profiles landed on different sites and at least one profile's own page scored Suspicious (≥ 0.4) or worse

Everything else adds up, capped at 1.0. With profiles compared, the job's score is the worst profile's score plus the cloaking weight:

| Signal | Weight |
|--------|--------|
| Lands on a raw IP address | 0.5 |
| Observed JS redirect (`location` assignment / `replace()` / `assign()` that fired) to another registrable domain; same-site navigations, including a page reloading itself, are not scored | 0.4 |
| JS obfuscation helpers (`atob`, `String.fromCharCode`), counted once, only together with a cross-site redirect, a brand-name hostname or a credential form | 0.4 |
| Brand name in the hostname that is not the brand's own domain (`zoom` in `us05web-zoom-...pages.dev`), counted once; exempt when the scan lands on the brand's own domain, which makes the hostname the brand's redirector (`googleplay.com` → `play.google.com`) | 0.4 |
| Credential form: a password input on a page that names a brand (title or hostname) it does not belong to | 0.4 |
| Click hijack: the click probe hit no link, yet the page went to another site, counted once | 0.4 |
| Download started by the page, on load or after the click probe (not an executable, e.g. an archive) | 0.4 |
| YARA: exploratory rule of severity 4–5, or production rule of severity 3, once | 0.4 |
| A script the page loads from another site was refused by its CDN as suspected malware (Cloudflare's interstitial in the script's place), once | 0.4 |
| The page's own code (inline, or a file on its own domain) loads a script from another site and either the loader or the loaded script is obfuscator.io-style code, once; a third party's loader (a tag manager) does not count | 0.4 |
| Profiles land on different sites (cloaking), none of them suspicious | 0.35 |
| Popup or new tab to another site (on load or on the click probe), counted once; same-site popups are not scored | 0.3 |
| Suspicious TLD (`.xyz`, `.top`, `.icu`, `.gq`, `.tk`, `.ml`, `.sbs`, `.click`, ... see `scorer.py`) | 0.3 |
| ClickFix lure text (Win+R and Ctrl+V instructions on one page) | 0.3 |
| Observed meta refresh to another registrable domain (a refresh without `url=` is a reload timer and is ignored) | 0.25 |
| More than 5 redirects | 0.2 |
| Redirected to a different registrable domain than the one submitted (unless it is a high-value domain) | 0.2 |
| Lands on a high-value brand domain (Google, X/Twitter, Apple, Microsoft) after a redirect | 0.2 |
| Page title that leads with a brand name (first three words) on a host that is not the brand's, unless a credential form already fired | 0.2 |
| Notification-permission prompt without a click (after the click probe it is reported, not weighted) | 0.2 |
| JS `location` code present in the page but it did not fire, counted once | 0.15 |
| Hosted on a free or disposable platform (`pages.dev`, `workers.dev`, `netlify.app`, `github.io`, ...) | 0.15 |
| Abuse-prone TLD (`.pro`, `.online`, `.shop`, `.site`, `.store`, `.live`, `.fun`, `.work`, `.website`, `.space`) | 0.15 |
| Clipboard write, on load or after the click probe (not a command) | 0.15 |
| Each browser-lock behavior on its own, except a lone `beforeunload` handler (0) | 0.15 |
| YARA: any other match, once | 0.15 |
| Meta refresh tag present in the page but it did not fire, counted once | 0.1 |
| A JavaScript dialog | 0.1 |
| JS obfuscation helpers with no cross-site redirect and no brand signal, counted once (replaces the 0.4 row) | 0.1 |

A result counts as a redirect chain only if at least one real redirect was observed (HTTP 3xx, meta refresh or JS location). Redirect code that did not fire, obfuscation and base64 findings are reported but don't make a chain on their own. Phishing pages usually don't redirect, so the brand, hosting and TLD rules work from the hostname and from the page itself (title, password inputs). Two findings are reported without a weight: navigation to an unreachable host, and a landing document that is not HTML. Brand tokens of six or more letters match inside a hostname label (`googleplay`); shorter ones only as a whole label (`pineapple.com` is not Apple). Base64 inside `data:` URIs is not reported as a payload. The brand, throwaway-hosting and TLD lists are module constants in `src/intelligence/scorer.py`. The weights are hand-tuned heuristics, not a trained model.

## Site survey

The URL probe above follows one URL. The site survey is for an owner who thinks their site has been hacked: they type a domain, wait about a minute, and get a report that says where the compromise is (the page or script URL, and the code around the match). When something is found, the report links to a cleanup service (`CLEANUP_URL`, below). The dashboard's form has a **Site survey** tab (the default) and a **URL probe** tab.

Every page is loaded in a real browser, in a fresh context (no cookies or storage carry over), as several kinds of visitor. Malware that only shows itself to some visitors, or only after its JavaScript runs, is caught by rendering rather than by fetching raw HTML once. The single-URL probe is unchanged.

### How a site survey works

1. `POST /site-scan` normalises the input to `https://<host>[:port]/` (any path, query and fragment are dropped), rejects a non-public host, creates a job of kind `site` in `queued`, and puts it on the `site` queue. One Celery task (`pnakotic.site_scan`) does the whole check with one browser and one egress proxy, under the same SSRF guard as the URL probe.
2. **Homepage.** The homepage is loaded in four profiles at once: `default`, `mobile-ios`, `googlebot` and `search-clicker`. If the `default` load fails with a network-level error (`net::ERR_…`) over https, all four are redone once over http and the report notes "Checked over http".
3. **The site is one host.** It is the host that was entered. If the `default` homepage load is redirected to another host on the same registrable domain (`www.example.com` → `example.com`), that host becomes the site and the report says so. Domains are compared with the public suffix list bundled with `tldextract` (never fetched at run time), so `a.github.io` and `b.github.io` are different sites. If the homepage lands on a different domain instead, that is a Suspicious finding on `/` ("Your homepage sends desktop visitors to …"), and the site stays the entered host.
4. **Pages.** Up to 5 internal pages are picked from the rendered links of the first homepage load that stayed on the site (`default`, then `mobile-ios`, `googlebot`, `search-clicker`). Only links on the site host (or its www/apex twin) that pass the egress check are kept. `wp-admin`, `wp-login.php`, `xmlrpc.php`, `wp-json`, feeds, logout and add-to-cart style URLs, `?replytocom=` and non-page files (images, PDF, archives, media, `.xml`, `.txt`, …) are dropped. One slot goes to each kind the site has, in this order: a post (a `/YYYY/MM/` path, `?p=N`, or the deepest path), a page (`/about/`), an archive (`/category/`, `/tag/`, `/author/`, `/page/2/`) and a contact page; the rest are filled in document order, preferring a first path segment not used yet. A homepage that left the site is never crawled: if no homepage load stayed on the site, only the 404 probe runs and the report says why.
5. **404 probe.** `/pnakotic-<12 random hex>/` is loaded too, since hacks hide in 404 templates. The report shows it as "Your 'page not found' page" (`probe: true` on its page and its blocks).
6. **Other pages.** Each picked page and the probe are loaded as `default`, `mobile-ios` and `googlebot`: up to 22 loads in all with the homepage. Screenshots are full-page for the homepage's `default` load and viewport-only for the rest. Each load goes through the same per-load pipeline as a URL probe (redirects, page behaviours, click probe, static analysis, YARA).
7. Each load is scored (site-mode scoring, below), each page's profiles are folded together for cloaking, and the findings are rolled up into the report and a verdict.

### Time budget

| Limit | Value |
|-------|-------|
| Site budget, from the start of the homepage loads | 150 s |
| Browser contexts at once | 6 |
| Extra time for loads still running at the deadline, then they are cancelled | 10 s |
| Celery soft / hard limit for the task | 240 s / 300 s |
| Per load | the URL probe's caps (30 s navigation, 3 s settle, 1.5 s click settle, 20 s YARA) |

Once the budget is spent no new load starts, and every load that did not run is listed as not checked.

### What a load can be

| State | Meaning |
|-------|---------|
| `checked` | The page loaded (any HTTP status) and its DOM was scanned. A 404 on the probe is the expected result. |
| `partial` | The navigation timed out but a DOM existed and was scanned. Findings count; the report says the page did not finish loading. |
| `not_checked` | Nothing usable was scanned, with a reason: `load_failed` (network error or Chrome's error page), `timeout` (no usable DOM), `budget` (never started, or cancelled) or `challenge` (a bot check). |

A bot-check page is the CDN's, not the site's, so its content is never scanned as if it were the site. A load counts as a challenge when the title is a known challenge title ("Just a moment…", "Attention Required! | Cloudflare"), or the HTML contains `cf-chl`, `cf_chl_opt`, `ddos-guard` or `_Incapsula_Resource`, at any status. `challenge-platform` and `captcha` count only on a 403 or 503 whose HTML is under 20 kB, because Cloudflare adds `challenge-platform` scripts to ordinary pages and plenty of sites mention a captcha.

### What counts as a finding

| Finding | Severity | Where it is shown |
|---------|----------|-------------------|
| YARA match with a production rule of severity 4 or 5 | Compromised | The page URL for the served HTML, the rendered DOM and frames; the script URL (with "loaded by") for a script file |
| Any other YARA match | Suspicious | As above |
| Page behaviour that is decisive in the URL probe: shell command on the clipboard, executable download, two or more browser-lock behaviours | Compromised | The page URL |
| Cloaking that is decisive (profiles landed on different sites and one scores 0.4 or more in site mode) | Compromised | The page URL, with the visitors who were steered |
| Cloaking that is not decisive, when the page's combined score is still 0.4 or more (for example only phones get a 302 to another domain) | Suspicious | The page URL: "Some visitors are sent to a different website", with those visitors and where they land |
| Homepage lands on another domain | Suspicious (Compromised if decisive cloaking) | `/` |
| Obfuscated injector: an inline block or same-site script with obfuscator.io markers that adds a script from another site | Suspicious | The page URL, with the injecting snippet and the loaded URL |
| Obfuscated script from another site, added by an inline block or same-site script that is itself plain (the loaded body carries the obfuscator.io markers) | Suspicious | The page URL, with the loaded URL |
| A script from another site that its CDN refused as suspected malware (Cloudflare's interstitial in the script's place) | Suspicious | The script URL, with "loaded by" naming the page and the code that added it |
| Code the page builds and runs at runtime (`eval`, `new Function`, an inserted inline script) that matches a YARA rule | Compromised or Suspicious, as for any YARA match | The page URL, "Built and run by code on this page while it loaded", naming the code that built it |
| Code the page builds and runs at runtime that carries obfuscator.io markers and matches no rule | Suspicious | The page URL: "Code on this page builds and runs hidden, scrambled code", with the snippet |
| A page whose own site-mode score is 0.4 or more, with no compromised finding of its own | Suspicious | The page URL, with the scoring lines under Details |

- **Served HTML and rendered DOM.** The HTML the server sent (`served`) is matched as well as the rendered DOM. A match in the served HTML points at the templates or database; a match only in the rendered DOM was added by a script while the page loaded.
- **Snippets.** The window around the first match is up to 240 bytes before and after it, 600 bytes in all, decoded as UTF-8 with replacement and NULs removed, with the match offsets and the 1-based line number. Only the window is stored, never the page or script.
- **Merging.** The same rule with the same snippet on several pages is one finding listing every page, so a footer injection on every page is one block. Each finding says which visitors saw it (all profiles, or for example only Googlebot).
- **Observed script injection.** Script requests started by a script are recorded from the browser's network events (200 per load, 50 injections). A requested script is tied to an inline block only when the initiator's line and column fall inside the block in the served HTML, or the block's text contains the requested URL. A tied YARA finding gains "this code loaded …", and a YARA-matched script gains "loaded by". An injection with no YARA match and no obfuscator markers is never a finding: Tag Manager, Analytics and ad networks do the same on clean sites. The markers are `string_array_rotation` (a function returning a string array plus a `push(shift())` rotation) and `hex_identifier_density` (30 or more `_0x…` identifiers, at least one per 200 characters), over the first 200 000 characters.
- **Owner wording.** A YARA finding shows the rule's `description` meta as written; anything else, or a rule without one, gets a generic plain line ("Code matching a known malware pattern", "Some visitors are sent to a different website", …).
- **Off-site landings.** When a load ends on another site, the code matched there belongs to that site: it is shown at the landing URL (or its script URL), marked as being on the website visitors were sent to, with the owner's pages that sent them. That page's injections and scripts are not reported as the site's.
- **Size.** A report holds at most 50 blocks, 20 findings per block, 200 findings in all (compromised ones kept first) and 20 pages per finding; what is left out is counted (`blocks_more`, each block's `findings_more`, `findings_more_total`). When YARA's per-load budget ran out the report notes that some content was too large to check in full.

### Site-mode scoring

The same `PnakoticScorer.score()` is used, with its weights unchanged. When a load lands on the owner's own site (the site host or its www twin), these identity signals are skipped, because they describe an unknown landing site, not a site the owner already runs:

| Skipped for an on-site landing | Why |
|--------------------------------|-----|
| `suspicious_tld`, `watch_tld` | A clean `.xyz` site is not suspect |
| `throwaway_hosting` | A site on `pages.dev` or `github.io` is not suspect |
| `brand_in_hostname`, `brand_in_title` | An owner's own name may contain a brand name |
| `js_obfuscated_only` | Most big bundles use `atob` |
| `ip_landing` | An owner site that was entered as an IP |

A brand-like on-site host also no longer lifts `atob` / `String.fromCharCode` to the 0.4 weight. All of these still apply to an off-site landing, where they describe where visitors were sent, and the URL probe never skips any. The site-mode score is also the one `combine()` uses for "cloaking is decisive when a profile's page scores 0.4 or more".

### Verdicts

| Verdict | When |
|---------|------|
| Compromised | Any finding is compromised, whatever else failed |
| Suspicious | No compromised finding, at least one suspicious one |
| Couldn't check | The homepage's `default` load was not checked (unreachable, bot check, out of time); the report gives the reason. Never Clean |
| Partly checked | No findings, but any homepage load was not checked, or more than half of the other loads were: "No malware found, but N of M checks couldn't run". Never Clean |
| Clean | Otherwise. Loads that were not checked are still listed. With no YARA rules loaded it reads "Clean (no malware rules loaded)" |

For Compromised and Suspicious the report links to `CLEANUP_URL` right under the verdict, with firmer wording for Compromised.

### The report

The report is grouped by where the code lives: finding blocks (one per page URL or script URL, each finding with its snippet, the match highlighted, the line number, how it was found, who saw it, the pages it was on and a collapsed Details), then **External scripts**, then **What was checked**. For a Clean site, What was checked comes first. The report body is plain language, not the dashboard's ritual vocabulary.

- **External scripts.** Every script requested from a host other than the site host, grouped by host, with the pages and profiles that loaded it and whether it is in the page's HTML or added by a script (and by which). Other subdomains of the site's own domain are listed and marked "your domain". It is informational and never changes the verdict. At most 100 hosts and 500 URLs are listed; the rest are counted.
- **What was checked.** Each page with its loads (profile, state, reason, landing, score, screenshot), clean pages folded into "N other pages clean", the number of YARA rule files, how many scripts and frames were scanned, and how many checks could not run.

The report is stored in the result's `metadata_json` (`site`) with no page or script bodies. Screenshots are under `pages/<n>/<profile>/landing_*.png`, where `<n>` is the page's index in the report (0 is the homepage).

### Exposure

The site survey is for internal use. It has no rate limit and no per-site cap. The `site-worker` service runs one worker at concurrency 1, so one site survey runs at a time and the rest wait in the `site` queue; the URL probe's workers (`-Q celery`) do not take that queue. Add a rate limit (per IP and per site) and a cap on concurrent checks before exposing it publicly.

## API

| Method & path | Description |
|---------------|-------------|
| `POST /scan` | Body `{"url": "https://…", "profile": "default", "compare_profiles": true}`. A URL with no scheme is probed as `https://`. Returns `201` with `task_id`. `400` for a non-public host, `422` for a scheme other than http(s) or an unknown profile, `503` if the queue is unavailable. |
| `POST /site-scan` | Body `{"site": "example.com"}`, a bare host or a URL. Returns `201` with `task_id`. `400` for a non-public host, `422` for input that is empty, not http(s), has credentials in it or has a bad port, `503` if the queue is unavailable. |
| `GET /tasks?limit=20` | Most recent jobs (newest first, `limit` 1–100), with results where available. Each job has a `kind`: `url` or `site`. |
| `GET /tasks/{id}/status` | `queued`, `running`, `completed` or `failed`, plus `error`. |
| `GET /tasks/{id}/results` | Final URL, score, hops, findings and artifact list. `404` until the scan has a result. |
| `GET /tasks/{id}/artifacts/{path}` | A stored artifact, e.g. `screenshots/landing_20261104_101500.png`. |
| `GET /health` | Liveness check. |

`/tasks` and `/tasks/{id}/results` return the same `result` object: `final_url`, `malicious_score`, `is_redirect_chain_detected`, `hops`, `artifacts`, `findings`, `decisive`, `variants` (each profile's landing, redirect count and own score, the requested one first), `cloaking` (landing per profile, or `null`), `yara` (rules loaded and what was scanned, or `null` when YARA is off) and `raw_error`. It also has `kind` (`url` or `site`; results stored before the site survey existed read as `url`). For a `site` job `final_url` is the homepage's `default` landing, `malicious_score` is the worst score of any load, `hops` is empty, and two more fields appear: `site` (the report: `site`, `entered`, `redirected_from`, `verdict`, `blocks`, `blocks_more`, `findings_more_total`, `external_scripts`, `checked`, `blocked_hosts`, `notes`) and `cleanup_url`.

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
| `CLEANUP_URL` | `https://elderward.space.fast` | API: the cleanup link in a Compromised or Suspicious site report. `docker-compose.yml` passes it to the `api` service from your shell or `.env` |

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
celery -A pnakotic.src.workers.celery_app worker -Q celery,site --loglevel=info
```

`-Q celery,site` makes this one worker take both URL probes (the default queue, `celery`) and site surveys (routed to `site`). Without `site` in `-Q`, a site survey stays queued. To mirror Docker instead, run one worker with `-Q celery` and a second with `-Q site --concurrency 1`.

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

Most tests need nothing installed beyond the Python requirements. The API and worker tests use a temporary SQLite database and a fake engine. The site-check logic that needs no browser (identity, page picking, snippets, findings, report) is tested without one. Browser tests use Chromium against a local server and are skipped if Chromium isn't installed. YARA tests write synthetic rules to a temporary folder (no real rules are needed or committed) and are skipped without yara-python. Two of them scan the real `google.com` and need network access.

Run a single test:

```bash
python3 -m pytest tests/test_engine.py::test_redirect_to_internal_host_is_blocked
```

## Project layout

```
src/api/            FastAPI app: endpoints, sweeper
src/workers/        Celery app, the scan task and the site-scan task
src/scanner/        Playwright engine, browser profiles, static analysis,
                    page-behavior hooks (behavior.py), YARA (yara_scan.py),
                    egress guard (netguard.py), artifact storage;
                    site survey: site_engine.py (orchestrator), site_identity.py,
                    page_picker.py, snippets.py, script_trace.py, obfuscation.py,
                    challenge.py, site_findings.py, site_report.py
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
