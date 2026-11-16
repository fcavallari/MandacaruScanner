# Mandacaru Rebrand Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Pnakotic's cosmic-horror ritual identity with Mandacaru's "Cosmic Sertão" identity across the dashboard, the API's user-facing strings, outside-visible identifiers, the woo testbed and the living docs, without touching the Python package name.

**Architecture:** A re-skin in place. The dashboard layout, grid, hierarchy and type scale stay. Colour tokens change in `index.css` / `tailwind.config.js`, with new `*-ink` / `*-fill` twins so text stays AA. The mark, wordmark, copy and the waiting scene are swapped component by component. Backend changes are string-level: API title, handler names, 404 messages, cleanup URL default, the `/mandacaru-<hex>/` probe path and two CDP strings. The woo testbed's names are renamed.

**Tech Stack:** React 18 + Vite + Tailwind (frontend, `npm run build` is the only check), FastAPI + Celery + pytest (backend), Docker Compose (stack, testbed).

**Spec:** `docs/superpowers/specs/2026-11-13-mandacaru-rebrand-design.md` (git-ignored; read it from the main checkout). Approved mockups: `.superpowers/brainstorm/23610-1794580006/content/{mark,palette,scene,wordmark}.html`.

## Global Constraints

- Product name in prose and UI: **Mandacaru**. Screen noun: **Field Station**. Sibling cleanup product: **Facheiro**.
- Cleanup URL default, verbatim: `https://facheiro.space.fast/`
- 404 probe path: `/mandacaru-<12 hex>/`
- Colours: charcoal `#171512`, rust `#A94B2A`, dry sand `#C4A46A`, mandacaru green `#65734B`, bone `#D8D0BD`, dried blood `#733B43`. Text twins: rust `#D2724F`, green `#8E9C70`, blood `#C46A72`. Button fill `#93401F` with bone text.
- WCAG AA: text ≥ 4.5:1. Meaning-carrying graphics ≥ 3:1: verdict and status dots, bars, the gauge fill, focus and selection lines, chain nodes and spine. Card borders, row rules and control outlines keep the current subtle data-terminal level; the dim empty-scene art and unlit traces are decorative and exempt. `#733B43` only ever as a block behind bone text.
- Colour for status and data (not just verdicts):
  - running status: muted text with a rust dot
  - chain landing node and spine: accent
  - high-value-landing marker and a cloaking variant's differing landing: warning (sand)
  - benign gauge fill: positive-fill
  - Failed: a neutral pill with the word "Failed"; the dried-blood block is only for Compromised and Malicious
  - error text, the ErrorNote dot and the form error border and dot: negative (`#C46A72`)
- Chain node label: "stop N" (not "hop N", which would contradict the "N redirects" and "N hops" counts).
- Fonts: Public Sans (text), IBM Plex Mono (URLs, IDs, numbers), Alfa Slab One with a carved-edge SVG filter for the wordmark only. Chakra Petch removed.
- Verdicts, data labels and "Maliciousness" stay literal. The site report body stays plain language. "Probe" stays the word for a scan; "specimen" appears only in the waiting scene's status line.
- Do **not** rename (left for the later package pass "B"): the `pnakotic` package and directory, `PnakoticEngine` / `PnakoticScorer`, Celery app and task names (`pnakotic.scan`, `pnakotic.site_scan`), Dockerfile user/paths, `alembic -c pnakotic/alembic.ini`, the Postgres user/db/password, `PNAKOTIC_TEST_*` markers, the woo testbed's served skimmer markers (`pnakotic-test-skimmer` script id and its lookup in `spike/skimmer_path.py`, "PNAKOTIC TEST SKIMMER" banners, the `[PNAKOTIC-TEST-SKIMMER]` console tag and the `PNAKOTIC-TEST-SKIMMER` note field), `.claude/launch.json`.
- Don't edit historical docs: `docs/superpowers/plans/*` (other than this file), `docs/superpowers/specs/*` (other than the rebrand spec), `docs/*-findings.md`, `docs/field-test-*`, `docs/forum-gap-analysis.md`, `SECURITY_REVIEW.md`, root `SKILL.md`. Leave the untracked `.taste-skill/*-legibility/` folders alone.
- No sound.

## Review Focus

1. **Old site reports in the DB.** A site survey completed before the rebrand still shows "Your 'page not found' page" (its stored `probe: true`), and its cleanup link now says Facheiro → pinned in Task 9's browser check.
2. **Dashboard over plain http (no `crypto.subtle`).** The waiting scene still draws, using the FNV fallback digests, with no console error → pinned in Task 7.
3. **Phone width (375px).** The lockup wraps without overflow. Scene tags, the mark and the status lines don't overlap or clip. A long hostname truncates in the status line → pinned in Tasks 5 and 7.
4. **Reduced motion.** The scene draws one still frame, and a queued→running change redraws that frame → pinned in Task 7.
5. **Google Fonts blocked.** The wordmark falls back to a slab/serif stack (`"Alfa Slab One", Rockwell, "Roboto Slab", Georgia, serif`), stays legible with the carved filter, and the header doesn't jump → pinned in Task 5.

---

### Task 0: Branch

- [ ] **Step 1:** From the current `ui-legibility` HEAD (it isn't merged to `main` yet, and the rebrand touches the same files), run `git switch -c rebrand-mandacaru`. Expected: on `rebrand-mandacaru`, with the untracked `.taste-skill/*-legibility/` folders still untracked.

### Task 1: Backend outside-visible strings

**Files:**
- Modify: `src/api/main.py` (FastAPI title :151, cleanup default :176, `start_ritual` :209, 404s :257 :269, `get_ritual_results` :264)
- Modify: `src/scanner/page_picker.py:214-216` (`probe_url`), `src/scanner/site_report.py:244-250` (probe detection)
- Modify: `src/scanner/engine.py:231` (world name), `:501` (warm-up expression)
- Modify: `docker-compose.yml:35` (`CLEANUP_URL` default)
- Test: `tests/test_api.py`, `tests/test_page_picker.py:38`, `tests/test_site_engine.py:21,24,92`, `tests/test_site_report.py:323,395-396,472`

**Interfaces:**
- Produces: `probe_url(site, token) -> "…/mandacaru-<token>/"`. The site report recognises the probe as the highest-index page whose path starts with `/mandacaru-`. `serialize_result` puts `cleanup_url` (default `https://facheiro.space.fast/`) on site results. API handler functions are named `start_scan` and `get_scan_results`. Routes don't change.

- [ ] **Step 1: Update the tests to the new values (they will fail)**
  - `test_api.py:428`: `assert main.serialize_result(row)["cleanup_url"] == "https://facheiro.space.fast/"`
  - Add `test_api.py::test_api_title_and_404_messages`: `main.app.title == "Mandacaru API"`. `GET /tasks/<unknown-id>` → 404 with `detail == "Scan not found"`. `GET /tasks/<known-but-unfinished-id>/results` → 404 with `detail == "No results for this scan yet"`. First read the handlers at `main.py:250-270` to see which route raises which message, and assert on those routes with the existing `db` fixture.
  - `test_page_picker.py:38`: expect `"https://example.com:8443/mandacaru-a1b2c3d4e5f6/"`.
  - `test_site_engine.py` and `test_site_report.py`: replace `/pnakotic-` with `/mandacaru-` in the expectations and fixtures. That includes the owner page `https://s.com/mandacaru-news/`, which keeps its role as "an owner page with the same prefix".
- [ ] **Step 2:** Run `python3 -m pytest tests/test_api.py tests/test_page_picker.py tests/test_site_report.py tests/test_site_engine.py -q`. Expected: the changed assertions FAIL.
- [ ] **Step 3: Implement.** Change the strings listed under Files. Docstrings there say `/mandacaru-<token>/`. The warm-up becomes `"'mandacaru' + '-warm-up'"` and the world name `"mandacaru-charset"`. `docker-compose.yml` becomes `CLEANUP_URL: ${CLEANUP_URL:-https://facheiro.space.fast/}`.
- [ ] **Step 4:** Run `python3 -m pytest -q`. Expected: all pass. Browser tests may skip without Chromium; note any skips.
- [ ] **Step 5:** Run `git grep -n -i "pnakotic-\|elderward\|ritual" -- src tests docker-compose.yml`. Expected: no hits.
- [ ] **Step 6: Commit** `rebrand: Mandacaru API strings, Facheiro cleanup URL, /mandacaru- probe path`.

### Task 2: Woo testbed names

**Files:**
- Rename: `tools/woo-testbed/plugins/pnakotic-test-gateway/` → `mandacaru-test-gateway/`, and its `pnakotic-test-gateway.php` → `mandacaru-test-gateway.php`
- Modify: everything under `tools/woo-testbed/` that `git grep -i pnakotic -- tools` lists: README, `docker-compose.yml`, `setup.sh`, `toggle.sh`, `check_checkouts.py`, `mu-plugins/*.php`, `plugins/**`, `spike/*.py`. Rename `mu-plugins/pnakotic-offline.php` (the name the README cites) if it exists, and otherwise wherever `setup.sh` writes it.

**Interfaces:**
- Produces:
  - compose project `mandacaru-woo-testbed`
  - gateway id `mandacaru_test`, plugin slug `mandacaru-test-gateway`
  - options `mandacaru_test_skimmer` and `mandacaru_test_skimmer_url`
  - env `MANDACARU_COLLECTOR_URL` and `MANDACARU_BLOCK_EXTERNAL`
  - admin password default `mandacaru-testbed`
  - PHP identifiers: every `pnakotic`/`Pnakotic`/`PNAKOTIC` becomes `mandacaru`/`Mandacaru`/`MANDACARU`, case preserved, **except the served skimmer markers**

- [ ] **Step 1:** Rename with `git mv` and replace in content, preserving case.
  - Lines that mention the *scanner* product in prose ("a Pnakotic worker") become "a Mandacaru worker".
  - **Keep unchanged** the test markers `mu-plugins/test-skimmer.php` serves into the store page: the `pnakotic-test-skimmer` script id (and its lookup in `spike/skimmer_path.py`), the "PNAKOTIC TEST SKIMMER" banner comments, the `[PNAKOTIC-TEST-SKIMMER]` console tag and the `note: 'PNAKOTIC-TEST-SKIMMER'` field. Private YARA rules may key on them; they move with `PNAKOTIC_TEST_*` in the later package pass.
- [ ] **Step 2:** Add one README note under the setup section: "Renamed from `pnakotic-woo-testbed`: run `docker compose -p pnakotic-woo-testbed down -v` once to drop the old project, then `./setup.sh`."
- [ ] **Step 3: Verify the scripts parse**
  - Run `bash -n tools/woo-testbed/setup.sh && bash -n tools/woo-testbed/toggle.sh`
  - Run `python3 -m py_compile tools/woo-testbed/check_checkouts.py tools/woo-testbed/spike/*.py`
  - Run `php -l` on each PHP file, if `php` is installed; otherwise run it via `docker run --rm -v "$PWD/tools/woo-testbed":/w php:8.2-cli php -l /w/<file>`

  Expected: no syntax errors.
- [ ] **Step 4:** Run `git grep -n -i pnakotic -- tools`. Expected: only the README's rename note and the kept skimmer markers listed in Step 1.
- [ ] **Step 5:** Ask the user before running the testbed itself (`setup.sh` creates containers). If they say yes: run `./setup.sh`, then `python3 check_checkouts.py`. Expected: both checkouts render the `mandacaru_test` card inputs.
- [ ] **Step 6: Commit** `rebrand: woo testbed names (mandacaru-woo-testbed, mandacaru_test gateway)`.

### Task 3: Colour tokens, fonts, grain

**Files:**
- Modify: `frontend/src/index.css` (`:root` tokens, header comment, scrollbar comment, body grain), `frontend/tailwind.config.js` (colours and font families, comments), `frontend/index.html` (title, font link), `frontend/package.json` and `frontend/package-lock.json` (`"name"`)

**Interfaces:**
- Produces Tailwind colour tokens, all through the existing `a("--x")` wrapper:

  | Token | Value | Use |
  |---|---|---|
  | `ground` | `#171512` | |
  | `surface` | `#12100d` | |
  | `raised` | `#1f1c18` | |
  | `active` | about `#1a1714` | |
  | `line` (`--border`) | `#332e27` | |
  | `rule` | `#24201b` | |
  | `control` | `#4a443a` | |
  | `ink` (`--text`) | `#D8D0BD` | |
  | `muted` | `#b3aa96` | |
  | `faint` | value chosen in Step 2 | |
  | `accent` | `#A94B2A` | lines, fills, focus, icons |
  | `accent-ink` | `#D2724F` | rust text |
  | `button` | `#93401F` | |
  | `positive` | `#8E9C70` | text and marks |
  | `positive-fill` | `#65734B` | bars |
  | `negative` | `#C46A72` | text, marks, bars |
  | `negative-fill` | `#733B43` | blocks behind bone text only |
  | `warning` | `#C4A46A` | |

  CSS vars `--pill-{positive,negative,warning,neutral}-bg` and `--pill-neutral-ink` are retinted. `--grid` is about `#2a2621`. Font families: `display: ['"Alfa Slab One"', 'Rockwell', '"Roboto Slab"', 'Georgia', 'serif']`; `sans` and `mono` are unchanged.

- [ ] **Step 1: Write the tokens.**
  - `--positive` no longer equals `--accent`.
  - `::selection` is a rust tint.
  - The header comment describes the Cosmic Sertão face; it must not mention abyss, phosphor or the deep.
  - The body gets the grain: a `background-image` holding an inline `data:image/svg+xml` `feTurbulence` noise (baseFrequency about 0.9), tinted bone at about 5–6% alpha, over `background-color: var(--ground)`. Cards are opaque, so they cover it.
- [ ] **Step 2: Check contrast.** Write a throwaway Node script in the session scratchpad that computes WCAG ratios, and assert:
  - `ink`, `muted`, `faint`, `accent-ink`, `positive`, `negative` and `warning` are ≥ 4.5 on `surface`, `ground`, `raised` and `active`
  - `muted` ≥ 8 on `surface`
  - `faint` ≥ 5.5 on `surface`
  - `ink` ≥ 4.5 on `button` and on `negative-fill`
  - `accent`, `positive-fill`, `negative` and `warning` ≥ 3 on `surface` and `raised` (graphics)
  - every pill ink ≥ 4.5 on its pill background

  `control`, `border` and `rule` stay at roughly today's subtle level. Report their ratios but don't assert them.

  Pick `faint` in `#8f8774`–`#9a917d` so it passes. Expected: every assertion prints PASS.
- [ ] **Step 3:** Update `index.html`: `<title>Mandacaru — Field Station</title>`, with the font link's `Chakra+Petch:wght@600` replaced by `Alfa+Slab+One`. Set the `package.json` name to `mandacaru-dashboard`, then run `npm install --package-lock-only` in `frontend/` so the lock's name fields follow.
- [ ] **Step 4:** Run `cd frontend && npm run build`. Expected: success. (Components still use `text-accent` as before; Task 6 audits them.)
- [ ] **Step 5: Commit** `rebrand: Cosmic Sertão colour tokens with reading twins, Alfa Slab One, grain`.

### Task 4: Mark and favicon

**Files:**
- Modify: `frontend/src/components/Mark.tsx`, `frontend/public/favicon.svg`, `frontend/src/App.tsx` (rail `aria-label`/`title`: "Mandacaru", "Field Station")

**Interfaces:**
- Produces:
  - `export default function Mark({ size = 24, className = '' }: { size?: number; className?: string })`: an `<svg viewBox="0 0 64 64">` in `currentColor`.
  - `export function MarkGlyph({ maskId }: { maskId: string })`: the 64-unit `<g>`, plus its `<mask id={maskId}>`, for use inside another SVG (the scene). `Mark` uses `MarkGlyph` with `useId()`.

- [ ] **Step 1:** Port the `cactus-a` symbol from `mark.html`. The trunk, arms, spines and baseline stay strokes in `currentColor`. The carved ribs move into a `<mask>` (white rect, ribs stroked black) applied to the trunk and arms group, so they're cut out, not painted. Docblock: the woodcut mandacaru (candelabra), with what each part is.
- [ ] **Step 2:** Write `favicon.svg`: a `#12100d` rounded square (rx 5 on a 24 viewBox, as today), with the mark in `#A94B2A`, scaled to fit and with strokes thickened so it reads at 16px. Ribs are cut with a mask. No reference to the sigil.
- [ ] **Step 3:** Run `npm run build`. Then, in the browser (Task 9's dev server), zoom on the tab favicon and the 32px rail mark. Expected: a recognisable candelabra at 16px, ribs visible as cuts at 32px and up.
- [ ] **Step 4: Commit** `rebrand: woodcut mandacaru mark and favicon`.

### Task 5: Header lockup and wordmark

**Files:**
- Modify: `frontend/src/components/Dashboard.tsx:211-222` (lockup), plus its header comments

**Interfaces:**
- Consumes: `Mark`, the Tailwind `font-display` family

- [ ] **Step 1:** The `h1` becomes `<span className="font-display …">MANDACARU</span>`, followed by `<span …>Field Station</span>` (Public Sans, muted, as "Observatory" was). The wordmark is about 30px desktop / 26px mobile, letter-spacing about 0.05em, with no `font-semibold` (Alfa Slab has one weight). It gets the carved edge: a hidden `<svg width="0" height="0">` holding `<filter id={useId()}>` with `feTurbulence` (fractalNoise, baseFrequency about 0.9, numOctaves 2, fixed seed) feeding `feDisplacementMap` (scale about 2). Apply it with `style={{ filter: \`url(#${id})\` }}` on the wordmark span only. It stays real text.
- [ ] **Step 2:** Run `npm run build`, then check in the browser at 1440px and 375px:
  - the lockup reads "MANDACARU Field Station" with the finding line under it
  - nothing overflows at 375px
  - the carved edge is visible but the letters are crisp at 1× DPR

  Then block `fonts.gstatic.com` (DevTools request blocking, or a `javascript_tool` reload with the font link removed). Expected: a slab or serif fallback that's still legible, and the header height changes by no more than a few px.
- [ ] **Step 3: Commit** `rebrand: MANDACARU · Field Station lockup with carved wordmark`.

### Task 6: Copy pass and accent audit

**Files:**
- Modify:
  - `frontend/src/components/Dashboard.tsx:85,111-113,129-136`
  - `ScanForm.tsx:114,132-147,212,243` (`SummonButton` → `InspectButton`)
  - `ScanList.tsx:203,206`
  - `SelectedScan.tsx:120,151-152,159,179`
  - `IntelPanel.tsx:66,93`
  - `KpiStrip.tsx:47`
  - `RedirectChain.tsx:157` and its top docblock
  - `SiteReport.tsx:20,673`
  - `frontend/src/lib/format.ts:222,231`
  - `frontend/src/lib/api.ts:132` (comment)
  - `DepthGauge.tsx:18` (benign fill)
  - every `text-accent` / accent usage listed in Step 2

- [ ] **Step 1: Replace the copy exactly as the spec's vocabulary table says.**
  - `The gate is sealed.` → `Can't inspect that.` (all three sites, including the http(s)-only and empty-site variants).
  - `The observatory is unreachable. No answer from ${API_BASE}.` → `No signal from the field station. No answer from ${API_BASE}.`
  - Every `… The deep is silent.` → `… No signal.`. KpiStrip: `Couldn't reach the field station. No signal.`
  - Empty title `No probes yet. The deep is quiet.` → `Nothing collected yet.`. Both subs → `Looks empty. It rarely is. Submit a site above to look closer.`
  - `format.ts`:
    - `'No probes yet. The deep is quiet.'` → `'Nothing collected yet.'`
    - `'… The deep is quiet.'` → `'No high-value landings, no failures. Quiet, for now.'`
    - `'Probes in flight — the deep has not answered yet.'` → `'Probes in the field. Nothing back yet.'`
  - `'The probe failed'` (Dashboard and SelectedScan) → `'Analysis interrupted'`.
  - Button: `Summon` / `Summoning…` → `Inspect` / `Inspecting…`.
  - `Descent` → `Trail`; `depth N` → `stop N`.
  - SiteReport: `Clean it up with Facheiro` / `If you think this is a hack, Facheiro can check and clean it`.
  - Comments in touched files that mention ritual, abyss, the deep, sigil or descent are reworded to the new identity.
- [ ] **Step 2: Accent audit.**
  - `text-accent` on **text** → `text-accent-ink`. Today that's `states.tsx:44`, `SiteReport.tsx:418,671`, `SelectedScan.tsx:24,94`, `ScanList.tsx:24` and `ProfileSplit.tsx:62`. Read each one: an icon keeps `text-accent`.
  - Lines, dots, selection insets, focus borders, highlight tints and chain nodes keep `accent`.
  - The submit button (`ScanForm.tsx:139`) becomes `bg-button text-ink`, with `hover:bg-button/85 active:bg-button/75 disabled:bg-button/60`.
  - Anything that used accent to mean **benign or good**, because positive used to equal accent, now uses positive. That's DepthGauge's benign fill → `bg-positive-fill`. Check `IntelPanel.tsx:91` and `ScanList.tsx:13`.
  - **Running status** (`ScanList.tsx:24-25`, `SelectedScan.tsx:24-25`): the text becomes `text-muted`, and the pulsing dot stays `bg-accent`.
  - **Chain landing node and live spine** (`RedirectChain.tsx:132-140,177`): stay accent.
  - **High-value landing marker** (`IntelPanel.tsx` around :31 and :100) and **a cloaking variant's differing landing** (`ProfileSplit.tsx:53,62`): use warning. The ProfileSplit selection inset can stay accent if it marks selection rather than difference; read it and decide.
  - **Failed** pill and status (`SelectedScan.tsx` around :31, `ScanList.tsx:31-32`): the neutral pill (`--pill-neutral-bg` / `--pill-neutral-ink`) with "Failed". Failed-probe error text, the `ErrorNote` dot (`states.tsx:38`) and the form error border and dot (`ScanForm.tsx:110,156,216`) stay `negative`.
  - A **Compromised or Malicious verdict pill or banner** (SiteReport `TONE.negative`, SelectedScan's `StatusMark`) becomes a `negative-fill` block with `ink` text. Smaller negative text (finding severity labels, list verdicts, scores) stays `text-negative`.
- [ ] **Step 3:** Run `cd frontend && npm run build`. Expected: success. Then run `git grep -n -i -E "abyss|the deep|ritual|sigil|summon|observatory|descent|elderward|gate is sealed|in the dark" -- frontend/src frontend/index.html`. Expected: only `ProbeRitual.tsx`, which Task 7 deletes.
- [ ] **Step 4: Commit** `rebrand: field-researcher copy, Facheiro link, accent/positive split`.

### Task 7: Waiting scene ("Strata") and empty ground

**Files:**
- Create: `frontend/src/components/FieldScene.tsx`
- Delete: `frontend/src/components/ProbeRitual.tsx`
- Modify: `frontend/src/components/SelectedScan.tsx` (import, `:156` running/queued body, `:150-153` empty body)

**Interfaces:**
- Consumes: `MarkGlyph({ maskId })` from Task 4; `TaskState`, `hostnameOf`
- Produces:
  - `export default function FieldScene({ task }: { task: TaskState })`: the queued/running body. It occupies the slot `ProbeRitual` did: `flex-1 min-h-[300px]`, bleeding to the card edges with the same negative margins.
  - `export function EmptyGround()`: the lead block's empty state, with the static, dimmed ground and the two copy lines.

- [ ] **Step 1: Move the honest-source helpers over** from `ProbeRitual.tsx`, unchanged: `probeSeeds`, `fnvHex`, `sha256Hex`, `URL_PROFILES`, `SITE_PROFILES`. Digests start as FNV and are swapped for SHA-256 when `crypto.subtle` resolves.
- [ ] **Step 2: Build the scene as an SVG** in a fixed viewBox (600×270, `preserveAspectRatio="xMidYMid slice"`), following the `scene.html` option A reference.
  - **Sky:** about 6 faint stars, positioned from digest bytes.
  - **Horizon:** a jagged polyline at y≈120, with the mark (`MarkGlyph`, about 66 units) standing on it in the left third, in `--accent`.
  - **Strata:** three jagged lines at y≈152/186/220 with cracks, with vertex jitter drawn from digest bytes.
  - **Traces:** 6 traces, with shape (hollow circle, cross, diamond, triangle, solid dot), x and depth (y 130–255) taken from successive digest bytes. Each tag is a 6-hex fragment of a digest, or a visitor-type name in clear.
  - **Motion:** CSS keyframes. The band sinks over 7s, and each trace's flash and tag `animation-delay` is `(y - 122) / 132 * 7s`. Use the token colours: band and line `--accent`, flash `--accent-ink`, settled about `#6b4a3a`, dim traces `--control`, strata `--border`, horizon `--faint`.
  - **Queued:** no band, traces unlit, the whole SVG at about 55% opacity.
  - **Reduced motion:** `@media (prefers-reduced-motion: reduce)` stops the animations and shows the still frame. The band is fixed halfway down, and the traces above it are lit and tagged.
  - **Restart:** remount on `task.task_id` (`key`) only. A status change re-renders the same instance.
- [ ] **Step 3: Status overlay** at the bottom, keeping today's gradient fade and `role="status"`.
  - Line 1: running shows `Checking <host>…` (site) or `Probing <host>…` (URL); queued shows `Waiting for a free worker…`. It truncates with an ellipsis on long hosts.
  - Line 2 (mono, faint): `<inspecting specimen|queued> · <site survey|probe> <id8>`.
- [ ] **Step 4: `EmptyGround`** is the same ground, static. The mark is about `#6b4a3a`, the strata about `#2a2621`, plus two barely visible unexamined traces. Below it: `Nothing collected yet.` (muted, 14px) and `Looks empty. It rarely is. Submit a site above to look closer.` (faint, 13px). `SelectedScan` renders it when there's no task. The probe list's `EmptyWell` stays text-only.
- [ ] **Step 5:** Run `npm run build`. Expected: success, with no reference to `ProbeRitual` left (`git grep -n ProbeRitual -- frontend` shows nothing).
- [ ] **Step 6: Browser check** (dev server + Docker API, see Task 9):
  - submit a site survey and see queued, then running: band sinking, traces flashing and tagged, status lines right
  - 375px width: nothing clipped or overlapping
  - `resize_window` / emulate `prefers-reduced-motion`: a still frame, and a queued→running change redraws it
  - in the page, run `Object.defineProperty(crypto, 'subtle', { value: undefined })` before selecting a running probe, or load the dashboard via a non-localhost http origin: the scene still draws, with no console errors
  - empty dashboard, with no tasks (point `VITE_API_BASE` at an empty API, or stub `fetch('/tasks')` → `[]` via `javascript_tool`): `EmptyGround` shows
- [ ] **Step 7: Commit** `rebrand: Strata waiting scene and empty ground replace the ritual scene`.

### Task 8: Living docs

**Files:**
- Modify: `README.md`, `CLAUDE.md`, `.taste-skill/notes.md`

- [ ] **Step 1: README.** The product name becomes Mandacaru (title and prose). Also:
  - the probe path becomes `/mandacaru-<12 random hex>/`
  - the `CLEANUP_URL` table row default becomes `https://facheiro.space.fast/`
  - "ritual vocabulary" becomes "the dashboard's field-station voice"

  Commands that use the `pnakotic` package or directory stay verbatim.
- [ ] **Step 2: CLAUDE.md.**
  - The "What this is" section names Mandacaru and adds a rename note, modelled on the existing "site check" note: renamed from Pnakotic; code identifiers (the `pnakotic.src` package and directory, Celery task names, `PnakoticEngine` / `PnakoticScorer`, Docker and DB names, `PNAKOTIC_TEST_*`) still say pnakotic until the package rename.
  - Update the probe path, the cleanup URL default, and the Frontend line "the ritual vocabulary stays in the chrome…".
  - Rewrite the "Frontend design" paragraph for the new face: charcoal ground with the six colours and their reading twins, and the rules (`*-ink` for text, `negative-fill` only behind bone text, accent ≠ positive). Also: the fonts, the grain, the Strata scene as the one animation exception, `EmptyGround`, the vocabulary (Field Station, probe, Trail/hop, "Can't inspect that." error prefix, specimen only in the scene), and the mark description.
- [ ] **Step 3: `.taste-skill/notes.md`.** Rewrite the Brief and "Style, face, signature" sections for Cosmic Sertão (the central principle; the palette with twins; Alfa Slab carved; mark A; Strata), plus Motion and States (new empty copy). Keep the grid arithmetic and the data inventory. The JSON reports in `.taste-skill/` are historical and stay untouched.
- [ ] **Step 4:** Run `git grep -n -i -E "abyss|phosphor|the deep|ritual|sigil|observatory|descent|elderward|gate is sealed" -- README.md CLAUDE.md .taste-skill/notes.md`. Expected: no hits, or only "renamed from" context.
- [ ] **Step 5: Commit** `docs: Mandacaru identity in README, CLAUDE.md and design notes`.

### Task 9: Whole-stack verification

- [ ] **Step 1:** Run `python3 -m pytest -q` and `cd frontend && npm run build`. Expected: all pass. Report any skips.
- [ ] **Step 2:** Run `git grep -n -i pnakotic -- . ':!docs/superpowers' ':!docs/*findings*' ':!docs/field-test*' ':!docs/forum-gap-analysis.md' ':!SECURITY_REVIEW.md' ':!SKILL.md'`. Expected: every hit is in the Global Constraints "do not rename" list (including the testbed's served skimmer markers), or is the CLAUDE.md rename note or the testbed README note.
- [ ] **Step 3: Run the stack.** Start it with `docker compose up --build -d` (API :8000), then the dashboard with `preview_start {name: "frontend-dev"}` (port 5174, from `../.claude/launch.json`). The API's CORS must allow :5174; check `main.py` and say so if it doesn't, without changing it silently.
- [ ] **Step 4: Visual pass**, with a screenshot of each:
  - empty dashboard
  - queued and running site survey
  - queued and running URL probe
  - a completed site survey that's Compromised (if no real one is available, use a stored one) and a Clean one
  - a completed URL probe with a Trail
  - the input-rejection error (submit `http://127.0.0.1`)
  - the API-down error (stop the api container)
  - 375px width
  - reduced motion

  Also, Review Focus 1: open a site survey completed before this branch. Expected: its "page not found" page is still labelled, and its cleanup link says Facheiro and points to `https://facheiro.space.fast/`.
- [ ] **Step 5:** Run `read_console_messages` with `onlyErrors`. Expected: none.
- [ ] **Step 6:** Report to the user with the screenshots. Push and open a PR only if asked.
