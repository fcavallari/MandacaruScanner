# Checkout Skimmer Check, Phase 1 + Spike: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the watch-only skimmer checks to every load (code built at runtime, card inputs inserted by unknown code, the checkout page on WooCommerce sites), and run the WooCommerce spike that phase 2 depends on.

**Architecture:** Two new capture modules plug into `PnakoticEngine._scan_in_context()`. `eval_capture.py` reads code built at runtime from CDP `Debugger.scriptParsed`. `card_watch.py` is a hidden init-script hook on DOM insertion that reports the JavaScript stack whenever card inputs are inserted. A pure `code_origin.py` decides whose code a stack belongs to. Results flow as before: YARA buffers and `metadata`, then `site_findings.py` blocks, then `site_report.py`, then the dashboard. The spike is a docker WooCommerce testbed plus scripts that answer the spec's §8 questions in a findings doc.

**Tech Stack:** Python 3, Playwright (async) + CDP, yara-python, pytest/pytest-asyncio, React/TypeScript dashboard, Docker (WordPress + WooCommerce + wp-cli) for the spike.

**Spec:** `docs/superpowers/specs/2026-11-10-checkout-skimmer-check-design.md` (approved 2026-11-10). Read §1–§4.1, §6 (phase 1 bullet), §8. Phase 2 (§4.2–§4.8, §5) is **not** in this plan; it gets its own plan after the spike.

## Global Constraints

- Branch: create `checkout-skimmer-phase1` from the current `ui-legibility` tip (c38dd6e or later). It holds the CDN-blocked-script work this plan builds on; `main` doesn't have it yet.
- The spec file is git-ignored (global ignore on `docs/superpowers/specs`): never `git add -f` it. This plan file is committed normally.
- `PnakoticScorer.WEIGHTS` and its exact-sum tests must not change. New signals in the scorer are unweighted finding strings only.
- Every page-supplied value is bounded: URLs cut to 300 characters, stack strings to 4 000 characters and 30 frames, at most 20 eval stages per load, 200 000 characters per stage, 2 000 000 bytes of stages per load, at most 20 card-insertion events per load. Overflow is counted, never dropped silently.
- Report data holds snippets only (`cut_snippet`, 600 bytes), never page, stage or script bodies.
- New result data goes in three places or it disappears: the worker's `metadata_json` (site report already carries it), `serialize_result()`, and `ScanResultData` / types in `frontend/src/lib/api.ts`.
- Code is imported as `pnakotic.src...`; tests import inside each test function; browser tests use `@requires_browser` and pass `host_allowed=` (via `_site_engine`).
- Hooks must be invisible to the page: wrapped functions keep native `toString()`, the binding name is random and deleted from `window` at once (same rules as `behavior.py`).
- Owner-facing text is plain language (CLAUDE.md "Site survey" and site-survey design §7); no jargon such as "eval" in a finding's main message.
- Run `python3 -m pytest` (all green, browser tests may skip) and `cd frontend && npm run build` before every commit that touches those areas.

## Review Focus

1. **A page that builds hundreds of functions at runtime** (page builders, template-heavy themes): capture stops at 20 stages, counts the rest, and the load finishes in normal time. Test in Task 2.
2. **A page with `debugger;` anti-analysis loops**: with the Debugger domain on, pauses are skipped and the load still finishes. Test in Task 2.
3. **A page that sets `Error.prepareStackTrace` or `Error.stackTraceLimit = 0`** to hide callers: an empty or unparseable stack counts as unknown code, so the signal still fires. Test in Task 4.
4. **A multi-megabyte `innerHTML` write**: the hook only tests the first 200 000 characters and doesn't slow the page noticeably. Test in Task 4.
5. **A non-WooCommerce site with a "/checkout" link**, and a WooCommerce site whose checkout redirects to the cart: the first gets no checkout page, the second's checkout is loaded and reported as the checkout page wherever it landed. Tests in Task 6.

---

### Task 1: Whose code it is (`code_origin.py`)

**Files:**
- Create: `src/scanner/code_origin.py`
- Test: `tests/test_code_origin.py`

**Interfaces:**
- Produces:
  - `Frame = NamedTuple("Frame", [("url", str), ("line", Optional[int]), ("eval", bool)])`
  - `parse_stack(stack: str) -> List[Frame]`: V8 stack text to frames; at most 30; input cut to 4 000 characters. `eval at` frames and `<anonymous>` / no-URL frames get `eval=True` and `url=""`.
  - `frame_owner(frame: Frame, site_host: str, page_url: str, inline_lines: Optional[List[Tuple[int, int]]]) -> str`: one of `"store"`, `"provider"`, `"vendor"`, `"unknown"`.
  - `stack_owner(frames: List[Frame], site_host: str, page_url: str, inline_lines) -> Tuple[str, List[str]]`: `("unknown", …)` if any frame is unknown **or `frames` is empty**; else `("vendor", [vendor names])` if any frame is a vendor; else `("store", [])`. A provider frame counts like a store frame here.
  - `inline_line_ranges(served_html: Optional[bytes]) -> List[Tuple[int, int]]`: 1-based `(first_line, last_line)` of every inline `<script>` block, built on `script_trace._inline_blocks` and `_line_starts` (make them importable; don't duplicate).
  - Constants: `STORE_CDN_HOSTS = {"c0.wp.com", "s0.wp.com", "code.jquery.com"}`; `STORE_CDN_PATH_HOSTS = {"cdnjs.cloudflare.com": "/ajax/libs/jquery", "cdn.jsdelivr.net": "/npm/jquery", "ajax.googleapis.com": "/ajax/libs/jquery"}`; `PAYMENT_PROVIDERS` (registrable domains: stripe.com, stripe.network, paypal.com, paypalobjects.com, braintreegateway.com, braintree-api.com, squareup.com, squarecdn.com, adyen.com, authorize.net, wordpress.com (WooPayments), klarna.com, klarnacdn.net, mollie.com); `KNOWN_VENDORS` (registrable domain → name: hotjar.com Hotjar, clarity.ms Microsoft Clarity, fullstory.com FullStory, signifyd.com Signifyd, sift.com Sift, klaviyo.com Klaviyo, google-analytics.com Google Analytics, googletagmanager.com Google Tag Manager).

Rules for `frame_owner`: `eval=True` gives unknown. Same registrable domain as `site_host` (`site_identity.registrable_domain`) gives store, except a frame whose URL is the page itself (fragment ignored): that is store only when `line` falls inside one of `inline_lines`, otherwise unknown (an inline script added at runtime). Then `STORE_CDN_HOSTS`, or a `STORE_CDN_PATH_HOSTS` host whose path starts with its prefix, give store. Provider and vendor domains are matched by registrable domain. Everything else is unknown.

- [ ] **Step 1: Write the failing tests**

```python
def test_parse_stack_reads_url_line_and_eval():
    from pnakotic.src.scanner.code_origin import parse_stack
    s = ("Error\n    at f (https://shop.com/wp-content/plugins/x/a.js:10:5)\n"
         "    at https://cdn.evil.io/s.js:1:200\n"
         "    at eval (eval at g (https://shop.com/a.js:3:1), <anonymous>:1:9)\n    at <anonymous>:2:3")
    fr = parse_stack(s)
    assert [(f.url, f.line, f.eval) for f in fr] == [
        ("https://shop.com/wp-content/plugins/x/a.js", 10, False), ("https://cdn.evil.io/s.js", 1, False),
        ("", None, True), ("", None, True)]

def test_parse_stack_is_bounded():
    from pnakotic.src.scanner.code_origin import parse_stack
    assert len(parse_stack("Error\n" + "    at https://a.com/x.js:1:1\n" * 500)) == 30

def test_jquery_on_a_cdn_is_the_store_but_other_jsdelivr_files_are_not():
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    own = lambda u: frame_owner(Frame(u, 1, False), "shop.com", "https://shop.com/checkout/", [])
    assert own("https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js") == "store"
    assert own("https://cdn.jsdelivr.net/gh/attacker/skim/s.js") == "unknown"
    assert own("https://c0.wp.com/c/6.6/wp-includes/js/jquery/jquery.min.js") == "store"
    assert own("https://js.stripe.com/v3/") == "provider"
    assert own("https://static.hotjar.com/c/hotjar-1.js") == "vendor"

def test_inline_frame_is_store_only_inside_a_served_script_block():
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    blocks = [(5, 9)]
    page = "https://shop.com/checkout/"
    assert frame_owner(Frame(page, 7, False), "shop.com", page, blocks) == "store"
    assert frame_owner(Frame(page, 2, False), "shop.com", page, blocks) == "unknown"

def test_any_unknown_frame_wins_and_empty_stack_is_unknown():
    from pnakotic.src.scanner.code_origin import Frame, stack_owner
    page = "https://shop.com/checkout/"
    store = Frame("https://shop.com/wp-includes/js/jquery/jquery.min.js", 2, False)
    assert stack_owner([store, Frame("https://evil.io/x.js", 1, False)], "shop.com", page, [])[0] == "unknown"
    assert stack_owner([store, Frame("https://static.hotjar.com/c/h.js", 1, False)], "shop.com", page, []) == ("vendor", ["Hotjar"])
    assert stack_owner([], "shop.com", page, [])[0] == "unknown"
```

- [ ] **Step 2: Run them, expect failure** — `python3 -m pytest tests/test_code_origin.py -v` → FAIL (module missing).
- [ ] **Step 3: Implement `code_origin.py`** per the Interfaces block. Parse with one bounded regex per line (`at (?:.{0,200}? \()?(https?://[^\s()]{1,300}?):(\d{1,7}):\d{1,7}\)?`); anything with `eval at` or no URL is an eval frame.
- [ ] **Step 4: Run them, expect PASS**, then the full suite.
- [ ] **Step 5: Commit** — `git add src/scanner/code_origin.py src/scanner/script_trace.py tests/test_code_origin.py && git commit -m "Add code_origin: decide whose code a JavaScript stack belongs to"`

---

### Task 2: Capture code built at runtime (`eval_capture.py`) and match it

**Files:**
- Create: `src/scanner/eval_capture.py`
- Modify: `src/scanner/engine.py` (`_scan_in_context`: attach, YARA buffers, metadata), `src/intelligence/scorer.py` (one unweighted string)
- Modify: `tests/_support.py` (`site_server` routes), `tests/test_site_load.py`, `tests/test_engine.py`
- Docs: CLAUDE.md "Malvertising detection beyond redirects" bullet and module table; README "How a scan works" step 8

**Interfaces:**
- Consumes: `code_origin.parse_stack`, `obfuscation.obfuscator_markers`, `snippets.cut_snippet`
- Produces:
  - `class EvalCapture` with `__init__(self)`, `async attach(self, cdp) -> None` (`Debugger.enable`, `Debugger.setSkipAllPauses {"skip": true}`, listen to `Debugger.scriptParsed`), `async drain(self, timeout: float = 5.0) -> None` (await pending `Debugger.getScriptSource` calls; call before the context closes), attributes `stages: List[Stage]`, `dropped: int`.
  - `Stage = dataclass(source: bytes, caller_url: str, caller_line: Optional[int])`: `caller_url` is the top `stackTrace.callFrames[0].url` of the event, or `""`.
  - Constants: `MAX_STAGES = 20`, `MAX_STAGE_CHARS = 200_000`, `MAX_STAGE_BYTES_TOTAL = 2_000_000`.
  - Which parsed scripts count as stages (to be confirmed in Step 1): `url == ""`, or `hasSourceURL` is true (a `//# sourceURL=` comment renames an eval'd script, so a stage can disguise itself as `https://shop/jquery.js`). Network scripts and the document's own inline scripts have a URL and no `sourceURL`, and are skipped.
  - Engine: `result.metadata["eval_stages"]`: list of `{"caller": str (≤300), "caller_line": int|None, "length": int, "markers": List[str], "context": dict (cut_snippet(source, 0, 0)), "yara_matched": bool}`, plus `metadata["eval_stages_dropped"]` when > 0. Kept in every mode.
  - YARA buffers: `("eval", caller_url or page.url, source)` placed **before** the script bodies (after the page and frame documents), so the 20 s YARA budget cuts script bodies first. In site mode, set `yara_matched` from `buffer_index`.
  - `scan_buffers` names every `eval` buffer `script.js`, whatever its URL, so JavaScript rules that condition on the extension apply.
  - Scorer: when any stage has markers, append the unweighted string `"Code built at runtime with obfuscator markers (not weighted)"`. No `WEIGHTS` change.

- [ ] **Step 1: Observe CDP before writing the filter.** A scratch script (not committed) that loads a local page and prints every `Debugger.scriptParsed` event's `url`, `hasSourceURL`, `stackTrace` and `length` for six cases: `eval`, `new Function`, string `setTimeout`, an `eval` whose source ends with `//# sourceURL=https://example.com/jquery.js`, a dynamically inserted inline `<script>` (`s.text = …; document.head.appendChild(s)`), and an ordinary inline script. Write the stage filter and the `caller` rule from that output, and record the observed fields in `eval_capture.py`'s docstring. If `stackTrace` is missing for `new Function`, try `Debugger.setAsyncCallStackDepth {"maxDepth": 1}`; if it is still missing, `caller` is `""`.
- [ ] **Step 2: Add `site_server` routes** in `tests/_support.py`: `/eval-stage` (an inline script doing `new Function("/*PNAKOTIC_TEST_EVAL*/ return 1")()` and an `eval(<the obf string already in _support>)`); `/eval-sourceurl` (`eval("/*PNAKOTIC_TEST_EVAL*/\n//# sourceURL=https://example.com/jquery.js")`); `/eval-template` (`new Function("obj", "return obj.a")` 3 times, no markers); `/eval-flood` (a loop of 500 `new Function("return " + i)`); `/eval-debugger` (`setInterval(() => { debugger; }, 10)` then `new Function("/*PNAKOTIC_TEST_EVAL*/")()`). In `_rules_dir`, write `raw/js_runtime_test_001.yara` by hand (not through `_RULE`): production, severity 5, marker `PNAKOTIC_TEST_EVAL`, condition `$a and filename matches /\.js$/`, so the test fails if eval buffers are named `page.html`.
- [ ] **Step 3: Write the failing tests** in `tests/test_site_load.py`:

```python
async def test_runtime_code_is_captured_matched_and_marked(site_server, tmp_path, yara_rules_dir):
    # LoadOptions(site=True) load of /eval-stage
    stages = r.metadata["eval_stages"]
    assert any(s["yara_matched"] for s in stages)
    assert any("string_array_rotation" in s["markers"] for s in stages)
    # caller: what Step 1 found. With a stack: every caller starts with site_server. Without: every caller == "".
    assert any(json.loads(h.evidence)["source"] == "eval" for h in r.hops if h.mechanism == "yara_match")

async def test_runtime_code_disguised_with_a_source_url_is_still_a_stage(site_server, tmp_path, yara_rules_dir):
    # /eval-sourceurl
    assert any(s["yara_matched"] for s in r.metadata["eval_stages"])

async def test_runtime_templates_are_captured_but_quiet(site_server, tmp_path):
    # /eval-template: stages present, no markers, no scoring string
    assert r.metadata["eval_stages"] and not any(s["markers"] for s in r.metadata["eval_stages"])

async def test_runtime_code_flood_is_capped(site_server, tmp_path):
    # /eval-flood
    assert len(r.metadata["eval_stages"]) == 20 and r.metadata["eval_stages_dropped"] >= 480

async def test_debugger_loop_does_not_stall_the_load(site_server, tmp_path, yara_rules_dir):
    # /eval-debugger, finishes and still matches
    assert any(s["yara_matched"] for s in r.metadata["eval_stages"])
```

And in `tests/test_engine.py` (offline): a `ScanResult` with `metadata["eval_stages"] = [{"markers": ["hex_identifier_density"], ...}]` scores exactly the same as without it, and its `scoring_findings` contain the unweighted string.

- [ ] **Step 4: Run them, expect failure.**
- [ ] **Step 5: Implement `EvalCapture`**, the `scan_buffers` naming change, and the wiring in `_scan_in_context`: attach on `guard.cdp` right after `tracer.attach` (before `goto`), `await evals.drain()` next to `scripts.drain()`, then build the buffers and metadata after the context closes. A stage without a caller is shown as "built at runtime on <page>".
- [ ] **Step 6: Add the scorer string**; run all tests, expect PASS (including the unchanged exact-sum scorer tests).
- [ ] **Step 7: Update CLAUDE.md and README**, then commit: `git commit -m "Capture code built at runtime and match it with YARA and the obfuscator markers"`

---

### Task 3: Report runtime-code findings in the site survey

**Files:**
- Modify: `src/scanner/site_findings.py` (`_yara_and_injections`, `MESSAGES`, a new `_runtime_code`), `src/scanner/site_report.py` (only if a new kind needs ordering), `frontend/src/lib/api.ts` (`FindingOrigin`), `frontend/src/components/SiteReport.tsx` (`ORIGINS`)
- Test: `tests/test_site_findings.py`, `tests/_support.py` (helper for an `eval` YARA hop)
- Docs: CLAUDE.md "Verdict and severity" paragraph; README "What counts as a finding" table

**Interfaces:**
- Consumes: Task 2's `metadata["eval_stages"]` and `yara_match` hops with `source == "eval"`.
- Produces:
  - New origin value `"runtime"`; in `ORIGINS`: `runtime: 'Built and run by code on this page while it loaded'`.
  - A YARA hit with `source == "eval"` becomes a finding at the page (`location_kind: "page"`, `origin: "runtime"`, severity by `_yara_tier` as today, key `("yara", rule, snippet text)`), with `initiator` set to the hit's `url` when it isn't the page URL.
  - `MESSAGES["runtime_obfuscated"] = "Code on this page builds and runs hidden, scrambled code"`; a stage with `markers` and `yara_matched == False` becomes a `suspicious` finding of kind `"runtime_code"`, `origin: "runtime"`, snippet = the stage's `context`, key `("runtime", caller, snippet text)` so the same stage on every page merges.
  - Off-site loads: like other off-site hits (landing URL, `offsite: true`); `_runtime_code` skips off-site loads.

- [ ] **Step 1: Write the failing tests:**

```python
def test_runtime_yara_hit_sits_on_the_page_as_runtime():
    # _load(0, "https://s.com/", "default", [_yara_hop("eval", "https://s.com/", "r1", 5, True, 0, "EVIL")])
    assert f["origin"] == "runtime" and f["severity"] == "compromised" and b["location"] == "https://s.com/"

def test_obfuscated_runtime_stage_is_suspicious_and_merges_across_pages():
    # two loads whose metadata["eval_stages"] has the same caller + context, markers set, yara_matched False
    [b] = blocks_for_each_page...; assert f["kind"] == "runtime_code" and f["severity"] == "suspicious"
    assert f["message"] == "Code on this page builds and runs hidden, scrambled code"

def test_runtime_stage_already_matched_by_yara_is_not_repeated():
    # yara_matched True -> only the YARA finding

def test_runtime_stage_without_markers_is_nothing():
```

- [ ] **Step 2: Run them, expect failure.**
- [ ] **Step 3: Implement** in `site_findings.py` (the `eval` source branch in `_yara_and_injections`, and `_runtime_code(c, load, site_host)` called from `build_blocks_and_overflow` next to the others).
- [ ] **Step 4: Frontend**: add `'runtime'` to `FindingOrigin` and the `ORIGINS` line. Run `npm run build`.
- [ ] **Step 5: Run all tests, expect PASS.** Update docs, then commit: `git commit -m "Report runtime-built malicious or scrambled code in the site survey"`

---

### Task 4: Watch card inputs being inserted (`card_watch.py`)

**Files:**
- Create: `src/scanner/card_watch.py`
- Modify: `src/scanner/behavior.py` (move the stealth prelude into a shared `HOOK_PRELUDE` string: `nativeText`, the patched `toString`, `wrap`; `_INIT_TEMPLATE` uses it unchanged in behaviour), `src/scanner/engine.py` (site mode only: attach before `new_page`, read after settle)
- Test: `tests/test_card_watch.py` (offline), `tests/test_site_load.py` (browser), `tests/_support.py` (routes)
- Docs: CLAUDE.md module table and `LoadOptions(site=True)` paragraph

**Interfaces:**
- Consumes: `code_origin.parse_stack`, `stack_owner`, `inline_line_ranges`.
- Produces:
  - `CARD_SELECTOR: str`: a CSS selector for card inputs. It must match `autocomplete` tokens `cc-number`, `cc-csc`, `cc-exp`, `cc-exp-month`, `cc-exp-year`, and name/id patterns for card number, CVC/CVV and card expiry. It must not match `billing_email`, `billing_postcode`, `coupon_code` or `account_password`. The exact patterns are the builder's, pinned by the tests.
  - `CARD_HTML_RE`: a bounded regex for an HTML string that would create such an input (used on the first 200 000 characters of an HTML argument).
  - `class CardWatcher` with `binding: str` (random), `async attach(self, ctx) -> None` (expose binding + init script), `events: List[dict]` (each `{"via": str, "stack": str}`, `via` one of `appendChild`, `insertBefore`, `replaceChild`, `append`, `prepend`, `replaceWith`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`), `dropped: int`. At most 20 events; the stack is cut to 4 000 characters.
  - `summarize(events, present: int, site_host: str, landing_url: str, served: Optional[bytes]) -> dict` returns `{"present": int, "inserted": [{"via", "owner", "vendors", "frames": [≤10 frame URLs, each ≤300]}], "dropped": int}`. `landing_url` is the page's final URL (the document the served HTML belongs to), not the requested one.
  - **Fails closed:** when `present > 0`, no event was recorded, and `CARD_HTML_RE` finds nothing in the served HTML, `summarize` adds `{"via": "unseen", "owner": "unknown", "vendors": [], "frames": []}`. That covers inputs the hooks can't see: a bare `<input>` renamed after insertion, `document.write`, adopted nodes.
  - Engine, site mode: `metadata["card_inputs"] = summarize(...)`, where `present` = `await page.locator(CARD_SELECTOR).count()` after the settle (Playwright's utility world, not the page's).
- Page side: inside each wrapped call, test the argument (node: `matches` / `querySelector` with `CARD_SELECTOR`; string: `CARD_HTML_RE` on its first 200 000 characters). Only on a hit, capture the stack with the saved `Error.captureStackTrace(obj, wrapped)`, temporarily setting `Error.prepareStackTrace = undefined` and `Error.stackTraceLimit = 30`, read `obj.stack`, restore both. Any failure there reports an empty stack.

- [ ] **Step 1: Add `site_server` routes:** `/card-store` (a same-origin script `/js/form.js` that `appendChild`s a form with `autocomplete="cc-number"`); `/card-skim` (an inline script that loads `http://localhost:<port>/skim.js`, and that cross-host script sets `innerHTML` with a card form, adapted from `woo-checkout-scanner/test-fixtures/fake-stripe-form-skimmer.html`); `/card-served` (card inputs in the served HTML, no script); `/card-hidden-stack` (the cross-host script first sets `Error.prepareStackTrace = () => ""` and `Error.stackTraceLimit = 0`, then inserts); `/card-big-html` (a same-origin script setting a 5 MB `innerHTML` with no card input, then one with); `/card-renamed` (the cross-host script appends a bare `<input>`, then sets `name="cardnumber"` and `autocomplete="cc-number"` on it).
- [ ] **Step 2: Write the failing tests.** Offline: `CARD_SELECTOR` matches and doesn't match the listed names (use a small HTML parsed with Playwright's `set_content` in one browser test, or `lxml.cssselect` if available; pick one and stay with it); `summarize` on hand-made stacks gives `owner` `unknown` for a cross-site frame and for an empty stack, and `store` for a same-site frame. Browser (`LoadOptions(site=True)`):

```python
# /card-store
assert ci["present"] >= 1 and [e["owner"] for e in ci["inserted"]] == ["store"]
# /card-skim
assert any(e["owner"] == "unknown" and any("localhost" in f for f in e["frames"]) for e in ci["inserted"])
# /card-served
assert ci["present"] >= 1 and ci["inserted"] == []
# /card-hidden-stack
assert any(e["owner"] == "unknown" for e in ci["inserted"])
# /card-big-html: the load finishes inside the usual timeout and the one card insertion is recorded
# /card-renamed
assert ci["present"] >= 1 and [e["via"] for e in ci["inserted"]] == ["unseen"] and ci["inserted"][0]["owner"] == "unknown"
# URL probe (no options): "card_inputs" not in metadata
# Hooks stay invisible with both init scripts installed: a test that attaches BehaviorRecorder and CardWatcher
# to a fresh context of the shared browser, opens /card-store, and evaluates in that page:
for fn in ("Element.prototype.appendChild", "Element.prototype.insertAdjacentHTML", "Function.prototype.toString",
           "Clipboard.prototype.writeText"):
    assert (await page.evaluate(f"{fn}.toString()")).endswith("{ [native code] }")
assert await page.evaluate("Object.keys(window).filter(k => k.startsWith('__')).length") == 0
```

- [ ] **Step 3: Run them, expect failure.**
- [ ] **Step 4: Implement** the prelude move (behaviour tests in `test_popups_personas.py` and `test_engine.py` must stay green untouched), `card_watch.py`, and the engine wiring.
- [ ] **Step 5: Run all tests, expect PASS.** Update docs, then commit: `git commit -m "Watch card inputs being inserted and record whose code did it"`

---

### Task 5: Card-input findings and the "own card fields" note

**Files:**
- Modify: `src/scanner/site_findings.py` (`MESSAGES`, `_card_inputs`), `src/scanner/site_report.py` (`_checked`: page flag), `frontend/src/lib/api.ts`, `frontend/src/components/SiteReport.tsx`
- Test: `tests/test_site_findings.py`, `tests/test_site_report.py`
- Docs: CLAUDE.md "Verdict and severity"; README "What counts as a finding"

**Interfaces:**
- Consumes: `metadata["card_inputs"]` from Task 4.
- Produces:
  - `MESSAGES["card_inputs"] = "Code from outside your site adds card payment fields to this page"`: a `suspicious` finding of kind `"card_inputs"`, `origin: "rendered"`, `location_kind: "page"`, no snippet, `details.frames` = the event's frames (≤10), key `("card_inputs", page_url, first unknown frame URL or "")`. One finding per page.
  - Vendor-only insertions add no finding; their names go in the page's details as `card_fields_vendors`.
  - `_checked` page entries gain `card_fields: bool`: true when any checked load of that page has `present > 0` or a store/vendor insertion. In `api.ts` this is `card_fields?: boolean` on the page type; `SiteReport.tsx` shows the line "This page has its own card payment fields" under the page in "What was checked".
  - Off-site loads add nothing.

- [ ] **Step 1: Write the failing tests:** an unknown insertion gives one suspicious `card_inputs` block at the page, and the verdict is Suspicious; a store-only insertion gives no block and `card_fields: True`; served-only inputs (`present: 1`, no insertions) give `card_fields: True` and no block; a vendor-only insertion gives no block.
- [ ] **Step 2: Run them, expect failure.**
- [ ] **Step 3: Implement**, then the frontend; `npm run build`.
- [ ] **Step 4: Run all tests, expect PASS.** Update docs, then commit: `git commit -m "Report card fields added by outside code, note a page's own card fields"`

---

### Task 6: Load the checkout page on WooCommerce sites, end to end

**Files:**
- Create: `src/scanner/woo.py`
- Modify: `src/scanner/engine.py` (site metadata `woocommerce`), `src/scanner/site_engine.py` (the extra job), `src/scanner/site_report.py` (`_checked`: `checkout` flag), `frontend/src/lib/api.ts`, `frontend/src/components/SiteReport.tsx`
- Test: `tests/test_woo.py`, `tests/test_site_engine.py`, `tests/_support.py`
- Docs: CLAUDE.md "Site survey" flow (new step between 3 and 4); README "How a site survey works"

**Interfaces:**
- Produces:
  - `looks_like_woocommerce(html: str) -> bool`: true on any of `/wp-content/plugins/woocommerce/`, `woocommerce_params`, `wc_add_to_cart_params`, `wc-block-` or a `class` attribute containing the word `woocommerce`, within the first 2 000 000 characters, bounded regexes.
  - `checkout_url(links: List[str], site_host: str, root: str) -> str`: the first on-site link whose last non-empty path segment is `checkout`, else `urljoin(root, "checkout/")`; fragment and query dropped.
  - Engine, site mode: `metadata["woocommerce"] = looks_like_woocommerce(served_text or content)`.
  - `SiteScanner.scan`: when any checked homepage load has `woocommerce` true, after `pick_pages`, it computes `checkout_url(links or [], site_host, root)`. Note that `root` is always `<scheme>://<site_host>[:port]/` (`_root()`), so the fallback is `/checkout/` at the server root even for a sub-path homepage in tests.
    - **Already picked:** if that URL is in `picked`, that page is the checkout page. No job is added, and it keeps its three profiles.
    - **Not picked:** if it passes `host_allowed`, it is appended to `urls` **before** the 404 probe, and its job runs in the `default` profile only.
    - Nothing else changes: same budget, same semaphore, picked pages untouched.
  - `build_report(..., checkout_index: Optional[int] = None)` (new keyword, default None) passes it to `_checked`, whose page entries gain `checkout: bool` (`index == checkout_index`). `api.ts`: `checkout?: boolean`; `SiteReport.tsx` labels it "Your checkout page" with the URL under it, like the probe.

- [ ] **Step 1: Write the failing unit tests** in `tests/test_woo.py`: each marker detected; a blog with a `/checkout` link and no marker is false; `checkout_url` prefers `/kassa/checkout/` from links, ignores `checkout` on another host, and falls back to `<root>checkout/`.
- [ ] **Step 2: Add `site_server` routes:**
  - `/woo/`: homepage with a `woocommerce` body class and **no** checkout link, so the root fallback is used.
  - `/checkout/`: an inline loader for the cross-host card skimmer from Task 4's `/card-skim`.
  - `/woo-linked/`: marker, links to `/woo-linked/checkout/`, a clean page, so it is picked.
  - `/woo-redirect/`: marker, links to `/woo-redirect/checkout/`, which returns 302 to `/woo-redirect/cart/`.
  - `/plain/`: no marker, links to `/plain/checkout/`.
- [ ] **Step 3: Write the failing site-engine tests:**

```python
# /woo/ (not picked): loaded once, default only, before the probe, verdict Suspicious
checkout = [p for p in report["checked"]["pages"] if p.get("checkout")]
assert len(checkout) == 1 and checkout[0]["url"].endswith("/checkout/")
assert [l["profile"] for l in checkout[0]["loads"]] == ["default"]
assert report["checked"]["pages"][-1]["probe"] is True
assert report["verdict"]["verdict"] == "suspicious"
# /woo-linked/ (already picked): exactly one page has checkout True, it is /woo-linked/checkout/ with 3 profiles,
#   and the page count equals a survey of the same site without the marker
# /plain/: no page has checkout True
# /woo-redirect/: the checkout page entry exists, its default landing ends in /cart/, its state is "checked"
```

- [ ] **Step 4: Run them, expect failure.**
- [ ] **Step 5: Implement** `woo.py`, the engine flag, the site-engine job, the report flag and the frontend label; `npm run build`.
- [ ] **Step 6: Run all tests, expect PASS.** Update docs, then commit: `git commit -m "Load the checkout page in site surveys of WooCommerce stores"`

---

### Task 7: WooCommerce testbed for the spike

Throwaway-grade, but committed: phase 2's live test (§6) reuses it.

**Files:**
- Create: `tools/woo-testbed/docker-compose.yml`, `tools/woo-testbed/setup.sh`, `tools/woo-testbed/README.md`, `tools/woo-testbed/plugins/pnakotic-test-gateway/pnakotic-test-gateway.php`, `tools/woo-testbed/mu-plugins/test-skimmer.php`, `tools/woo-testbed/collector/server.py`

**Interfaces:**
- Produces: a store on `http://localhost:8088`, admin and data via `docker compose run --rm wpcli …`, and a collector on `http://localhost:8099` that appends every request (method, path, query, body) to `collector/requests.jsonl`.
  - Products: three simple, in-stock products (one priced 1.00), one out of stock, one variable.
  - Pages: `/checkout/` with the block checkout (WooCommerce default), `/checkout-classic/` with `[woocommerce_checkout]`. A wp-cli toggle switches which one is the store's checkout page.
  - The test gateway: id `pnakotic_test`, renders native card inputs (`autocomplete="cc-number"`, `cc-exp`, `cc-csc`) in the payment box for both the classic and block checkouts, and always fails payment server-side.
  - `test-skimmer.php`: adapted from `woo-checkout-scanner/test-fixtures/test-skimmer.functions.php`. It reads what is typed in the card number field and sends it to the collector on blur and on a Place Order click (one `fetch` POST, one image beacon). It is off unless the option `pnakotic_test_skimmer` is `1`.
- No accounts and no outside network beyond pulling images.

- [ ] **Step 1: Write the compose file and `setup.sh`** (idempotent: install WordPress, WooCommerce, the gateway, products, pages, set the store address and currency, enable the gateway, disable emails with `woocommerce_email_*_enabled=no`).
- [ ] **Step 2: Bring it up and verify**: `docker compose up -d && ./setup.sh`, then `curl -s localhost:8088/wp-json/wc/store/v1/products | python3 -m json.tool | head` lists the products, and a manual add to cart in a browser shows both checkouts with the test gateway's card fields.
- [ ] **Step 3: Write the README** (start, reset, toggle the checkout and the skimmer, read the collector, count orders by status with `wpcli wc shop_order list --status=any --fields=id,status`).
- [ ] **Step 4: Commit**: `git commit -m "Add a local WooCommerce testbed for checkout-check work"`

---

### Task 8: Run the spike and write the findings

**Files:**
- Create: `tools/woo-testbed/spike/*.py` (one Playwright script per question, plain async Playwright, not Pnakotic's engine, because the egress guard refuses localhost), `docs/checkout-spike-findings.md`

**Interfaces:**
- Produces: `docs/checkout-spike-findings.md` with one section per §8 question: the answer, how it was observed (the script and the output lines that show it), and for both checkouts where they differ. It ends with "What this changes in the design": each spec statement the spike contradicts, quoted with its section number, and the proposed replacement. If nothing changes, say so.

The five questions (spec §8):
1. What does `/checkout/` do with an empty cart, block and classic?
2. Does `/?add-to-cart=<id>` fill the cart the block checkout reads?
3. Which Store API product query returns an in-stock, purchasable, simple product, cheapest first?
4. Which requests create an order in each checkout? When does the block checkout create its `checkout-draft` order (which request), and how long is stock held? After arming a guard that fails every non-GET request, then clicking Place Order with the test gateway selected and the card fields filled, does any order exist outside `checkout-draft`, and did any draft change status? Repeat 5 times per checkout.
5. With CDP `Fetch.enable` on the page session, are requests from a cross-site iframe and a dedicated worker paused? (Serve a test iframe and worker from the collector host.) If not, does `Target.setAutoAttach` with `flatten: true` plus `Fetch.enable` per attached target reach them?

- [ ] **Step 1: Write and run one script per question** against the testbed; save their output under `tools/woo-testbed/spike/out/` (git-ignored).
- [ ] **Step 2: Also run the skimmer path once:** enable `pnakotic_test_skimmer`, fill and blur the card field, click Place Order with the guard armed, and confirm the collector got the typed number before the click (blur) and that the guard's record has the click-time POST body.
- [ ] **Step 3: Write `docs/checkout-spike-findings.md`.**
- [ ] **Step 4: Commit**: `git commit -m "Spike: what WooCommerce does at checkout, and whether the order guard holds"`
- [ ] **Step 5: Stop.** Bring the findings to the user before any phase 2 planning.
