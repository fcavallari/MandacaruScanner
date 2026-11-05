# Site Quick Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "site check" scan kind. It takes a host, loads its homepage and a few varied pages as several visitor types, and reports each compromise at the URL where the code lives, with a snippet. It also gives a Compromised / Suspicious / Partly checked / Clean / Couldn't check verdict and a list of external scripts.

**Architecture:** One new Celery task on its own `site` queue. It runs a `SiteScanner` that opens one browser and one egress proxy. It loads the homepage (4 profiles), picks pages from its links, and loads those (3 profiles each) with bounded concurrency inside a 150 s budget. Each load reuses `PnakoticEngine._scan_in_context()` with a new `LoadOptions(site=True)`, which captures the served HTML, links, script requests and per-buffer YARA matches with context snippets. Pure modules then turn the per-load results into finding blocks, external scripts and a verdict. The result is stored in `metadata_json["site"]`, served with `kind: "site"` and rendered by a new dashboard view.

**Tech Stack:** Python 3.10+, FastAPI, Celery/Redis, SQLAlchemy/Alembic, Playwright (Chromium), yara-python, `tldextract` (new), React + TypeScript + Tailwind.

**Spec:** `docs/superpowers/specs/2026-11-05-site-quick-check-design.md`. Read it with this plan; section references (§) point there.

## Global Constraints

- The URL probe is unchanged. `POST /scan`, `run_scan_worker`'s signature and meaning, `PnakoticEngine.scan()`, the scorer's `WEIGHTS` and its exact-sum tests, and the probe's YARA hop shape all stay as they are.
- Site identity: the exact host scanned. Only the `default` homepage load can move it, and only to a host on the same registrable domain. Registrable domains come from a **bundled** public-suffix list, private domains included (so `github.io` is a suffix). The list is never fetched at runtime.
- Homepage profiles: `default`, `mobile-ios`, `googlebot`, `search-clicker`. Page profiles: `default`, `mobile-ios`, `googlebot`.
- At most 5 picked pages, plus one 404 probe at `<scheme>://<site_host>/pnakotic-<12 hex>/`.
- Budget: 150 s site wall time. At most 6 contexts at once. A 10 s grace period for loads still running at the deadline, then cancel.
- Every load gets a fresh browser context.
- Screenshots: full-page only for the homepage `default` load; viewport for every other load. Path `pages/<n>/<profile>/landing_*.png` (`n` = 0 for the homepage).
- Snippet window: up to 240 bytes before and 240 after the match, 600 bytes in all. UTF-8 with replacement, NULs stripped. 1-based line number.
- Script requests recorded per load: at most 200. Injections (script-initiated script requests) kept per load: at most 50.
- External scripts per site: 100 hosts, 500 URLs, URLs truncated at 300 characters.
- Report size caps: 50 finding blocks, 20 pages listed per finding, 20 URLs in `loaded_by`/`loaded`. Past each cap, keep a count. (My call, not in the spec: these bound `metadata_json`.)
- Celery task `pnakotic.site_scan` on queue `site`: soft time limit 240 s, hard 300 s. The compose `site-worker` runs `-Q site --concurrency 1`, 1 replica.
- `CLEANUP_URL` env var, default `https://elderward.space.fast`.
- Verdict labels, verbatim: Compromised / Suspicious / Partly checked / Clean / Couldn't check. API values: `compromised`, `suspicious`, `partly_checked`, `clean`, `couldnt_check`.
- The report body is plain language. The ritual vocabulary stays in the dashboard's chrome and form errors only.
- New result data goes in three places: the worker's `metadata_json`, `serialize_result()`, and `ScanResultData` in `frontend/src/lib/api.ts`.
- All page-supplied input is bounded: capped lengths and counts, and regexes with bounded quantifiers.

## Review Focus

1. **Hostile or huge homepages:** a DOM with 100k links, or `href`s full of `javascript:` and data URIs. `extract_links` must stay capped and fast (Task 2 test `test_extract_links_caps_and_filters`).
2. **Messy site input:** `Example.COM/blog?x=1`, `http://example.com:8443`, `münchen.de`, `user:pw@example.com`, bare IP. The input must normalise to a lower-case punycode host with any port kept, and reject credentials (Task 1 test `test_normalize_site_input_messy`).
3. **Homepage redirect chains:** `http://www.x.co.uk` → `https://x.co.uk` → `https://shop.x.co.uk/`. The site host must follow every same-domain hop and stop at the first cross-domain one (Task 1 test `test_resolve_site_host_chain`).
4. **The same rule matching everywhere:** one infected footer script loaded by every page, as every profile. That must stay one block, with the pages and visitors bounded by the caps (Task 7 test `test_blocks_caps_and_single_block_for_shared_script`).
5. **Injection without served HTML:** the 404 probe, a 5xx page, or a page whose served body wasn't captured. `find_injections` must still report the injection with `block: None` and tie nothing (Task 5 test `test_find_injections_without_served_html`).

---

### Task 1: Site identity

**Files:**
- Create: `src/scanner/site_identity.py`
- Modify: `requirements.txt` (add `tldextract>=5.1,<6`)
- Test: `tests/test_site_identity.py`

**Interfaces:**
- Produces (every `host` / `site_host` value in this plan is a lower-case hostname **without a port**; URLs keep their port):
  - `registrable_domain(host: str) -> str` (`''` for an IP, an empty host, or a host with no public suffix such as `localhost`)
  - `same_domain(a: str, b: str) -> bool` (compares `registrable_domain(x) or x`, so `127.0.0.1` and `localhost` are different domains)
  - `www_twin(host: str) -> str` (`www.x.com` ↔ `x.com`)
  - `on_site(host: str, site_host: str) -> bool` (equal, or the www twin)
  - `normalize_site_input(raw: str) -> str` (returns `"https://<host>[:port]/"`; raises `ValueError`)
  - `resolve_site_host(entered_host: str, landing_url: str) -> tuple[str, Optional[str]]` (returns `(site_host, offsite_domain)`)

- [ ] **Step 1: Write the failing tests**

```python
def test_registrable_domain_uses_private_psl():
    assert registrable_domain("a.github.io") == "a.github.io"
    assert registrable_domain("www.example.co.uk") == "example.co.uk"
    assert registrable_domain("127.0.0.1") == ""

def test_same_domain_and_on_site():
    assert same_domain("www.example.com", "shop.example.com")
    assert not same_domain("a.github.io", "b.github.io")
    assert not same_domain("127.0.0.1", "localhost")
    assert on_site("www.example.com", "example.com") and on_site("example.com", "www.example.com")
    assert not on_site("blog.example.com", "example.com")

def test_normalize_site_input_messy():
    assert normalize_site_input("Example.COM/blog?x=1") == "https://example.com/"
    assert normalize_site_input("http://example.com:8443/a") == "https://example.com:8443/"
    assert normalize_site_input("münchen.de") == "https://xn--mnchen-3ya.de/"
    for bad in ("", "   ", "ftp://x.com", "user:pw@example.com", "https://"):
        with pytest.raises(ValueError):
            normalize_site_input(bad)

def test_resolve_site_host_chain():
    assert resolve_site_host("www.x.co.uk", "https://shop.x.co.uk/") == ("shop.x.co.uk", None)
    assert resolve_site_host("example.com", "https://example.com/home") == ("example.com", None)
    assert resolve_site_host("a.github.io", "https://b.github.io/") == ("a.github.io", "b.github.io")
    assert resolve_site_host("x.com", "") == ("x.com", None)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_site_identity.py -v`
Expected: FAIL with `ModuleNotFoundError: ... site_identity`

- [ ] **Step 3: Implement `src/scanner/site_identity.py`**

- Use one module-level `tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)`. That uses only the bundled snapshot.
- Punycode with `host.encode("idna")`, falling back to the raw host on `UnicodeError`.
- `normalize_site_input` prepends `https://` when there's no scheme, rejects userinfo and non-http(s) schemes, and always outputs `https`. The http fallback is the scanner's job.
- `resolve_site_host` compares only the landing's host: same host or same registrable domain gives `(landing_host, None)`; otherwise `(entered_host, registrable_domain(landing_host) or landing_host)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pip install 'tldextract>=5.1,<6' && python3 -m pytest tests/test_site_identity.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add requirements.txt src/scanner/site_identity.py tests/test_site_identity.py
git commit -m "Add site identity helpers with a bundled public-suffix list"
```

### Task 2: Link extraction and page picking

**Files:**
- Create: `src/scanner/page_picker.py`
- Test: `tests/test_page_picker.py`

**Interfaces:**
- Consumes: `on_site`, `www_twin` (Task 1)
- Produces:
  - `extract_links(html: str, base_url: str, limit: int = 2000) -> list[str]` (absolute, fragment dropped, scheme and host lower-cased, http(s) only, first-seen order, deduplicated; parsing stops at `limit` anchors)
  - `pick_pages(links: list[str], site_host: str, homepage_url: str, limit: int = 5) -> list[str]`
  - `probe_url(homepage_url: str, token: str) -> str`

- [ ] **Step 1: Write the failing tests**

```python
HOME = "https://example.com/"

def test_pick_pages_fills_one_of_each_kind_in_order():
    links = [HOME, "https://example.com/about/", "https://example.com/2024/05/lemon-tart/",
             "https://example.com/category/cakes/", "https://example.com/contact-us/",
             "https://example.com/shop/item/", "https://example.com/shop/other/"]
    assert pick_pages(links, "example.com", HOME) == [
        "https://example.com/2024/05/lemon-tart/", "https://example.com/about/",
        "https://example.com/category/cakes/", "https://example.com/contact-us/",
        "https://example.com/shop/item/"]

def test_pick_pages_drops_admin_feeds_media_and_offsite():
    links = ["https://example.com/wp-admin/", "https://example.com/wp-login.php", "https://example.com/feed/",
             "https://example.com/wp-json/wp/v2/posts", "https://example.com/?replytocom=3",
             "https://example.com/a.pdf", "https://example.com/b.jpg", "https://blog.example.com/x/",
             "https://other.com/x/", "https://www.example.com/kept/"]
    assert pick_pages(links, "example.com", HOME) == ["https://example.com/kept/"]  # www twin rewritten

def test_extract_links_caps_and_filters():
    html = "".join(f'<a href="/p{i}/">x</a>' for i in range(100_000)) + '<a href="javascript:alert(1)">j</a>'
    links = extract_links(html, HOME)
    assert len(links) == 2000 and links[0] == "https://example.com/p0/"
    assert extract_links('<a href="data:text/html,x">d</a><a href="#top">t</a>', HOME) == ["https://example.com/"]

def test_probe_url():
    assert probe_url("https://example.com:8443/", "a1b2c3d4e5f6") == "https://example.com:8443/pnakotic-a1b2c3d4e5f6/"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_page_picker.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `src/scanner/page_picker.py`**

Use `html.parser.HTMLParser`, and stop collecting once `limit` anchors are seen. Classify each candidate with these regexes; the kinds are filled in this order (§4.3):
- post: `^/\d{4}/\d{2}/`, `[?&]p=\d+`, else the deepest path
- page: a single path segment
- archive: `/(category|tag|author)/` or `/page/\d+/`
- contact: `contact|kontakt|contacto|contatto`

Fill the remaining slots in document order, preferring a first path segment not used yet. Drop rules are as in §4.3. The homepage itself never counts.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_page_picker.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/page_picker.py tests/test_page_picker.py
git commit -m "Add homepage link extraction and varied page selection"
```

### Task 3: Context snippets and per-buffer YARA results

**Files:**
- Create: `src/scanner/snippets.py`
- Modify: `src/scanner/yara_scan.py` (`scan_buffers`)
- Test: `tests/test_snippets.py`, `tests/test_engine.py` (YARA section)

**Interfaces:**
- Produces:
  - `cut_snippet(data: bytes, start: int, end: int, before: int = 240, after: int = 240, cap: int = 600) -> dict` with keys `text: str`, `match_start: int`, `match_end: int` (character offsets in `text`) and `line: int`.
  - `scan_buffers(rules, buffers, per_buffer: bool = False)`. With `per_buffer=True` it returns one finding per (rule, buffer index). Each finding has the existing keys plus `"offset": int` (the match start in the buffer, in bytes), `"buffer_index": int` and `"context": cut_snippet(...)`. With `per_buffer=False` the output is byte-for-byte what it is today.

- [ ] **Step 1: Write the failing tests**

```python
def test_cut_snippet_window_offsets_and_line():
    data = b"line1\nline2\n" + b"a" * 300 + b"EVIL" + b"b" * 300
    s = cut_snippet(data, 312, 316)
    assert s["line"] == 3
    assert s["text"][s["match_start"]:s["match_end"]] == "EVIL"
    assert len(s["text"].encode()) <= 600 and s["match_start"] == 240

def test_cut_snippet_edges_cap_and_bad_utf8():
    s = cut_snippet(b"EVIL\x00tail", 0, 4)
    assert s["match_start"] == 0 and "\x00" not in s["text"]
    s = cut_snippet(b"x" * 10 + b"M" * 1000, 10, 1010)
    assert len(s["text"]) <= 600 and s["match_start"] == 0   # an oversized match is trimmed, context dropped first
    s = cut_snippet(b"\xff\xfeEVIL", 2, 6)
    assert s["text"][s["match_start"]:s["match_end"]] == "EVIL"
```

In `tests/test_engine.py`, next to `test_yara_bounds_and_dedupes`:

```python
@requires_yara
@pytest.mark.asyncio
async def test_yara_per_buffer_keeps_each_buffer_with_context(yara_rules_dir):
    from pnakotic.src.scanner.yara_scan import load_rules, scan_buffers
    rules = load_rules()
    bufs = [("served", "https://s/", b"<p>PNAKOTIC_TEST_SKIMMER</p>"),
            ("script", "https://s/a.js", b"x\nPNAKOTIC_TEST_SKIMMER")]
    per, _ = await scan_buffers(rules, bufs, per_buffer=True)
    assert sorted((f["source"], f["buffer_index"]) for f in per) == [("script", 1), ("served", 0)]
    js = next(f for f in per if f["source"] == "script")
    assert js["context"]["line"] == 2 and js["offset"] == 2
    folded, _ = await scan_buffers(rules, bufs)
    assert len(folded) == 1 and folded[0]["hits"] == 2 and "context" not in folded[0]
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_snippets.py "tests/test_engine.py::test_yara_per_buffer_keeps_each_buffer_with_context" -v`
Expected: FAIL (`ModuleNotFoundError`, then `TypeError: unexpected keyword argument 'per_buffer'`)

- [ ] **Step 3: Implement `cut_snippet` and the `per_buffer` path**

- `cut_snippet` decodes the before, match and after byte slices separately, so `match_start` and `match_end` are exact.
- The match is trimmed to `cap`. The leftover is split as `before = min(before, leftover // 2, start)` and `after = min(after, leftover - before, len(data) - end)`.
- In `scan_buffers`, take `instances[0].offset` and `matched_length` from the rule's first string match. When there's no instance, the context is `None`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_snippets.py tests/test_engine.py -k "snippet or yara" -v`
Expected: PASS, including the existing YARA tests

- [ ] **Step 5: Commit**

```bash
git add src/scanner/snippets.py src/scanner/yara_scan.py tests/test_snippets.py tests/test_engine.py
git commit -m "Keep YARA matches per buffer with a bounded context snippet"
```

### Task 4: Site-mode scoring

**Files:**
- Modify: `src/intelligence/scorer.py` (`PnakoticScorer.score`, plus a new module constant)
- Test: `tests/test_engine.py` (scoring section)

**Interfaces:**
- Consumes: `on_site` (Task 1)
- Produces:
  - `IDENTITY_SIGNALS = ("suspicious_tld", "watch_tld", "throwaway_hosting", "brand_in_hostname", "brand_in_title", "js_obfuscated_only")`
  - `PnakoticScorer.score(result: ScanResult, site_host: Optional[str] = None) -> float`. When `site_host` is set and the landing host is `on_site`, the `IDENTITY_SIGNALS` weights and their findings are skipped. `combine()` is unchanged.

- [ ] **Step 1: Write the failing tests**

```python
def _scored_site(target, final, mechanisms, site_host):
    from pnakotic.src.intelligence.scorer import PnakoticScorer
    from pnakotic.src.scanner.models import RedirectHop, ScanResult
    result = ScanResult(target_url=target, final_url=final)
    result.hops = [RedirectHop(url=target, mechanism=m) for m in mechanisms]
    return PnakoticScorer().score(result, site_host=site_host), result.metadata["scoring_findings"]

def test_site_mode_drops_identity_signals_on_site():
    score, findings = _scored_site("https://shop.xyz/", "https://shop.xyz/", ["js_obfuscation"], "shop.xyz")
    assert score == pytest.approx(0.0)
    assert not any("TLD" in f or "obfuscation" in f for f in findings)
    score, _ = _scored_site("https://zoom-help.github.io/", "https://zoom-help.github.io/", [], "zoom-help.github.io")
    assert score == pytest.approx(0.0)

def test_site_mode_keeps_identity_signals_off_site():
    _, findings = _scored_site("https://shop.com/", "https://evil.xyz/", [], "shop.com")
    assert "Suspicious TLD: .xyz" in findings

def test_probe_scoring_unchanged_without_site_host():
    score, _ = _scored("https://shop.xyz/", "https://shop.xyz/")
    assert score == pytest.approx(0.3)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_engine.py -k "site_mode or probe_scoring_unchanged" -v`
Expected: FAIL with `TypeError: score() got an unexpected keyword argument 'site_host'`

- [ ] **Step 3: Implement the parameter**

Compute `skip = set(IDENTITY_SIGNALS) if site_host and host and on_site(host, site_host) else set()` once, and guard each of the six weight blocks with `if "<key>" not in skip`. The brand detection still runs, because `credential_form` depends on it.

- [ ] **Step 4: Run the whole scorer suite**

Run: `python3 -m pytest tests/test_engine.py -k scoring -v`
Expected: PASS. The existing exact-sum tests are unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/intelligence/scorer.py tests/test_engine.py
git commit -m "Score site-check loads without site-identity weights when on the owner's site"
```

### Task 5: Obfuscation markers and script-injection tracing (pure parts)

**Files:**
- Create: `src/scanner/obfuscation.py`, `src/scanner/script_trace.py`
- Test: `tests/test_script_trace.py`

**Interfaces:**
- Consumes: `cut_snippet` (Task 3), `same_domain` (Task 1)
- Produces:
  - `obfuscator_markers(js: str) -> list[str]`. Returns a subset of `["string_array_rotation", "hex_identifier_density"]`. Input is capped at 200 000 characters.
  - `record_from_event(event: dict, main_frame_id: str) -> Optional[dict]`. Maps a CDP `Network.requestWillBeSent` event of `type == "Script"` to a record with these keys:
    - `url` (≤ 300 characters)
    - `main_frame: bool`, `frame_url: str`
    - `initiator: "parser" | "script" | "other"`
    - `initiator_url: Optional[str]`
    - `line: Optional[int]`, `column: Optional[int]` (0-based, from CDP)
  - `class ScriptTracer`: `__init__(self)`, `attach(self, cdp, main_frame_id: str) -> Awaitable[None]` (sends `Network.enable`), `records: list[dict]` (capped at 200).
  - `find_injections(records: list[dict], page_url: str, served_html: Optional[bytes], script_bodies: dict[str, bytes]) -> list[dict]`. Keeps only script-initiated records whose `url` is on a different registrable domain from `page_url`, at most 50. Each item has:
    - `requested_url`
    - `initiator_kind: "inline" | "script"` (inline when `initiator_url` equals `page_url` with the fragment ignored)
    - `initiator_url`
    - `block: Optional[{"start": int, "end": int}]` (byte offsets of the inline `<script>` body in `served_html`)
    - `markers: list[str]`
    - `context: Optional[dict]` (`cut_snippet` of the block's first 600 bytes, or of the initiating file around `line`)

- [ ] **Step 1: Write the failing tests**

```python
LOADER = "<html><body><script>;;(function(f,i,u,w,s){w=f.createElement(i);s=f.getElementsByTagName(i)[0];w.async=1;w.src=u;s.parentNode.insertBefore(w,s);})(document,'script','https://content-website-analytics.com/script.js');</script></body></html>"
OBF = "function _0x34e5(){var _0x18b8=['a','b'];_0x34e5=function(){return _0x18b8;};return _0x34e5();}" \
      "(function(_0x44e7,_0x5d16){var _0x7eb7=_0x44e7();while(!![]){try{break;}catch(_0x1){_0x7eb7['push'](_0x7eb7['shift']());}}}(_0x34e5,0x1));"

def test_obfuscator_markers():
    assert "string_array_rotation" in obfuscator_markers(OBF)
    assert obfuscator_markers(LOADER) == []
    assert obfuscator_markers("!function(e,t){'use strict';var n=[],r=Object.getPrototypeOf;}(window)") == []

def test_find_injections_resolves_inline_block_by_position():
    rec = {"url": "https://content-website-analytics.com/script.js", "main_frame": True, "frame_url": "https://s.com/",
           "initiator": "script", "initiator_url": "https://s.com/", "line": 0, "column": 30}
    [inj] = find_injections([rec], "https://s.com/", LOADER.encode(), {})
    assert inj["initiator_kind"] == "inline" and inj["block"] is not None
    assert LOADER.encode()[inj["block"]["start"]:inj["block"]["end"]].startswith(b";;(function")

def test_find_injections_falls_back_to_block_containing_target_host():
    rec = {"url": "https://content-website-analytics.com/script.js", "main_frame": True, "frame_url": "https://s.com/",
           "initiator": "script", "initiator_url": "https://s.com/", "line": None, "column": None}
    [inj] = find_injections([rec], "https://s.com/", LOADER.encode(), {})
    assert inj["block"] is not None

def test_find_injections_ignores_same_domain_and_parser_requests():
    recs = [{"url": "https://cdn.s.com/a.js", "initiator": "script", "initiator_url": "https://s.com/",
             "line": 0, "column": 0, "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://x.com/a.js", "initiator": "parser", "initiator_url": "https://s.com/",
             "line": 0, "column": 0, "main_frame": True, "frame_url": "https://s.com/"}]
    assert find_injections(recs, "https://s.com/", LOADER.encode(), {}) == []

def test_find_injections_without_served_html():
    rec = {"url": "https://x.com/a.js", "initiator": "script", "initiator_url": "https://s.com/404/",
           "line": 3, "column": 1, "main_frame": True, "frame_url": "https://s.com/404/"}
    [inj] = find_injections([rec], "https://s.com/404/", None, {})
    assert inj["block"] is None and inj["context"] is None

def test_record_from_event_maps_initiators():
    ev = {"type": "Script", "frameId": "F", "documentURL": "https://s.com/", "request": {"url": "https://x.com/a.js"},
          "initiator": {"type": "script", "stack": {"callFrames": [{"url": "https://s.com/", "lineNumber": 4, "columnNumber": 9}]}}}
    assert record_from_event(ev, "F") == {"url": "https://x.com/a.js", "main_frame": True, "frame_url": "https://s.com/",
                                          "initiator": "script", "initiator_url": "https://s.com/", "line": 4, "column": 9}
    assert record_from_event({**ev, "type": "Image"}, "F") is None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_script_trace.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement both modules**

`obfuscation.py`:
- A string-array function: `function\s+[\w$]{1,12}\s*\(\s*\)\s*\{\s*(?:var|let|const)\s+[\w$]{1,12}\s*=\s*\[`
- **and** a rotation, one of:
  - `\[\s*'push'\s*\]\s*\(\s*[\w$]{1,12}\s*\[\s*'shift'\s*\]\s*\(\s*\)\s*\)`
  - `\.push\(\s*[\w$]{1,12}\.shift\(\s*\)\s*\)`

  Together these give `string_array_rotation`.
- `hex_identifier_density`: at least 30 matches of `\b_0x[0-9a-f]{4,6}\b` **and** at least one per 200 characters.

`script_trace.py`:
- For a `script` initiator with no frame of its own, `record_from_event` walks `stack.parent`. Take the top frame's `url`, `lineNumber` and `columnNumber`.
- `find_injections` locates inline blocks in `served_html` with a bounded regex over `<script\b[^>]{0,500}>` … `</script>` (case-insensitive, at most 500 blocks).
  - It maps `(line, column)` to a byte offset by counting newlines.
  - It picks the block containing that offset. Otherwise it picks the first block containing the requested URL or its host.
  - Markers come from the block text, or from `script_bodies[initiator_url]` for a file initiator.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_script_trace.py -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/obfuscation.py src/scanner/script_trace.py tests/test_script_trace.py
git commit -m "Trace which script injected each script and flag obfuscator.io injectors"
```

### Task 6: Engine site-mode load

**Files:**
- Create: `src/scanner/challenge.py`
- Modify: `src/scanner/engine.py` (`PnakoticEngine.scan`, `_scan_in_context`, plus a new `LoadOptions` and `browser_session`)
- Create: `tests/_support.py` (shared test helpers)
- Modify: `tests/test_engine.py` (import the moved helpers)
- Test: `tests/test_site_load.py` (browser, local server)

**Interfaces:**
- Consumes: Tasks 2, 3, 5
- Produces:
  - `looks_like_challenge(status: Optional[int], title: str, html: str) -> bool` in `challenge.py`. Markers: `cf-chl`, `challenge-platform`, `cf_chl_opt`, the title "Just a moment...", `Attention Required! | Cloudflare`, `ddos-guard`, `/_Incapsula_Resource`. True for any marker, and for a 403/503 whose HTML is under 20 kB and contains a marker or `captcha`.
  - `@dataclass class LoadOptions: shot_dir: Optional[str] = None; full_page: bool = True; site: bool = False` in `engine.py`.
  - `PnakoticEngine.browser_session() -> AsyncContextManager[tuple[Browser, EgressProxy]]` (launch, proxy start and stop, extracted from `scan()`; `scan()` uses it).
  - `_scan_in_context(self, browser, target_url, profile_name, task_folder, primary, options: Optional[LoadOptions] = None)`. When `options.site` is true, `result.metadata` gains:
    - `main_status: Optional[int]`: the last main-frame navigation response status, any code, from the load phase
    - `served_bytes: int`
    - `links: list[str]` (`extract_links` over the rendered DOM, limit 2000)
    - `script_requests: list[dict]`
    - `injections: list[dict]`
    - `challenge: bool`

    Also, YARA runs with `per_buffer=True` over the buffers below, and each `yara_match` hop's evidence carries `offset`, `buffer_index`, `context` and `source`. The buffers are `served` (the last main-frame navigation response body, capped at `MAX_BUFFER_BYTES`), then `page`, the frames, and the scripts.

    Without options, behaviour is exactly as today.

- [ ] **Step 1: Write the failing tests**

Create `tests/_support.py`. Test modules import from it as `from _support import ...`; pytest's default import mode puts `tests/` on `sys.path`.
- Move `requires_browser`, `requires_yara`, `_rules_dir` and the `yara_rules_dir` fixture here from `tests/test_engine.py`, and import them back there. Fixtures are made available with `from _support import yara_rules_dir  # noqa: F401` in each module that needs them.
- Add `_site_engine(tmp_path)`: a `PnakoticEngine(task_id="site-job", timeout_ms=10000, host_allowed=…)` that allows only `127.0.0.1` and `localhost`, with `ArtifactManager(base_dir=str(tmp_path))`. Tasks 6 and 9 use it.

Add a module fixture `site_server` to `tests/_support.py` (same style as `local_site` in `tests/test_engine.py`). It yields `http://127.0.0.1:<port>` and serves:
- `/`: the Task 5 loader in an inline script, pointing at `http://localhost:<port>/payload.js`. That's another domain to `same_domain`, and the test's `host_allowed` allows it.
- `/payload.js`: a script body containing `PNAKOTIC_TEST_SKIMMER`.
- `/challenge`: a 403 with a `<script src="/cdn-cgi/challenge-platform/h/b">` body.
- `/clean.js`: a script with no marker.
- anything else: a 404 page with no marker.

Task 9 adds more paths to this fixture. `requires_yara` tests need the `yara_rules_dir` fixture from `_support`.

```python
@requires_browser
@pytest.mark.asyncio
async def test_site_load_captures_served_links_scripts_and_injection(site_server, tmp_path, yara_rules_dir):
    engine = _site_engine(tmp_path)   # host_allowed: 127.0.0.1 and localhost
    async with engine.browser_session() as (browser, _proxy):
        r = await engine._scan_in_context(browser, f"{site_server}/", "default", engine.artifacts.create_task_folder("j"),
                                          primary=True, options=LoadOptions(site=True, shot_dir="pages/0/default"))
    assert r.metadata["main_status"] == 200 and r.metadata["served_bytes"] > 0
    assert any(rec["url"].endswith("/payload.js") and rec["initiator"] == "script" for rec in r.metadata["script_requests"])
    [inj] = r.metadata["injections"]
    assert inj["initiator_kind"] == "inline" and inj["block"] is not None
    srcs = {json.loads(h.evidence)["source"] for h in r.hops if h.mechanism == "yara_match"}
    assert "script" in srcs
    assert os.path.isdir(tmp_path / "j" / "pages" / "0" / "default")

@requires_browser
@pytest.mark.asyncio
async def test_site_load_flags_challenge(site_server, tmp_path):
    engine = _site_engine(tmp_path)
    async with engine.browser_session() as (browser, _):
        r = await engine._scan_in_context(browser, f"{site_server}/challenge", "googlebot", engine.artifacts.create_task_folder("j"),
                                          primary=False, options=LoadOptions(site=True, shot_dir="pages/1/googlebot", full_page=False))
    assert r.metadata["challenge"] is True and r.metadata["main_status"] == 403

def test_looks_like_challenge():
    assert looks_like_challenge(403, "Just a moment...", "<html>")
    assert looks_like_challenge(200, "", '<script src="/cdn-cgi/challenge-platform/h/b"></script>')
    assert not looks_like_challenge(403, "Forbidden", "<h1>Forbidden</h1>")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_site_load.py -v`
Expected: FAIL (`ImportError: LoadOptions`)

- [ ] **Step 3: Implement**

- In `on_resp`, when `options.site` is set, record every main-frame navigation response's status and keep a reference to the last non-3xx one. In the analysis step, read its body with `await resp.body()` inside `try/except BROWSER_ERRORS`, capped.
- Attach `ScriptTracer` to `guard.cdp` right after `Page.getFrameTree`, using `main_frame_id`.
- Compute `injections` after `scripts.drain()`, with the script bodies keyed by URL.
- The screenshot dir is `os.path.join(task_folder, options.shot_dir)` when it's given. `full_page=options.full_page`.
- Keep every existing step's error handling as it is.

- [ ] **Step 4: Run the new tests and the whole engine suite**

Run: `python3 -m pytest tests/test_site_load.py tests/test_engine.py tests/test_popups_personas.py -v`
Expected: PASS. The existing probe tests are unchanged.

- [ ] **Step 5: Commit**

```bash
git add src/scanner/challenge.py src/scanner/engine.py tests/_support.py tests/test_engine.py tests/test_site_load.py
git commit -m "Capture served HTML, links, script initiators and per-buffer YARA in site-mode loads"
```

### Task 7: Finding blocks

**Files:**
- Create: `src/scanner/site_findings.py`
- Test: `tests/test_site_findings.py`

**Interfaces:**
- Consumes: the `ScanResult.metadata` keys from Task 6; `behavior_events`, `evidence_of` (`behavior.py`); `PnakoticScorer._decisive`; `on_site`, `same_domain` (Task 1)
- Produces:
  - `@dataclass class Load` with fields:
    - `page_index: int`, `page_url: str`, `profile: str`
    - `state: str` (`"checked" | "partial" | "not_checked"`)
    - `reason: Optional[str]`
    - `result: Optional[ScanResult]`
    - `shot: Optional[str]`
  - `MESSAGES: dict[str, str]`: the plain line per finding kind. Keys are `yara`, `clipboard`, `download`, `browser_lock`, `cloaking`, `offsite_homepage`, `injection` and `page_score`.
  - `build_blocks(loads: list[Load], site_host: str, offsite_domain: Optional[str]) -> list[dict]`. Each block is `{"location": str, "location_kind": "page" | "script", "findings": [finding, …]}`, and each finding is a dict with these keys:
    - `id` (a stable merge key)
    - `severity: "compromised" | "suspicious"`
    - `kind`
    - `message` (the YARA rule's `description` when it's set, else `MESSAGES[kind]`)
    - `snippet` (a `cut_snippet` dict or `None`)
    - `origin: "served" | "rendered" | "frame" | "script" | None`
    - `visitors: list[str]`, `all_visitors: bool`
    - `pages: list[str]`, `pages_more: int`
    - `loaded_by: list[str]`, `loaded: list[str]`
    - `details: dict` (`rule`, `signature_id`, `mechanism`, `profiles`, `screenshots`, `scoring` strings)

    Blocks are ordered compromised first, then by location. They're capped as in Global Constraints.

Rules to implement (§5.1–5.5):
- **YARA hit:** `compromised` when it's production with severity ≥ 4, else `suspicious`.
  - Origin: `served` → "served"; `page` → "rendered", and only when the same rule has no `served` hit on that load; `frame` → "frame"; `script` → a block at the script URL.
  - Merge key: for HTML origins, `(kind, rule, snippet text)`; the block sits at the first page and `pages` lists every page. For script origins, `(kind, rule, script URL)`; the block sits at the script URL, with the pages that loaded it in `loaded_by`.
- **Injection tie:** an `injections` item whose `block` contains a `served` YARA hit's `offset` on the same load adds `requested_url` to that finding's `loaded`. A YARA hit on a script whose URL equals an injection's `requested_url` gets `loaded_by` `"inline on <page>"` or the initiator URL.
- **Untied injection:** an injection with markers and no tie becomes a `suspicious` `injection` finding at the page, with `snippet = context` and `loaded = [requested_url]`.
- **Behaviour:** `PnakoticScorer._decisive(behavior_events(result.hops))` → `compromised`, with the kind taken from the event.
- **Cloaking:** a decisive cloaking result (`metadata["cloaking"]["suspicious"]` non-empty on the page's combined `default` result) → `compromised`.
- **Off-site homepage:** when `offsite_domain` is set → `suspicious` at `/`, upgraded to `compromised` when cloaking on the homepage is decisive. The message comes from `MESSAGES["offsite_homepage"]` with the domain, plus "If you moved your site, check the new domain" when every homepage load landed on that domain.
- **Page score:** a load whose `malicious_score` ≥ 0.4 and that has no compromised finding of its own → `suspicious` `page_score`, with `details.scoring` = that load's `scoring_findings`.
- **Not findings:** loads in state `not_checked`, and `challenge` loads, contribute nothing.

- [ ] **Step 1: Write the test helpers, then the failing tests**

Add to `tests/_support.py` (created in Task 6):
- Add `_yara_hop(source, url, rule, sev, production, offset, text) -> RedirectHop`. It's a `yara_match` hop whose JSON evidence is:
  - `id: "yara_match"`, `rule`, `signature_id: 1`, `severity: sev`, `production`
  - `description: f"Synthetic {rule}"`
  - `source`, `url`, `offset`, `buffer_index: 0`, `hits: 1`
  - `context: {"text": text, "match_start": 0, "match_end": len(text), "line": 1}`
- Add `_load(page_index, page_url, profile, hops=(), injections=(), state="checked", reason=None, final_url=None, script_requests=(), score=0.0) -> Load`. It wraps a `ScanResult(target_url=page_url, final_url=final_url or page_url, hops=list(hops), malicious_score=score)` whose metadata is `injections`, `script_requests`, `scoring_findings=[]`, `decisive_findings=[]` and `cloaking=None`.
- Add `_result(**metadata) -> ScanResult` for Task 8. It sets `page_signals={"title": metadata.pop("title", "x")}` and the rest of the metadata as given.

```python
def test_served_hit_is_one_block_per_page_with_snippet():
    blocks = build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("served", "https://s.com/", "r1", 5, True, 40, "EVIL")])], "s.com", None)
    [b] = blocks
    assert b["location"] == "https://s.com/" and b["findings"][0]["severity"] == "compromised"
    assert b["findings"][0]["origin"] == "served" and b["findings"][0]["message"] == "Synthetic r1"

def test_rendered_only_hit_says_added_by_script():
    [b] = build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("page", "https://s.com/", "r1", 3, True, 10, "X")])], "s.com", None)
    assert b["findings"][0]["origin"] == "rendered" and b["findings"][0]["severity"] == "suspicious"

def test_same_footer_on_every_page_merges_into_one_block():
    loads = [_load(i, f"https://s.com/p{i}/", "default", [_yara_hop("served", f"https://s.com/p{i}/", "r1", 5, True, 5, "FOOT")]) for i in range(4)]
    [b] = build_blocks(loads, "s.com", None)
    assert b["location"] == "https://s.com/p0/"
    assert b["findings"][0]["pages"] == [f"https://s.com/p{i}/" for i in range(4)]
```

The merge key for HTML origins is `(kind, rule, snippet text)`. The block's location is the first page in page order.

```python
def test_script_match_lands_under_script_url_with_loaded_by():
    loads = [_load(i, f"https://s.com/p{i}/", "default", [_yara_hop("script", "https://s.com/wp-content/x.js", "r2", 5, True, 0, "Z")]) for i in range(2)]
    [b] = build_blocks(loads, "s.com", None)
    assert b["location_kind"] == "script" and b["findings"][0]["loaded_by"] == ["https://s.com/p0/", "https://s.com/p1/"]

def test_injection_ties_only_inside_block():
    hop = _yara_hop("served", "https://s.com/", "r1", 5, True, 120, "LOADER")
    inj = {"requested_url": "https://bad.org/x.js", "initiator_kind": "inline", "initiator_url": "https://s.com/",
           "block": {"start": 100, "end": 300}, "markers": [], "context": None}
    [b] = build_blocks([_load(0, "https://s.com/", "default", [hop], injections=[inj])], "s.com", None)
    assert b["findings"][0]["loaded"] == ["https://bad.org/x.js"]
    far = {**inj, "block": {"start": 500, "end": 600}}
    [b] = build_blocks([_load(0, "https://s.com/", "default", [hop], injections=[far])], "s.com", None)
    assert b["findings"][0]["loaded"] == []

def test_obfuscated_untied_injection_is_suspicious_and_plain_one_is_nothing():
    inj = {"requested_url": "https://bad.org/x.js", "initiator_kind": "inline", "initiator_url": "https://s.com/",
           "block": {"start": 0, "end": 50}, "markers": ["string_array_rotation"], "context": {"text": "…", "match_start": 0, "match_end": 1, "line": 1}}
    [b] = build_blocks([_load(0, "https://s.com/", "default", [], injections=[inj])], "s.com", None)
    assert b["findings"][0]["kind"] == "injection" and b["findings"][0]["severity"] == "suspicious"
    assert build_blocks([_load(0, "https://s.com/", "default", [], injections=[{**inj, "markers": []}])], "s.com", None) == []

def test_visitors_subset_and_all():
    hop = _yara_hop("served", "https://s.com/", "r1", 5, True, 1, "G")
    loads = [_load(0, "https://s.com/", p, [hop] if p == "googlebot" else []) for p in ("default", "mobile-ios", "googlebot")]
    [b] = build_blocks(loads, "s.com", None)
    assert b["findings"][0]["visitors"] == ["googlebot"] and b["findings"][0]["all_visitors"] is False

def test_blocks_caps_and_single_block_for_shared_script():
    loads = [_load(i, f"https://s.com/p{i}/", p, [_yara_hop("script", "https://s.com/f.js", "r", 5, True, 0, "F")])
             for i in range(30) for p in ("default", "mobile-ios", "googlebot")]
    [b] = build_blocks(loads, "s.com", None)
    f = b["findings"][0]
    assert len(f["loaded_by"]) == 20 and f["all_visitors"] is True

def test_offsite_homepage_finding():
    [b] = build_blocks([_load(0, "https://s.com/", "default", [], final_url="https://elsewhere.net/")], "s.com", "elsewhere.net")
    assert b["findings"][0]["kind"] == "offsite_homepage" and "elsewhere.net" in b["findings"][0]["message"]

def test_not_checked_and_challenge_loads_add_nothing():
    assert build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("served", "https://s.com/", "r", 5, True, 0, "E")], state="not_checked")], "s.com", None) == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_site_findings.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `site_findings.py`**

Implement it as the rules above. `MESSAGES` copy (exact):
- `yara`: "Code matching a known malware pattern"
- `clipboard`: "The page tries to put a command on visitors' clipboard"
- `download`: "The page starts a download on its own"
- `browser_lock`: "The page tries to lock visitors' browser"
- `cloaking`: "Some visitors are sent to a different website"
- `offsite_homepage`: "Your homepage sends desktop visitors to {domain}"
- `injection`: "Hidden code loads a script from another website into your page"
- `page_score`: "This page does things malicious pages do"

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_site_findings.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/scanner/site_findings.py tests/_support.py tests/test_site_findings.py
git commit -m "Turn site-check loads into finding blocks grouped where the code lives"
```

### Task 8: Load states, external scripts, verdict, report

**Files:**
- Create: `src/scanner/site_report.py`
- Test: `tests/test_site_report.py`

**Interfaces:**
- Consumes: `Load`, `build_blocks` (Task 7); `looks_like_challenge` results through `metadata["challenge"]` (Task 6); `on_site`, `same_domain` (Task 1)
- Produces:
  - `classify_load(result: Optional[ScanResult], error: Optional[str]) -> tuple[str, Optional[str]]`, in this order:
    1. an error or no result → `("not_checked", "load_failed")`, or `"budget"` / `"timeout"` when the error is exactly that string
    2. `metadata["challenge"]` → `("not_checked", "challenge")`
    3. `metadata["navigation_failed"]` → `("not_checked", "load_failed")`
    4. a `raw_error` containing `Timeout` with `served_bytes == 0` and an empty title → `("not_checked", "timeout")`
    5. a `raw_error` containing `Timeout` otherwise → `("partial", None)`
    6. else `("checked", None)`
  - `external_scripts(loads: list[Load], site_host: str, blocks: list[dict]) -> dict` returns `{"hosts": [...], "hosts_more": int, "urls_more": int}`. Each host is `{"host", "your_domain": bool, "urls": [...]}`, and each URL entry is:
    - `url`, `pages`, `profiles`
    - `how: "html" | "script"`, `injected_by: Optional[str]`
    - `in_frame: Optional[str]`
    - `finding: bool`

    The order is §5.6.
  - `site_verdict(blocks: list[dict], loads: list[Load], rules_loaded: bool) -> dict` returns `{"verdict": str, "label": str, "summary": str, "rules_loaded": bool}`.
  - `build_report(entered_host: str, site_host: str, offsite_domain: Optional[str], loads: list[Load], rules_count: int, blocked_hosts: list[str], notes: list[str]) -> dict` returns:
    - `site`, `entered`, `redirected_from`
    - `verdict`
    - `blocks`
    - `external_scripts`
    - `checked`: `{"pages": [{"index", "url", "loads": [{"profile", "state", "reason", "status", "screenshot", "score"}]}], "rules": int, "scripts_scanned": int, "frames_scanned": int, "not_checked": int, "total": int}`
    - `notes`

- [ ] **Step 1: Write the failing tests**

```python
def test_verdict_rows():
    ok = lambda i, p: _load(i, f"https://s.com/{i}", p, state="checked")
    home = [ok(0, p) for p in ("default", "mobile-ios", "googlebot", "search-clicker")]
    rest = [ok(i, p) for i in range(1, 4) for p in ("default", "mobile-ios", "googlebot")]
    comp = [{"findings": [{"severity": "compromised"}]}]
    sus = [{"findings": [{"severity": "suspicious"}]}]
    assert site_verdict(comp, home + rest, True)["verdict"] == "compromised"
    assert site_verdict(sus, home + rest, True)["verdict"] == "suspicious"
    assert site_verdict([], home + rest, True)["verdict"] == "clean"
    dead = [_load(0, "https://s.com/", "default", state="not_checked", reason="load_failed")] + home[1:]
    assert site_verdict([], dead + rest, True)["verdict"] == "couldnt_check"
    assert site_verdict(comp, dead + rest, True)["verdict"] == "compromised"
    half = home + [_load(i, "u", p, state="not_checked", reason="budget") if i < 3 else ok(i, p) for i in range(1, 4) for p in ("default", "mobile-ios", "googlebot")]
    assert site_verdict([], half, True)["verdict"] == "partly_checked"
    gb = home[:2] + [_load(0, "https://s.com/", "googlebot", state="not_checked", reason="challenge"), home[3]]
    assert site_verdict([], gb + rest, True)["label"] == "Partly checked"
    assert site_verdict([], home + rest, False)["summary"] == "Clean (no malware rules loaded)"

def test_classify_load():
    assert classify_load(None, "budget") == ("not_checked", "budget")
    assert classify_load(_result(challenge=True), None) == ("not_checked", "challenge")
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=900, title="Home"), None) == ("partial", None)
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=0, title=""), None) == ("not_checked", "timeout")
    assert classify_load(_result(), None) == ("checked", None)

def test_external_scripts_grouping_order_and_caps():
    recs = [{"url": "https://www.googletagmanager.com/gtm.js?id=1", "initiator": "parser", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://bad.org/x.js", "initiator": "script", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://cdn.s.com/a.js", "initiator": "parser", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://s.com/own.js", "initiator": "parser", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"}]
    out = external_scripts([_load(0, "https://s.com/", "default", script_requests=recs)], "s.com", [])
    hosts = [h["host"] for h in out["hosts"]]
    assert hosts == ["bad.org", "cdn.s.com", "www.googletagmanager.com"]  # script-injected first, then alphabetical
    assert out["hosts"][1]["your_domain"] is True and out["hosts"][0]["urls"][0]["how"] == "script"
    many = [{**recs[0], "url": f"https://h{i}.com/{'a' * 400}.js"} for i in range(600)]
    out = external_scripts([_load(0, "https://s.com/", "default", script_requests=many)], "s.com", [])
    assert len(out["hosts"]) == 100 and out["hosts_more"] == 500 and len(out["hosts"][0]["urls"][0]["url"]) <= 300
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_site_report.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `site_report.py`**

- Homepage loads are those with `page_index == 0`. "More than half of the stage-2 loads" counts loads with `page_index > 0`.
- Summary copy:
  - Compromised: `"Compromised · {n} findings on {p} of {total_pages} pages"`
  - Partly checked: `"No malware found, but {k} of {m} checks couldn't run"`
  - Couldn't check: `"We couldn't reach this site"`, or `"This site showed our scanner a bot check"` for `challenge`
- The `finding: true` flag on an external URL is set when the URL equals a block's `location`, or appears in a finding's `loaded` list.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_site_report.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/scanner/site_report.py tests/test_site_report.py
git commit -m "Add site-check verdict, load states, external scripts and report assembly"
```

### Task 9: SiteScanner orchestrator

**Files:**
- Create: `src/scanner/site_engine.py`
- Test: `tests/test_site_engine.py` (browser, local server)

**Interfaces:**
- Consumes: everything above; `PnakoticEngine.browser_session`, `_scan_in_context`, `scorer.score(result, site_host)`, `scorer.combine`
- Produces:
  - `HOMEPAGE_PROFILES = ("default", "mobile-ios", "googlebot", "search-clicker")`, `PAGE_PROFILES = ("default", "mobile-ios", "googlebot")`
  - `@dataclass class SiteOutcome` with fields:
    - `report: dict`
    - `homepage_url: str`, `final_url: str`
    - `worst_score: float`
    - `redirect_chain: bool`
    - `artifact_manifest: dict`
    - `raw_error: Optional[str]`
  - `class SiteScanner`: `__init__(self, engine: PnakoticEngine, budget_s: float = 150.0, concurrency: int = 6, grace_s: float = 10.0, page_limit: int = 5)`, and `async scan(self, homepage_url: str) -> SiteOutcome`

Flow (§4):
1. Open one `browser_session()`, and run the 4 homepage loads at once.
2. If the `default` load has `navigation_failed` with a `net::ERR_` `raw_error` on `https`, rerun all 4 on `http://` once, and note "Checked over http".
3. Run `resolve_site_host(entered_host, default.final_url)`.
4. Score each load with `score(result, site_host)`, then `combine(default_result, "default", {others})` per page.
5. Links come from the first on-site homepage load, in `HOMEPAGE_PROFILES` order. Then `pick_pages` plus `probe_url(…, secrets.token_hex(6))`. If no homepage load stayed on the site, only the probe runs, with the note "No pages could be picked because the homepage left the site".
6. Stage-2 loads run under an `asyncio.Semaphore(concurrency)`.
   - A load only starts if `monotonic() < deadline`; otherwise it's `Load(state="not_checked", reason="budget")`.
   - At the deadline, `asyncio.wait(pending, timeout=grace_s)`, then cancel the rest, as `reason="budget"`.
7. Classify each load (`classify_load`), and `build_report`.
8. The screenshot path is `pages/<n>/<profile>`, and `full_page` only for `(0, "default")`.
9. `site_host` isn't checked against `host_allowed` here, because the browser egress guard enforces it per request. Every picked URL **is** checked with `await engine.host_allowed(host)` before it's queued, and dropped if it fails.
10. Bugs and `SoftTimeLimitExceeded` propagate. A `BROWSER_ERRORS` exception on a single load becomes `not_checked: load_failed`.

- [ ] **Step 1: Write the failing tests**

The `site_server` fixture (Task 6) gains these paths:
- `/` also links to `/2024/05/post/`, `/about/` and `/category/x/`. Those three pages and `/` carry an identical inline `<script>/*PNAKOTIC_TEST_SKIMMER*/</script>` footer.
- `/g/` has no links and no footer. Its HTML carries the footer only when the User-Agent contains `Googlebot`.
- `/hang/` sleeps 20 s before answering.
- `/plain/` has no links and no footer, and holds a GA-shaped plain loader (the Task 5 `LOADER` shape) to `http://localhost:<port>/clean.js`.
- `/obf/` has no links and no footer, and holds the Task 5 `OBF` code followed by an `insertBefore` loader to `http://localhost:<port>/clean.js`.
- `/to-other/` is a 302 to `http://localhost:<port>/about/`.

Run SiteScanner with `budget_s=8` where the budget matters.

```python
@requires_browser
@pytest.mark.asyncio
async def test_site_scan_compromised_with_snippet_and_merged_footer(site_server, tmp_path, yara_rules_dir):
    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/")
    r = out.report
    assert r["verdict"]["verdict"] == "compromised"
    footer = [b for b in r["blocks"] if b["findings"][0]["details"]["rule"] == "js_skimmer_test_001" and b["location_kind"] == "page"]
    assert len(footer) == 1 and len(footer[0]["findings"][0]["pages"]) >= 3
    assert footer[0]["findings"][0]["snippet"]["line"] >= 1
    assert [p["index"] for p in r["checked"]["pages"]][-1] == len(r["checked"]["pages"]) - 1  # probe last
    assert any("/pnakotic-" in p["url"] for p in r["checked"]["pages"])

@requires_browser
@pytest.mark.asyncio
async def test_site_scan_googlebot_only_visitor(site_server, tmp_path, yara_rules_dir):
    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/g/")
    f = out.report["blocks"][0]["findings"][0]
    assert f["visitors"] == ["googlebot"]

@requires_browser
@pytest.mark.asyncio
async def test_site_scan_obfuscated_injector_is_suspicious_plain_loader_is_clean(site_server, tmp_path):
    assert (await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/obf/")).report["verdict"]["verdict"] == "suspicious"
    assert (await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/plain/")).report["verdict"]["verdict"] == "clean"

@requires_browser
@pytest.mark.asyncio
async def test_site_scan_budget_marks_not_checked(site_server, tmp_path):
    out = await SiteScanner(_site_engine(tmp_path), budget_s=8, grace_s=1).scan(f"{site_server}/hang/")
    assert out.report["verdict"]["verdict"] == "couldnt_check"
    assert out.report["checked"]["not_checked"] >= 1

@requires_browser
@pytest.mark.asyncio
async def test_site_scan_offsite_homepage_not_crawled(site_server, tmp_path):
    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/to-other/")
    kinds = [f["kind"] for b in out.report["blocks"] for f in b["findings"]]
    assert "offsite_homepage" in kinds
    pages = [p["url"] for p in out.report["checked"]["pages"]]
    assert len(pages) == 2 and "/pnakotic-" in pages[1]   # only the probe after the homepage
```

(`same_domain("127.0.0.1", "localhost")` is false (Task 1), so `/to-other/` exercises the off-site path.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_site_engine.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement `site_engine.py`**

Implement the flow above. `worst_score` is the max of the per-page combined scores. `redirect_chain` is true when any load has `is_redirect_chain_detected`. `artifact_manifest` is `engine.artifacts.get_task_manifest(engine.task_id)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_site_engine.py -v`
Expected: PASS (browser tests are skipped without Chromium; say so if they skip)

- [ ] **Step 5: Commit**

```bash
git add src/scanner/site_engine.py tests/_support.py tests/test_site_engine.py
git commit -m "Add the site quick-check orchestrator: homepage, page picking, budgeted loads"
```

### Task 10: Job kind, worker task, site queue

**Files:**
- Modify: `src/database/models.py` (`ScanJob.kind`), `src/workers/celery_app.py`, `docker-compose.yml`
- Create: `alembic/versions/0002_job_kind.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `SiteScanner`, `SiteOutcome` (Task 9)
- Produces:
  - `ScanJob.kind = Column(String, nullable=False, default="url", server_default="url")`
  - Celery task `run_site_scan_worker(job_id: str, homepage_url: str)` named `"pnakotic.site_scan"`, with `soft_time_limit=240, time_limit=300`
  - `celery_app.conf.task_routes = {"pnakotic.site_scan": {"queue": "site"}}`
  - The stored `metadata_json` is `{"kind": "site", "site": report, "artifact_manifest": …, "raw_error": …, "blocked_hosts": …, "scan_time": …}`
  - The result row's columns come from `SiteOutcome`: `target_url = homepage_url`, `final_url`, `malicious_score = worst_score`, `is_redirect_chain_detected = redirect_chain`.

- [ ] **Step 1: Write the failing tests**

Follow `test_worker_success_writes_result_and_replaces_stale_row`.
- Give `_add_job` a `kind="url"` keyword argument.
- Add a `fake_site_scanner` fixture. It monkeypatches `pnakotic.src.scanner.site_engine.SiteScanner` with a class whose `async scan(url)` returns `SiteOutcome(report={"verdict": {"verdict": "clean"}}, homepage_url=url, final_url=url, worst_score=0.0, redirect_chain=False, artifact_manifest={}, raw_error=None)`.
- Read the result row with `Session().query(models.ScanResult).filter_by(job_id=...).one()`.

```python
def test_site_worker_writes_report_and_is_idempotent(db, fake_site_scanner):
    from pnakotic.src.database import models
    from pnakotic.src.workers.celery_app import run_site_scan_worker
    _add_job(db, "s1", "queued", kind="site")
    run_site_scan_worker("s1", "https://s.com/")
    s = db(); row = s.query(models.ScanResult).filter_by(job_id="s1").one(); s.close()
    assert row.metadata_json["kind"] == "site" and row.metadata_json["site"]["verdict"]["verdict"] == "clean"
    assert _job(db, "s1").status == "completed"
    assert run_site_scan_worker("s1", "https://s.com/").startswith("Already completed")

def test_site_task_is_routed_to_site_queue():
    from pnakotic.src.workers.celery_app import celery_app
    assert celery_app.conf.task_routes["pnakotic.site_scan"] == {"queue": "site"}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_api.py -k "site_worker or site_queue" -v`
Expected: FAIL (`ImportError: run_site_scan_worker`)

- [ ] **Step 3: Implement**

- Copy `run_scan_worker`'s lifecycle: skip completed jobs, set `running` and `updated_at`, delete the stale result row, mark `failed` on an exception. Import inside the task body.
- The migration adds `kind` with `server_default="url"`, and downgrade drops it.
- Compose gains a `site-worker` service: the `worker` service's settings with `command: celery -A pnakotic.src.workers.celery_app worker -Q site --concurrency 1 --loglevel=info` and `replicas: 1`.
- The existing `worker` gets `-Q celery`, so it doesn't take site tasks.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_api.py -v`
Expected: PASS (existing worker tests included)

- [ ] **Step 5: Commit**

```bash
git add src/database/models.py alembic/versions/0002_job_kind.py src/workers/celery_app.py docker-compose.yml tests/test_api.py
git commit -m "Add site-check job kind, worker task and dedicated site queue"
```

### Task 11: API

**Files:**
- Modify: `src/api/main.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `normalize_site_input` (Task 1), `run_site_scan_worker` (Task 10)
- Produces:
  - `POST /site-scan` taking `{"site": str}` (1–2048 characters) and returning `201` with `{"task_id", "status": "queued", "artifact_dir"}`. It returns `422` when `normalize_site_input` raises, `400` from `_assert_public_host(homepage)`, and `503` when dispatch fails (the job is marked failed, as in `/scan`).
  - `serialize_result()` adds `"kind": meta.get("kind", "url")`. For sites it also adds `"site": meta.get("site")` and `"cleanup_url": os.getenv("CLEANUP_URL", "https://elderward.space.fast")`.
  - `/tasks` entries gain `"kind": job.kind or "url"`.

- [ ] **Step 1: Write the failing tests**

```python
def test_site_scan_dispatches_and_lists_kind(client, monkeypatch):
    sent = []
    class FakeTask:
        @staticmethod
        def delay(*a): sent.append(a)
    monkeypatch.setattr(main, "run_site_scan_worker", FakeTask)
    async def _noop_async(*a, **k): return None
    monkeypatch.setattr(main, "_assert_public_host", _noop_async)
    r = client.post("/site-scan", json={"site": "Example.COM/blog"})
    assert r.status_code == 201 and sent[0][1] == "https://example.com/"
    assert client.get("/tasks").json()["tasks"][0]["kind"] == "site"

def test_site_scan_rejects_bad_input_and_internal_host(client):
    assert client.post("/site-scan", json={"site": "ftp://x"}).status_code == 422
    assert client.post("/site-scan", json={"site": "127.0.0.1"}).status_code == 400

def test_serialize_result_site_fields(monkeypatch):
    monkeypatch.setenv("CLEANUP_URL", "https://clean.example/")
    row = models.ScanResult(id="r", job_id="j", target_url="https://s.com/", metadata_json={"kind": "site", "site": {"verdict": {}}})
    out = main.serialize_result(row)
    assert out["kind"] == "site" and out["site"] == {"verdict": {}} and out["cleanup_url"] == "https://clean.example/"
    assert main.serialize_result(models.ScanResult(id="r2", job_id="j2", target_url="x", metadata_json={}))["kind"] == "url"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m pytest tests/test_api.py -k "site_scan or serialize_result_site" -v`
Expected: FAIL with `404` on `/site-scan`

- [ ] **Step 3: Implement**

`POST /site-scan` is `async` for the DNS check, and runs DB and dispatch through `run_in_threadpool`, like `/scan`. The job is `kind="site"`, `profile="default"`, `target_url=homepage`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_api.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/api/main.py tests/test_api.py
git commit -m "Expose POST /site-scan and return kind and the site report"
```

### Task 12: Dashboard

**Files:**
- Modify: `frontend/src/lib/api.ts`, `frontend/src/components/ScanForm.tsx`, `frontend/src/components/SelectedScan.tsx`, `frontend/src/components/ScanList.tsx`, `frontend/src/components/Dashboard.tsx` (whatever wiring the form needs)
- Create: `frontend/src/components/SiteReport.tsx`

**Interfaces:**
- Consumes: the API shape from Task 11
- Produces:
  - in `api.ts`:
    - `TaskState.kind: 'url' | 'site'`
    - `ScanResultData.kind?`, `site?: SiteReportData | null`, `cleanup_url?: string`
    - interfaces `SiteReportData`, `SiteBlock`, `SiteFinding`, `ExternalScriptHost`, `SiteChecked` that mirror Tasks 7–8 field for field
    - `startSiteScan(site: string): Promise<string>`
  - `SiteReport({ taskId, result }: { taskId: string; result: ScanResultData })`

Layout A (§6). Top to bottom:
1. The verdict line, with its literal label and the summary. When `redirected_from` is set, add "Scanned <site> (<redirected_from> redirects here)". Add each entry of `notes` as a quiet line under it.
2. The cleanup pointer, linking to `result.cleanup_url`, shown only for `compromised` and `suspicious`. Copy for Compromised: "Clean it up with Elderward". For Suspicious: "If you think this is a hack, Elderward can check and clean it".
3. Finding blocks, each with:
   - the location URL in Plex Mono
   - per finding: severity, the plain message, the snippet with `<mark>` over `match_start..match_end`, and "line N"
   - the origin line: served → "Found in the HTML your server sent"; rendered → "Added by a script while the page loaded"; script → "In this script file"
   - who saw it: "Seen by every visitor type", or "Only: googlebot, …"
   - the page list
   - a collapsed **Details** section: rule, signature ID, profiles, `loaded` / `loaded_by`, and screenshot links through `artifactUrl`
4. **External scripts**, collapsed per host.
5. **What was checked**: pages × visitor types with each state and reason (`partial` reads "didn't finish loading; what loaded was checked"), the rule count or "Malware rules not configured", and "N other pages clean".

`ScanForm` gains a two-option switch, **Site check** (the default; one input, placeholder `example.com`) and **URL probe** (today's form, unchanged). `SelectedScan` renders `SiteReport` when `task.kind === 'site'` and today's view otherwise. `ScanList` shows a small `SITE` / `URL` tag. Use only the existing Tailwind tokens and `.taste-skill/notes.md` rules: 1px accent selection, no glow.

- [ ] **Step 1: Add the types and `startSiteScan`, then type-check**

Run: `cd frontend && npm run build`
Expected: PASS (types compile; no UI yet)

- [ ] **Step 2: Build `SiteReport.tsx`, the form switch and the list tag**

- [ ] **Step 3: Type-check and build**

Run: `cd frontend && npm run build`
Expected: PASS with no TypeScript errors

- [ ] **Step 4: Check it in the browser against the running stack**

Run: `docker compose up --build -d`, open `http://localhost:5173`, and run a Site check against a real WordPress site. Confirm all of these, and screenshot the result:
- the verdict
- the "What was checked" section
- the external scripts list
- a Couldn't check result for `nonexistent-pnakotic-test.invalid`
- that the URL probe still works

- [ ] **Step 5: Commit**

```bash
git add frontend/src
git commit -m "Add the Site check form and layout-A site report to the dashboard"
```

### Task 13: Docs

**Files:**
- Modify: `README.md`, `CLAUDE.md`

- [ ] **Step 1: Update the docs**

- README: a "Site check" section covering what it does, the profiles, pages, budget and verdicts, `POST /site-scan`, `CLEANUP_URL`, and the `site-worker` service. Add a `kind` note to the API table.
- CLAUDE.md:
  - the site-check flow and its modules (`site_identity`, `page_picker`, `snippets`, `script_trace`, `obfuscation`, `challenge`, `site_findings`, `site_report`, `site_engine`)
  - `LoadOptions(site=True)`
  - the `site` queue
  - that site-mode scoring must not touch `WEIGHTS`
  - the three-places rule now covering `kind`, `site` and `cleanup_url`

- [ ] **Step 2: Run the full suite**

Run: `python3 -m pytest -q`
Expected: PASS. Note any browser tests that were skipped.

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "Document the site quick check"
```
