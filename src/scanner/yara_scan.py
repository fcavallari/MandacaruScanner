"""YARA rules over what the page actually ran: the rendered landing HTML, its frames, and
the body of every script it loaded (malvertising and injected skimmers live in scripts
that come from somewhere else, often an ad iframe).

The rules are not part of this repository. YARA_RULES_DIR points at a rules directory
(read-only in Docker); when it is unset or empty, scanning is off. Two layouts are
understood:

* a tree split by target (`html/`, `raw/`, `php/`, ...): every
  `html/` rule plus the `raw/` rules whose file name starts with `js` or `html`. PHP rules
  target server files and would only add noise on a rendered page.
* anything else: every `*.yar` / `*.yara` file under the directory.

Each file is compiled in its own namespace with the `filename` external defined (rules
may condition on it, e.g. `filename matches` a `.js` pattern). A file that fails to compile is skipped, not fatal.

All scanned bytes are attacker-controlled. libyara bounds its own regex work, every
match() call has a timeout, the number and size of buffers are capped, and the whole
scan has a time budget, so one hostile page can't pin the worker.
"""
import asyncio
import glob
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from .script_trace import blocked_script_reason
from .snippets import cut_snippet

YARA_MECHANISM = "yara_match"

MAX_SCRIPTS = 60               # script bodies kept per page
MAX_FLAGGED = 20               # script responses a CDN blocked as malware, recorded per page
MAX_PROBES = 20                # ORB-dropped script responses re-fetched per page (see ScriptCollector)
PROBE_TIMEOUT_MS = 5000        # per re-fetch
PROBE_MAX_BYTES = 262144       # a re-fetched body larger than this (by Content-Length) is not read
MAX_FRAMES = 10                # subframe documents kept per page
MAX_BUFFER_BYTES = 2_000_000   # per buffer (larger ones are truncated)
MAX_TOTAL_BYTES = 12_000_000   # per page, across buffers
MATCH_TIMEOUT_S = 5            # per match() call (libyara's own timeout)
SCAN_BUDGET_S = 20.0           # per page, across buffers
MAX_TEXT = 300

_lock = threading.Lock()
_cache: Dict[str, Optional["YaraRules"]] = {}


def _rule_files(root: str) -> List[str]:
    if os.path.isdir(os.path.join(root, "html")) or os.path.isdir(os.path.join(root, "raw")):
        files = glob.glob(os.path.join(root, "html", "*.yar*"))
        files += [f for f in glob.glob(os.path.join(root, "raw", "*.yar*"))
                  if os.path.basename(f).lower().startswith(("js", "html"))]
    else:
        files = glob.glob(os.path.join(root, "**", "*.yar"), recursive=True)
        files += glob.glob(os.path.join(root, "**", "*.yara"), recursive=True)
    return sorted(f for f in set(files) if f.endswith((".yar", ".yara")) and os.path.isfile(f))


class YaraRules:
    def __init__(self, rules, count: int, skipped: List[str]):
        self.rules = rules
        self.count = count
        self.skipped = skipped

    @classmethod
    def compile_dir(cls, root: str) -> Optional["YaraRules"]:
        import yara  # imported lazily: scanning is optional

        files = _rule_files(root)
        good: Dict[str, str] = {}
        skipped = []
        for i, path in enumerate(files):
            try:
                yara.compile(filepath=path, externals={"filename": ""})
            except yara.Error as exc:
                skipped.append(f"{os.path.basename(path)}: {str(exc)[:160]}")
                continue
            good[f"f{i}"] = path  # one namespace per file: same-named rules can't collide
        if not good:
            return None
        rules = yara.compile(filepaths=good, externals={"filename": ""})
        return cls(rules, len(good), skipped)

    def match(self, data: bytes, filename: str) -> list:
        import yara

        try:
            return self.rules.match(data=data, externals={"filename": filename}, timeout=MATCH_TIMEOUT_S)
        except yara.TimeoutError:
            return []


def load_rules() -> Optional[YaraRules]:
    """The process-wide compiled rules for YARA_RULES_DIR, or None when scanning is off."""
    root = os.environ.get("YARA_RULES_DIR", "").strip()
    if not root or not os.path.isdir(root):
        return None
    with _lock:
        if root not in _cache:
            try:
                compiled = YaraRules.compile_dir(root)
            except ImportError:
                print("[yara] yara-python is not installed; YARA scanning is off")
                compiled = None
            if compiled:
                print(f"[yara] {compiled.count} rule files from {root}"
                      + (f", {len(compiled.skipped)} skipped" if compiled.skipped else ""))
                for line in compiled.skipped[:20]:
                    print(f"[yara] skipped {line}")
            else:
                print(f"[yara] no usable rules under {root}; YARA scanning is off")
            _cache[root] = compiled
        return _cache[root]


def _text(value: Any) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).replace("\x00", "")[:MAX_TEXT]


def _meta_int(meta: dict, key: str, default: int = 0) -> int:
    try:
        return int(meta.get(key, default))
    except (TypeError, ValueError):
        return default


def _snippet(match) -> str:
    for string_match in getattr(match, "strings", [])[:1]:
        for instance in getattr(string_match, "instances", [])[:1]:
            return _text(bytes(instance.matched_data[:80]))
    return ""


class ScriptCollector:
    """Keeps the bodies of the scripts a page loads (bounded), for scan_buffers().

    Also records, in ``flagged``, the script responses a CDN refused as malware (see
    ``script_trace.blocked_script_reason``): those scripts never ran and have no body to
    scan, but the refusal itself is evidence. Bounded separately (MAX_FLAGGED) so blocked
    responses never crowd out the bodies.

    Such a refusal is an HTML page in a script's place. For a cross-origin script Chromium's
    opaque-response blocking drops it before any response event fires (the request fails
    with ``net::ERR_BLOCKED_BY_ORB``; neither Playwright nor CDP sees status or body), so
    those few requests are fetched once more through the browser context's request API:
    same user agent and cookies, same launch-level egress proxy, which still refuses any
    non-public host (the URL is attacker-supplied). Bounded by MAX_PROBES per page, a
    timeout and a body-size cap, so a hostile page can't turn this into a fetch loop.
    """

    def __init__(self):
        self.scripts: List[Tuple[str, bytes]] = []
        self.flagged: List[dict] = []  # {"url", "status", "reason"}, one per URL
        self.total = 0
        self.dropped = 0
        self.probes = 0  # ORB-dropped script responses re-fetched (attempts)
        self._tasks: set = set()
        self._flag_tasks: set = set()

    def watch(self, page) -> None:
        page.on("response", self._on_response)
        page.on("requestfailed", lambda request: self._on_failed(request, page.context))

    def _on_response(self, response) -> None:
        try:
            if response.request.resource_type != "script":
                return
            status = response.status
        except Exception:
            return
        if not (200 <= status < 300):
            # Only a 403 can be an interstitial; anything else is an ordinary failed load.
            if status == 403 and len(self.flagged) + len(self._flag_tasks) < MAX_FLAGGED:
                task = asyncio.ensure_future(self._flag(response))
                self._flag_tasks.add(task)
                task.add_done_callback(self._flag_tasks.discard)
            return
        if len(self.scripts) + len(self._tasks) >= MAX_SCRIPTS:
            self.dropped += 1
            return
        task = asyncio.ensure_future(self._keep(response))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _flag(self, response) -> None:
        try:
            body = await response.body()
        except Exception:
            return  # page or context already closed, or a body Playwright can't give us
        try:
            headers = dict(response.headers or {})
        except Exception:
            headers = {}
        self._record(response.url, response.status, headers, body)

    def _record(self, url: str, status: int, headers: dict, body: bytes) -> None:
        reason = blocked_script_reason(status, headers, body)
        url = _text(url)
        if reason is None or any(f["url"] == url for f in self.flagged) or len(self.flagged) >= MAX_FLAGGED:
            return
        self.flagged.append({"url": url, "status": status, "reason": reason})

    def _on_failed(self, request, context) -> None:
        try:
            if request.resource_type != "script" or "ERR_BLOCKED_BY_ORB" not in str(request.failure or ""):
                return
            url = request.url
        except Exception:
            return
        if not url.startswith(("http://", "https://")) or self.probes >= MAX_PROBES:
            return
        if len(self.flagged) + len(self._flag_tasks) >= MAX_FLAGGED:
            return
        self.probes += 1
        task = asyncio.ensure_future(self._probe(context, url))
        self._flag_tasks.add(task)
        task.add_done_callback(self._flag_tasks.discard)

    async def _probe(self, context, url: str) -> None:
        """Fetch an ORB-dropped script URL once more to see the page that stood in for it."""
        try:
            response = await context.request.get(url, max_redirects=0, timeout=PROBE_TIMEOUT_MS,
                                                 fail_on_status_code=False)
        except Exception:
            return  # refused by the egress proxy, timed out, or the context is gone
        try:
            headers = {k.lower(): v for k, v in (response.headers or {}).items()}
            try:
                length = int(headers.get("content-length") or 0)
            except ValueError:
                length = 0
            body = b"" if length > PROBE_MAX_BYTES else await response.body()
        except Exception:
            return
        finally:
            try:
                await response.dispose()
            except Exception:
                pass
        self._record(url, response.status, headers, body[:PROBE_MAX_BYTES])

    async def _keep(self, response) -> None:
        try:
            length = int(response.headers.get("content-length") or 0)
        except ValueError:
            length = 0
        if length > MAX_BUFFER_BYTES * 4:  # don't pull a huge body just to truncate it
            self.dropped += 1
            return
        try:
            body = await response.body()
        except Exception:
            return  # page or context already closed, or a body Playwright can't give us
        if self.total >= MAX_TOTAL_BYTES:
            self.dropped += 1
            return
        body = body[:MAX_BUFFER_BYTES]
        self.total += len(body)
        self.scripts.append((_text(response.url), body))

    async def drain(self, timeout: float = 5.0) -> None:
        """Wait (bounded) for body fetches still in flight."""
        pending = list(self._tasks) + list(self._flag_tasks)
        if pending:
            await asyncio.wait(pending, timeout=timeout)


def _first_instance(match):
    for string_match in getattr(match, "strings", [])[:1]:
        for instance in getattr(string_match, "instances", [])[:1]:
            return instance
    return None


async def scan_buffers(rules: YaraRules, buffers: List[Tuple[str, str, bytes]],
                       per_buffer: bool = False) -> Tuple[List[dict], dict]:
    """Match every (source, url, data) buffer; one finding per rule (first hit, hit count).

    With per_buffer=True there is one finding per (rule, buffer) instead, each carrying
    `buffer_index` (position in `buffers`), `offset` (byte offset of the rule's first string
    match in the buffer) and `context` (cut_snippet around it); `offset` and `context` are
    None when the rule matched without a string instance.

    Runs libyara in a worker thread so the event loop (other profiles' pages) keeps going.
    """
    findings: Dict[Any, dict] = {}
    started = time.monotonic()
    scanned = 0
    total = 0
    exhausted = False
    for index, (source, url, data) in enumerate(buffers):
        if time.monotonic() - started > SCAN_BUDGET_S or total >= MAX_TOTAL_BYTES * 2:
            exhausted = True
            break
        data = data[:MAX_BUFFER_BYTES]
        total += len(data)
        # Rules may condition on the extension; script URLs often have none (/t/collect).
        # Runtime-built code is JavaScript whatever it claims to be (a stage can borrow a sourceURL).
        name = os.path.basename(url.split("?", 1)[0].split("#", 1)[0])
        if source == "eval":
            name = "script.js"
        elif "." not in name:
            name = "script.js" if source == "script" else "page.html"
        matches = await asyncio.to_thread(rules.match, data, name)
        scanned += 1
        for m in matches:
            key: Any = f"{m.namespace}:{m.rule}"
            if per_buffer:
                key = (key, index)
            if key in findings:
                findings[key]["hits"] += 1
                continue
            meta = dict(getattr(m, "meta", {}) or {})
            tags = list(getattr(m, "tags", []) or [])
            finding = findings[key] = {
                "id": "yara_match",
                "rule": _text(m.rule),
                "signature_id": _meta_int(meta, "signatureId"),
                "severity": _meta_int(meta, "severity"),
                "production": "production" in tags or meta.get("production") is True,
                "description": _text(meta.get("description", "")),
                "source": source,
                "url": url,
                "snippet": _snippet(m),
                "hits": 1,
            }
            if per_buffer:
                instance = _first_instance(m)
                finding["buffer_index"] = index
                finding["offset"] = instance.offset if instance else None
                finding["context"] = (cut_snippet(data, instance.offset, instance.offset + instance.matched_length)
                                      if instance else None)
    stats = {"rules": rules.count, "buffers": scanned, "bytes": total, "budget_exhausted": exhausted}
    return list(findings.values()), stats
