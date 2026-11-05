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

from .snippets import cut_snippet

YARA_MECHANISM = "yara_match"

MAX_SCRIPTS = 60               # script bodies kept per page
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
    """Keeps the bodies of the scripts a page loads (bounded), for scan_buffers()."""

    def __init__(self):
        self.scripts: List[Tuple[str, bytes]] = []
        self.total = 0
        self.dropped = 0
        self._tasks: set = set()

    def watch(self, page) -> None:
        page.on("response", self._on_response)

    def _on_response(self, response) -> None:
        try:
            if response.request.resource_type != "script" or not (200 <= response.status < 300):
                return
        except Exception:
            return
        if len(self.scripts) + len(self._tasks) >= MAX_SCRIPTS:
            self.dropped += 1
            return
        task = asyncio.ensure_future(self._keep(response))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

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
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=timeout)


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
        name = os.path.basename(url.split("?", 1)[0].split("#", 1)[0])
        if "." not in name:
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
