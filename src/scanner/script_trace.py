"""Which script started each script request, and where in the page that script sits.

``record_from_event`` / ``ScriptTracer`` turn CDP ``Network.requestWillBeSent`` events
into small records. ``find_injections`` keeps the script-started requests that go to
another site and, for inline initiators, finds the ``<script>`` block in the served HTML
(byte offsets, so a YARA match offset can be compared against it).

All page-supplied input is bounded: capped record and block counts, a bounded open-tag
regex, and a close-tag search that is a plain ``bytes.find`` moving forward only.
"""
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urldefrag

from .obfuscation import MAX_CHARS, obfuscator_markers
from .site_identity import same_domain
from .snippets import cut_snippet

MAX_RECORDS = 200
MAX_INJECTIONS = 50
MAX_INLINE_BLOCKS = 500
MAX_OPEN_TAGS = 5000  # open tags examined, whatever they turn out to hold
MAX_URL_CHARS = 300
MAX_PARENT_DEPTH = 20
BLOCK_CONTEXT_BYTES = 600

_OPEN_TAG_RE = re.compile(rb"<script\b[^>]{0,500}>", re.IGNORECASE)
_CLOSE_TAG = b"</script"


def _int_or_none(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _top_frame(stack: Any) -> Optional[Dict[str, Any]]:
    """The top call frame of a CDP stack trace, looking through ``parent`` when a stack
    has no frames of its own."""
    for _ in range(MAX_PARENT_DEPTH):
        if not isinstance(stack, dict):
            return None
        frames = stack.get("callFrames")
        if isinstance(frames, list) and frames and isinstance(frames[0], dict):
            return frames[0]
        stack = stack.get("parent")
    return None


def record_from_event(event: Dict[str, Any], main_frame_id: str) -> Optional[Dict[str, Any]]:
    """A record for a ``Network.requestWillBeSent`` event of ``type == "Script"``, else None."""
    if not isinstance(event, dict) or event.get("type") != "Script":
        return None
    request = event.get("request")
    url = request.get("url") if isinstance(request, dict) else None
    if not isinstance(url, str) or not url:
        return None
    initiator = event.get("initiator")
    if not isinstance(initiator, dict):
        initiator = {}
    kind = initiator.get("type")
    initiator_url = line = column = None  # type: Any
    if kind == "script":
        frame = _top_frame(initiator.get("stack"))
        if frame is not None:
            initiator_url, line, column = frame.get("url"), frame.get("lineNumber"), frame.get("columnNumber")
        else:
            initiator_url = initiator.get("url")
        kind_out = "script"
    elif kind == "parser":
        initiator_url, line, column = initiator.get("url"), initiator.get("lineNumber"), initiator.get("columnNumber")
        kind_out = "parser"
    else:
        kind_out = "other"
    frame_url = event.get("documentURL")
    return {
        "url": url[:MAX_URL_CHARS],
        "main_frame": event.get("frameId") == main_frame_id,
        "frame_url": frame_url[:MAX_URL_CHARS] if isinstance(frame_url, str) else "",
        "initiator": kind_out,
        "initiator_url": initiator_url[:MAX_URL_CHARS] if isinstance(initiator_url, str) and initiator_url else None,
        "line": _int_or_none(line),
        "column": _int_or_none(column),
    }


class ScriptTracer:
    """Collects the script requests of one page load (at most 200)."""

    def __init__(self) -> None:
        self.records = []  # type: List[Dict[str, Any]]
        self._main_frame_id = ""

    async def attach(self, cdp: Any, main_frame_id: str) -> None:
        self._main_frame_id = main_frame_id
        cdp.on("Network.requestWillBeSent", self._on_request)
        await cdp.send("Network.enable")

    def _on_request(self, event: Dict[str, Any]) -> None:
        if len(self.records) >= MAX_RECORDS:
            return
        record = record_from_event(event, self._main_frame_id)
        if record is not None:
            self.records.append(record)


def _inline_blocks(data: bytes, lowered: bytes) -> List[Tuple[int, int]]:
    """``(start, end)`` byte offsets of the first 500 non-empty inline ``<script>`` bodies.
    ``lowered`` is ``data.lower()`` (ASCII-only on bytes, so the offsets line up)."""
    blocks = []  # type: List[Tuple[int, int]]
    pos = 0
    for _ in range(MAX_OPEN_TAGS):
        match = _OPEN_TAG_RE.search(data, pos)
        if match is None:
            break
        start = match.end()
        end = lowered.find(_CLOSE_TAG, start)
        if end < 0:
            break  # no close tag anywhere after this point, so none for a later open tag either
        if end > start:
            blocks.append((start, end))
            if len(blocks) >= MAX_INLINE_BLOCKS:
                break
        pos = end + len(_CLOSE_TAG)
    return blocks


def _offset_of(data: bytes, line: Optional[int], column: Optional[int]) -> Optional[int]:
    """Byte offset of the 0-based CDP ``(line, column)`` in ``data``."""
    if line is None:
        return None
    line_start = 0
    for _ in range(line):
        nl = data.find(b"\n", line_start)
        if nl < 0:
            return None
        line_start = nl + 1
    column = column or 0
    line_end = data.find(b"\n", line_start)
    if line_end < 0:
        line_end = len(data)
    chunk = data[line_start:min(line_end, line_start + column * 4)]
    # CDP columns count characters, not bytes
    return line_start + len(chunk.decode("utf-8", "replace")[:column].encode("utf-8"))


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _pick_block(blocks: List[Tuple[int, int]], lowered: bytes, offset: Optional[int],
                url: str) -> Optional[Tuple[int, int]]:
    if offset is not None:
        for start, end in blocks:
            if start <= offset < end:
                return start, end
    needles = [n for n in (url.lower().encode("utf-8", "replace"), _host(url).encode("utf-8", "replace")) if n]
    if not needles:
        return None
    for needle in needles:  # the full URL beats the bare host
        for start, end in blocks:
            if lowered.find(needle, start, end) >= 0:
                return start, end
    return None


def _markers_of(raw: bytes) -> List[str]:
    return obfuscator_markers(raw[:MAX_CHARS * 4].decode("utf-8", "replace"))


def find_injections(records: List[Dict[str, Any]], page_url: str, served_html: Optional[bytes],
                    script_bodies: Dict[str, bytes]) -> List[Dict[str, Any]]:
    """Script-started requests for a script on another registrable domain than the page.

    ``initiator_kind`` is ``inline`` when the initiating script is the page itself
    (fragment ignored) and ``script`` when it is a file. For an inline initiator, ``block``
    is the byte range of its ``<script>`` body in ``served_html``.
    """
    page_key = urldefrag(page_url or "")[0]
    page_host = _host(page_url or "")
    blocks = None  # type: Optional[List[Tuple[int, int]]]
    lowered = b""
    out = []  # type: List[Dict[str, Any]]
    for rec in records:
        if len(out) >= MAX_INJECTIONS:
            break
        if rec.get("initiator") != "script":
            continue
        url = rec.get("url") or ""
        if not url.startswith(("http://", "https://")):
            continue
        host = _host(url)
        if not host or not page_host or same_domain(host, page_host):
            continue
        initiator_url = rec.get("initiator_url")
        line, column = rec.get("line"), rec.get("column")
        inline = initiator_url is not None and urldefrag(initiator_url)[0] == page_key
        block = None  # type: Optional[Dict[str, int]]
        markers = []  # type: List[str]
        context = None  # type: Optional[Dict[str, Any]]
        if inline:
            if served_html is not None:
                if blocks is None:
                    lowered = served_html.lower()
                    blocks = _inline_blocks(served_html, lowered)
                picked = _pick_block(blocks, lowered, _offset_of(served_html, line, column), url)
                if picked is not None:
                    block = {"start": picked[0], "end": picked[1]}
                    markers = _markers_of(served_html[picked[0]:picked[1]])
                    context = cut_snippet(served_html, picked[0], picked[1], before=0, after=0,
                                          cap=BLOCK_CONTEXT_BYTES)
        elif initiator_url is not None and initiator_url in script_bodies:
            body = script_bodies[initiator_url]
            markers = _markers_of(body)
            offset = _offset_of(body, line, column)
            if offset is not None:
                context = cut_snippet(body, offset, offset + 1)
        out.append({
            "requested_url": url,
            "initiator_kind": "inline" if inline else "script",
            "initiator_url": initiator_url,
            "block": block,
            "markers": markers,
            "context": context,
        })
    return out
