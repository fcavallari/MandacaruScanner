"""Which script started each script request, and where in the page that script sits.

``record_from_event`` / ``ScriptTracer`` turn CDP ``Network.requestWillBeSent`` events
into small records. ``find_injections`` keeps the script-started requests that go to
another site and, for inline initiators, finds the ``<script>`` block in the served HTML
(byte offsets, so a YARA match offset can be compared against it).

Each injection also carries ``body_markers``: the obfuscator markers of the script that was
loaded, when its body was kept. A plain loader (a URL assembled at runtime, say) fetching
obfuscator.io output shows nothing in the loader and everything in the body.

``blocked_script_reason`` names a script response the CDN refused on the visitor's behalf
(Cloudflare's "Suspected Malware" interstitial): the script never ran, so there is no body
to match, but a vendor's malware verdict on a script a page loads is evidence in itself.

All page-supplied input is bounded: capped record and block counts, a bounded open-tag
regex, and a close-tag search that is a plain ``bytes.find`` moving forward only.
"""
import re
from typing import Any, Container, Dict, List, Optional, Tuple
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
MAX_STACK_FRAMES = 50  # frames looked at per stack segment
BLOCK_CONTEXT_BYTES = 600
INTERSTITIAL_HEAD_BYTES = 65536  # how much of a blocked script's response body is examined

_INTERSTITIALS = (
    # (reason, the marker the body must carry, the vendor name in the body or the Server header)
    ("cloudflare_suspected_malware", b"Suspected Malware", b"cloudflare"),
)
# The reasons `blocked_script_reason` can return, and the vendor to name for each. The scorer
# and the site report ignore any other reason.
FLAGGED_VENDORS: Dict[str, str] = {"cloudflare_suspected_malware": "Cloudflare"}

_OPEN_TAG_RE = re.compile(rb"<script\b[^>]{0,500}>", re.IGNORECASE)
_CLOSE_TAG = b"</script"


def _int_or_none(value: Any) -> Optional[int]:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _top_frame(stack: Any, harness_ids: Container[str] = ()) -> Optional[Dict[str, Any]]:
    """The top call frame of a CDP stack trace, looking through ``parent`` when a stack
    has no frames of its own. Frames of the harness's own scripts (``harness_ids``, CDP script
    ids: our hooks wrap ``appendChild`` and friends, so a loader's call runs through them) are
    passed over."""
    for _ in range(MAX_PARENT_DEPTH):
        if not isinstance(stack, dict):
            return None
        frames = stack.get("callFrames")
        if isinstance(frames, list):
            for frame in frames[:MAX_STACK_FRAMES]:
                if isinstance(frame, dict) and frame.get("scriptId") not in harness_ids:
                    return frame
        stack = stack.get("parent")
    return None


def record_from_event(event: Dict[str, Any], main_frame_id: str,
                      harness_ids: Container[str] = ()) -> Optional[Dict[str, Any]]:
    """A record for a ``Network.requestWillBeSent`` event of ``type == "Script"``, else None."""
    if not isinstance(event, dict) or event.get("type") != "Script":
        return None
    if event.get("redirectResponse"):
        return None  # a redirect hop is the same request continuing, already recorded
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
        frame = _top_frame(initiator.get("stack"), harness_ids)
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

    def __init__(self, harness_ids: Container[str] = ()) -> None:
        self.records = []  # type: List[Dict[str, Any]]
        self._main_frame_id = ""
        self._harness_ids = harness_ids  # EvalCapture.harness_script_ids: filled as scripts are parsed

    async def attach(self, cdp: Any, main_frame_id: str) -> None:
        self._main_frame_id = main_frame_id
        cdp.on("Network.requestWillBeSent", self._on_request)
        await cdp.send("Network.enable")

    def _on_request(self, event: Dict[str, Any]) -> None:
        if len(self.records) >= MAX_RECORDS:
            return
        record = record_from_event(event, self._main_frame_id, self._harness_ids)
        if record is not None:
            self.records.append(record)


def inline_blocks(data: bytes, lowered: bytes) -> List[Tuple[int, int]]:
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


def line_starts(data: bytes, upto: int) -> List[int]:
    """Byte offsets where lines 0..``upto`` start (fewer if ``data`` has fewer lines).
    One forward pass, built once per document and shared by every record."""
    starts = [0]
    while len(starts) <= upto:
        nl = data.find(b"\n", starts[-1])
        if nl < 0:
            break
        starts.append(nl + 1)
    return starts


def _offset_of(data: bytes, starts: List[int], line: Optional[int],
               column: Optional[int]) -> Optional[int]:
    """Byte offset of the 0-based CDP ``(line, column)`` in ``data``; ``starts`` is
    ``line_starts(data, ...)`` covering ``line``."""
    if line is None or line >= len(starts):
        return None
    line_start = starts[line]
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
    is the byte range of its ``<script>`` body in ``served_html``. ``markers`` are the
    obfuscator markers of the initiating code; ``body_markers`` those of the script it
    loaded, when ``script_bodies`` has that body (an empty list otherwise).
    """
    page_key = urldefrag(page_url or "")[0]
    page_host = _host(page_url or "")
    blocks = None  # type: Optional[List[Tuple[int, int]]]
    lowered = b""
    html_starts = None  # type: Optional[List[int]]
    body_starts = {}  # type: Dict[str, List[int]]
    max_line = max([r["line"] for r in records if isinstance(r.get("line"), int)] or [0])
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
                    blocks = inline_blocks(served_html, lowered)
                    html_starts = line_starts(served_html, max_line)
                picked = _pick_block(blocks, lowered, _offset_of(served_html, html_starts, line, column), url)
                if picked is not None:
                    block = {"start": picked[0], "end": picked[1]}
                    markers = _markers_of(served_html[picked[0]:picked[1]])
                    context = cut_snippet(served_html, picked[0], picked[1], before=0, after=0,
                                          cap=BLOCK_CONTEXT_BYTES)
        elif initiator_url is not None and initiator_url in script_bodies:
            body = script_bodies[initiator_url]
            markers = _markers_of(body)
            if initiator_url not in body_starts:
                body_starts[initiator_url] = line_starts(body, max_line)
            offset = _offset_of(body, body_starts[initiator_url], line, column)
            if offset is not None:
                context = cut_snippet(body, offset, offset + 1)
        out.append({
            "requested_url": url,
            "initiator_kind": "inline" if inline else "script",
            "initiator_url": initiator_url,
            "block": block,
            "markers": markers,
            "body_markers": _markers_of(script_bodies[url]) if url in script_bodies else [],
            "context": context,
        })
    return out


def blocked_script_reason(status: int, headers: Dict[str, str], body: bytes) -> Optional[str]:
    """Why a CDN refused a script on the visitor's behalf, or None for a served script or a plain
    error. Only Cloudflare's "Suspected Malware" page is known; it must name Cloudflare in the
    first 64 kB of the body or in the Server header. ``body`` is attacker-reachable (it comes
    from the script's host), so only its head is read and only fixed substrings are looked for.
    """
    if status != 403 or not isinstance(body, (bytes, bytearray)):
        return None
    head = bytes(body[:INTERSTITIAL_HEAD_BYTES])
    server = str((headers or {}).get("server") or "").lower().encode("utf-8", "replace")
    for reason, marker, vendor in _INTERSTITIALS:
        if marker in head and (vendor in head.lower() or vendor in server):
            return reason
    return None
