"""Whose code is it: decide whether a JavaScript stack belongs to the store, a payment
provider, a known vendor, or unknown code.

Every stack string and URL here is page-supplied, so it is bounded: the stack is cut to
``MAX_STACK_CHARS`` characters and parsed into at most ``MAX_FRAMES`` frames, and a frame URL
is at most 300 characters. A frame that can't be read (``eval``, ``<anonymous>``, no URL, a
URL that is too long) is an eval frame with an empty URL, which counts as unknown code.

A frame at the page's own URL is store code only when its script is one of the inline
``<script>`` blocks the server sent, matched by content: the frame carries V8's script hash
(``sha256=<hex>`` after the location, written by ``card_watch``'s stack formatter) and it must
equal the SHA-256 of a served block (``inline_script_hashes``). A line number is not enough: an
event handler attribute a script sets at runtime (``onerror="…"``) also runs at the page URL,
at line 1 or wherever the parser was, plus any newlines its text starts with.

"Store" means no frame on the recorded stack was outside code, not that the store's code is
proven to have done it. Known limits: a skimmer written to evade this check can read as the
store's by
- inserting through a store function scheduled on a timer (a bound jQuery method: only store
  frames are on the stack when it runs);
- setting an event handler while ``history.replaceState`` points the document at a same-host
  script path (the handler's frame then names that path, a store file);
- writing an event handler with ``document.open()`` / ``write()`` at a served inline block's
  exact position on a one-line page (the block's text, so its hash, at the block's start);
- pre-filling the 20 event slots with store re-renders (later insertions are only counted);
- padding past the 5 000-sibling walk the hook does for HTML handed over as an object.
It can also turn a finding into "couldn't check" (``judge_stack``'s ``verified``) by flooding
the parse-position record past 2 000 scripts. Phase 2's test-card exfiltration check, which
watches where typed card data goes, is the decisive one; this is a watch-only signal.
"""
import hashlib
import re
from bisect import bisect_right
from typing import Collection, Dict, List, NamedTuple, Optional, Set, Tuple
from urllib.parse import urldefrag, urlsplit

from .script_trace import inline_blocks, line_starts
from .site_identity import registrable_domain


class Frame(NamedTuple):
    url: str
    line: Optional[int]
    eval: bool
    hash: Optional[str] = None  # V8's SHA-256 of the frame's script (lower-case hex), when known

MAX_STACK_CHARS = 4000
MAX_FRAMES = 30

STORE_CDN_HOSTS = {"c0.wp.com", "s0.wp.com", "code.jquery.com"}
# Hosts that serve anyone's files, so only the jQuery family counts as the store's own. Each
# prefix must be followed by the end of the path, "/", "@" or "." (see ``_path_has_prefix``):
# ``/npm/jquery@3.7.1/x.js`` matches, ``/npm/jquery-evil@1/x.js`` does not.
STORE_CDN_PATH_HOSTS = {
    "cdnjs.cloudflare.com": ("/ajax/libs/jquery", "/ajax/libs/jqueryui", "/ajax/libs/jquery-migrate"),
    "cdn.jsdelivr.net": ("/npm/jquery", "/npm/jquery-ui", "/npm/jquery-ui-dist", "/npm/jquery-migrate"),
    "ajax.googleapis.com": ("/ajax/libs/jquery", "/ajax/libs/jqueryui"),
}  # type: Dict[str, Tuple[str, ...]]
PAYMENT_PROVIDERS = {
    "stripe.com", "stripe.network", "paypal.com", "paypalobjects.com",
    "braintreegateway.com", "braintree-api.com", "squareup.com", "squarecdn.com",
    "adyen.com", "authorize.net", "wordpress.com",  # wordpress.com: WooPayments
    "klarna.com", "klarnacdn.net", "mollie.com",
}
KNOWN_VENDORS = {
    "hotjar.com": "Hotjar",
    "clarity.ms": "Microsoft Clarity",
    "fullstory.com": "FullStory",
    "signifyd.com": "Signifyd",
    "sift.com": "Sift",
    "klaviyo.com": "Klaviyo",
    "google-analytics.com": "Google Analytics",
    "googletagmanager.com": "Google Tag Manager",
}  # type: Dict[str, str]

_FRAME_START_RE = re.compile(r"^\s*at\s")
# card_watch's formatter writes a frame as exactly "    at <url>:<line>:<column>", optionally
# followed by " sha256=<hex>", and only for a URL matching ^https?://[^\s()]+$ of at most 300
# characters; everything else is "    at <anonymous>" or "    at eval (eval at <anonymous>)".
# So the location is anchored right after "at " and the hash is the only thing after it: no
# function name, query string or text inside a URL can pose as a location.
_LOCATION_RE = re.compile(r"^\s*at (https?://[^\s()]{1,300}?):(\d{1,7}):\d{1,7}(?: sha256=([0-9a-f]{64}))?$")
_EVAL_FRAME = Frame("", None, True)


def whole_lines(text: str, limit: int = MAX_STACK_CHARS) -> str:
    """``text`` cut to ``limit`` characters without a partial last line: a cut that lands
    inside a line drops that line (a frame cut short could end in a different location)."""
    text = text or ""
    if len(text) <= limit:
        return text
    if text[limit] == "\n":
        return text[:limit]
    cut = text[:limit]
    return cut[:cut.rfind("\n")] if "\n" in cut else ""


def parse_stack(stack: str) -> List[Frame]:
    """card_watch's stack text (its formatter is the only producer; V8's own text is not read)
    to at most 30 frames. The input is cut to 4 000 characters at a line end."""
    frames = []  # type: List[Frame]
    for text in whole_lines(stack).split("\n"):
        if not _FRAME_START_RE.match(text):
            continue
        match = None if "eval at" in text else _LOCATION_RE.match(text)
        if match is None:
            frames.append(_EVAL_FRAME)
        else:
            frames.append(Frame(match.group(1), int(match.group(2)), False, match.group(3)))
        if len(frames) >= MAX_FRAMES:
            break
    return frames


def stack_was_cut(stack: str) -> bool:
    """True when ``parse_stack`` leaves part of ``stack`` out: the text is over 4 000
    characters, or the kept part holds more than 30 frame lines."""
    stack = stack or ""
    if len(stack) > MAX_STACK_CHARS:
        return True
    return sum(1 for text in stack.split("\n") if _FRAME_START_RE.match(text)) > MAX_FRAMES


def inline_line_ranges(served_html: Optional[bytes]) -> List[Tuple[int, int]]:
    """1-based ``(first_line, last_line)`` of every inline ``<script>`` block in the served
    HTML (the same blocks ``find_injections`` sees). Where a block is, not whose code a frame
    is: ownership goes by ``inline_script_hashes``."""
    if not served_html:
        return []
    blocks = inline_blocks(served_html, served_html.lower())
    if not blocks:
        return []
    starts = line_starts(served_html, len(served_html))
    return [(bisect_right(starts, start), bisect_right(starts, max(start, end - 1)))
            for start, end in blocks]


# WHATWG windows-1252: cp1252, with the five bytes cp1252 leaves undefined read as U+0081 etc.
_C1 = {}  # type: Dict[int, str]
for _byte in range(0x80, 0xA0):
    try:
        _C1[_byte] = bytes([_byte]).decode("cp1252")
    except UnicodeDecodeError:
        pass


def _windows_1252(data: bytes) -> str:
    return data.decode("latin-1").translate(_C1)


def _normalized(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")  # the HTML parser's newline rule


def inline_script_texts(served_html: Optional[bytes]) -> List[str]:
    """The text of every inline ``<script>`` block in the served HTML as the browser runs it on
    a UTF-8 page: decoded as UTF-8, with CRLF and CR turned into LF."""
    if not served_html:
        return []
    return [_normalized(served_html[start:end].decode("utf-8", "replace"))
            for start, end in inline_blocks(served_html, served_html.lower())]


def inline_script_hashes(served_html: Optional[bytes]) -> Set[str]:
    """SHA-256 (hex) of each served inline block's text, which is what V8 reports as the
    script hash of that block (observed in Chromium 148 for ASCII, UTF-8, CRLF, CR and
    one-line pages). Each block is hashed as UTF-8 and as windows-1252 (what Chromium reads a
    page without a declared charset as); a page in another charset has non-ASCII blocks that
    match neither, so their frames read as unknown."""
    return set(served_block_positions(served_html))


_BOM = b"\xef\xbb\xbf"
_DECODERS = (lambda raw: raw.decode("utf-8", "replace"), _windows_1252)


def _utf16_len(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def served_block_positions(served_html: Optional[bytes]) -> Dict[str, Set[Tuple[int, int]]]:
    """``{hash: {(line, column)}}`` for every served inline block: the SHA-256 of its text (as
    ``inline_script_hashes``) and where its text starts in the document, in CDP's coordinates
    (0-based line, 0-based column in UTF-16 units, after a leading BOM is dropped and CRLF / CR
    become LF), as ``Debugger.scriptParsed`` reports the block (``startLine``, ``startColumn``).
    Each block is read as UTF-8 and as windows-1252, so it can have two hashes and positions."""
    out = {}  # type: Dict[str, Set[Tuple[int, int]]]
    if not served_html:
        return out
    data = served_html[len(_BOM):] if served_html.startswith(_BOM) else served_html
    blocks = inline_blocks(data, data.lower())
    for decode in _DECODERS:
        line, column, done = 0, 0, 0
        for start, end in blocks:
            chunk = _normalized(decode(data[done:start]))  # ends with ">", so no CRLF is split
            breaks = chunk.count("\n")
            if breaks:
                line += breaks
                column = _utf16_len(chunk[chunk.rfind("\n") + 1:])
            else:
                column += _utf16_len(chunk)
            done = start
            digest = hashlib.sha256(_normalized(decode(data[start:end])).encode("utf-8")).hexdigest()
            out.setdefault(digest, set()).add((line, column))
    return out


# The charsets ``served_block_positions`` reads blocks in (Chromium's names, as
# ``document.characterSet`` gives them; ISO-8859-1 and US-ASCII are windows-1252 there).
READ_CHARSETS = {"utf-8", "windows-1252"}
_CONTROL_BYTES = re.compile(rb"[\x00-\x08\x0b\x0e-\x1f\x7f]")


def blocks_readable(served_html: Optional[bytes], charset: Optional[str]) -> bool:
    """Whether the served inline blocks' hashes and positions can be computed as the browser
    read them. ``charset`` is ``document.characterSet`` as the browser decided it (None when it
    couldn't be read). Readable when it is one ``served_block_positions`` decodes, or when the
    bytes up to the end of the last inline block are UTF-8 without control characters:
    Playwright's ``Response.body()`` gives a document's text as the browser decoded it,
    re-encoded as UTF-8 (CDP ``Network.getResponseBody`` of a text resource), so a Shift_JIS
    page usually arrives readable; raw bytes in another charset (a body CDP handed over
    undecoded) are seldom valid UTF-8, and ISO-2022-JP's escapes are control bytes. A page
    without inline blocks found has nothing to read."""
    if (charset or "").lower() in READ_CHARSETS or not served_html:
        return True
    blocks = inline_blocks(served_html, served_html.lower())
    if not blocks:
        return True
    head = served_html[:max(end for _, end in blocks)]
    if _CONTROL_BYTES.search(head):
        return False
    try:
        head.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def trusted_inline_hashes(served_html: Optional[bytes],
                          parsed: Optional[Dict[str, Set[Tuple[int, int]]]]) -> Set[str]:
    """The served-block hashes that make a page-URL frame count as the store's. ``parsed`` is every
    script the browser parsed whose frames carry the document URL (keyed by ``embedderName``, so a
    served block ending in a ``//# sourceURL`` comment is there too), plus every runtime script that
    named itself with one, ``{hash: {(startLine, startColumn)}}`` (``EvalCapture.positions_at``),
    or None when that record is incomplete. A hash counts only
    when the browser parsed it and every script with it starts where a served block starts: an
    event handler or a runtime script with a served block's exact text has the same hash, but
    not a served block's position, and then no frame with that hash is the store's."""
    if not parsed:
        return set()
    served = served_block_positions(served_html)
    return {digest for digest, where in parsed.items() if where and where <= served.get(digest, set())}


def _parts(url: str) -> Tuple[str, str]:
    """``(host, path)`` of ``url``, lower-case host; empty strings when it can't be read."""
    try:
        parts = urlsplit(url)
        return (parts.hostname or "").lower(), parts.path
    except ValueError:
        return "", ""


def _path_has_prefix(path: str, prefix: str) -> bool:
    """``path`` starts with ``prefix`` and the prefix ends a path segment or package name
    (end of path, ``/``, ``@`` or ``.``)."""
    return path.startswith(prefix) and (len(path) == len(prefix) or path[len(prefix)] in "/@.")


def _owner_key(host: str) -> str:
    """A host's registrable domain; one without (an IP, ``localhost``) stands for itself,
    so ``127.0.0.1`` and ``localhost`` are different owners."""
    host = host.rstrip(".")
    return registrable_domain(host) or host


def is_page_frame(frame: Frame, site_host: str, page_url: str) -> bool:
    """The frame runs at the page's own URL (fragment ignored) on the site: a served inline
    block, or an event handler or inline script set at runtime, told apart only by script hash
    and parse position."""
    if frame.eval or not frame.url:
        return False
    host = _parts(frame.url)[0]
    site_key = _owner_key((site_host or "").lower())
    return (bool(host) and bool(site_key) and _owner_key(host) == site_key
            and urldefrag(frame.url)[0] == urldefrag(page_url or "")[0])


def frame_owner(frame: Frame, site_host: str, page_url: str,
                inline_hashes: Optional[Collection[str]]) -> str:
    """``store``, ``provider``, ``vendor`` or ``unknown`` for one stack frame.
    ``inline_hashes``: ``inline_script_hashes`` of the served HTML."""
    if frame.eval or not frame.url:
        return "unknown"
    host, path = _parts(frame.url)
    if not host:
        return "unknown"
    key = _owner_key(host)
    site_key = _owner_key((site_host or "").lower())
    if site_key and key == site_key:
        if is_page_frame(frame, site_host, page_url):
            # the page's own URL: store code only when its script is a block the server sent
            if frame.hash and frame.hash in (inline_hashes or ()):
                return "store"
            return "unknown"  # an inline script or event handler added at runtime, or no hash
        return "store"
    if host in STORE_CDN_HOSTS:
        return "store"
    if any(_path_has_prefix(path, prefix) for prefix in STORE_CDN_PATH_HOSTS.get(host, ())):
        return "store"
    if key in PAYMENT_PROVIDERS:
        return "provider"
    if key in KNOWN_VENDORS:
        return "vendor"
    return "unknown"


class StackJudgement(NamedTuple):
    owner: str  # store | vendor | unknown (a payment provider's frame counts like a store frame)
    vendors: List[str]  # known vendors' names, when the owner is "vendor"
    verified: bool  # False: unknown only through page-URL frames the load couldn't check
    first_unknown: str  # URL of the first unknown frame ("" for eval / <anonymous> / none)


def judge_stack(frames: List[Frame], site_host: str, page_url: str,
                inline_hashes: Optional[Collection[str]], page_frames_checked: bool = True) -> StackJudgement:
    """Whose code a stack is, with every frame classified (``stack_owner`` is the short form).

    ``page_frames_checked`` is False when this load couldn't tell a served inline block from
    code set at runtime at the page URL (no parse record, no served HTML, a charset it can't
    hash, no script hash in this browser): a page-URL frame then reads unknown without proof
    either way. The owner is still ``unknown``, but ``verified`` is False when every unknown
    frame is such a page-URL frame. Any other unknown frame (another site, eval, ``<anonymous>``),
    or no frames at all, keeps it True: that is outside code whatever the load could check."""
    if not frames:
        return StackJudgement("unknown", [], True, "")
    vendors = []  # type: List[str]
    unknown = []  # type: List[Frame]
    for frame in frames:
        owner = frame_owner(frame, site_host, page_url, inline_hashes)
        if owner == "unknown":
            unknown.append(frame)
        elif owner == "vendor":
            name = KNOWN_VENDORS.get(_owner_key(_parts(frame.url)[0]), "")
            if name and name not in vendors:
                vendors.append(name)
    if unknown:
        verified = page_frames_checked or not all(is_page_frame(f, site_host, page_url) for f in unknown)
        return StackJudgement("unknown", [], verified, unknown[0].url)
    if vendors:
        return StackJudgement("vendor", vendors, True, "")
    return StackJudgement("store", [], True, "")


def stack_owner(frames: List[Frame], site_host: str, page_url: str,
                inline_hashes: Optional[Collection[str]]) -> Tuple[str, List[str]]:
    """``("unknown", [])`` if any frame is unknown or there are no frames; else
    ``("vendor", names)`` if any frame is a known vendor; else ``("store", [])``. A payment
    provider's frame counts like a store frame."""
    judged = judge_stack(frames, site_host, page_url, inline_hashes)
    return judged.owner, judged.vendors
