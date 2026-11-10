"""Whose code is it: decide whether a JavaScript stack belongs to the store, a payment
provider, a known vendor, or unknown code.

Every stack string and URL here is page-supplied, so it is bounded: the stack is cut to
``MAX_STACK_CHARS`` characters and parsed into at most ``MAX_FRAMES`` frames, and a frame URL
is at most 300 characters. A frame that can't be read (``eval``, ``<anonymous>``, no URL, a
URL that is too long) is an eval frame with an empty URL, which counts as unknown code.
"""
import re
from bisect import bisect_right
from typing import Dict, List, NamedTuple, Optional, Tuple
from urllib.parse import urldefrag, urlsplit

from .script_trace import inline_blocks, line_starts
from .site_identity import registrable_domain

Frame = NamedTuple("Frame", [("url", str), ("line", Optional[int]), ("eval", bool)])

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
# V8 puts the real location last on the line, so read it from the end: a function name
# containing "(https://store/...)" can't pose as the location. A URL has no spaces or parens.
_LOCATION_RE = re.compile(r"(?:(?<=\()|(?<=\s))(https?://[^\s()]{1,300}?):(\d{1,7}):\d{1,7}\)?\s*$")
_EVAL_FRAME = Frame("", None, True)


def parse_stack(stack: str) -> List[Frame]:
    """V8 stack text to at most 30 frames (input cut to 4 000 characters)."""
    frames = []  # type: List[Frame]
    for text in (stack or "")[:MAX_STACK_CHARS].split("\n"):
        if not _FRAME_START_RE.match(text):
            continue
        match = None if "eval at" in text else _LOCATION_RE.search(text)
        if match is None:
            frames.append(_EVAL_FRAME)
        else:
            frames.append(Frame(match.group(1), int(match.group(2)), False))
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
    HTML (the same blocks ``find_injections`` sees)."""
    if not served_html:
        return []
    blocks = inline_blocks(served_html, served_html.lower())
    if not blocks:
        return []
    starts = line_starts(served_html, len(served_html))
    return [(bisect_right(starts, start), bisect_right(starts, max(start, end - 1)))
            for start, end in blocks]


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


def frame_owner(frame: Frame, site_host: str, page_url: str,
                inline_lines: Optional[List[Tuple[int, int]]]) -> str:
    """``store``, ``provider``, ``vendor`` or ``unknown`` for one stack frame."""
    if frame.eval or not frame.url:
        return "unknown"
    host, path = _parts(frame.url)
    if not host:
        return "unknown"
    key = _owner_key(host)
    site_key = _owner_key((site_host or "").lower())
    if site_key and key == site_key:
        if urldefrag(frame.url)[0] == urldefrag(page_url or "")[0]:
            # the page's own URL: store code only when it is in a script block the server sent
            line = frame.line
            if line is not None and any(a <= line <= b for a, b in (inline_lines or [])):
                return "store"
            return "unknown"  # an inline script added at runtime
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


def stack_owner(frames: List[Frame], site_host: str, page_url: str,
                inline_lines: Optional[List[Tuple[int, int]]]) -> Tuple[str, List[str]]:
    """``("unknown", [])`` if any frame is unknown or there are no frames; else
    ``("vendor", names)`` if any frame is a known vendor; else ``("store", [])``. A payment
    provider's frame counts like a store frame."""
    if not frames:
        return "unknown", []
    vendors = []  # type: List[str]
    for frame in frames:
        owner = frame_owner(frame, site_host, page_url, inline_lines)
        if owner == "unknown":
            return "unknown", []
        if owner == "vendor":
            name = KNOWN_VENDORS.get(_owner_key(_parts(frame.url)[0]), "")
            if name and name not in vendors:
                vendors.append(name)
    if vendors:
        return "vendor", vendors
    return "store", []
