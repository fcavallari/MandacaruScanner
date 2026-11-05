"""Site identity for the site quick check.

Every ``host`` / ``site_host`` in these helpers is a lower-case hostname without a port;
URLs keep their port. Registrable domains come from the public-suffix snapshot bundled
with tldextract (private domains included, so ``github.io`` is a suffix). The list is
never fetched at runtime and no cache directory is written.
"""
import re
from typing import Optional, Tuple
from urllib.parse import urlsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=True,
)

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")
_BAD_HOST_CHARS_RE = re.compile(r"[\s\x00-\x1f\x7f]")


def registrable_domain(host: str) -> str:
    """The registrable domain of ``host``, or '' for an IP, an empty host, or a host
    with no public suffix (such as ``localhost``)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    ext = _EXTRACT(host)
    if not ext.suffix or not ext.domain:
        return ""
    return "{}.{}".format(ext.domain, ext.suffix)


def same_domain(a: str, b: str) -> bool:
    """True when both hosts share a registrable domain; a host without one stands for
    itself, so ``127.0.0.1`` and ``localhost`` are different domains."""
    if not a or not b:
        return False
    return (registrable_domain(a) or a) == (registrable_domain(b) or b)


def www_twin(host: str) -> str:
    """``www.x.com`` -> ``x.com`` and ``x.com`` -> ``www.x.com``."""
    if not host:
        return ""
    if host.startswith("www."):
        return host[len("www."):]
    return "www." + host


def on_site(host: str, site_host: str) -> bool:
    """True when ``host`` is the site host itself or its www twin."""
    if not host or not site_host:
        return False
    return host == site_host or host == www_twin(site_host)


def _ascii_host(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def normalize_site_input(raw: str) -> str:
    """Turn whatever was typed into ``https://<host>[:port]/``.

    Path, query and fragment are dropped; the scheme is always https (the http fallback
    is the scanner's job). Raises ValueError for empty input, a non-http(s) scheme,
    credentials in the URL, a missing host or a bad port.
    """
    text = (raw or "").strip()
    if not text:
        raise ValueError("Enter a website address.")
    if not _SCHEME_RE.match(text):
        text = "https://" + text
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        raise ValueError("That doesn't look like a website address.")
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https addresses can be checked.")
    if "@" in parts.netloc:
        raise ValueError("Addresses with a username or password can't be checked.")
    host = (parts.hostname or "").strip(".").lower()
    if not host or _BAD_HOST_CHARS_RE.search(host):
        raise ValueError("That doesn't look like a website address.")
    host = _ascii_host(host)
    if ":" in host:  # IPv6 literal, urlsplit stripped the brackets
        host = "[{}]".format(host)
    return "https://{}{}/".format(host, ":{}".format(port) if port is not None else "")


def resolve_site_host(entered_host: str, landing_url: str) -> Tuple[str, Optional[str]]:
    """Decide which host the site check is about after the homepage load.

    Returns ``(site_host, offsite_domain)``. A landing on the same host or the same
    registrable domain moves the site to the landing host; anything else keeps the
    entered host and reports the domain the visitor ended up on.
    """
    try:
        landing_host = (urlsplit(landing_url or "").hostname or "").lower()
    except ValueError:
        landing_host = ""
    if not landing_host:
        return entered_host, None
    if same_domain(entered_host, landing_host):
        return landing_host, None
    return entered_host, registrable_domain(landing_host) or landing_host
