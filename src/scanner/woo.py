"""WooCommerce detection and the checkout page's URL, for the site survey.

Pure: no I/O. The input is attacker-controlled, so only the first ``MAX_CHARS`` characters are
read and every regex is bounded and cannot backtrack across the document.
"""
import re
from typing import List, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

from .site_identity import on_site

MAX_CHARS = 2_000_000

# Substrings that only a WooCommerce page carries (searched in the lower-cased text).
_MARKERS = ("/wp-content/plugins/woocommerce/", "woocommerce_params", "wc_add_to_cart_params", "wc-block-")

# A class attribute's value: at most 1 000 characters and no '<' or '>', so an unterminated
# value is abandoned after 1 000 characters and the scan moves on to the next ``class=``.
_CLASS_RE = re.compile(r"""\bclass\s{0,20}=\s{0,20}(?:"([^"<>]{0,1000})"|'([^'<>]{0,1000})')""")
_WORD_RE = re.compile(r"\bwoocommerce\b")


def looks_like_woocommerce(html: Optional[str]) -> bool:
    """True when the markup carries a WooCommerce marker: the plugin's path, one of its script
    variables, a ``wc-block-`` class, or a ``class`` attribute containing the word ``woocommerce``."""
    if not isinstance(html, str) or not html:
        return False
    text = html[:MAX_CHARS].lower()
    if any(marker in text for marker in _MARKERS):
        return True
    for match in _CLASS_RE.finditer(text):
        if _WORD_RE.search(match.group(1) or match.group(2) or ""):
            return True
    return False


def _netloc(host: str, port: Optional[int]) -> str:
    host = "[{}]".format(host) if ":" in host else host
    return host if port is None else "{}:{}".format(host, port)


def checkout_url(links: List[str], site_host: str, root: str) -> str:
    """The store's checkout page: the first on-site link whose last non-empty path segment is
    ``checkout`` (fragment and query dropped, a www/apex twin rewritten to ``site_host``), else
    ``checkout/`` under ``root``."""
    site = (site_host or "").strip("[]").lower()
    for link in links or []:
        if not isinstance(link, str):
            continue
        try:
            parts = urlsplit(link)
            port = parts.port
        except ValueError:
            continue
        host = (parts.hostname or "").lower()
        if parts.scheme.lower() not in ("http", "https") or not host or not on_site(host, site):
            continue
        segments = [s for s in parts.path.split("/") if s]
        if segments and segments[-1].lower() == "checkout":
            return urlunsplit((parts.scheme.lower(), _netloc(site, port), parts.path, "", ""))
    return urljoin(root, "checkout/")
