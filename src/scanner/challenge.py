"""Bot-check and challenge pages (Cloudflare, DDoS-Guard, Incapsula).

A challenge page is the CDN's, not the site's: its content must not be read as a clean
pass. Plain substring checks over capped, lower-cased input (the page is attacker-controlled).
"""
from typing import Optional

TITLE_MARKERS = ("just a moment...", "attention required! | cloudflare")
HTML_MARKERS = ("cf-chl", "cf_chl_opt", "ddos-guard", "/_incapsula_resource")
# Only on a small 403/503: Cloudflare injects /cdn-cgi/challenge-platform/scripts/jsd/main.js
# into ordinary pages, and plenty of sites mention a captcha.
BLOCKED_PAGE_MARKERS = ("challenge-platform", "captcha")
SMALL_PAGE_BYTES = 20_000
MAX_HTML_CHARS = 2_000_000


def looks_like_challenge(status: Optional[int], title: str, html: str) -> bool:
    """True for a challenge title or a challenge-only HTML marker at any status, and for a
    403/503 whose HTML is under 20 kB and mentions challenge-platform or a captcha."""
    title = (title or "")[:1000].lower()
    if any(m in title for m in TITLE_MARKERS):
        return True
    html = html or ""
    text = html[:MAX_HTML_CHARS].lower()
    if any(m in text for m in HTML_MARKERS):
        return True
    small = len(html) < SMALL_PAGE_BYTES and len(html.encode("utf-8", "replace")) < SMALL_PAGE_BYTES
    return status in (403, 503) and small and any(m in text for m in BLOCKED_PAGE_MARKERS)
