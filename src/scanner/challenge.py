"""Bot-check and challenge pages (Cloudflare, DDoS-Guard, Incapsula).

A challenge page is the CDN's, not the site's: its content must not be read as a clean
pass. Plain substring checks over capped, lower-cased input (the page is attacker-controlled).
"""
from typing import Optional

HTML_MARKERS = ("cf-chl", "challenge-platform", "cf_chl_opt", "ddos-guard", "/_incapsula_resource")
TITLE_MARKERS = ("just a moment...", "attention required! | cloudflare")
SMALL_PAGE_BYTES = 20_000  # a 403/503 this small that mentions a captcha is a challenge
MAX_HTML_CHARS = 2_000_000


def looks_like_challenge(status: Optional[int], title: str, html: str) -> bool:
    """True for any known challenge marker in the title or HTML, and for a 403/503 whose
    HTML is under 20 kB and mentions a captcha."""
    title = (title or "")[:1000].lower()
    if any(m in title for m in TITLE_MARKERS):
        return True
    html = html or ""
    small = len(html) < SMALL_PAGE_BYTES and len(html.encode("utf-8", "replace")) < SMALL_PAGE_BYTES
    text = html[:MAX_HTML_CHARS].lower()
    if any(m in text for m in HTML_MARKERS):
        return True
    return status in (403, 503) and small and "captcha" in text
