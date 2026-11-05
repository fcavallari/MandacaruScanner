"""Regex-based static analysis of a scanned page's HTML.

The page content is attacker-controlled, so every regex here must run in time
linear in its input. Two signatures used unbounded lazy/greedy runs (`.*?`,
`[^>]*`): each unmatched opener (`atob('` or `<meta ` with no terminator) then
scanned to the end of the input, giving O(openers x length) cost (tens of
seconds on a ~2 MB page). Those runs are now bounded ({0,N}), and
`analyze_content` caps the input at MAX_CONTENT_CHARS, so the worst case is
small and linear.

There is deliberately no separate timeout. Python's `re` cannot be interrupted
from inside the process without signals; `signal.alarm` would collide with
Celery's soft-time-limit signal handling; and a thread-based timeout cannot
kill the regex, leaving a runaway thread burning CPU in a reused prefork worker.
Bounded quantifiers plus the input cap avoid the problem instead of reacting
to it.
"""
import re
from typing import List, Dict, Any

# Hard cap on how much HTML analyze_content will look at (in characters).
MAX_CONTENT_CHARS = 2_000_000


# data: URIs (inline images, fonts), stripped before the b64_payload scan. Greedy char classes
# with a bounded media-type prefix: linear, no nesting.
DATA_URI_RE = re.compile(r"data:[A-Za-z0-9.+/-]{1,80};base64,[A-Za-z0-9+/=]+")


# Maps a signature id to the RedirectHop mechanism it implies. A regex hit on the landing
# page only shows that redirect code is *present*: a redirect that fires is observed through
# CDP in the engine (mechanism meta_refresh / js_location), so these map to the secondary
# "code present but did not fire" mechanisms, which are not in REDIRECT_MECHANISMS.
# Obfuscation helpers are a scoring signal but not evidence that the page navigated anywhere.
# Signatures not listed here surface as generic "static_analysis" hops.
SIGNATURE_MECHANISMS = {
    "meta_refresh": "meta_refresh_code",
    "js_location_assignment": "js_location_code",
    "js_atob": "js_obfuscation",
    "js_fromCharCode": "js_obfuscation",
    "clickfix_lure": "clickfix_lure",
}


# ClickFix lure: an instruction to open the Run box (Win+R) and one to paste (Ctrl+V) on the
# same page. The engine never clicks the fake CAPTCHA, so this text is often all that shows;
# the clipboard write itself is recorded by behavior.py when it fires. Two independent
# searches rather than one "A ... B" regex: a bounded gap between them would still cost
# O(openers x gap) on a page stuffed with "win+r".
CLICKFIX_RUN = re.compile(r"(?:\bwin(?:dows)?(?:\s{0,3}key)?|⊞)\s{0,3}(?:\+|and)\s{0,3}[\"']?r\b", re.IGNORECASE)
CLICKFIX_PASTE = re.compile(r"(?:\bctrl|\bcmd|⌘)\s{0,3}\+\s{0,3}v\b", re.IGNORECASE)


class StaticAnalyst:
    def __init__(self):
        self.SIGNATURES = {
            # The literal is bounded to 4096 chars (quantifier DoS, see module docstring).
            # [^'"] also matches newlines, so multi-line base64 strings still match
            # without DOTALL.
            "js_atob": re.compile(r"atob\(\s*['\"][^'\"]{0,4096}['\"]\s*\)", re.IGNORECASE),
            "js_fromCharCode": re.compile(r"String\.fromCharCode\(", re.IGNORECASE),
            # Assignment OR replace()/assign() calls; works with or without .href.
            "js_location_assignment": re.compile(
                r"(?:window|document|top)\.location(?:\.href)?\s*=\s*['\"]"
                r"|location\.(?:replace|assign)\(",
                re.IGNORECASE,
            ),
            # Attribute-order independent: http-equiv may appear before or after content.
            "meta_refresh": re.compile(
                r"<meta[^>]{0,2000}http-equiv\s*=\s*['\"]?refresh['\"]?[^>]{0,2000}>",
                re.IGNORECASE,
            ),
            # Long base64-ish runs (>= 60 chars); filtered in _is_meaningful to cut false positives.
            "b64_payload": re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"),
        }

    def analyze_content(self, html: str) -> List[Dict[str, Any]]:
        findings = []
        original_len = len(html)
        truncated = original_len > MAX_CONTENT_CHARS
        if truncated:
            html = html[:MAX_CONTENT_CHARS]
        for name, pattern in self.SIGNATURES.items():
            haystack = html
            if name == "b64_payload":
                # Inline images and fonts are base64 by design: not a payload.
                haystack = DATA_URI_RE.sub("", html)
            matches = [m for m in pattern.findall(haystack) if self._is_meaningful(name, m)]
            if matches:
                snippet = matches[0][:50]
                findings.append({
                    "type": "signature_match",
                    "id": name,
                    "count": len(matches),
                    "snippet": snippet + ("..." if len(matches[0]) > 50 else ""),
                })
        run = CLICKFIX_RUN.search(html)
        if run and CLICKFIX_PASTE.search(html):
            findings.append({
                "type": "signature_match",
                "id": "clickfix_lure",
                "count": 1,
                "snippet": run.group(0)[:50],
            })
        if truncated:
            findings.append({
                "type": "content_truncated",
                "id": "content_truncated",
                "count": 1,
                "snippet": f"{original_len} chars, analyzed first {MAX_CONTENT_CHARS}",
            })
        return findings

    @staticmethod
    def _is_meaningful(signature_id: str, match: str) -> bool:
        if signature_id == "meta_refresh":
            # A refresh without url= only reloads the same page (a timer), it goes nowhere.
            return "url=" in match.lower()
        if signature_id != "b64_payload":
            return True
        # Real base64 payloads almost always contain '+' or '/', or end with '=' padding;
        # pure-alnum runs of 60+ chars are usually minified identifiers or hex hashes.
        return ("+" in match) or ("/" in match) or match.endswith("=")
