"""Link extraction and page picking for the site quick check.

``extract_links`` reads the anchors of a rendered homepage; ``pick_pages`` chooses up to
a handful of varied internal pages to visit; ``probe_url`` builds the 404-template probe.
Hosts are lower-case and port-less when compared; URLs keep their port. All page-supplied
input is bounded and handled in linear time: the HTML is capped, anchors are found with a
regex tokenizer (not ``html.parser``, which rescans the buffer on every unterminated
``<!--`` and goes quadratic), each tag is limited to a bounded length that cannot span a
``<``, and scanning stops after ``limit`` anchors.
"""
import html as html_lib
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit
import re

from .site_identity import on_site

_MAX_HTML_CHARS = 4_000_000
_MAX_URL_CHARS = 2048

_NON_PAGE_EXTENSIONS = frozenset(
    "jpg jpeg png gif webp svg ico bmp avif tif tiff heic "
    "pdf doc docx xls xlsx ppt pptx csv rtf "
    "zip gz tgz tar rar 7z bz2 xz dmg exe msi apk iso "
    "mp3 mp4 m4a m4v mov avi wav webm ogg flac mkv wmv "
    "xml txt css js json map woff woff2 ttf eot".split()
)
_EXTENSION_RE = re.compile(r"\.([a-z0-9]{1,6})$")

_DROP_PATH_RE = re.compile(
    r"(?:^|/)(?:wp-admin|wp-json|feed)(?:/|$)"
    r"|/(?:wp-login|xmlrpc)\.php$"
    r"|(?<![a-z0-9])(?:log-?out|sign-?out|logoff)(?![a-z0-9])"
    r"|add[-_]to[-_]cart"
)
_DROP_QUERY_RE = re.compile(
    r"(?:^|&)(?:replytocom|feed|rest_route|add-to-cart|add_to_cart|remove_item|removed_item)(?:=|&|$)"
    r"|(?:^|&)action=(?:logout|logoff|delete|remove)(?:&|$)"
)

_DATE_POST_RE = re.compile(r"^/\d{4}/\d{2}/")
_QUERY_POST_RE = re.compile(r"(?:^|&)p=\d+(?:&|$)")
_ARCHIVE_RE = re.compile(r"/(?:category|tag|author)/|/page/\d{1,6}/")
_CONTACT_RE = re.compile(r"contact|kontakt|contacto|contatto")


# One token is either a comment opener or an anchor start tag. The tag body may not contain
# '<' or '>' (so an unterminated '<a' flood is scanned once, not once per start) and is
# at most 4096 characters.
_TOKEN_RE = re.compile(r"<!--|<a\s[^<>]{0,4096}>", re.IGNORECASE)
_HREF_RE = re.compile(r"\shref\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))", re.IGNORECASE)


def _anchor_hrefs(markup: str, limit: int) -> List[str]:
    """Raw ``href`` values of the first ``limit`` ``<a href>`` tags, skipping comments.
    Linear in the size of ``markup``."""
    hrefs = []  # type: List[str]
    pos = 0
    while len(hrefs) < limit:
        token = _TOKEN_RE.search(markup, pos)
        if token is None:
            break
        if token.group(0) == "<!--":
            end = markup.find("-->", token.end())
            if end < 0:  # an unterminated comment swallows the rest of the document
                break
            pos = end + 3
            continue
        pos = token.end()
        href = _HREF_RE.search(token.group(0))
        if href is not None:
            value = next(g for g in href.groups() if g is not None)
            hrefs.append(html_lib.unescape(value))
    return hrefs


def _netloc(host: str, port: Optional[int]) -> str:
    if ":" in host:  # IPv6 literal
        host = "[{}]".format(host)
    return "{}:{}".format(host, port) if port is not None else host


def _split(url: str) -> Optional[Tuple[str, str, Optional[int], str, str]]:
    """``(scheme, host, port, path, query)`` of an http(s) URL with a host, else None."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        return None
    return scheme, host, port, parts.path or "/", parts.query


def _normalize(url: str) -> Optional[str]:
    """Absolute http(s) URL with the fragment and any credentials dropped and the scheme
    and host lower-cased; None for anything else."""
    split = _split(url)
    if split is None:
        return None
    scheme, host, port, path, query = split
    return urlunsplit((scheme, _netloc(host, port), path, query, ""))


def extract_links(html: str, base_url: str, limit: int = 2000) -> List[str]:
    """Absolute http(s) links of the ``<a href>`` anchors in ``html``, in first-seen order
    and without duplicates. Parsing stops once ``limit`` anchors have been seen."""
    hrefs = _anchor_hrefs((html or "")[:_MAX_HTML_CHARS], max(limit, 0))
    seen = set()
    links = []
    for href in hrefs:
        href = href.strip()
        if len(href) > _MAX_URL_CHARS:
            continue
        try:
            url = _normalize(urljoin(base_url, href))
        except ValueError:
            continue
        if url is None or len(url) > _MAX_URL_CHARS or url in seen:
            continue
        seen.add(url)
        links.append(url)
    return links


def _is_dropped(path: str, query: str) -> bool:
    if _DROP_PATH_RE.search(path) or _DROP_QUERY_RE.search(query):
        return True
    ext = _EXTENSION_RE.search(path.rsplit("/", 1)[-1])
    return bool(ext and ext.group(1) in _NON_PAGE_EXTENSIONS)


class _Candidate:
    def __init__(self, url: str, path: str, query: str) -> None:
        self.url = url
        lower = path.lower()
        slashed = lower if lower.endswith("/") else lower + "/"
        self.segments = [s for s in lower.split("/") if s]
        self.first_segment = self.segments[0] if self.segments else ""
        self.is_post = bool(_DATE_POST_RE.search(lower) or _QUERY_POST_RE.search(query.lower()))
        self.is_archive = bool(_ARCHIVE_RE.search(slashed))
        self.is_contact = bool(_CONTACT_RE.search(lower))
        plain = not (self.is_archive or self.is_contact)
        self.is_page = plain and len(self.segments) == 1
        self.depth_for_post = len(self.segments) if plain and len(self.segments) >= 2 else 0


def pick_pages(links: List[str], site_host: str, homepage_url: str, limit: int = 5) -> List[str]:
    """Up to ``limit`` varied internal pages: a post, a page, an archive and a contact
    page when the site has them, then more links in document order (a first path segment
    not used yet preferred). Links on the www/apex twin of ``site_host`` are rewritten to
    ``site_host``; off-site links, admin/feed/action URLs, non-page files and the
    homepage itself are dropped."""
    site = (site_host or "").strip("[]").lower()
    home = _split(homepage_url)
    home_path = home[3].rstrip("/") if home else ""
    candidates = []  # type: List[_Candidate]
    seen = set()
    for link in links:
        split = _split(link)
        if split is None:
            continue
        scheme, host, port, path, query = split
        if not on_site(host, site):
            continue
        if _is_dropped(path.lower(), query.lower()):
            continue
        key = (scheme, port, path.rstrip("/"), query)
        if key in seen or (path.rstrip("/") == home_path and not query):
            continue  # a repeat, or the homepage itself
        seen.add(key)
        url = urlunsplit((scheme, _netloc(site, port), path, query, ""))
        candidates.append(_Candidate(url, path, query))

    limit = min(limit, len(candidates))
    picked = []  # type: List[_Candidate]

    def take(match) -> None:
        if len(picked) >= limit:
            return
        for cand in candidates:
            if cand not in picked and match(cand):
                picked.append(cand)
                return

    take(lambda c: c.is_post)
    if not any(c.is_post for c in picked):  # no dated or ?p=N post: the deepest path stands in
        deepest = max((c.depth_for_post for c in candidates if c not in picked), default=0)
        if deepest:
            take(lambda c: c.depth_for_post == deepest)
    take(lambda c: c.is_page)
    take(lambda c: c.is_archive)
    take(lambda c: c.is_contact)

    used = set(c.first_segment for c in picked)
    for cand in candidates:  # variety first: a first path segment not used yet
        if len(picked) >= limit:
            break
        if cand not in picked and cand.first_segment not in used:
            picked.append(cand)
            used.add(cand.first_segment)
    for cand in candidates:
        if len(picked) >= limit:
            break
        if cand not in picked:
            picked.append(cand)
    return [c.url for c in picked]


def probe_url(homepage_url: str, token: str) -> str:
    """The 404-template probe: ``<scheme>://<host[:port]>/pnakotic-<token>/``."""
    parts = urlsplit(homepage_url)
    return "{}://{}/pnakotic-{}/".format(parts.scheme, parts.netloc, token)
