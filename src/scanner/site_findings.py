"""Finding blocks for the site quick check: what the site owner reads (spec §5.1-5.5, §6.2).

``build_blocks`` turns the per-load results of one site check into blocks, one per place
the owner has to fix something: a page URL for HTML matches, behaviours, cloaking and the
off-site homepage, or a script URL for a match in a script file. Identical findings on
several pages merge into one finding that lists every page. Pure: no I/O, no browser.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from ..intelligence.scorer import PnakoticScorer
from .behavior import LOCK_BEHAVIORS, behavior_events, evidence_of
from .models import ScanResult
from .profiles import PROFILES
from .site_identity import on_site, same_domain
from .yara_scan import YARA_MECHANISM

# Report size caps (global constraints): they bound the result's metadata_json.
MAX_BLOCKS = 50
MAX_PAGES = 20         # pages listed per finding; the rest are counted in pages_more
MAX_URLS = 20          # URLs in loaded_by / loaded; the rest in loaded_by_more / loaded_more
MAX_DETAIL_ITEMS = 20  # screenshots and scoring strings kept in a finding's details
MAX_DETAIL_TEXT = 300  # characters kept from a scoring string

SUSPICIOUS_SCORE = 0.4

MESSAGES: Dict[str, str] = {
    "yara": "Code matching a known malware pattern",
    "clipboard": "The page tries to put a command on visitors' clipboard",
    "download": "The page starts a download on its own",
    "browser_lock": "The page tries to lock visitors' browser",
    "cloaking": "Some visitors are sent to a different website",
    "offsite_homepage": "Your homepage sends desktop visitors to {domain}",
    "injection": "Hidden code loads a script from another website into your page",
    "page_score": "This page does things malicious pages do",
}
MOVED_SITE = "If you moved your site, check the new domain"

_HTML_ORIGINS = {"served": "served", "page": "rendered", "frame": "frame"}
_PROFILE_ORDER = {name: i for i, name in enumerate(PROFILES)}


@dataclass
class Load:
    """One (page, profile) load of a site check."""
    page_index: int
    page_url: str
    profile: str
    state: str  # "checked" | "partial" | "not_checked"
    reason: Optional[str]
    result: Optional[ScanResult]
    shot: Optional[str]


class _Finding:
    """A finding while loads are folded in; ``out()`` gives the report dict."""

    def __init__(self, key: tuple, severity: str, kind: str, message: str, snippet: Optional[dict],
                 origin: Optional[str], location: str, location_kind: str, mechanism: str,
                 rule: Optional[str] = None, signature_id: Optional[int] = None, initiator: Optional[str] = None):
        self.key = key
        self.severity = severity
        self.kind = kind
        self.message = message
        self.snippet = snippet
        self.origin = origin
        self.location = location
        self.location_kind = location_kind
        self.mechanism = mechanism
        self.rule = rule
        self.signature_id = signature_id
        self.initiator = initiator
        self.visitors: List[str] = []
        self.pages: List[str] = []
        self.loaded_by: List[str] = []
        self.loaded: List[str] = []
        self.screenshots: List[str] = []
        self.scoring: List[str] = []

    def out(self, profiles_by_page: Dict[str, set]) -> dict:
        visitors = sorted(self.visitors, key=lambda p: (_PROFILE_ORDER.get(p, len(_PROFILE_ORDER)), p))
        checked = set()
        for page in self.pages:
            checked |= profiles_by_page.get(page, set())
        return {
            "id": "{}:{}".format(self.kind, hashlib.sha1(json.dumps(self.key).encode("utf-8")).hexdigest()[:16]),
            "severity": self.severity,
            "kind": self.kind,
            "message": self.message,
            "snippet": self.snippet,
            "origin": self.origin,
            "visitors": visitors,
            "all_visitors": bool(visitors) and checked <= set(visitors),
            "pages": self.pages[:MAX_PAGES],
            "pages_more": max(0, len(self.pages) - MAX_PAGES),
            "loaded_by": self.loaded_by[:MAX_URLS],
            "loaded_by_more": max(0, len(self.loaded_by) - MAX_URLS),
            "loaded": self.loaded[:MAX_URLS],
            "loaded_more": max(0, len(self.loaded) - MAX_URLS),
            "details": {
                "rule": self.rule,
                "signature_id": self.signature_id,
                "mechanism": self.mechanism,
                "profiles": visitors,
                "screenshots": self.screenshots[:MAX_DETAIL_ITEMS],
                "scoring": self.scoring[:MAX_DETAIL_ITEMS],
                "initiator": self.initiator,
            },
        }


def _append(items: List[str], value: Optional[str]) -> None:
    if value and value not in items:
        items.append(value)


def _hostname(url: Any) -> str:
    try:
        return (urlsplit(url).hostname or "") if isinstance(url, str) else ""
    except ValueError:
        return ""


def _usable(load: Load) -> bool:
    """not_checked loads and bot-challenge pages say nothing about the site."""
    return (load.state != "not_checked" and load.result is not None
            and not load.result.metadata.get("challenge"))


def _injections(result: ScanResult) -> List[dict]:
    return [i for i in result.metadata.get("injections") or []
            if isinstance(i, dict) and isinstance(i.get("requested_url"), str)]


def _snippet(value: Any) -> Optional[dict]:
    return value if isinstance(value, dict) else None


def _own_score(result: ScanResult) -> Tuple[float, List[str]]:
    """The load's own score and scoring strings. combine() folds the other profiles into the
    page's default result (worst score, "[profile] ..." findings); its summary keeps the default
    load's own score from before the fold."""
    findings = [f for f in result.metadata.get("scoring_findings") or [] if isinstance(f, str)]
    variants = [v for v in result.metadata.get("variants") or [] if isinstance(v, dict)]
    requested = next((v for v in variants if v.get("requested")), None)
    if requested is None or not isinstance(requested.get("malicious_score"), (int, float)):
        return result.malicious_score, findings
    others = ["[{}] ".format(v.get("profile")) for v in variants if not v.get("requested")]
    return float(requested["malicious_score"]), [f for f in findings if not f.startswith(tuple(others))]


class _Collector:
    def __init__(self):
        self.found: Dict[tuple, _Finding] = {}
        self.compromised_loads: set = set()  # id() of loads with a compromised finding of their own

    def add(self, load: Load, key: tuple, *, visitors: Optional[List[str]] = None, **fields) -> _Finding:
        finding = self.found.get(key)
        if finding is None:
            finding = self.found[key] = _Finding(key, **fields)
        elif fields["severity"] == "compromised":
            finding.severity = "compromised"
        if fields["severity"] == "compromised":
            self.compromised_loads.add(id(load))
        for profile in (visitors if visitors is not None else [load.profile]):
            _append(finding.visitors, profile)
        _append(finding.pages, load.page_url)
        _append(finding.screenshots, load.shot)
        return finding


def _yara_and_injections(c: _Collector, load: Load, site_host: str) -> None:
    result = load.result
    hits = evidence_of(result.hops, YARA_MECHANISM)
    injections = _injections(result)
    tied = set()  # indexes of injections attached to a YARA finding
    served_rules = {str(h.get("rule") or "") for h in hits if h.get("source") == "served"}
    served_missing = result.metadata.get("served_bytes") == 0

    for hit in hits:
        source = hit.get("source")
        rule = str(hit.get("rule") or "")
        snippet = _snippet(hit.get("context"))
        common = dict(
            severity="compromised" if PnakoticScorer._yara_tier(hit) == "decisive" else "suspicious",
            kind="yara", message=hit.get("description") or MESSAGES["yara"], snippet=snippet,
            mechanism=YARA_MECHANISM, rule=rule, signature_id=hit.get("signature_id"),
        )
        if source == "script":
            url = str(hit.get("url") or "")
            finding = c.add(load, ("yara", rule, url), origin="script", location=url, location_kind="script", **common)
            _append(finding.loaded_by, load.page_url)
            for i, inj in enumerate(injections):
                if inj["requested_url"] == url:  # this script was injected: name the code that did it
                    tied.add(i)
                    _append(finding.loaded_by, "inline on {}".format(load.page_url)
                            if inj.get("initiator_kind") == "inline" else inj.get("initiator_url"))
                if inj.get("initiator_kind") == "script" and inj.get("initiator_url") == url:
                    tied.add(i)  # this script injected another one
                    _append(finding.loaded, inj["requested_url"])
        elif source in _HTML_ORIGINS:
            if source == "page" and rule in served_rules:
                continue  # already reported from the HTML the server sent
            # Without the served HTML we can't tell whether a script added it.
            origin = None if source == "page" and served_missing else _HTML_ORIGINS[source]
            text = snippet.get("text", "") if snippet else ""
            finding = c.add(load, ("yara", rule, text), origin=origin, location=load.page_url,
                            location_kind="page", **common)
            offset = hit.get("offset")
            if source == "served" and isinstance(offset, int):
                for i, inj in enumerate(injections):
                    block = inj.get("block")
                    if (inj.get("initiator_kind") == "inline" and isinstance(block, dict)
                            and isinstance(block.get("start"), int) and isinstance(block.get("end"), int)
                            and block["start"] <= offset < block["end"]):
                        tied.add(i)
                        _append(finding.loaded, inj["requested_url"])

    # An obfuscated inline or on-site injector of a cross-site script (find_injections only
    # keeps cross-site requests) is suspicious on its own.
    for i, inj in enumerate(injections):
        if i in tied or not inj.get("markers"):
            continue
        kind = inj.get("initiator_kind")
        if kind == "script" and not on_site(_hostname(inj.get("initiator_url")), site_host):
            continue
        if kind not in ("inline", "script"):
            continue
        snippet = _snippet(inj.get("context"))
        initiator = inj.get("initiator_url") if kind == "script" else None
        key = ("injection", kind, initiator or "", snippet.get("text", "") if snippet else "")
        finding = c.add(load, key, severity="suspicious", kind="injection", message=MESSAGES["injection"],
                        snippet=snippet, origin="served" if kind == "inline" else "script",
                        location=load.page_url, location_kind="page", mechanism="script_injection",
                        initiator=initiator)
        _append(finding.loaded, inj["requested_url"])


def _behaviour(c: _Collector, load: Load) -> None:
    events = behavior_events(load.result.hops)
    groups = {
        "clipboard": [e for e in events if e.get("id") == "clipboard_write"],
        "download": [e for e in events if e.get("id") == "download"],
        "browser_lock": [e for e in events if e.get("id") in LOCK_BEHAVIORS],
    }
    for kind, subset in groups.items():
        decisive = PnakoticScorer._decisive(subset)  # each subset can only meet its own rule
        if decisive:
            finding = c.add(load, (kind, load.page_url), severity="compromised", kind=kind, message=MESSAGES[kind],
                            snippet=None, origin=None, location=load.page_url, location_kind="page",
                            mechanism="page_behavior")
            for text in decisive:
                _append(finding.scoring, text[:MAX_DETAIL_TEXT])


def _cloaking_decisive(load: Load) -> Optional[dict]:
    if load.profile != "default":
        return None  # combine() writes the page's cloaking on its default result
    cloaking = load.result.metadata.get("cloaking")
    return cloaking if isinstance(cloaking, dict) and cloaking.get("suspicious") else None


def _cloaking_strings(load: Load) -> List[str]:
    return [f[:MAX_DETAIL_TEXT] for f in load.result.metadata.get("decisive_findings") or []
            if isinstance(f, str) and f.startswith("Decisive: cloaking")]


def _cloaking(c: _Collector, load: Load) -> None:
    cloaking = _cloaking_decisive(load)
    if cloaking is None:
        return
    steered = [p for p in cloaking.get("steered") or [] if isinstance(p, str)]
    finding = c.add(load, ("cloaking", load.page_url), visitors=steered or [load.profile], severity="compromised",
                    kind="cloaking", message=MESSAGES["cloaking"], snippet=None, origin=None,
                    location=load.page_url, location_kind="page", mechanism="cloaking")
    for text in _cloaking_strings(load):
        _append(finding.scoring, text)


def _offsite(c: _Collector, homepage: List[Load], site_host: str, domain: str) -> None:
    landed = [l for l in homepage if same_domain(_hostname(l.result.final_url), domain)]
    cloaked = [l for l in homepage if _cloaking_decisive(l) is not None]
    message = MESSAGES["offsite_homepage"].format(domain=domain)
    if landed and len(landed) == len(homepage):
        message = "{}. {}".format(message, MOVED_SITE)
    location = homepage[0].page_url if homepage else "https://{}/".format(site_host)
    fields = dict(severity="compromised" if cloaked else "suspicious", kind="offsite_homepage", message=message,
                  snippet=None, origin=None, location=location, location_kind="page", mechanism="offsite_homepage")
    key = ("offsite_homepage", domain)
    if not landed:  # the default load decided the domain, but wasn't usable
        anchor = Load(0, location, "default", "not_checked", None, None, None)
        c.add(anchor, key, **fields)
    for load in landed:
        c.add(load, key, **fields)
    for load in cloaked:
        finding = c.add(load, key, visitors=[], **fields)
        for text in _cloaking_strings(load):
            _append(finding.scoring, text)


def _page_score(c: _Collector, load: Load) -> None:
    if id(load) in c.compromised_loads:
        return
    score, findings = _own_score(load.result)
    if score < SUSPICIOUS_SCORE:
        return
    finding = c.add(load, ("page_score", load.page_url), severity="suspicious", kind="page_score",
                    message=MESSAGES["page_score"], snippet=None, origin=None, location=load.page_url,
                    location_kind="page", mechanism="page_score")
    for text in findings:
        _append(finding.scoring, text[:MAX_DETAIL_TEXT])


def build_blocks(loads: List[Load], site_host: str, offsite_domain: Optional[str]) -> List[dict]:
    """The report's finding blocks: compromised first, then by location, at most MAX_BLOCKS."""
    usable = [l for l in sorted(loads, key=lambda l: l.page_index) if _usable(l)]
    profiles_by_page: Dict[str, set] = {}
    for load in usable:
        profiles_by_page.setdefault(load.page_url, set()).add(load.profile)

    c = _Collector()
    for load in usable:
        _yara_and_injections(c, load, site_host)
        _behaviour(c, load)
        _cloaking(c, load)
    if offsite_domain:
        _offsite(c, [l for l in usable if l.page_index == 0], site_host, offsite_domain)
    for load in usable:
        _page_score(c, load)

    grouped: Dict[Tuple[str, str], List[dict]] = {}
    for finding in c.found.values():
        grouped.setdefault((finding.location_kind, finding.location), []).append(finding.out(profiles_by_page))
    blocks = []
    for (kind, location), findings in grouped.items():
        findings.sort(key=lambda f: f["severity"] != "compromised")
        blocks.append({"location": location, "location_kind": kind, "findings": findings})
    blocks.sort(key=lambda b: (b["findings"][0]["severity"] != "compromised", b["location"]))
    return blocks[:MAX_BLOCKS]
