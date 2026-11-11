"""Load states, external scripts, the verdict and the stored report of a site quick check
(spec §5.5, §5.6, §6.3).

Pure: no I/O, no browser. Everything read from a load's result is page-supplied, so every
count and length in the output is bounded.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .models import ScanResult
from .challenge import VENDORS
from .profiles import PROFILES
from .script_trace import MAX_URL_CHARS  # 300, the external-scripts rule
from .code_origin import KNOWN_VENDORS
from .site_findings import (Load, build_blocks_and_overflow, cap_findings, card_insertions, ended_off_site, own_score,
                            usable_load)
from .site_identity import on_site, same_domain

# External scripts per site (global constraints): hosts, and URLs over all listed hosts.
MAX_HOSTS = 100
MAX_EXTERNAL_URLS = 500
MAX_BLOCKED_HOSTS = 100

_PROFILE_ORDER = {name: i for i, name in enumerate(PROFILES)}

LABELS = {
    "compromised": "Compromised",
    "suspicious": "Suspicious",
    "partly_checked": "Partly checked",
    "clean": "Clean",
    "couldnt_check": "Couldn't check",
}

# The couldn't-check summary says why the homepage wasn't checked (spec §5.5).
COULDNT_CHECK = {
    "challenge": "This site showed our scanner a bot check",
    "budget": "We ran out of time before the homepage loaded",
    "timeout": "The homepage took too long to load",
    None: "We couldn't reach this site",  # load_failed, or no homepage load at all
}


NOTE_YARA_BUDGET = "Some page content was too large to check in full for malware patterns"


def _yara_cut(load: Load) -> bool:
    """YARA's per-load byte or time budget ran out, so some buffers weren't scanned."""
    stats = load.result.metadata.get("yara")
    return isinstance(stats, dict) and stats.get("budget_exhausted") is True


def _profile_key(profile: str) -> Tuple[int, str]:
    return (_PROFILE_ORDER.get(profile, len(_PROFILE_ORDER)), profile)


def _url(value: Any) -> str:
    return value[:MAX_URL_CHARS] if isinstance(value, str) else ""


def _hostname(url: Any) -> str:
    try:
        return (urlsplit(url).hostname or "") if isinstance(url, str) else ""
    except ValueError:
        return ""


def classify_load(result: Optional[ScanResult], error: Optional[str]) -> Tuple[str, Optional[str]]:
    """The state of one (page, profile) load and, when it wasn't checked, why (spec §5.5)."""
    if error or result is None:
        return "not_checked", (error if error in ("budget", "timeout") else "load_failed")
    metadata = result.metadata
    if metadata.get("challenge"):
        return "not_checked", "challenge"
    if metadata.get("navigation_failed"):
        return "not_checked", "load_failed"
    if "Timeout" in str(metadata.get("raw_error") or ""):
        signals = metadata.get("page_signals")
        title = signals.get("title") if isinstance(signals, dict) else None
        if not metadata.get("served_bytes") and not title:
            return "not_checked", "timeout"  # no usable DOM
        return "partial", None
    return "checked", None


def _finding_urls(blocks: List[dict]) -> set:
    """URLs a finding involves: a block located at a script, or loaded by a finding's code."""
    urls = set()
    for block in blocks:
        location = block.get("location")
        if isinstance(location, str):
            urls.add(location)
        for finding in block.get("findings") or []:
            urls.update(u for u in finding.get("loaded") or [] if isinstance(u, str))
    return urls


def _inline_or_script(record: dict, page_url: str) -> str:
    """Who added a script-injected request: the initiating script's URL, or 'inline on <page>'."""
    initiator = record.get("initiator_url")
    if not isinstance(initiator, str) or not initiator or initiator in (page_url, record.get("frame_url")):
        return "inline on {}".format(page_url)
    return _url(initiator)


def external_scripts(loads: List[Load], site_host: str, blocks: List[dict]) -> dict:
    """Every script requested from a host other than the site's, grouped by host (spec §5.6).

    Listed, never scored. Hosts come in the §5.6 order: tied to a finding, then seen only by
    some visitors, then added by a script, then the rest alphabetically. At most MAX_HOSTS
    hosts and MAX_EXTERNAL_URLS URLs are listed; ``hosts_more`` counts the hosts left out and
    ``urls_more`` the URLs left out of listed hosts. A bot-check page's scripts are not the
    site's, so those loads are skipped, and so are loads that were not checked or that ended
    on another site (that page's scripts are not the site's either).
    """
    usable = sorted((l for l in loads if usable_load(l) and not ended_off_site(l.result, site_host)),
                    key=lambda l: l.page_index)
    profiles_by_page = {}  # type: Dict[str, set]
    for load in usable:
        profiles_by_page.setdefault(_url(load.page_url), set()).add(load.profile)

    seen = {}  # type: Dict[str, Dict[str, dict]]
    for load in usable:
        page_url = _url(load.page_url)
        for record in load.result.metadata.get("script_requests") or []:
            if not isinstance(record, dict) or not isinstance(record.get("url"), str):
                continue
            host = _hostname(record["url"])
            if not host or on_site(host, site_host):
                continue
            url = _url(record["url"])
            entry = seen.setdefault(host, {}).setdefault(url, {
                "url": url, "pages": [], "profiles": set(), "how": "html", "injected_by": None, "in_frame": None})
            if page_url not in entry["pages"]:
                entry["pages"].append(page_url)
            entry["profiles"].add(load.profile)
            if record.get("initiator") == "script":
                entry["how"] = "script"
                if entry["injected_by"] is None:
                    entry["injected_by"] = _inline_or_script(record, page_url)
            if record.get("main_frame") is False and entry["in_frame"] is None:
                entry["in_frame"] = _hostname(record.get("frame_url")) or "unknown"

    tied = _finding_urls(blocks)
    hosts = []
    for host, entries in seen.items():
        urls = []
        for entry in entries.values():
            visitors = set()
            for page in entry["pages"]:
                visitors |= profiles_by_page.get(page, set())
            urls.append({
                "url": entry["url"],
                "pages": entry["pages"],
                "profiles": sorted(entry["profiles"], key=_profile_key),
                "how": entry["how"],
                "injected_by": entry["injected_by"],
                "in_frame": entry["in_frame"],
                "finding": entry["url"] in tied,
                "_some": entry["profiles"] < visitors,
            })
        urls.sort(key=lambda u: (not u["finding"], u["how"] != "script", u["url"]))
        hosts.append({
            "host": host,
            "your_domain": same_domain(host, site_host),
            "urls": urls,
            "_rank": (not any(u["finding"] for u in urls), not any(u["_some"] for u in urls),
                      not any(u["how"] == "script" for u in urls), host),
        })
    hosts.sort(key=lambda h: h["_rank"])

    listed = []  # type: List[dict]
    urls_left = MAX_EXTERNAL_URLS
    urls_more = 0
    for host in hosts:
        if len(listed) >= MAX_HOSTS or urls_left <= 0:
            break
        keep = host["urls"][:urls_left]
        urls_left -= len(keep)
        urls_more += len(host["urls"]) - len(keep)
        listed.append({
            "host": host["host"],
            "your_domain": host["your_domain"],
            "urls": [{k: v for k, v in u.items() if not k.startswith("_")} for u in keep],
        })
    return {"hosts": listed, "hosts_more": len(hosts) - len(listed), "urls_more": urls_more}


def _pages_with_findings(blocks: List[dict]) -> set:
    pages = set()
    for block in blocks:
        for finding in block.get("findings") or []:
            listed = [p for p in finding.get("pages") or [] if isinstance(p, str)]
            pages.update(listed)
            if not listed and isinstance(block.get("location"), str):
                pages.add(block["location"])  # a finding with no page list stands at its block's location
    return pages


def _count(n: int, noun: str) -> str:
    return "{} {}".format(n, noun if n == 1 else noun + "s")


NOTE_CARDS_UNCHECKED = "No malware found, but we couldn't check who added some card payment fields"


def site_verdict(blocks: List[dict], loads: List[Load], rules_loaded: bool, findings_more_total: int = 0,
                 cards_unchecked: bool = False) -> dict:
    """The site verdict (spec §5.5): the label and a one-line summary for the report header.
    ``findings_more_total`` (findings dropped by the report-wide cap) counts in the summary.
    ``cards_unchecked`` (a checked page's ``card_fields_unchecked``) keeps a would-be Clean
    verdict at Partly checked: unchecked must never read as Clean."""
    severities = [f.get("severity") for b in blocks for f in b.get("findings") or []]
    not_checked = [l for l in loads if l.state == "not_checked"]
    homepage = [l for l in loads if l.page_index == 0]
    default = next((l for l in homepage if l.profile == "default"), None)
    later = [l for l in loads if l.page_index > 0]

    if "compromised" in severities or "suspicious" in severities:
        verdict = "compromised" if "compromised" in severities else "suspicious"
        count = len(severities) + sum(b.get("findings_more") or 0 for b in blocks) + findings_more_total
        summary = "{} · {} on {} of {} pages".format(
            LABELS[verdict], _count(count, "finding"), len(_pages_with_findings(blocks)),
            len({l.page_index for l in loads}))
    elif default is None or default.state == "not_checked":
        verdict = "couldnt_check"
        summary = COULDNT_CHECK.get(default.reason if default is not None else None, COULDNT_CHECK[None])
    elif (any(l.state == "not_checked" for l in homepage)
          or 2 * sum(1 for l in later if l.state == "not_checked") > len(later)):
        verdict = "partly_checked"
        summary = "No malware found, but {} of {} checks couldn't run".format(len(not_checked), len(loads))
    elif cards_unchecked:
        verdict = "partly_checked"
        summary = NOTE_CARDS_UNCHECKED
    else:
        verdict = "clean"
        summary = "Clean" if rules_loaded else "Clean (no malware rules loaded)"
    return {"verdict": verdict, "label": LABELS[verdict], "summary": summary, "rules_loaded": rules_loaded}


def _probe_index(loads: List[Load]) -> Optional[int]:
    """The 404 probe: the page with the highest index whose path starts with /pnakotic-."""
    for load in sorted(loads, key=lambda l: -l.page_index):
        try:
            path = urlsplit(load.page_url).path if isinstance(load.page_url, str) else ""
        except ValueError:
            continue
        if path.startswith("/pnakotic-"):
            return load.page_index
    return None


_VENDOR_NAMES = set(KNOWN_VENDORS.values())


def _card_fields(loads: List[Load], site_host: str) -> dict:
    """What the page's checked, on-site loads say about its own card fields (none of it is a
    finding): ``card_fields`` when a load counted card inputs on the page or saw the store's, a
    payment provider's or a known vendor's code insert them; ``card_fields_unchecked`` when whose
    code inserted them couldn't be checked on some load (``verified`` false); the known vendors
    whose code inserted them (names from the vendor list only)."""
    fields = unchecked = False
    vendors = []  # type: List[str]
    for load in loads:
        if not usable_load(load) or ended_off_site(load.result, site_host):
            continue
        cards = load.result.metadata.get("card_inputs")
        present = cards.get("present") if isinstance(cards, dict) else None
        if isinstance(present, int) and not isinstance(present, bool) and present > 0:
            fields = True
        for event in card_insertions(load.result):
            owner = event.get("owner")
            if owner in ("store", "provider", "vendor"):
                fields = True
            if owner == "unknown" and event.get("verified") is False:
                fields = unchecked = True
            if owner == "vendor" and isinstance(event.get("vendors"), list):
                for name in event["vendors"]:
                    if name in _VENDOR_NAMES and name not in vendors:
                        vendors.append(name)
    return {"card_fields": fields, "card_fields_unchecked": unchecked, "card_fields_vendors": vendors}


def _checked(loads: List[Load], rules_count: int, probe: Optional[int], site_host: str) -> dict:
    by_page = {}  # type: Dict[int, List[Load]]
    for load in loads:
        by_page.setdefault(load.page_index, []).append(load)
    pages = []
    for index in sorted(by_page):
        page_loads = sorted(by_page[index], key=lambda l: _profile_key(l.profile))
        pages.append({
            "index": index,
            "url": _url(page_loads[0].page_url),
            "probe": index == probe,
            **_card_fields(page_loads, site_host),
            "loads": [{
                "profile": l.profile,
                "state": l.state,
                "reason": l.reason,
                "status": l.result.metadata.get("main_status") if l.result else None,
                "screenshot": l.shot,
                "score": own_score(l.result)[0] if l.result else None,
                "landing": _url(l.result.final_url) if l.result else None,
            } for l in page_loads],
        })

    scripts, frames = set(), set()
    for load in loads:
        if not usable_load(load):
            continue
        for record in load.result.metadata.get("script_requests") or []:
            if not isinstance(record, dict):
                continue
            if isinstance(record.get("url"), str):
                scripts.add(_url(record["url"]))
            if record.get("main_frame") is False and isinstance(record.get("frame_url"), str) and record["frame_url"]:
                frames.add(_url(record["frame_url"]))
    return {
        "pages": pages,
        "rules": rules_count,
        "scripts_scanned": len(scripts),
        "frames_scanned": len(frames),
        "not_checked": sum(1 for l in loads if l.state == "not_checked"),
        "total": len(loads),
    }


def challenge_summary(loads: List[Load]) -> Optional[dict]:
    """The bot-check alert: how many loads a CDN challenge kept out, whether the homepage was one,
    and the vendor most of them named (only a known name; the page supplied it). None if none."""
    blocked = [l for l in loads if l.state == "not_checked" and l.reason == "challenge"]
    if not blocked:
        return None
    vendors = [l.result.metadata.get("challenge_vendor") for l in blocked if l.result is not None]
    vendors = [v for v in vendors if v in VENDORS]
    return {
        "vendor": Counter(vendors).most_common(1)[0][0] if vendors else None,
        "loads": len(blocked),
        "of": len(loads),
        "homepage": any(l.page_index == 0 for l in blocked),
    }


def build_report(entered_host: str, site_host: str, offsite_domain: Optional[str], loads: List[Load],
                 rules_count: int, blocked_hosts: List[str], notes: List[str]) -> dict:
    """The site report stored in the result's metadata_json."""
    blocks, blocks_more = build_blocks_and_overflow(loads, site_host, offsite_domain)
    blocks, emptied, findings_more_total = cap_findings(blocks)
    blocks_more += emptied
    if any(_yara_cut(l) for l in loads if usable_load(l)):
        notes = list(notes) + [NOTE_YARA_BUDGET]
    probe = _probe_index(loads)
    probe_url = next((_url(l.page_url) for l in loads if l.page_index == probe), None) if probe is not None else None
    for block in blocks:
        block["probe"] = block["location_kind"] == "page" and block["location"] == probe_url
    checked = _checked(loads, rules_count, probe, site_host)
    cards_unchecked = any(p["card_fields_unchecked"] for p in checked["pages"])
    return {
        "site": site_host,
        "entered": entered_host,
        "redirected_from": entered_host if entered_host != site_host else None,
        "verdict": site_verdict(blocks, loads, rules_count > 0, findings_more_total, cards_unchecked),
        "blocks": blocks,
        "blocks_more": blocks_more,  # blocks past MAX_BLOCKS, plus blocks the findings cap left empty
        "findings_more_total": findings_more_total,  # findings dropped by the report-wide MAX_FINDINGS cap
        "external_scripts": external_scripts(loads, site_host, blocks),
        "checked": checked,
        "blocked_hosts": list(dict.fromkeys(h[:253] for h in blocked_hosts if isinstance(h, str)))[:MAX_BLOCKED_HOSTS],
        "notes": list(notes),
        "challenge": challenge_summary(loads),  # a CDN bot check kept some loads out
    }
