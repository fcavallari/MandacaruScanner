import ipaddress
import json
import re
from urllib.parse import urljoin, urlparse

from ..scanner.models import ScanResult, REDIRECT_MECHANISMS

_MICROSOFT = (
    "microsoft.com", "live.com", "office.com", "office365.com", "outlook.com",
    "microsoftonline.com", "sharepoint.com", "onedrive.com",
)

# Well-known brand token -> the brand's own (legitimate) domains. A hostname containing the
# token but not under one of these domains is a lookalike. Hostnames under CC_BRANDS' names
# are also treated as the brand's own for country-code variants (see _cc_variant).
BRANDS = {
    "zoom": ("zoom.us", "zoom.com"),
    "godaddy": ("godaddy.com",),
    "google": ("google.com", "google.co.uk", "googleapis.com", "goog", "withgoogle.com", "google.com.br",
               "googleusercontent.com", "googlesyndication.com", "googleadservices.com",
               "googletagmanager.com", "google-analytics.com", "gstatic.com"),
    "paypal": ("paypal.com", "paypal.me", "paypalobjects.com"),
    "microsoft": _MICROSOFT,
    "office365": _MICROSOFT,
    "outlook": _MICROSOFT,
    "onedrive": _MICROSOFT,
    "sharepoint": _MICROSOFT,
    "dhl": ("dhl.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com", "adobe.io", "adobe.net", "adobelogin.com"),
    "dropbox": ("dropbox.com", "dropboxusercontent.com"),
    "apple": ("apple.com", "icloud.com"),
    "icloud": ("icloud.com", "apple.com"),
    "amazon": ("amazon.com", "amazonaws.com", "amazon-adsystem.com", "media-amazon.com"),
    "netflix": ("netflix.com", "nflxso.net", "nflximg.net"),
    "facebook": ("facebook.com", "fb.com", "meta.com", "fbcdn.net", "facebook.net"),
    "instagram": ("instagram.com", "cdninstagram.com"),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me"),
    "telegram": ("telegram.org", "telegram.me", "t.me"),
    "binance": ("binance.com", "binance.us"),
    "coinbase": ("coinbase.com",),
    "metamask": ("metamask.io",),
    "linkedin": ("linkedin.com", "licdn.com", "lnkd.in"),
    "usps": ("usps.com", "usps.gov"),
    "fedex": ("fedex.com",),
    "chase": ("chase.com", "jpmorganchase.com"),
    "wellsfargo": ("wellsfargo.com",),
    "santander": ("santander.com",),
    "bbva": ("bbva.com",),
    "mercadolibre": ("mercadolibre.com",),
    "steam": ("steampowered.com", "steamcommunity.com", "steamstatic.com"),
    "roblox": ("roblox.com",),
    "discord": ("discord.com", "discord.gg", "discordapp.com", "discordapp.net"),
    "tiktok": ("tiktok.com", "tiktokv.com", "tiktokcdn.com"),
}

# Brands that also own country-code domains (google.de, google.co.uk, amazon.com.au,
# mercadolibre.com.ar, ...). Handled by a helper instead of listing every country.
CC_BRANDS = {"google", "amazon", "mercadolibre", "dhl", "santander", "bbva"}
# ccTLDs handed out free / abused by throwaway registrations: never trusted as a brand's own.
_ABUSED_CCTLDS = {"tk", "ml", "ga", "cf", "gq", "pw"}

# Free / disposable hosting platforms (a list of hostname suffixes, not public suffixes).
THROWAWAY_HOSTING = (
    "edgeone.dev", "pages.dev", "workers.dev", "web.core.windows.net", "blob.core.windows.net",
    "netlify.app", "vercel.app", "github.io", "firebaseapp.com", "web.app", "weebly.com",
    "glitch.me", "r2.dev", "surge.sh", "webflow.io", "wixsite.com", "000webhostapp.com",
    "repl.co", "onrender.com", "herokuapp.com", "azurewebsites.net", "s3.amazonaws.com",
    "trycloudflare.com", "ngrok-free.app", "ngrok.io",
)

_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _cc_variant(host: str, name: str) -> bool:
    """True for name.<cc>, name.co.<cc> and name.com.<cc> (e.g. google.de, amazon.co.uk)."""
    parts = host.split(".")
    cc_ok = lambda cc: len(cc) == 2 and cc.isalpha() and cc not in _ABUSED_CCTLDS
    if len(parts) >= 2 and parts[-2] == name and cc_ok(parts[-1]):
        return True
    return len(parts) >= 3 and parts[-3] == name and parts[-2] in ("co", "com") and cc_ok(parts[-1])


def is_brand_domain(token: str, host: str) -> bool:
    """Is `host` one of the brand's own domains (or a subdomain of one)?"""
    if any(_under(host, d) for d in BRANDS[token]):
        return True
    return token in CC_BRANDS and _cc_variant(host, token)


def brands_in(text: str):
    """Brand tokens named in `text` (a hostname or a page title), in BRANDS order.

    Split on non-alphanumerics (so on . - _ in hostnames). A brand token of 6+ characters
    matches inside a label (`googleplay` contains `google`); 5 or fewer (zoom, apple, steam,
    chase, dhl, ...) only as a whole label, so `pineapple.com` is not Apple.
    """
    labels = [t for t in _NON_ALNUM.split(text.lower()) if t]
    found = []
    for token in BRANDS:
        if len(token) >= 6:
            hit = any(token in label for label in labels)
        else:
            hit = token in labels
        if hit:
            found.append(token)
    return found


class PnakoticScorer:
    def __init__(self):
        self.SUSPICIOUS_TLDS = {
            "xyz", "top", "icu", "gq", "tk", "ml",
            "cf", "ga", "sbs", "cfd", "click", "buzz", "rest", "bond", "lat", "cyou", "monster", "pw",
        }
        # Second tier: legitimate sites use these too, but scams cluster on them. Disjoint from the first.
        self.WATCH_TLDS = {"pro", "online", "shop", "site", "store", "live", "fun", "work", "website", "space"}
        self.HIGH_VALUE = {"google.com", "x.com", "twitter.com", "apple.com", "microsoft.com"}
        self.WEIGHTS = {
            "suspicious_tld": 0.3,
            "meta_refresh": 0.25,
            "js_location": 0.4,
            # Redirect code found in the page that never fired: weak signal, applied once each.
            "meta_refresh_code": 0.1,
            "js_location_code": 0.15,
            "js_obfuscated": 0.4,  # applied once, however many obfuscation signatures match
            "deep_chain": 0.2,
            "ip_landing": 0.5,
            "high_value_landing": 0.2,
            "brand_in_hostname": 0.4,  # applied once
            "throwaway_hosting": 0.15,
            "credential_form": 0.4,
            "cross_domain_redirect": 0.2,
            "watch_tld": 0.15,
            "brand_in_title": 0.2,
            "js_obfuscated_only": 0.1,  # obfuscation helpers with no cross-site redirect and no brand
            # Each applied once, and only when the destination is another site.
            "popup_cross_site": 0.3,
            "click_hijack": 0.4,
        }

    def score(self, result: ScanResult) -> float:
        score = 0.0
        findings = []

        host, tld = self._host_and_tld(result.final_url)
        redirect_hops = [h for h in result.hops if h.mechanism in REDIRECT_MECHANISMS]

        # Landing on a raw IP address is a classic malvertising / parking pattern.
        if host and self._is_ip(host):
            score += self.WEIGHTS["ip_landing"]
            findings.append(f"IP landing: {host}")

        if tld in self.SUSPICIOUS_TLDS:
            score += self.WEIGHTS["suspicious_tld"]
            findings.append(f"Suspicious TLD: .{tld}")

        # Only real redirects count; passive static findings are hops too but not chain depth.
        if len(redirect_hops) > 5:
            score += self.WEIGHTS["deep_chain"]
            findings.append(f"Deep chain ({len(redirect_hops)} redirects)")

        # Unweighted: says why a scan ended in ERR_BLOCKED_BY_CLIENT.
        blocked = result.metadata.get("blocked_hosts") or []
        if blocked:
            findings.append(f"Blocked request(s) to non-public host: {', '.join(blocked[:5])}")

        if result.metadata.get("redirect_loop"):
            findings.append("Redirect loop suspected (max hops reached)")

        # Classic malvertising: hop through junk, land on a high-value brand domain.
        if host and self._apex(host) in self.HIGH_VALUE and len(redirect_hops) > 0:
            score += self.WEIGHTS["high_value_landing"]
            findings.append(f"High-value landing after {len(redirect_hops)} redirect(s): {host}")

        # A navigation inside one registrable domain (a site routing between its own pages) is
        # not a redirect worth scoring; only ones that leave the site are.
        same_site_seen = set()
        for hop in result.hops:
            if hop.mechanism not in ("meta_refresh", "js_location"):
                continue
            if self._hop_crosses_sites(hop):
                if hop.mechanism == "meta_refresh":
                    score += self.WEIGHTS["meta_refresh"]
                    findings.append("Meta refresh detected")
                else:
                    score += self.WEIGHTS["js_location"]
                    findings.append("JS location manipulation")
            elif hop.mechanism not in same_site_seen:
                same_site_seen.add(hop.mechanism)
                label = "Meta refresh" if hop.mechanism == "meta_refresh" else "JS navigation"
                findings.append(f"{label} within the same site: {self._host_and_tld(hop.url)[0]}")

        if any(h.mechanism == "meta_refresh_code" for h in result.hops):
            score += self.WEIGHTS["meta_refresh_code"]
            findings.append("Meta refresh code present (did not fire)")
        if any(h.mechanism == "js_location_code" for h in result.hops):
            score += self.WEIGHTS["js_location_code"]
            findings.append("JS location code present (did not fire)")

        # Phishing-oriented signals are computed here (the obfuscation rule depends on them) but
        # their findings are appended below, after the existing ones.
        signals = result.metadata.get("page_signals") or {}
        target_host, _ = self._host_and_tld(result.target_url)
        title = signals.get("title") if isinstance(signals.get("title"), str) else ""

        brand_hit = None  # (token, host) of the first lookalike hostname
        for candidate in (host, target_host):
            if not candidate or self._is_ip(candidate):
                continue
            # A lookalike that lands on the brand's own domain is the brand's redirector
            # (googleplay.com -> play.google.com), not an impersonation.
            brand_hit = next(((t, candidate) for t in brands_in(candidate)
                              if not is_brand_domain(t, candidate)
                              and not (host and is_brand_domain(t, host))), None)
            if brand_hit:
                break

        # A password field alone proves nothing (every login page has one); it matters when
        # the page or hostname claims a brand that the serving host does not belong to.
        credential_token = None
        if self._int(signals.get("password_inputs")) >= 1 and host:
            candidates = ([brand_hit[0]] if brand_hit else []) + brands_in(title)
            credential_token = next((t for t in candidates if not is_brand_domain(t, host)), None)

        # atob / fromCharCode appear in most big sites' bundles. They only matter next to
        # something else: a redirect that left the site, or a brand being impersonated.
        if any(h.mechanism == "js_obfuscation" for h in result.hops):
            if (any(self._hop_crosses_sites(h) for h in redirect_hops)
                    or brand_hit or credential_token):
                score += self.WEIGHTS["js_obfuscated"]
                findings.append("JS obfuscation helpers (atob / String.fromCharCode)")
            else:
                score += self.WEIGHTS["js_obfuscated_only"]
                findings.append("JS obfuscation helpers present (no cross-site redirect)")

        # Popups and click hijacks: the visitor's page opened or became someone else's site.
        # Same-site ones (a site's own share window, a same-site click handler) stay unscored.
        popups = self._cross_site_targets(result.hops, "popup_open")
        if popups:
            score += self.WEIGHTS["popup_cross_site"]
            on_click = any(t == "click" for _, t in popups)
            hosts = list(dict.fromkeys(h for h, _ in popups))
            findings.append(f"Popup to another site{' on click' if on_click else ''}: {', '.join(hosts[:3])}")
        hijacks = self._cross_site_targets(result.hops, "click_hijack")
        if hijacks:
            score += self.WEIGHTS["click_hijack"]
            findings.append(f"Click on the page sent it to another site: {hijacks[0][0]}")

        # --- Phishing-oriented rules: pages that never redirect still give themselves away. ---
        if brand_hit:
            score += self.WEIGHTS["brand_in_hostname"]
            findings.append(f"Brand name in hostname: {brand_hit[0]} on {brand_hit[1]}")

        for suffix in THROWAWAY_HOSTING:
            if any(h and _under(h, suffix) for h in (host, target_host)):
                score += self.WEIGHTS["throwaway_hosting"]
                findings.append(f"Free hosting platform: {suffix}")
                break

        if credential_token:
            score += self.WEIGHTS["credential_form"]
            findings.append(f"Credential form impersonating {credential_token} on {host}")

        # Page title that leads with a brand name (the first three words), on a host that is
        # not the brand's. Weaker than a credential form, so it does not stack with one.
        if not credential_token and host:
            lead = [w for w in _NON_ALNUM.split(title.lower()) if w][:3]
            title_brand = next((t for t in BRANDS if t in lead and not is_brand_domain(t, host)), None)
            if title_brand:
                score += self.WEIGHTS["brand_in_title"]
                findings.append(f"Brand name leads page title: {title_brand} on {host}")

        if (redirect_hops and host and target_host
                and self._apex(host) != self._apex(target_host)
                and self._apex(host) not in self.HIGH_VALUE):
            score += self.WEIGHTS["cross_domain_redirect"]
            findings.append(
                f"Redirected to a different domain: {self._apex(target_host)} -> {self._apex(host)}")

        if tld in self.WATCH_TLDS:
            score += self.WEIGHTS["watch_tld"]
            findings.append(f"Abuse-prone TLD: .{tld}")

        # Unweighted: explain an empty or odd landing.
        failed = result.metadata.get("navigation_failed")
        if failed:
            failed_host, _ = self._host_and_tld(failed if isinstance(failed, str) else "")
            findings.append(f"Navigation failed: {failed_host or failed} unreachable")
        content_type = signals.get("content_type")
        if content_type and not str(content_type).startswith(("text/html", "application/xhtml")):
            findings.append(f"Landing document is not HTML: {content_type}")

        result.malicious_score = round(min(score, 1.0), 4)  # float sums like 0.6000000000000001 leak into the API
        result.metadata["scoring_findings"] = findings
        return result.malicious_score

    def _hop_crosses_sites(self, hop) -> bool:
        """Did this observed redirect leave the registrable domain it was issued from?

        Unknown destinations (no `to` / Location, or unparseable) count as crossing: the
        old, stricter behaviour.
        """
        try:
            if hop.mechanism == "http_3xx":
                to = next((v for k, v in (hop.headers or {}).items() if k.lower() == "location"), "")
            else:
                ev = json.loads(hop.evidence) if hop.evidence else {}
                to = ev.get("to") if isinstance(ev, dict) else ""
            if not to:
                return True
            to_host, _ = self._host_and_tld(urljoin(hop.url, str(to)))
            from_host, _ = self._host_and_tld(hop.url)
        except (ValueError, AttributeError):
            return True
        if not to_host or not from_host:
            return True
        return self._site(to_host) != self._site(from_host)

    def _site(self, host: str) -> str:
        """What counts as 'the same site': the apex, or the whole address for an IP."""
        return host if self._is_ip(host) else self._apex(host)

    def _cross_site_targets(self, hops, mechanism: str):
        """(destination host, trigger) for each `mechanism` hop that leaves the opener's site."""
        out = []
        for hop in hops:
            if hop.mechanism != mechanism or not hop.evidence:
                continue
            try:
                ev = json.loads(hop.evidence)
            except ValueError:
                continue
            if not isinstance(ev, dict):
                continue
            try:
                to_url = urljoin(hop.url, str(ev.get("to") or ""))
            except ValueError:  # malformed, attacker-supplied URL
                continue
            to_host, _ = self._host_and_tld(to_url)
            from_host, _ = self._host_and_tld(hop.url)
            if to_host and from_host and self._site(to_host) != self._site(from_host):
                out.append((to_host, ev.get("trigger") or "load"))
        return out

    @staticmethod
    def _host_and_tld(url):
        if not url:
            return "", ""
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            return "", ""
        tld = host.split(".")[-1] if "." in host else ""
        return host, tld

    @staticmethod
    def _int(value) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _apex(host: str) -> str:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else host
