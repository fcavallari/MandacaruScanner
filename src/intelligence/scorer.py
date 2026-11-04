import ipaddress
from urllib.parse import urlparse

from ..scanner.models import ScanResult, REDIRECT_MECHANISMS


class PnakoticScorer:
    def __init__(self):
        self.SUSPICIOUS_TLDS = {"xyz", "top", "icu", "gq", "tk", "ml"}
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

        for hop in result.hops:
            if hop.mechanism == "meta_refresh":
                score += self.WEIGHTS["meta_refresh"]
                findings.append("Meta refresh detected")
            elif hop.mechanism == "js_location":
                score += self.WEIGHTS["js_location"]
                findings.append("JS location manipulation")

        if any(h.mechanism == "meta_refresh_code" for h in result.hops):
            score += self.WEIGHTS["meta_refresh_code"]
            findings.append("Meta refresh code present (did not fire)")
        if any(h.mechanism == "js_location_code" for h in result.hops):
            score += self.WEIGHTS["js_location_code"]
            findings.append("JS location code present (did not fire)")

        if any(h.mechanism == "js_obfuscation" for h in result.hops):
            score += self.WEIGHTS["js_obfuscated"]
            findings.append("JS obfuscation helpers (atob / String.fromCharCode)")

        result.malicious_score = min(score, 1.0)
        result.metadata["scoring_findings"] = findings
        return result.malicious_score

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
