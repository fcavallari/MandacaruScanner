import ipaddress
from urllib.parse import urlparse

from ..scanner.behavior import LOCK_BEHAVIORS, behavior_events, evidence_of
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
            # Landing-page behavior (behavior.py), each applied once. The strong forms of these
            # (a shell command on the clipboard, an executable download, a browser lock) are
            # decisive instead; see _decisive().
            "clipboard_write": 0.15,
            "download": 0.4,
            "lock_behavior": 0.15,  # per distinct lock behavior
            "notification_request": 0.2,
            "window_open": 0.1,
            "dialog": 0.1,
            "clickfix_lure": 0.3,  # "Win+R ... Ctrl+V" instructions in the page text
            # Profiles landed on different registrable domains (combine()); decisive when the
            # steered-to page is itself Suspicious or worse.
            "cloaking": 0.35,
            # YARA rule hits on the page, its frames or its scripts (yara_scan.py), applied once
            # each tier. A production rule of severity 4-5 is decisive instead.
            "yara_strong": 0.4,  # an exploratory rule of severity >= 4, or a production rule of 3
            "yara_weak": 0.15,   # anything else that matched
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

        if any(h.mechanism == "clickfix_lure" for h in result.hops):
            score += self.WEIGHTS["clickfix_lure"]
            findings.append("ClickFix lure text: asks the visitor to press Win+R and paste")

        events = behavior_events(result.hops)
        score += self._behavior_support(events, findings)
        yara_hits = evidence_of(result.hops, "yara_match")
        score += self._yara_support(yara_hits, findings)

        # Decisive indicators settle the verdict on their own; they lead the findings.
        decisive = self._decisive(events) + self._yara_decisive(yara_hits)
        if decisive:
            score = 1.0
            findings = decisive + findings
        result.metadata["decisive_findings"] = decisive

        result.malicious_score = min(score, 1.0)
        result.metadata["scoring_findings"] = findings
        return result.malicious_score

    def combine(self, result: ScanResult, profile: str, variants: dict) -> float:
        """Fold the comparison profiles into the job's (already scored) result.

        `variants` maps profile name -> its scored ScanResult, or an error string when that
        profile's page failed. The job score is the worst profile's score, so a payload shown
        only to iOS is not hidden behind a clean desktop view. Cloaking is landing on a
        different registrable domain depending on the profile: a supporting signal on its
        own (sites do send phones to an app store), decisive when any profile's own page
        scores Suspicious or worse.
        """
        landings = {profile: self._landing_apex(result)}
        summaries = [self._summary(profile, result, requested=True)]  # its own score, before the fold
        decisive = list(result.metadata.get("decisive_findings", []))
        findings = list(result.metadata.get("scoring_findings", []))
        own = set(findings)
        worst = result.malicious_score

        for name, variant in variants.items():
            if not isinstance(variant, ScanResult):
                summaries.append({"profile": name, "error": str(variant)[:256]})
                continue
            landings[name] = self._landing_apex(variant)
            worst = max(worst, variant.malicious_score)
            for f in variant.metadata.get("scoring_findings", []):
                if f not in own:
                    findings.append(f"[{name}] {f}")
            decisive += [f"[{name}] {f}" for f in variant.metadata.get("decisive_findings", [])]
            summaries.append(self._summary(name, variant))

        score = worst
        cloaking = None
        apexes = {a for a in landings.values() if a}
        if len(apexes) > 1:
            by_apex: dict = {}
            for name, apex in landings.items():
                if apex:
                    by_apex.setdefault(apex, []).append(name)
            # The majority landing is the "shown to most" page; the rest were steered elsewhere.
            common = max(by_apex, key=lambda a: (len(by_apex[a]), a == landings[profile]))
            steered = {name: apex for name, apex in landings.items() if apex and apex != common}
            scores = {profile: result.malicious_score}
            scores.update({n: v.malicious_score for n, v in variants.items() if isinstance(v, ScanResult)})
            # Either side can be the payload: phones steered to a scam while desktops get the
            # real page, or most profiles get the scam while a bot-like one gets a google.com
            # fallback. So any profile whose own page is Suspicious makes the split decisive.
            bad = sorted(n for n, apex in landings.items() if apex and scores.get(n, 0.0) >= 0.4)
            detail = "; ".join(f"{name} → {apex}" for name, apex in sorted(landings.items()) if apex)
            cloaking = {"landings": landings, "common": common, "steered": sorted(steered), "suspicious": bad}
            if bad:
                decisive.insert(0, f"Decisive: cloaking, profiles land on different sites and {', '.join(bad)} "
                                   f"got a suspicious page ({detail})")
            else:
                score += self.WEIGHTS["cloaking"]
                findings.insert(0, f"Cloaking: landing depends on the browser profile ({detail})")

        if decisive:
            score = 1.0
            findings = [f for f in decisive if f not in findings] + findings
        result.malicious_score = min(score, 1.0)
        result.metadata["scoring_findings"] = findings
        result.metadata["decisive_findings"] = decisive
        result.metadata["variants"] = summaries
        result.metadata["cloaking"] = cloaking
        return result.malicious_score

    @staticmethod
    def _summary(profile: str, result: ScanResult, requested: bool = False) -> dict:
        return {
            "profile": profile,
            "requested": requested,
            "final_url": result.final_url,
            "malicious_score": result.malicious_score,
            "redirects": sum(1 for h in result.hops if h.mechanism in REDIRECT_MECHANISMS),
            "decisive": result.metadata.get("decisive_findings", []),
            "raw_error": result.metadata.get("raw_error"),
        }

    def _landing_apex(self, result: ScanResult) -> str:
        """Registrable-ish domain the profile ended on; '' when its page never loaded."""
        if result.metadata.get("raw_error") and (result.final_url or "") == result.target_url:
            return ""
        host, _ = self._host_and_tld(result.final_url)
        return host if (host and self._is_ip(host)) else (self._apex(host) if host else "")

    @staticmethod
    def _yara_tier(hit) -> str:
        """decisive: a production rule of severity 4-5. strong: an exploratory rule of severity
        4-5, or a production rule of 3. weak: anything else (exploratory rules are still being
        tuned against false positives, so they never decide a verdict alone)."""
        severity, production = hit.get("severity", 0), bool(hit.get("production"))
        if production and severity >= 4:
            return "decisive"
        if severity >= 4 or (production and severity == 3):
            return "strong"
        return "weak"

    def _yara_decisive(self, hits) -> list:
        return [f"Decisive: known malicious code, YARA {h.get('rule')} (severity {h.get('severity')}) "
                f"in {h.get('source')} {h.get('url', '')[:100]}: {h.get('description', '')[:120]}"
                for h in hits if self._yara_tier(h) == "decisive"]

    def _yara_support(self, hits, findings) -> float:
        tiers = {"strong": [], "weak": []}
        for h in hits:
            tier = self._yara_tier(h)
            if tier in tiers:
                tiers[tier].append(h)
        score = 0.0
        for tier in ("strong", "weak"):
            if tiers[tier]:
                score += self.WEIGHTS[f"yara_{tier}"]
            for h in tiers[tier]:
                kind = "production" if h.get("production") else "exploratory"
                findings.append(f"YARA {h.get('rule')} ({kind}, severity {h.get('severity')}) in {h.get('source')}: "
                                f"{h.get('description', '')[:120]}")
        return score

    @staticmethod
    def _decisive(events) -> list:
        out = []
        command = next((e for e in events if e.get("id") == "clipboard_write" and e.get("command")), None)
        if command:
            out.append(f"Decisive: page wrote a shell command to the clipboard (ClickFix): {command.get('text', '')[:120]}")
        exe = next((e for e in events if e.get("id") == "download" and e.get("executable")), None)
        if exe:
            out.append(f"Decisive: download of {exe.get('filename') or 'an executable'} started without a click")
        locks = sorted({e.get("id") for e in events} & LOCK_BEHAVIORS)
        if len(locks) >= 2:
            out.append(f"Decisive: browser-lock pattern (tech-support scam): {', '.join(locks)}")
        return out

    def _behavior_support(self, events, findings) -> float:
        ids = {e.get("id") for e in events}
        score = 0.0
        if any(e.get("id") == "clipboard_write" and not e.get("command") for e in events):
            score += self.WEIGHTS["clipboard_write"]
            findings.append("Clipboard write without a click")
        downloads = [e for e in events if e.get("id") == "download" and not e.get("executable")]
        if downloads:
            score += self.WEIGHTS["download"]
            findings.append(f"Download started without a click: {downloads[0].get('filename') or 'unnamed file'}")
        # A lone beforeunload handler is everyday analytics and unsaved-form code (google.com
        # installs one), so it only counts as part of the two-behavior lock pattern.
        for lock in sorted((ids & LOCK_BEHAVIORS) - {"beforeunload_trap"}):
            score += self.WEIGHTS["lock_behavior"]
            findings.append(f"Browser-lock behavior: {lock}")
        if "notification_request" in ids:
            score += self.WEIGHTS["notification_request"]
            findings.append("Push-notification permission requested on load")
        if "window_open" in ids:
            score += self.WEIGHTS["window_open"]
            findings.append("Popup attempt (window.open)")
        if "dialog" in ids:
            score += self.WEIGHTS["dialog"]
            findings.append("JavaScript dialog shown on load")
        return score

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
