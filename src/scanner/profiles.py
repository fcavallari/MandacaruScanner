"""Visitor personas. Hacked sites often redirect only some visitors: phones, people
arriving from Google or Facebook, or Googlebot (cloaking). Each profile plays one of them.

`{chrome}` in a user agent is replaced with the major version of the browser actually
scanning (see `user_agent_for`). A Chrome token years out of date is itself a bot tell
that cloakers use to hide from scanners, so the UA follows the real build.
"""
from dataclasses import dataclass, field
from typing import Dict, List

# Used when the browser's version can't be read.
FALLBACK_CHROME_MAJOR = "142"


@dataclass
class BrowserProfile:
    name: str
    user_agent: str
    viewport: Dict[str, int]
    extra_headers: Dict[str, str] = field(default_factory=dict)
    is_mobile: bool = False
    has_touch: bool = False
    # User-Agent Client Hints (the sec-ch-ua* headers and navigator.userAgentData). Left alone,
    # Chrome sends its real brand list, which names "HeadlessChrome" whatever the UA string
    # says. `brands` are brand names; versions are filled from the browser. An empty list (iOS
    # Safari, which has no client hints) still sends an empty sec-ch-ua, but names nothing.
    hint_brands: List[str] = field(default_factory=lambda: ["Chromium", "Google Chrome"])
    hint_platform: str = "Linux"
    hint_platform_version: str = ""
    hint_model: str = ""

    def user_agent_for(self, browser_version: str) -> str:
        return self.user_agent.replace("{chrome}", _major(browser_version))

    def user_agent_metadata(self, browser_version: str) -> dict:
        """CDP Emulation.UserAgentMetadata matching this persona."""
        major = _major(browser_version)
        full = browser_version if browser_version and browser_version.split(".")[0] == major else f"{major}.0.0.0"
        brands = [{"brand": b, "version": major} for b in self.hint_brands]
        if brands:
            brands.append({"brand": "Not/A)Brand", "version": "99"})
        return {
            "brands": brands,
            "fullVersionList": [dict(b, version=full if b["brand"] != "Not/A)Brand" else "99.0.0.0") for b in brands],
            "platform": self.hint_platform,
            "platformVersion": self.hint_platform_version,
            "architecture": "" if self.is_mobile else "x86",
            "model": self.hint_model,
            "mobile": self.is_mobile,
        }


def _major(browser_version: str) -> str:
    major = (browser_version or "").split(".")[0]
    return major if major.isdigit() else FALLBACK_CHROME_MAJOR


DESKTOP_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Safari/537.36"
DESKTOP_VIEWPORT = {"width": 1920, "height": 1080}

PROFILES = {
    "default": BrowserProfile(name="Default Desktop", user_agent=DESKTOP_UA, viewport=DESKTOP_VIEWPORT),
    # iOS 26 freezes the OS token at 18_6; Safari's version is the real one.
    "mobile-ios": BrowserProfile(
        name="Mobile iOS",
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
        viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True,
        hint_brands=[], hint_platform="",
    ),
    "mobile-android": BrowserProfile(
        name="Mobile Android",
        user_agent="Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Mobile Safari/537.36",
        viewport={"width": 412, "height": 915}, is_mobile=True, has_touch=True,
        hint_platform="Android", hint_platform_version="14.0.0", hint_model="Pixel 8",
    ),
    # Google's result links carry referrer policy `origin`, so a click from a result sends exactly this.
    "search-clicker": BrowserProfile(
        name="Google Search Referrer", user_agent=DESKTOP_UA, viewport=DESKTOP_VIEWPORT,
        extra_headers={"Referer": "https://www.google.com/"},
    ),
    # A link tapped in the Facebook app on Android: the in-app WebView ("wv", FB_IAB), the
    # l.facebook.com link shim as referrer, and the app's package in X-Requested-With.
    "facebook-android": BrowserProfile(
        name="Facebook app (Android)",
        user_agent="Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/AP2A.240805.005; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/{chrome}.0.0.0 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/480.0.0.38.109;]",
        viewport={"width": 412, "height": 915}, is_mobile=True, has_touch=True,
        extra_headers={"Referer": "https://l.facebook.com/", "X-Requested-With": "com.facebook.katana"},
        hint_brands=["Android WebView", "Chromium"], hint_platform="Android",
        hint_platform_version="14.0.0", hint_model="Pixel 8",
    ),
    # Googlebot Smartphone (mobile-first indexing). This only defeats cloaking that checks the
    # user agent: a cloaker that verifies Googlebot by reverse DNS still sees a datacenter IP.
    "googlebot": BrowserProfile(
        name="Googlebot (smartphone)",
        user_agent="Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{chrome}.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        viewport={"width": 412, "height": 732}, is_mobile=True, has_touch=True,
        hint_brands=["Chromium"], hint_platform="Android", hint_platform_version="6.0.1", hint_model="Nexus 5X",
    ),
}
