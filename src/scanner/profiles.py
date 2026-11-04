from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class BrowserProfile:
    name: str
    user_agent: str
    viewport: Dict[str, int]
    extra_headers: Dict[str, str] = field(default_factory=dict)
    is_mobile: bool = False
    has_touch: bool = False

PROFILES = {
    "default": BrowserProfile(name="Default Desktop", user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", viewport={"width": 1920, "height": 1080}),
    "mobile-ios": BrowserProfile(name="Mobile iOS", user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True, extra_headers={"Sec-CH-UA-Mobile": "?1"}),
    "mobile-android": BrowserProfile(name="Mobile Android", user_agent="Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36", viewport={"width": 412, "height": 915}, is_mobile=True, has_touch=True, extra_headers={"Sec-CH-UA-Mobile": "?1"}),
    "search-clicker": BrowserProfile(name="Google Search Referrer", user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", viewport={"width": 1920, "height": 1080}, extra_headers={"Referer": "https://www.google.com/"})
}

