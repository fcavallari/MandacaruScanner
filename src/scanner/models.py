from datetime import datetime
from typing import List, Optional, Dict, Any

from pydantic import BaseModel, Field


# Mechanisms that represent an actual redirect (as opposed to passive static findings
# such as 'js_obfuscation' or 'static_analysis').
REDIRECT_MECHANISMS = {"http_3xx", "meta_refresh", "js_location"}


class RedirectHop(BaseModel):
    url: str
    status_code: Optional[int] = None
    headers: Dict[str, str] = {}
    # default_factory: a plain `= datetime.now()` is evaluated once at import time.
    timestamp: datetime = Field(default_factory=datetime.now)
    # Observed navigations: 'http_3xx', 'meta_refresh', 'js_location' (the redirects), plus
    # 'client_navigation' (anchor click, form submit, ... informational).
    # From the landing-page regexes: 'meta_refresh_code', 'js_location_code' (redirect code
    # present but did not fire), 'js_obfuscation', 'static_analysis'.
    mechanism: str
    evidence: Optional[str] = None


class ScanResult(BaseModel):
    target_url: str
    start_time: datetime = Field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    hops: List[RedirectHop] = []
    malicious_score: float = 0.0
    final_url: Optional[str] = None
    is_redirect_chain_detected: bool = False
    metadata: Dict[str, Any] = {}
