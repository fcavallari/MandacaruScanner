"""Markers of obfuscator.io-style JavaScript.

Every regex here runs over page-supplied text, so quantifiers are bounded and the input
is capped.
"""
import re
from typing import List

MAX_CHARS = 200000

# A function that returns/holds a string array ...
_ARRAY_FUNCTION_RE = re.compile(
    r"function\s+[\w$]{1,12}\s*\(\s*\)\s*\{\s*(?:var|let|const)\s+[\w$]{1,12}\s*=\s*\[")
# ... and the push(shift()) rotation that scrambles it.
_ROTATION_RES = (
    re.compile(r"\[\s*'push'\s*\]\s*\(\s*[\w$]{1,12}\s*\[\s*'shift'\s*\]\s*\(\s*\)\s*\)"),
    re.compile(r"\.push\(\s*[\w$]{1,12}\.shift\(\s*\)\s*\)"),
)
_HEX_IDENT_RE = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
_HEX_MIN_COUNT = 30
_HEX_CHARS_PER_MATCH = 200


def obfuscator_markers(js: str) -> List[str]:
    """Which of ``string_array_rotation`` / ``hex_identifier_density`` the first 200 000
    characters of ``js`` show."""
    js = (js or "")[:MAX_CHARS]
    markers = []  # type: List[str]
    if _ARRAY_FUNCTION_RE.search(js) and any(rx.search(js) for rx in _ROTATION_RES):
        markers.append("string_array_rotation")
    hex_count = len(_HEX_IDENT_RE.findall(js))
    if hex_count >= _HEX_MIN_COUNT and hex_count * _HEX_CHARS_PER_MATCH >= len(js):
        markers.append("hex_identifier_density")
    return markers
