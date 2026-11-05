"""A bounded text window around a match in an attacker-controlled buffer.

The before, match and after byte slices are decoded separately (UTF-8 with replacement,
NULs stripped), so the match's character offsets in the returned text are exact.
"""
from typing import Any, Dict


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", "replace").replace("\x00", "")


def cut_snippet(data: bytes, start: int, end: int, before: int = 240, after: int = 240,
                cap: int = 600) -> Dict[str, Any]:
    """The text around data[start:end]: up to `before` bytes ahead and `after` behind, `cap` bytes in all.

    Returns `text`, `match_start` / `match_end` (character offsets of the match in `text`) and
    `line` (1-based line number of the match start). A match longer than `cap` is trimmed to it
    and the context is dropped first.
    """
    start = max(0, min(start, len(data)))
    end = max(start, min(end, len(data)))
    end = min(end, start + cap)
    leftover = cap - (end - start)
    before = max(0, min(before, leftover // 2, start))
    after = max(0, min(after, leftover - before, len(data) - end))
    head = _decode(data[start - before:start])
    body = _decode(data[start:end])
    tail = _decode(data[end:end + after])
    return {
        "text": head + body + tail,
        "match_start": len(head),
        "match_end": len(head) + len(body),
        "line": data.count(b"\n", 0, start) + 1,
    }
