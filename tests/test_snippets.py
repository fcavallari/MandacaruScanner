def test_cut_snippet_window_offsets_and_line():
    from pnakotic.src.scanner.snippets import cut_snippet

    data = b"line1\nline2\n" + b"a" * 300 + b"EVIL" + b"b" * 300
    s = cut_snippet(data, 312, 316)
    assert s["line"] == 3
    assert s["text"][s["match_start"]:s["match_end"]] == "EVIL"
    assert len(s["text"].encode()) <= 600 and s["match_start"] == 240


def test_cut_snippet_edges_cap_and_bad_utf8():
    from pnakotic.src.scanner.snippets import cut_snippet

    s = cut_snippet(b"EVIL\x00tail", 0, 4)
    assert s["match_start"] == 0 and "\x00" not in s["text"]
    s = cut_snippet(b"x" * 10 + b"M" * 1000, 10, 1010)
    assert len(s["text"]) <= 600 and s["match_start"] == 0   # an oversized match is trimmed, context dropped first
    s = cut_snippet(b"\xff\xfeEVIL", 2, 6)
    assert s["text"][s["match_start"]:s["match_end"]] == "EVIL"
