def test_parse_stack_reads_url_line_and_eval():
    """parse_stack reads card_watch's formatter output (the only producer), not V8's own text."""
    from pnakotic.src.scanner.code_origin import parse_stack
    s = ("Error\n    at https://shop.com/wp-content/plugins/x/a.js:10:5\n"
         "    at https://cdn.evil.io/s.js:1:200\n"
         "    at eval (eval at <anonymous>)\n    at <anonymous>\n"
         "    at f (https://shop.com/a.js:3:1)")  # V8's own form: not ours, so unreadable
    fr = parse_stack(s)
    assert [(f.url, f.line, f.eval) for f in fr] == [
        ("https://shop.com/wp-content/plugins/x/a.js", 10, False), ("https://cdn.evil.io/s.js", 1, False),
        ("", None, True), ("", None, True), ("", None, True)]


def test_parse_stack_is_bounded():
    from pnakotic.src.scanner.code_origin import parse_stack
    assert len(parse_stack("Error\n" + "    at https://a.com/x.js:1:1\n" * 500)) == 30


def test_parse_stack_reads_the_location_right_after_at_and_nothing_inside_it():
    """A store URL inside a frame's text (a function name, a query string with "(", a data: URL's
    comment) can't pose as the location: the location is anchored right after "at "."""
    from pnakotic.src.scanner.code_origin import parse_stack
    for text in ("    at x (https://shop.com/a.js:1:1) y (https://evil.io/s.js:7:3)",
                 "    at https://evil.io/s.js?(https://shop.com/a.js:1:97",
                 "    at data:text/javascript,x// https://shop.com/wp-includes/js/jquery/jquery.min.js:1:5",
                 "    at https://evil.io/s.js:1:2 https://shop.com/a.js:3:4"):
        assert [(f.url, f.eval) for f in parse_stack("Error\n" + text)] == [("", True)], text


def test_parse_stack_handles_async_ports_and_junk():
    from pnakotic.src.scanner.code_origin import parse_stack
    s = ("TypeError: x\n    at https://shop.com:8443/a.js:4:2\n"
         "    at blob:https://shop.com/uuid:1:1\n    not a frame\n")
    assert [(f.url, f.line, f.eval) for f in parse_stack(s)] == [
        ("https://shop.com:8443/a.js", 4, False), ("", None, True)]
    assert parse_stack("") == []


def test_jquery_on_a_cdn_is_the_store_but_other_jsdelivr_files_are_not():
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    own = lambda u: frame_owner(Frame(u, 1, False), "shop.com", "https://shop.com/checkout/", [])
    assert own("https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js") == "store"
    assert own("https://cdn.jsdelivr.net/gh/attacker/skim/s.js") == "unknown"
    assert own("https://c0.wp.com/c/6.6/wp-includes/js/jquery/jquery.min.js") == "store"
    assert own("https://js.stripe.com/v3/") == "provider"
    assert own("https://static.hotjar.com/c/hotjar-1.js") == "vendor"


def test_same_site_is_store_and_ip_and_localhost_are_different_owners():
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    page = "http://127.0.0.1:8000/checkout/"
    own = lambda u, host="127.0.0.1": frame_owner(Frame(u, 1, False), host, page, [])
    assert own("http://127.0.0.1:8000/a.js") == "store"
    assert own("http://localhost:8000/a.js") == "unknown"
    assert frame_owner(Frame("https://cdn.shop.com/a.js", 1, False), "www.shop.com", page, []) == "store"
    assert frame_owner(Frame("https://a.js", 1, True), "shop.com", page, []) == "unknown"
    assert frame_owner(Frame("", None, True), "shop.com", page, []) == "unknown"


def test_inline_frame_is_store_only_when_its_script_is_a_served_block():
    """A page-URL frame is store code only when its script hash is a served inline block's. Its
    line is no proof: an event handler set at runtime also runs at the page URL, at any line."""
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    served, handler = "a" * 64, "b" * 64
    page = "https://shop.com/checkout/"
    assert frame_owner(Frame(page, 7, False, served), "shop.com", page, {served}) == "store"
    assert frame_owner(Frame(page + "#x", 7, False, served), "shop.com", page, {served}) == "store"
    assert frame_owner(Frame(page, 7, False, handler), "shop.com", page, {served}) == "unknown"
    assert frame_owner(Frame(page, 7, False), "shop.com", page, {served}) == "unknown"  # no hash: unknown
    assert frame_owner(Frame(page, 7, False, served), "shop.com", page, None) == "unknown"
    assert frame_owner(Frame(page, 7, False, served), "shop.com", page + "#y", set()) == "unknown"
    # another file of the site needs no hash
    assert frame_owner(Frame("https://shop.com/a.js", 7, False), "shop.com", page, set()) == "store"


def test_parse_stack_reads_the_script_hash_after_the_location():
    from pnakotic.src.scanner.code_origin import parse_stack
    h = "0123456789abcdef" * 4
    s = (f"Error\n    at https://shop.com/checkout/:3:5 sha256={h}\n    at https://shop.com/a.js:1:1\n"
         f"    at f (https://shop.com/b.js:2:2) sha256={h[:-1]}\n")
    assert [(f.url, f.line, f.hash) for f in parse_stack(s)] == [
        ("https://shop.com/checkout/", 3, h), ("https://shop.com/a.js", 1, None), ("", None, None)]


def test_a_stack_cut_inside_a_line_drops_that_line():
    """A 4 000-character cut can end a line just after an embedded store location: that line is
    dropped, not read."""
    from pnakotic.src.scanner.code_origin import parse_stack, stack_was_cut, whole_lines
    tail = "    at https://evil.io/" + "a" * 50 + ".js?https://shop.com/:3:5"
    head = "Error\n" + "    at https://evil.io/x.js:1:1\n" * 3
    stack = head + "x" * (4000 - len(head) - len(tail)) + "\n" + tail + "9:9"
    assert len(stack) > 4000 and stack_was_cut(stack)
    assert all(f.url != "https://shop.com/" for f in parse_stack(stack))
    assert whole_lines("ab\ncd", 4) == "ab" and whole_lines("ab\ncd", 2) == "ab" and whole_lines("abcd", 2) == ""
    assert whole_lines("ab\ncd", 10) == "ab\ncd"


def test_served_block_positions_are_cdp_coordinates():
    """0-based line and UTF-16 column of each block's text, after a BOM and with CRLF as LF
    (matched against Chromium 148's Debugger.scriptParsed on six pages)."""
    import hashlib

    from pnakotic.src.scanner.code_origin import served_block_positions
    sha = lambda t: hashlib.sha256(t.encode("utf-8")).hexdigest()
    html = "\ufeff<html>\r\n<p>\U0001F600</p> <script>a()</script><script>b()</script>".encode("utf-8")
    pos = served_block_positions(html)
    # line 1 is "<p>" + an emoji (2 UTF-16 units) + "</p> <script>": a() starts at column 18
    assert (1, 18) in pos[sha("a()")] and (1, 38) in pos[sha("b()")]
    assert (1, 20) in pos[sha("a()")]  # the windows-1252 reading counts the emoji's 4 bytes
    assert served_block_positions(None) == {}


def test_a_served_hash_is_trusted_only_when_every_copy_sits_at_a_served_block():
    import hashlib

    from pnakotic.src.scanner.code_origin import trusted_inline_hashes
    html = b"<html><head><script>var a = 1;</script></head></html>"
    h = hashlib.sha256(b"var a = 1;").hexdigest()
    assert trusted_inline_hashes(html, {h: {(0, 20)}}) == {h}
    assert trusted_inline_hashes(html, {h: {(0, 20), (0, 0)}}) == set()  # a handler with the same text
    assert trusted_inline_hashes(html, {h: {(0, 0)}}) == set()
    assert trusted_inline_hashes(html, {}) == set()  # never parsed (no debugger): not proven
    assert trusted_inline_hashes(html, None) == set()  # the record overflowed


def test_inline_script_hashes_are_the_served_blocks_as_the_browser_runs_them():
    import hashlib

    from pnakotic.src.scanner.code_origin import inline_script_hashes, inline_script_texts
    html = ("<html>\r\n<script>\r\nvar a = 'caf\u00e9';\rvar b;\r\n</script>\r\n<script src='x.js'></script>"
            "<script>one()</script>\n").encode("utf-8")
    assert inline_script_texts(html) == ["\nvar a = 'caf\u00e9';\nvar b;\n", "one()"]
    assert inline_script_hashes(html) >= {hashlib.sha256(t.encode("utf-8")).hexdigest()
                                          for t in ("\nvar a = 'caf\u00e9';\nvar b;\n", "one()")}
    assert inline_script_hashes(None) == set() and inline_script_hashes(b"") == set()
    # a page with no declared charset is read as windows-1252 (0x80 is the euro sign there, 0x81 is U+0081)
    raw = b"<script>x = '\x80\x81\xe9'</script>"
    assert hashlib.sha256("x = '\u20ac\u0081\u00e9'".encode("utf-8")).hexdigest() in inline_script_hashes(raw)


def test_inline_line_ranges_are_one_based_line_spans_of_script_blocks():
    from pnakotic.src.scanner.code_origin import inline_line_ranges
    html = (b"<html>\n<script>\nvar a=1;\nvar b=2;\n</script>\n<p>x</p>\n"
            b"<script src='x.js'></script>\n<script>one()</script>\n")
    assert inline_line_ranges(html) == [(2, 4), (8, 8)]
    assert inline_line_ranges(None) == []
    assert inline_line_ranges(b"") == []


def test_stack_was_cut_reports_frame_and_character_overflow():
    from pnakotic.src.scanner.code_origin import stack_was_cut
    line = "    at https://a.com/x.js:1:1\n"
    assert stack_was_cut("Error\n" + line * 31) is True
    assert stack_was_cut("Error\n" + line * 30) is False
    assert stack_was_cut("Error\n" + "x" * 4000) is True
    assert stack_was_cut("") is False


def test_cdn_path_hosts_match_whole_package_names_only():
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    own = lambda u: frame_owner(Frame(u, 1, False), "shop.com", "https://shop.com/checkout/", [])
    assert own("https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js") == "store"
    assert own("https://cdn.jsdelivr.net/npm/jquery-ui@1.13.2/dist/jquery-ui.min.js") == "store"
    assert own("https://cdn.jsdelivr.net/npm/jquery-migrate@3.4.1/dist/m.js") == "store"
    assert own("https://cdn.jsdelivr.net/npm/jquery-evil@1/x.js") == "unknown"
    assert own("https://cdn.jsdelivr.net/npm/jquery") == "store"
    assert own("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js") == "store"
    assert own("https://cdnjs.cloudflare.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js") == "store"
    assert own("https://cdnjs.cloudflare.com/ajax/libs/jquery-evil/1/x.js") == "unknown"
    assert own("https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js") == "store"
    assert own("https://ajax.googleapis.com/ajax/libs/jqueryui/1.13.2/jquery-ui.min.js") == "store"
    assert own("https://ajax.googleapis.com/ajax/libs/jqueryx/1/x.js") == "unknown"


def test_a_dot_never_ends_a_cdn_package_name():
    # anyone can publish an npm package called jquery.<anything>, so "." is not a boundary on any host
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    own = lambda u: frame_owner(Frame(u, 1, False), "shop.com", "https://shop.com/checkout/", [])
    assert own("https://cdn.jsdelivr.net/npm/jquery.cdn@1/x.js") == "unknown"
    assert own("https://cdn.jsdelivr.net/npm/jquery.evil/x.js") == "unknown"
    assert own("https://cdn.jsdelivr.net/npm/jquery-ui.skim@1/x.js") == "unknown"
    assert own("https://cdnjs.cloudflare.com/ajax/libs/jquery.evil/1/x.js") == "unknown"
    assert own("https://ajax.googleapis.com/ajax/libs/jquery.evil/1/x.js") == "unknown"
    # the real jQuery CDN paths end the package name with "/" or "@"
    assert own("https://cdn.jsdelivr.net/npm/jquery/dist/jquery.min.js") == "store"
    assert own("https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js") == "store"
    assert own("https://cdnjs.cloudflare.com/ajax/libs/jquery-migrate/3.4.1/jquery-migrate.min.js") == "store"
    assert own("https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js") == "store"
