def test_parse_stack_reads_url_line_and_eval():
    from pnakotic.src.scanner.code_origin import parse_stack
    s = ("Error\n    at f (https://shop.com/wp-content/plugins/x/a.js:10:5)\n"
         "    at https://cdn.evil.io/s.js:1:200\n"
         "    at eval (eval at g (https://shop.com/a.js:3:1), <anonymous>:1:9)\n    at <anonymous>:2:3")
    fr = parse_stack(s)
    assert [(f.url, f.line, f.eval) for f in fr] == [
        ("https://shop.com/wp-content/plugins/x/a.js", 10, False), ("https://cdn.evil.io/s.js", 1, False),
        ("", None, True), ("", None, True)]


def test_parse_stack_is_bounded():
    from pnakotic.src.scanner.code_origin import parse_stack
    assert len(parse_stack("Error\n" + "    at https://a.com/x.js:1:1\n" * 500)) == 30


def test_parse_stack_reads_the_real_location_not_a_spoofed_function_name():
    from pnakotic.src.scanner.code_origin import parse_stack
    s = "Error\n    at x (https://shop.com/a.js:1:1) y (https://evil.io/s.js:7:3)"
    assert [(f.url, f.line) for f in parse_stack(s)] == [("https://evil.io/s.js", 7)]


def test_parse_stack_handles_async_ports_and_junk():
    from pnakotic.src.scanner.code_origin import parse_stack
    s = ("TypeError: x\n    at async go (https://shop.com:8443/a.js:4:2)\n"
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


def test_inline_frame_is_store_only_inside_a_served_script_block():
    from pnakotic.src.scanner.code_origin import Frame, frame_owner
    blocks = [(5, 9)]
    page = "https://shop.com/checkout/"
    assert frame_owner(Frame(page, 7, False), "shop.com", page, blocks) == "store"
    assert frame_owner(Frame(page, 2, False), "shop.com", page, blocks) == "unknown"
    assert frame_owner(Frame(page + "#x", 7, False), "shop.com", page, blocks) == "store"
    assert frame_owner(Frame(page, 2, False), "shop.com", page + "#y", blocks) == "unknown"
    assert frame_owner(Frame(page, None, False), "shop.com", page, blocks) == "unknown"
    assert frame_owner(Frame(page, 7, False), "shop.com", page, None) == "unknown"


def test_any_unknown_frame_wins_and_empty_stack_is_unknown():
    from pnakotic.src.scanner.code_origin import Frame, stack_owner
    page = "https://shop.com/checkout/"
    store = Frame("https://shop.com/wp-includes/js/jquery/jquery.min.js", 2, False)
    assert stack_owner([store, Frame("https://evil.io/x.js", 1, False)], "shop.com", page, [])[0] == "unknown"
    assert stack_owner([store, Frame("https://static.hotjar.com/c/h.js", 1, False)], "shop.com", page, []) == ("vendor", ["Hotjar"])
    assert stack_owner([], "shop.com", page, [])[0] == "unknown"


def test_stack_owner_store_provider_and_vendor_names_are_unique_in_order():
    from pnakotic.src.scanner.code_origin import Frame, stack_owner
    page = "https://shop.com/checkout/"
    f = lambda u: Frame(u, 1, False)
    assert stack_owner([f("https://shop.com/a.js"), f("https://js.stripe.com/v3/")],
                       "shop.com", page, []) == ("store", [])
    frames = [f("https://static.hotjar.com/a.js"), f("https://www.clarity.ms/t.js"),
              f("https://script.hotjar.com/b.js"), f("https://shop.com/a.js")]
    assert stack_owner(frames, "shop.com", page, []) == ("vendor", ["Hotjar", "Microsoft Clarity"])


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
