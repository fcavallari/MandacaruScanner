import asyncio
import time

LOADER = "<html><body><script>;;(function(f,i,u,w,s){w=f.createElement(i);s=f.getElementsByTagName(i)[0];w.async=1;w.src=u;s.parentNode.insertBefore(w,s);})(document,'script','https://content-website-analytics.com/script.js');</script></body></html>"
OBF = "function _0x34e5(){var _0x18b8=['a','b'];_0x34e5=function(){return _0x18b8;};return _0x34e5();}" \
      "(function(_0x44e7,_0x5d16){var _0x7eb7=_0x44e7();while(!![]){try{break;}catch(_0x1){_0x7eb7['push'](_0x7eb7['shift']());}}}(_0x34e5,0x1));"


def _rec(**kw):
    base = {"url": "https://content-website-analytics.com/script.js", "main_frame": True,
            "frame_url": "https://s.com/", "initiator": "script", "initiator_url": "https://s.com/",
            "line": None, "column": None}
    base.update(kw)
    return base


def test_obfuscator_markers():
    from pnakotic.src.scanner.obfuscation import obfuscator_markers
    assert "string_array_rotation" in obfuscator_markers(OBF)
    assert obfuscator_markers(LOADER) == []
    assert obfuscator_markers("!function(e,t){'use strict';var n=[],r=Object.getPrototypeOf;}(window)") == []


def test_obfuscator_markers_hex_density_and_alt_rotation():
    from pnakotic.src.scanner.obfuscation import obfuscator_markers
    dense = " ".join("_0x%04x" % (0x1000 + i) for i in range(40))
    assert obfuscator_markers(dense) == ["hex_identifier_density"]
    sparse = dense + " " * 20000
    assert obfuscator_markers(sparse) == []
    few = " ".join("_0x%04x" % (0x1000 + i) for i in range(10))
    assert obfuscator_markers(few) == []
    rot = "function a(){var b=['x'];}  b.push(b.shift());"
    assert obfuscator_markers(rot) == ["string_array_rotation"]
    # an array function without a rotation, and a rotation without an array function, are not enough
    assert obfuscator_markers("function a(){var b=['x'];}") == []
    assert obfuscator_markers("b.push(b.shift());") == []


def test_obfuscator_markers_caps_input_and_stays_fast():
    from pnakotic.src.scanner.obfuscation import obfuscator_markers
    # the marker sits past the 200 000 character cap, so it is not seen
    assert obfuscator_markers("x" * 200000 + OBF) == []
    for hostile in ["function a" + " " * 190000, "function " * 22000, "function a(){var b" + " " * 190000,
                    ".push(" * 30000, "['push'](" * 20000]:
        t0 = time.time()
        obfuscator_markers(hostile)
        assert time.time() - t0 < 1.0


def test_find_injections_resolves_inline_block_by_position():
    from pnakotic.src.scanner.script_trace import find_injections
    rec = {"url": "https://content-website-analytics.com/script.js", "main_frame": True, "frame_url": "https://s.com/",
           "initiator": "script", "initiator_url": "https://s.com/", "line": 0, "column": 30}
    [inj] = find_injections([rec], "https://s.com/", LOADER.encode(), {})
    assert inj["initiator_kind"] == "inline" and inj["block"] is not None
    assert LOADER.encode()[inj["block"]["start"]:inj["block"]["end"]].startswith(b";;(function")
    assert inj["requested_url"] == rec["url"] and inj["initiator_url"] == "https://s.com/"
    assert inj["markers"] == []
    assert inj["context"]["text"].startswith(";;(function")


def test_find_injections_falls_back_to_block_containing_target_host():
    from pnakotic.src.scanner.script_trace import find_injections
    rec = {"url": "https://content-website-analytics.com/script.js", "main_frame": True, "frame_url": "https://s.com/",
           "initiator": "script", "initiator_url": "https://s.com/", "line": None, "column": None}
    [inj] = find_injections([rec], "https://s.com/", LOADER.encode(), {})
    assert inj["block"] is not None


def test_find_injections_ignores_same_domain_and_parser_requests():
    from pnakotic.src.scanner.script_trace import find_injections
    recs = [{"url": "https://cdn.s.com/a.js", "initiator": "script", "initiator_url": "https://s.com/",
             "line": 0, "column": 0, "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://x.com/a.js", "initiator": "parser", "initiator_url": "https://s.com/",
             "line": 0, "column": 0, "main_frame": True, "frame_url": "https://s.com/"}]
    assert find_injections(recs, "https://s.com/", LOADER.encode(), {}) == []


def test_find_injections_without_served_html():
    from pnakotic.src.scanner.script_trace import find_injections
    rec = {"url": "https://x.com/a.js", "initiator": "script", "initiator_url": "https://s.com/404/",
           "line": 3, "column": 1, "main_frame": True, "frame_url": "https://s.com/404/"}
    [inj] = find_injections([rec], "https://s.com/404/", None, {})
    assert inj["block"] is None and inj["context"] is None


def test_find_injections_inline_ignores_fragment_and_picks_block_by_line_and_column():
    from pnakotic.src.scanner.script_trace import find_injections
    html = ("<html>\n<script>var a=1;</script>\n<p>x</p>\n"
            "<script>/* é */ document.body.appendChild(s); load('https://evil.example/x.js')</script>\n</html>")
    data = html.encode()
    col = html.split("\n")[3].index("document.body")  # characters, not bytes
    rec = _rec(url="https://evil.example/x.js", initiator_url="https://s.com/#top", line=3, column=col)
    [inj] = find_injections([rec], "https://s.com/", data, {})
    assert inj["initiator_kind"] == "inline"
    assert data[inj["block"]["start"]:inj["block"]["end"]].startswith(b"/* \xc3\xa9 */ document.body")
    # a position inside the first block wins over the host match in the second one
    rec2 = _rec(url="https://evil.example/zzz.js", initiator_url="https://s.com/", line=1, column=10)
    [inj2] = find_injections([rec2], "https://s.com/", data, {})
    assert data[inj2["block"]["start"]:inj2["block"]["end"]] == b"var a=1;"


def test_find_injections_script_initiator_uses_file_body_for_markers_and_context():
    from pnakotic.src.scanner.script_trace import find_injections
    body = ("\n" * 5 + OBF).encode()
    rec = _rec(initiator_url="https://s.com/app.js", line=5, column=3)
    [inj] = find_injections([rec], "https://s.com/", LOADER.encode(), {"https://s.com/app.js": body})
    assert inj["initiator_kind"] == "script" and inj["block"] is None
    assert inj["markers"] == ["string_array_rotation"]
    assert inj["context"]["line"] == 6 and "_0x34e5" in inj["context"]["text"]
    # no body for the file: no markers, no context
    [inj2] = find_injections([rec], "https://s.com/", LOADER.encode(), {})
    assert inj2["markers"] == [] and inj2["context"] is None


def test_find_injections_caps_at_50_and_skips_non_http_targets():
    from pnakotic.src.scanner.script_trace import find_injections
    recs = [_rec(url="https://h%d.example/a.js" % i) for i in range(80)]
    recs.insert(0, _rec(url="data:text/javascript,1"))
    out = find_injections(recs, "https://s.com/", LOADER.encode(), {})
    assert len(out) == 50 and all(i["requested_url"].startswith("https://") for i in out)


def test_find_injections_hostile_html_is_fast_and_capped():
    from pnakotic.src.scanner.script_trace import find_injections
    rec = _rec(url="https://x.example/a.js", line=0, column=5)
    for html in [b"<script" * 150000, b"<script>" * 150000, b"<script src=a></script>" * 40000,
                 b"<script " + b"a" * 400000, b"<script>x</script>" * 100000 + b"\n" * 1000]:
        t0 = time.time()
        out = find_injections([rec], "https://s.com/", html, {})
        assert time.time() - t0 < 1.0
        assert len(out) == 1
    # only the first 500 inline blocks are considered
    html = b"".join(b"<script>v%d;</script>" % i for i in range(600)) + b"<script>https://x.example/a.js</script>"
    [inj] = find_injections([_rec(url="https://x.example/a.js")], "https://s.com/", html, {})
    assert inj["block"] is None


def test_find_injections_many_newlines_many_records_is_fast():
    from pnakotic.src.scanner.script_trace import find_injections
    html = b"\n" * 2000000 + b"<script>load('https://h0.example/a.js')</script>"
    recs = [_rec(url="https://h%d.example/a.js" % i, line=1999990, column=3) for i in range(60)]
    body = b"\n" * 2000000 + b"x"
    recs += [_rec(url="https://g%d.example/a.js" % i, initiator_url="https://s.com/app.js", line=1999999, column=0)
             for i in range(60)]
    t0 = time.time()
    out = find_injections(recs, "https://s.com/", html, {"https://s.com/app.js": body})
    assert time.time() - t0 < 1.0
    assert len(out) == 50
    # a line past the end of the document finds no offset, falling back to the host search
    [inj] = find_injections([_rec(url="https://h0.example/a.js", line=5000000, column=0)], "https://s.com/", html, {})
    assert inj["block"] is not None


def test_find_injections_block_matching_is_case_insensitive():
    from pnakotic.src.scanner.script_trace import find_injections
    html = b"<P>x</P><SCRIPT type='text/javascript'>load('HTTPS://X.EXAMPLE/a.js')</SCRIPT >"
    [inj] = find_injections([_rec(url="https://x.example/a.js", line=0, column=0)], "https://s.com/", html, {})
    assert inj["block"] is not None
    assert html[inj["block"]["start"]:inj["block"]["end"]].startswith(b"load(")


def test_record_from_event_maps_initiators():
    from pnakotic.src.scanner.script_trace import record_from_event
    ev = {"type": "Script", "frameId": "F", "documentURL": "https://s.com/", "request": {"url": "https://x.com/a.js"},
          "initiator": {"type": "script", "stack": {"callFrames": [{"url": "https://s.com/", "lineNumber": 4, "columnNumber": 9}]}}}
    assert record_from_event(ev, "F") == {"url": "https://x.com/a.js", "main_frame": True, "frame_url": "https://s.com/",
                                          "initiator": "script", "initiator_url": "https://s.com/", "line": 4, "column": 9}
    assert record_from_event({**ev, "type": "Image"}, "F") is None


def test_record_from_event_parser_other_parent_and_truncation():
    from pnakotic.src.scanner.script_trace import record_from_event
    base = {"type": "Script", "frameId": "G", "documentURL": "https://s.com/p", "request": {"url": "https://x.com/" + "a" * 400}}
    parser = record_from_event({**base, "initiator": {"type": "parser", "url": "https://s.com/p", "lineNumber": 7}}, "F")
    assert parser["initiator"] == "parser" and parser["initiator_url"] == "https://s.com/p"
    assert parser["line"] == 7 and parser["column"] is None and parser["main_frame"] is False
    assert len(parser["url"]) == 300
    other = record_from_event({**base, "initiator": {"type": "preload"}}, "G")
    assert other["initiator"] == "other" and other["initiator_url"] is None and other["line"] is None
    nested = {"type": "script", "stack": {"callFrames": [], "parent": {"callFrames": [
        {"url": "https://s.com/lib.js", "lineNumber": 2, "columnNumber": 1}]}}}
    r = record_from_event({**base, "initiator": nested}, "G")
    assert (r["initiator"], r["initiator_url"], r["line"], r["column"]) == ("script", "https://s.com/lib.js", 2, 1)
    bare = record_from_event({**base, "initiator": {"type": "script"}}, "G")
    assert bare["initiator"] == "script" and bare["initiator_url"] is None
    assert record_from_event({"type": "Script"}, "G") is None


def test_record_from_event_skips_redirect_hops():
    from pnakotic.src.scanner.script_trace import record_from_event
    ev = {"type": "Script", "frameId": "F", "documentURL": "https://s.com/", "request": {"url": "https://x.com/b.js"},
          "initiator": {"type": "parser", "url": "https://s.com/", "lineNumber": 1},
          "redirectResponse": {"url": "https://x.com/a.js", "status": 302}}
    assert record_from_event(ev, "F") is None
    del ev["redirectResponse"]
    assert record_from_event(ev, "F") is not None


class _FakeCDP:
    def __init__(self):
        self.sent = []
        self.handlers = {}

    async def send(self, method, params=None):
        self.sent.append(method)

    def on(self, event, handler):
        self.handlers[event] = handler


def test_script_tracer_collects_script_requests_and_caps_at_200():
    from pnakotic.src.scanner.script_trace import ScriptTracer
    cdp = _FakeCDP()
    tracer = ScriptTracer()
    assert tracer.records == []
    asyncio.run(tracer.attach(cdp, "F"))
    assert cdp.sent == ["Network.enable"]
    handler = cdp.handlers["Network.requestWillBeSent"]

    def ev(i, typ="Script"):
        return {"type": typ, "frameId": "F", "documentURL": "https://s.com/", "request": {"url": "https://x.com/%d.js" % i},
                "initiator": {"type": "parser", "url": "https://s.com/", "lineNumber": 1}}
    handler(ev(0, "Image"))
    assert tracer.records == []
    for i in range(250):
        handler(ev(i))
    assert len(tracer.records) == 200 and tracer.records[0]["url"] == "https://x.com/0.js"
