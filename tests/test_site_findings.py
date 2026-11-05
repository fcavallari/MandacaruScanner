"""Finding blocks for the site quick check (site_findings.build_blocks), from hand-built loads."""


def test_served_hit_is_one_block_per_page_with_snippet():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    blocks = build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("served", "https://s.com/", "r1", 5, True, 40, "EVIL")])], "s.com", None)
    [b] = blocks
    assert b["location"] == "https://s.com/" and b["findings"][0]["severity"] == "compromised"
    assert b["findings"][0]["origin"] == "served" and b["findings"][0]["message"] == "Synthetic r1"
    f = b["findings"][0]
    assert f["snippet"]["text"] == "EVIL" and f["details"]["rule"] == "r1" and f["details"]["signature_id"] == 1


def test_rendered_only_hit_says_added_by_script():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    [b] = build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("page", "https://s.com/", "r1", 3, True, 10, "X")])], "s.com", None)
    assert b["findings"][0]["origin"] == "rendered" and b["findings"][0]["severity"] == "suspicious"


def test_rendered_hit_is_dropped_when_the_served_html_has_the_same_rule():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    hops = [_yara_hop("served", "https://s.com/", "r1", 5, True, 3, "A"), _yara_hop("page", "https://s.com/", "r1", 5, True, 9, "A2")]
    [b] = build_blocks([_load(0, "https://s.com/", "default", hops)], "s.com", None)
    assert [f["origin"] for f in b["findings"]] == ["served"]


def test_frame_hit_sits_under_the_page():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    [b] = build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("frame", "https://ads.net/f", "r1", 2, False, 0, "Q")])], "s.com", None)
    assert b["location"] == "https://s.com/" and b["findings"][0]["origin"] == "frame"


def test_yara_rule_without_description_uses_the_generic_line():
    import json

    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import MESSAGES, build_blocks

    hop = _yara_hop("served", "https://s.com/", "r1", 5, True, 0, "E")
    hop.evidence = json.dumps({**json.loads(hop.evidence), "description": ""})
    [b] = build_blocks([_load(0, "https://s.com/", "default", [hop])], "s.com", None)
    assert b["findings"][0]["message"] == MESSAGES["yara"] == "Code matching a known malware pattern"


def test_same_footer_on_every_page_merges_into_one_block():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    loads = [_load(i, f"https://s.com/p{i}/", "default", [_yara_hop("served", f"https://s.com/p{i}/", "r1", 5, True, 5, "FOOT")]) for i in range(4)]
    [b] = build_blocks(loads, "s.com", None)
    assert b["location"] == "https://s.com/p0/"
    assert b["findings"][0]["pages"] == [f"https://s.com/p{i}/" for i in range(4)]


def test_different_snippets_of_one_rule_stay_apart():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    loads = [_load(i, f"https://s.com/p{i}/", "default", [_yara_hop("served", f"https://s.com/p{i}/", "r1", 5, True, 5, f"T{i}")]) for i in range(2)]
    assert [b["location"] for b in build_blocks(loads, "s.com", None)] == ["https://s.com/p0/", "https://s.com/p1/"]


def test_script_match_lands_under_script_url_with_loaded_by():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    loads = [_load(i, f"https://s.com/p{i}/", "default", [_yara_hop("script", "https://s.com/wp-content/x.js", "r2", 5, True, 0, "Z")]) for i in range(2)]
    [b] = build_blocks(loads, "s.com", None)
    assert b["location_kind"] == "script" and b["findings"][0]["loaded_by"] == ["https://s.com/p0/", "https://s.com/p1/"]
    assert b["location"] == "https://s.com/wp-content/x.js" and b["findings"][0]["origin"] == "script"
    assert b["findings"][0]["pages"] == ["https://s.com/p0/", "https://s.com/p1/"]


def test_injection_ties_only_inside_block():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    hop = _yara_hop("served", "https://s.com/", "r1", 5, True, 120, "LOADER")
    inj = {"requested_url": "https://bad.org/x.js", "initiator_kind": "inline", "initiator_url": "https://s.com/",
           "block": {"start": 100, "end": 300}, "markers": [], "context": None}
    [b] = build_blocks([_load(0, "https://s.com/", "default", [hop], injections=[inj])], "s.com", None)
    assert b["findings"][0]["loaded"] == ["https://bad.org/x.js"]
    far = {**inj, "block": {"start": 500, "end": 600}}
    [b] = build_blocks([_load(0, "https://s.com/", "default", [hop], injections=[far])], "s.com", None)
    assert b["findings"][0]["loaded"] == []


def test_injection_tie_end_is_exclusive_and_a_tied_obfuscated_injector_is_not_repeated():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    inj = {"requested_url": "https://bad.org/x.js", "initiator_kind": "inline", "initiator_url": "https://s.com/",
           "block": {"start": 100, "end": 120}, "markers": ["string_array_rotation"], "context": None}
    at_end = _yara_hop("served", "https://s.com/", "r1", 5, True, 120, "L")
    blocks = build_blocks([_load(0, "https://s.com/", "default", [at_end], injections=[inj])], "s.com", None)
    assert sorted(f["kind"] for f in blocks[0]["findings"]) == ["injection", "yara"]
    at_start = _yara_hop("served", "https://s.com/", "r1", 5, True, 100, "L")
    [b] = build_blocks([_load(0, "https://s.com/", "default", [at_start], injections=[inj])], "s.com", None)
    assert [f["kind"] for f in b["findings"]] == ["yara"] and b["findings"][0]["loaded"] == ["https://bad.org/x.js"]


def test_matched_script_names_the_code_that_loaded_it():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    inline = {"requested_url": "https://bad.org/x.js", "initiator_kind": "inline", "initiator_url": "https://s.com/",
              "block": None, "markers": ["string_array_rotation"], "context": None}
    by_file = {**inline, "initiator_kind": "script", "initiator_url": "https://s.com/loader.js"}
    hop = _yara_hop("script", "https://bad.org/x.js", "r2", 5, True, 0, "Z")
    loads = [_load(0, "https://s.com/", "default", [hop], injections=[inline]),
             _load(1, "https://s.com/a/", "default", [hop], injections=[by_file])]
    [b] = build_blocks(loads, "s.com", None)
    assert b["findings"][0]["loaded_by"] == ["https://s.com/", "inline on https://s.com/", "https://s.com/a/",
                                             "https://s.com/loader.js"]


def test_matched_injecting_file_gains_what_it_loaded():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    inj = {"requested_url": "https://bad.org/x.js", "initiator_kind": "script", "initiator_url": "https://s.com/loader.js",
           "block": None, "markers": [], "context": None}
    hop = _yara_hop("script", "https://s.com/loader.js", "r2", 5, True, 0, "Z")
    [b] = build_blocks([_load(0, "https://s.com/", "default", [hop], injections=[inj])], "s.com", None)
    assert b["findings"][0]["loaded"] == ["https://bad.org/x.js"]


def test_obfuscated_untied_injection_is_suspicious_and_plain_one_is_nothing():
    from _support import _load
    from pnakotic.src.scanner.site_findings import build_blocks

    inj = {"requested_url": "https://bad.org/x.js", "initiator_kind": "inline", "initiator_url": "https://s.com/",
           "block": {"start": 0, "end": 50}, "markers": ["string_array_rotation"], "context": {"text": "…", "match_start": 0, "match_end": 1, "line": 1}}
    [b] = build_blocks([_load(0, "https://s.com/", "default", [], injections=[inj])], "s.com", None)
    assert b["findings"][0]["kind"] == "injection" and b["findings"][0]["severity"] == "suspicious"
    assert b["findings"][0]["loaded"] == ["https://bad.org/x.js"] and b["findings"][0]["snippet"] == inj["context"]
    assert build_blocks([_load(0, "https://s.com/", "default", [], injections=[{**inj, "markers": []}])], "s.com", None) == []


def test_obfuscated_injecting_file_counts_only_when_it_is_on_the_site():
    from _support import _load
    from pnakotic.src.scanner.site_findings import build_blocks

    inj = {"requested_url": "https://bad.org/x.js", "initiator_kind": "script", "initiator_url": "https://www.s.com/t.js",
           "block": None, "markers": ["hex_identifier_density"], "context": None}
    [b] = build_blocks([_load(0, "https://s.com/", "default", [], injections=[inj])], "s.com", None)
    assert b["location"] == "https://s.com/" and b["findings"][0]["kind"] == "injection"
    gtm = {**inj, "initiator_url": "https://www.googletagmanager.com/gtm.js"}
    assert build_blocks([_load(0, "https://s.com/", "default", [], injections=[gtm])], "s.com", None) == []


def test_visitors_subset_and_all():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    hop = _yara_hop("served", "https://s.com/", "r1", 5, True, 1, "G")
    loads = [_load(0, "https://s.com/", p, [hop] if p == "googlebot" else []) for p in ("default", "mobile-ios", "googlebot")]
    [b] = build_blocks(loads, "s.com", None)
    assert b["findings"][0]["visitors"] == ["googlebot"] and b["findings"][0]["all_visitors"] is False


def test_blocks_caps_and_single_block_for_shared_script():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    loads = [_load(i, f"https://s.com/p{i}/", p, [_yara_hop("script", "https://s.com/f.js", "r", 5, True, 0, "F")])
             for i in range(30) for p in ("default", "mobile-ios", "googlebot")]
    [b] = build_blocks(loads, "s.com", None)
    f = b["findings"][0]
    assert len(f["loaded_by"]) == 20 and f["all_visitors"] is True
    assert f["loaded_by_more"] == 10 and len(f["pages"]) == 20 and f["pages_more"] == 10


def test_blocks_are_capped_compromised_first():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import MAX_BLOCKS, build_blocks

    loads = [_load(i, f"https://s.com/p{i:02d}/", "default",
                   [_yara_hop("served", f"https://s.com/p{i:02d}/", "r", 5 if i >= 40 else 2, True, 0, f"E{i}")])
             for i in range(60)]
    blocks = build_blocks(loads, "s.com", None)
    assert len(blocks) == MAX_BLOCKS == 50
    assert [b["location"] for b in blocks[:20]] == [f"https://s.com/p{i:02d}/" for i in range(40, 60)]
    assert all(b["findings"][0]["severity"] == "suspicious" for b in blocks[20:])


def test_overflow_counts_the_blocks_past_the_cap():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks, build_blocks_and_overflow

    loads = [_load(i, f"https://s.com/p{i:02d}/", "default", [_yara_hop("served", f"https://s.com/p{i:02d}/", "r", 2, True, 0, f"E{i}")])
             for i in range(57)]
    blocks, more = build_blocks_and_overflow(loads, "s.com", None)
    assert len(blocks) == 50 and more == 7 and blocks == build_blocks(loads, "s.com", None)
    assert build_blocks_and_overflow(loads[:3], "s.com", None)[1] == 0


def test_a_block_keeps_twenty_findings_compromised_first():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    hops = [_yara_hop("frame", f"https://ads{i}.net/", f"r{i:02d}", 2, True, 0, f"F{i}") for i in range(24)]
    hops.append(_yara_hop("served", "https://s.com/", "zz", 5, True, 0, "BAD"))
    [b] = build_blocks([_load(0, "https://s.com/", "default", hops)], "s.com", None)
    assert len(b["findings"]) == 20 and b["findings_more"] == 5
    assert b["findings"][0]["details"]["rule"] == "zz"
    assert [f["message"] for f in b["findings"][1:3]] == ["Synthetic r00", "Synthetic r01"]


def test_long_urls_are_cut_to_300_characters_and_still_merge():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    long_js = "https://s.com/" + "a" * 1000 + ".js"
    long_page = "https://s.com/" + "p" * 1000
    inj = {"requested_url": long_js[:300], "initiator_kind": "script", "initiator_url": "https://s.com/" + "i" * 1000,
           "block": None, "markers": [], "context": None}
    loads = [_load(0, long_page + "0", "default", [_yara_hop("script", long_js, "r", 5, True, 0, "Z")], injections=[inj]),
             _load(1, long_page + "1", "default", [_yara_hop("script", long_js, "r", 5, True, 0, "Z")])]
    [b] = build_blocks(loads, "s.com", None)
    [f] = b["findings"]
    assert b["location"] == long_js[:300]
    assert f["pages"] == [long_page[:300]] and all(len(u) == 300 for u in f["loaded_by"])
    obf = {**inj, "requested_url": "https://bad.org/" + "x" * 1000, "initiator_url": "https://s.com/" + "i" * 1000,
           "markers": ["string_array_rotation"]}
    [b] = build_blocks([_load(0, long_page, "default", injections=[obf])], "s.com", None)
    [f] = b["findings"]
    assert len(b["location"]) == 300 and len(f["loaded"][0]) == 300 and len(f["details"]["initiator"]) == 300


def test_behaviour_findings_are_compromised():
    import json

    from _support import _load
    from pnakotic.src.scanner.models import RedirectHop
    from pnakotic.src.scanner.site_findings import build_blocks

    def ev(**e):
        return RedirectHop(url="https://s.com/", mechanism="page_behavior", evidence=json.dumps(e))

    hops = [ev(id="clipboard_write", text="powershell -c iwr", command=True),
            ev(id="download", filename="setup.exe", executable=True),
            ev(id="fullscreen_request"), ev(id="keyboard_lock"),
            ev(id="clipboard_write", text="hello", command=False)]
    [b] = build_blocks([_load(0, "https://s.com/", "mobile-ios", hops)], "s.com", None)
    assert [(f["kind"], f["severity"]) for f in b["findings"]] == [
        ("browser_lock", "compromised"), ("clipboard", "compromised"), ("download", "compromised")]
    assert "powershell" in b["findings"][1]["details"]["scoring"][0]
    assert b["findings"][1]["visitors"] == ["mobile-ios"]


def test_decisive_cloaking_on_the_default_load():
    from _support import _load
    from pnakotic.src.scanner.site_findings import build_blocks

    home = _load(0, "https://s.com/", "default")
    home.result.metadata["cloaking"] = {"landings": {"default": "s.com", "mobile-ios": "evil.net"}, "common": "s.com",
                                        "steered": ["mobile-ios"], "suspicious": ["mobile-ios"]}
    [b] = build_blocks([home, _load(0, "https://s.com/", "mobile-ios", final_url="https://evil.net/")], "s.com", None)
    [f] = b["findings"]
    assert f["kind"] == "cloaking" and f["severity"] == "compromised" and f["visitors"] == ["mobile-ios"]
    home.result.metadata["cloaking"]["suspicious"] = []
    assert build_blocks([home], "s.com", None) == []


def test_offsite_homepage_finding():
    from _support import _load
    from pnakotic.src.scanner.site_findings import build_blocks

    [b] = build_blocks([_load(0, "https://s.com/", "default", [], final_url="https://elsewhere.net/")], "s.com", "elsewhere.net")
    assert b["findings"][0]["kind"] == "offsite_homepage" and "elsewhere.net" in b["findings"][0]["message"]


def test_offsite_homepage_wording_and_upgrade():
    from _support import _load
    from pnakotic.src.scanner.site_findings import build_blocks

    def homepage(cloaked):
        home = _load(0, "https://s.com/", "default", final_url="https://www.elsewhere.net/")
        if cloaked:
            home.result.metadata["cloaking"] = {"landings": {}, "common": "elsewhere.net",
                                                "steered": ["googlebot"], "suspicious": ["default"]}
        return [home, _load(0, "https://s.com/", "googlebot", final_url="https://s.com/" if cloaked else "https://elsewhere.net/")]

    [b] = build_blocks(homepage(False), "s.com", "elsewhere.net")
    [f] = b["findings"]
    assert f["severity"] == "suspicious" and f["visitors"] == ["default", "googlebot"]
    assert f["message"] == "Your homepage sends desktop visitors to elsewhere.net. If you moved your site, check the new domain"
    [b] = build_blocks(homepage(True), "s.com", "elsewhere.net")
    offsite = next(f for f in b["findings"] if f["kind"] == "offsite_homepage")
    assert offsite["severity"] == "compromised" and offsite["message"] == "Your homepage sends desktop visitors to elsewhere.net"


def test_page_score_finding_only_without_a_compromised_finding():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    load = _load(1, "https://s.com/a/", "default", score=0.5)
    load.result.metadata["scoring_findings"] = ["Credential form"]
    [b] = build_blocks([load], "s.com", None)
    assert b["findings"][0]["kind"] == "page_score" and b["findings"][0]["severity"] == "suspicious"
    assert b["findings"][0]["details"]["scoring"] == ["Credential form"]
    hit = _load(1, "https://s.com/a/", "default", [_yara_hop("served", "https://s.com/a/", "r", 5, True, 0, "E")], score=1.0)
    [b] = build_blocks([hit], "s.com", None)
    assert [f["kind"] for f in b["findings"]] == ["yara"]
    assert build_blocks([_load(1, "https://s.com/a/", "default", score=0.39)], "s.com", None) == []


def test_page_score_uses_the_default_loads_own_score_after_combine():
    from _support import _load
    from pnakotic.src.scanner.site_findings import build_blocks

    home = _load(0, "https://s.com/", "default", score=0.6)  # combine() folded mobile-ios's 0.6 in
    home.result.metadata["variants"] = [{"profile": "default", "requested": True, "malicious_score": 0.1},
                                        {"profile": "mobile-ios", "malicious_score": 0.6}]
    home.result.metadata["scoring_findings"] = ["Own thing", "[mobile-ios] Phone thing"]
    phone = _load(0, "https://s.com/", "mobile-ios", score=0.6)
    phone.result.metadata["scoring_findings"] = ["Phone thing"]
    [b] = build_blocks([home, phone], "s.com", None)
    [f] = b["findings"]
    assert f["visitors"] == ["mobile-ios"] and f["details"]["scoring"] == ["Phone thing"]


def test_not_checked_and_challenge_loads_add_nothing():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    assert build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("served", "https://s.com/", "r", 5, True, 0, "E")], state="not_checked")], "s.com", None) == []
    challenged = _load(0, "https://s.com/", "default", [_yara_hop("served", "https://s.com/", "r", 5, True, 0, "E")], score=1.0)
    challenged.result.metadata["challenge"] = True
    assert build_blocks([challenged], "s.com", None) == []


def test_partial_load_findings_count():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_findings import build_blocks

    [b] = build_blocks([_load(0, "https://s.com/", "default", [_yara_hop("served", "https://s.com/", "r", 5, True, 0, "E")], state="partial")], "s.com", None)
    assert b["findings"][0]["severity"] == "compromised"
