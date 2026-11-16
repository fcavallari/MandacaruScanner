"""Load states, external scripts, verdict and report assembly (site_report), from hand-built loads."""


def test_verdict_rows():
    from _support import _load
    from mandacaru.src.scanner.site_report import site_verdict

    ok = lambda i, p: _load(i, f"https://s.com/{i}", p, state="checked")
    home = [ok(0, p) for p in ("default", "mobile-ios", "googlebot", "search-clicker")]
    rest = [ok(i, p) for i in range(1, 4) for p in ("default", "mobile-ios", "googlebot")]
    comp = [{"findings": [{"severity": "compromised"}]}]
    sus = [{"findings": [{"severity": "suspicious"}]}]
    assert site_verdict(comp, home + rest, True)["verdict"] == "compromised"
    assert site_verdict(sus, home + rest, True)["verdict"] == "suspicious"
    assert site_verdict([], home + rest, True)["verdict"] == "clean"
    dead = [_load(0, "https://s.com/", "default", state="not_checked", reason="load_failed")] + home[1:]
    assert site_verdict([], dead + rest, True)["verdict"] == "couldnt_check"
    assert site_verdict(comp, dead + rest, True)["verdict"] == "compromised"
    half = home + [_load(i, "u", p, state="not_checked", reason="budget") if i < 3 else ok(i, p) for i in range(1, 4) for p in ("default", "mobile-ios", "googlebot")]
    assert site_verdict([], half, True)["verdict"] == "partly_checked"
    gb = home[:2] + [_load(0, "https://s.com/", "googlebot", state="not_checked", reason="challenge"), home[3]]
    assert site_verdict([], gb + rest, True)["label"] == "Partly checked"
    assert site_verdict([], home + rest, False)["summary"] == "Clean (no malware rules loaded)"


def test_verdict_labels_summaries_and_flags():
    from _support import _load
    from mandacaru.src.scanner.site_report import site_verdict

    ok = lambda i, p: _load(i, f"https://s.com/{i}", p, state="checked")
    nc = lambda i, p, r: _load(i, f"https://s.com/{i}", p, state="not_checked", reason=r)
    loads = [ok(0, "default"), ok(0, "googlebot"), ok(1, "default"), ok(2, "default")]
    blocks = [{"location": "https://s.com/1", "findings": [{"severity": "compromised", "pages": ["https://s.com/1", "https://s.com/2"]},
                                                          {"severity": "suspicious", "pages": ["https://s.com/1"]}],
               "findings_more": 1},
              {"location": "https://s.com/0", "findings": [{"severity": "suspicious"}]}]  # no pages: the location stands in
    v = site_verdict(blocks, loads, True)
    assert (v["verdict"], v["label"], v["rules_loaded"]) == ("compromised", "Compromised", True)
    assert v["summary"] == "Compromised · 4 findings on 3 of 3 pages"
    assert site_verdict([{"findings": [{"severity": "compromised"}]}], loads, False)["rules_loaded"] is False

    v = site_verdict([], [nc(0, "default", "load_failed")] + loads[1:], True)
    assert (v["label"], v["summary"]) == ("Couldn't check", "We couldn't reach this site")
    v = site_verdict([], [nc(0, "default", "challenge")] + loads[1:], True)
    assert v["summary"] == "This site showed our scanner a bot check"
    # A homepage default load that is missing altogether is never Clean either.
    assert site_verdict([], loads[1:], True)["verdict"] == "couldnt_check"

    v = site_verdict([], [ok(0, "default"), nc(0, "googlebot", "timeout"), ok(1, "default"), ok(2, "default")], True)
    assert (v["verdict"], v["summary"]) == ("partly_checked", "No malware found, but 1 of 4 checks couldn't run")
    # Exactly half of the stage-2 loads not checked is still Clean; more than half is not.
    assert site_verdict([], [ok(0, "default"), nc(1, "default", "budget"), ok(2, "default")], True)["verdict"] == "clean"
    assert site_verdict([], [ok(0, "default"), nc(1, "default", "budget"), nc(2, "default", "budget"), ok(3, "default")], True)["verdict"] == "partly_checked"
    v = site_verdict([], loads, True)
    assert (v["verdict"], v["label"], v["summary"]) == ("clean", "Clean", "Clean")


def test_classify_load():
    from _support import _result
    from mandacaru.src.scanner.site_report import classify_load

    assert classify_load(None, "budget") == ("not_checked", "budget")
    assert classify_load(_result(challenge=True), None) == ("not_checked", "challenge")
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=900, title="Home"), None) == ("partial", None)
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=0, title=""), None) == ("not_checked", "timeout")
    assert classify_load(_result(), None) == ("checked", None)


def test_classify_load_order_and_failures():
    from _support import _result
    from mandacaru.src.scanner.site_report import classify_load

    assert classify_load(None, None) == ("not_checked", "load_failed")
    assert classify_load(None, "timeout") == ("not_checked", "timeout")
    assert classify_load(None, "boom") == ("not_checked", "load_failed")
    assert classify_load(_result(), "budget") == ("not_checked", "budget")  # an error wins over a result
    assert classify_load(_result(navigation_failed="https://s.com/"), None) == ("not_checked", "load_failed")
    # A bot check outranks a failed navigation and a timeout.
    assert classify_load(_result(challenge=True, navigation_failed="u", raw_error="Timeout 1ms"), None) == ("not_checked", "challenge")
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=0, title="Home"), None) == ("partial", None)
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=900, title=""), None) == ("partial", None)
    assert classify_load(_result(raw_error="net::ERR_ABORTED"), None) == ("checked", None)


def test_external_scripts_grouping_order_and_caps():
    from _support import _load
    from mandacaru.src.scanner.site_report import external_scripts

    recs = [{"url": "https://www.googletagmanager.com/gtm.js?id=1", "initiator": "parser", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://bad.org/x.js", "initiator": "script", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://cdn.s.com/a.js", "initiator": "parser", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"},
            {"url": "https://s.com/own.js", "initiator": "parser", "initiator_url": "https://s.com/", "main_frame": True, "frame_url": "https://s.com/"}]
    out = external_scripts([_load(0, "https://s.com/", "default", script_requests=recs)], "s.com", [])
    hosts = [h["host"] for h in out["hosts"]]
    assert hosts == ["bad.org", "cdn.s.com", "www.googletagmanager.com"]  # script-injected first, then alphabetical
    assert out["hosts"][1]["your_domain"] is True and out["hosts"][0]["urls"][0]["how"] == "script"
    many = [{**recs[0], "url": f"https://h{i}.com/{'a' * 400}.js"} for i in range(600)]
    out = external_scripts([_load(0, "https://s.com/", "default", script_requests=many)], "s.com", [])
    assert len(out["hosts"]) == 100 and out["hosts_more"] == 500 and len(out["hosts"][0]["urls"][0]["url"]) <= 300


def test_external_script_entries_merge_loads_and_say_how():
    from _support import _load
    from mandacaru.src.scanner.site_report import external_scripts

    def rec(url, initiator="parser", initiator_url="https://s.com/", main_frame=True, frame_url="https://s.com/"):
        return {"url": url, "initiator": initiator, "initiator_url": initiator_url, "main_frame": main_frame, "frame_url": frame_url}

    loads = [
        _load(0, "https://s.com/", "default", script_requests=[
            rec("https://ads.net/a.js"), rec("https://ads.net/in.js", "script", None),
            rec("https://ads.net/by.js", "script", "https://tags.io/loader.js"),
            rec("https://ads.net/fr.js", "parser", None, False, "https://widgets.com/f"), rec("data:text/javascript,1")]),
        _load(0, "https://s.com/", "googlebot", script_requests=[rec("https://ads.net/a.js"), rec("https://ads.net/only-bot.js")]),
        _load(1, "https://s.com/about", "default", script_requests=[rec("https://ads.net/a.js")]),
        _load(1, "https://s.com/about", "mobile-ios", state="not_checked", reason="timeout"),  # no scripts recorded
    ]
    out = external_scripts(loads, "s.com", [])
    assert out["hosts_more"] == 0 and out["urls_more"] == 0
    [host] = out["hosts"]
    assert host["host"] == "ads.net" and host["your_domain"] is False
    urls = {u["url"]: u for u in host["urls"]}
    a = urls["https://ads.net/a.js"]
    assert a["pages"] == ["https://s.com/", "https://s.com/about"] and a["profiles"] == ["default", "googlebot"]
    assert (a["how"], a["injected_by"], a["in_frame"], a["finding"]) == ("html", None, None, False)
    assert (urls["https://ads.net/in.js"]["how"], urls["https://ads.net/in.js"]["injected_by"]) == ("script", "inline on https://s.com/")
    assert urls["https://ads.net/by.js"]["injected_by"] == "https://tags.io/loader.js"
    assert urls["https://ads.net/fr.js"]["in_frame"] == "widgets.com"
    assert urls["https://ads.net/only-bot.js"]["profiles"] == ["googlebot"]


def test_external_scripts_order_tiers_and_finding_flag():
    from _support import _load
    from mandacaru.src.scanner.site_report import external_scripts

    def rec(url, initiator="parser"):
        return {"url": url, "initiator": initiator, "initiator_url": None, "main_frame": True, "frame_url": "https://s.com/"}

    loads = [
        _load(0, "https://s.com/", "default", script_requests=[
            rec("https://a-plain.com/p.js"), rec("https://b-script.com/s.js", "script"), rec("https://c-some.com/c.js"),
            rec("https://d-found.com/f.js"), rec("https://e-loaded.com/l.js")]),
        _load(0, "https://s.com/", "googlebot", script_requests=[rec("https://a-plain.com/p.js"), rec("https://b-script.com/s.js", "script")]),
    ]
    blocks = [{"location": "https://d-found.com/f.js", "findings": []},
              {"location": "https://s.com/", "findings": [{"loaded": ["https://e-loaded.com/l.js"]}, {}]}]
    out = external_scripts(loads, "s.com", blocks)
    assert [h["host"] for h in out["hosts"]] == ["d-found.com", "e-loaded.com", "c-some.com", "b-script.com", "a-plain.com"]
    flags = {u["url"]: u["finding"] for h in out["hosts"] for u in h["urls"]}
    assert flags == {"https://d-found.com/f.js": True, "https://e-loaded.com/l.js": True, "https://c-some.com/c.js": False,
                     "https://b-script.com/s.js": False, "https://a-plain.com/p.js": False}


def test_external_scripts_url_cap_and_challenge_pages():
    from _support import _load
    from mandacaru.src.scanner.site_report import external_scripts

    recs = [{"url": f"https://big.com/{i}.js", "initiator": "parser", "initiator_url": None, "main_frame": True, "frame_url": "https://s.com/"}
            for i in range(200)]
    loads = [_load(i, f"https://s.com/{i}", "default", script_requests=[{**r, "url": f"https://big.com/{i}/{j}.js"} for j, r in enumerate(recs)])
             for i in range(3)]
    loads.append(_load(3, "https://s.com/3", "default", script_requests=recs[:1]))
    loads[-1].result.metadata["challenge"] = True  # a bot check page's scripts are not the site's
    out = external_scripts(loads, "s.com", [])
    assert sum(len(h["urls"]) for h in out["hosts"]) == 500 and out["urls_more"] == 100 and out["hosts_more"] == 0


def test_build_report_assembles_everything():
    from _support import _load, _yara_hop
    from mandacaru.src.scanner.site_report import build_report

    recs = [{"url": "https://ads.net/a.js", "initiator": "parser", "initiator_url": None, "main_frame": False, "frame_url": "https://f.com/x"},
            {"url": "https://s.com/own.js", "initiator": "parser", "initiator_url": None, "main_frame": True, "frame_url": "https://s.com/"}]
    hit = _load(0, "https://s.com/", "default", [_yara_hop("served", "https://s.com/", "r1", 5, True, 3, "EVIL")], script_requests=recs, score=0.3)
    hit.shot = "pages/0/default/landing_1.png"
    hit.result.metadata["main_status"] = 200
    bot = _load(0, "https://s.com/", "googlebot", state="not_checked", reason="challenge")
    bot.result = None
    about = _load(1, "https://s.com/about", "default", script_requests=recs[:1])
    about.result.metadata["main_status"] = 404
    report = build_report("www.s.com", "s.com", None, [hit, bot, about], 12, ["10.0.0.1"], ["note"])
    assert report["site"] == "s.com" and report["entered"] == "www.s.com" and report["redirected_from"] == "www.s.com"
    assert report["verdict"]["verdict"] == "compromised" and report["verdict"]["rules_loaded"] is True
    assert report["verdict"]["summary"] == "Compromised · 1 finding on 1 of 2 pages"
    assert [b["location"] for b in report["blocks"]] == ["https://s.com/"] and report["blocks_more"] == 0
    assert [h["host"] for h in report["external_scripts"]["hosts"]] == ["ads.net"]
    checked = report["checked"]
    assert (checked["rules"], checked["not_checked"], checked["total"]) == (12, 1, 3)
    assert checked["scripts_scanned"] == 2 and checked["frames_scanned"] == 1
    assert [(p["index"], p["url"]) for p in checked["pages"]] == [(0, "https://s.com/"), (1, "https://s.com/about")]
    assert checked["pages"][0]["loads"] == [
        {"profile": "default", "state": "checked", "reason": None, "status": 200, "screenshot": "pages/0/default/landing_1.png", "score": 0.3,
         "landing": "https://s.com/"},
        {"profile": "googlebot", "state": "not_checked", "reason": "challenge", "status": None, "screenshot": None, "score": None,
         "landing": None}]
    assert checked["pages"][1]["loads"][0]["status"] == 404
    assert report["notes"] == ["note"] and report["blocked_hosts"] == ["10.0.0.1"]

    same = build_report("s.com", "s.com", None, [_load(0, "https://s.com/", "default")], 0, [], [])
    assert same["redirected_from"] is None and same["verdict"]["summary"] == "Clean (no malware rules loaded)"
    assert same["blocks"] == [] and same["external_scripts"] == {"hosts": [], "hosts_more": 0, "urls_more": 0}
    assert same["checked"]["pages"][0]["loads"][0]["score"] == 0.0


def test_build_report_counts_blocks_past_the_cap():
    from _support import _load, _yara_hop
    from mandacaru.src.scanner.site_report import build_report

    loads = [_load(0, "https://s.com/", "default", [_yara_hop("script", f"https://s.com/{i}.js", f"r{i}", 5, True, 0, "X") for i in range(60)])]
    report = build_report("s.com", "s.com", None, loads, 1, [], [])
    assert len(report["blocks"]) == 50 and report["blocks_more"] == 10


def test_build_report_keeps_200_findings_in_all_compromised_first():
    from _support import _load, _yara_hop
    from mandacaru.src.scanner.site_report import build_report

    # 20 script blocks of 12 suspicious findings, then one page block with 5 compromised and 5 suspicious.
    hops = [_yara_hop("script", f"https://s.com/a{i:02}.js", f"r{j:02}", 2, False, 0, "S") for i in range(20) for j in range(12)]
    hops += [_yara_hop("served", "https://s.com/", f"c{j}", 5, True, 0, f"C{j}") for j in range(5)]
    hops += [_yara_hop("served", "https://s.com/", f"s{j}", 2, False, 0, f"S{j}") for j in range(5)]
    r = build_report("s.com", "s.com", None, [_load(0, "https://s.com/", "default", hops)], 1, [], [])
    findings = [f for b in r["blocks"] for f in b["findings"]]
    assert len(findings) == 200 and sum(f["severity"] == "compromised" for f in findings) == 5
    assert r["blocks"][0]["location"] == "https://s.com/" and len(r["blocks"][0]["findings"]) == 10
    # 190 more: 15 whole script blocks and 10 of the 16th; the last 4 are left empty and dropped.
    assert [len(b["findings"]) for b in r["blocks"][1:]] == [12] * 15 + [10]
    assert r["findings_more_total"] == 50 and r["blocks_more"] == 4
    assert all(b["findings_more"] == 0 for b in r["blocks"])
    assert r["verdict"]["summary"] == "Compromised · 250 findings on 1 of 1 pages"

    small = build_report("s.com", "s.com", None, [_load(0, "https://s.com/", "default", hops[:3])], 1, [], [])
    assert small["findings_more_total"] == 0 and small["blocks_more"] == 0


def test_build_report_notes_a_yara_budget_cut():
    from _support import _load
    from mandacaru.src.scanner.site_report import build_report

    cut = _load(1, "https://s.com/a/", "default")
    cut.result.metadata["yara"] = {"rules": 1, "buffers": 3, "bytes": 10, "budget_exhausted": True}
    ok = _load(0, "https://s.com/", "default")
    ok.result.metadata["yara"] = {"rules": 1, "buffers": 3, "bytes": 10, "budget_exhausted": False}
    note = "Some page content was too large to check in full for malware patterns"
    assert build_report("s.com", "s.com", None, [ok, cut, cut], 1, [], ["Checked over http"])["notes"] == ["Checked over http", note]
    assert build_report("s.com", "s.com", None, [ok], 1, [], [])["notes"] == []
    unused = _load(1, "https://s.com/a/", "default", state="not_checked", reason="timeout")
    unused.result.metadata["yara"] = {"budget_exhausted": True}
    assert build_report("s.com", "s.com", None, [ok, unused], 1, [], [])["notes"] == []
    assert build_report("s.com", "s.com", None, [ok], 1, [], [])["verdict"]["verdict"] == "clean"


def test_couldnt_check_summary_gives_the_reason():
    from _support import _load
    from mandacaru.src.scanner.site_report import site_verdict

    for reason, summary in [("challenge", "This site showed our scanner a bot check"),
                            ("budget", "We ran out of time before the homepage loaded"),
                            ("timeout", "The homepage took too long to load"),
                            ("load_failed", "We couldn't reach this site"), (None, "We couldn't reach this site")]:
        v = site_verdict([], [_load(0, "https://s.com/", "default", state="not_checked", reason=reason)], True)
        assert (v["verdict"], v["summary"]) == ("couldnt_check", summary)
    assert site_verdict([], [], True)["summary"] == "We couldn't reach this site"


def test_report_flags_a_bot_check_with_vendor_and_counts():
    from _support import _load
    from mandacaru.src.scanner.site_report import build_report, challenge_summary

    ok = _load(0, "https://s.com/", "mobile-ios")
    blocked = [_load(0, "https://s.com/", "default", state="not_checked", reason="challenge"),
               _load(1, "https://s.com/a/", "default", state="not_checked", reason="challenge")]
    blocked[0].result.metadata["challenge_vendor"] = "cloudflare"
    blocked[1].result.metadata["challenge_vendor"] = "cloudflare"
    timed_out = _load(1, "https://s.com/a/", "googlebot", state="not_checked", reason="timeout")
    report = build_report("s.com", "s.com", None, [ok, *blocked, timed_out], 1, [], [])
    assert report["challenge"] == {"vendor": "cloudflare", "loads": 2, "of": 4, "homepage": True}
    assert report["verdict"]["verdict"] == "couldnt_check"

    # only later pages blocked, vendor unknown
    later = _load(1, "https://s.com/a/", "default", state="not_checked", reason="challenge")
    assert challenge_summary([ok, later]) == {"vendor": None, "loads": 1, "of": 2, "homepage": False}
    # a page-supplied value that isn't a known vendor is dropped, never echoed
    later.result.metadata["challenge_vendor"] = "<script>"
    assert challenge_summary([ok, later])["vendor"] is None
    # a load whose own result is missing still counts
    later.result = None
    assert challenge_summary([ok, later])["loads"] == 1
    # no bot check, no alert
    assert challenge_summary([ok, timed_out]) is None
    assert build_report("s.com", "s.com", None, [ok], 1, [], [])["challenge"] is None


def test_verdict_clean_paths_pinned():
    from _support import _load
    from mandacaru.src.scanner.site_report import site_verdict

    ok = lambda i, p, **kw: _load(i, f"https://s.com/{i}", p, **kw)
    # A homepage default load that only partly finished still counts as checked.
    loads = [ok(0, "default", state="partial"), ok(0, "googlebot"), ok(1, "default"), ok(2, "default")]
    assert site_verdict([], loads, True)["verdict"] == "clean"
    # A homepage-only run (no stage-2 loads) has nothing to be "more than half" of.
    assert site_verdict([], [ok(0, "default"), ok(0, "mobile-ios")], True)["verdict"] == "clean"


def test_external_scripts_skip_loads_that_ended_off_site():
    from _support import _load
    from mandacaru.src.scanner.site_report import build_report

    rec = {"url": "https://cdn.evil.net/x.js", "initiator": "parser", "initiator_url": None, "main_frame": True}
    own = {**rec, "url": "https://ads.net/a.js"}
    loads = [_load(0, "https://s.com/", "default", script_requests=[own]),
             _load(0, "https://s.com/", "mobile-ios", final_url="https://evil.net/", script_requests=[rec, own])]
    hosts = build_report("s.com", "s.com", None, loads, 1, [], [])["external_scripts"]["hosts"]
    assert [(h["host"], h["urls"][0]["profiles"]) for h in hosts] == [("ads.net", ["default"])]


def test_the_checkout_page_is_flagged_by_index():
    from _support import _load
    from mandacaru.src.scanner.site_report import build_report

    loads = [_load(0, "https://s.com/", "default"), _load(1, "https://s.com/kassa/checkout/", "default"),
             _load(2, "https://s.com/mandacaru-0123456789ab/", "default")]
    r = build_report("s.com", "s.com", None, loads, 1, [], [], checkout_index=1)
    assert [p["checkout"] for p in r["checked"]["pages"]] == [False, True, False]
    assert [p["checkout"] for p in build_report("s.com", "s.com", None, loads, 1, [], [])["checked"]["pages"]] == [False] * 3


def _checkout_page(*loads):
    from mandacaru.src.scanner.site_report import build_report

    home = _home()
    pages = build_report("s.com", "s.com", None, [home, *loads], 1, [], [], checkout_index=1)["checked"]["pages"]
    assert pages[0]["checkout_state"] is None  # not the checkout page
    return pages[1]


def _home():
    from _support import _load
    return _load(0, "https://s.com/", "default")


def _with_status(load, status):
    load.result.metadata["main_status"] = status
    return load


def test_the_checkout_page_says_where_its_load_landed():
    """A store's checkout answers 302 to the cart when the cart is empty, and a store whose checkout
    isn't at /checkout/ answers the fallback with a 404: the page entry says which, from the first
    usable load in profile order, so the report never calls a cart or a 404 "your checkout page"."""
    from _support import _load

    url = "https://s.com/checkout/"
    stayed = _checkout_page(_with_status(_load(1, url, "default"), 200))
    assert (stayed["checkout_state"], stayed["checkout_landing"], stayed["checkout_status"]) == ("loaded", None, 200)
    # the same path, give or take a trailing slash, the scheme, the www twin, a query or a fragment
    for landing in ("https://s.com/checkout", "http://www.s.com/checkout/?x=1#pay"):
        same = _checkout_page(_with_status(_load(1, url, "default", final_url=landing), 200))
        assert same["checkout_state"] == "loaded" and same["checkout_landing"] is None, landing
    cart = _checkout_page(_with_status(_load(1, url, "default", final_url="https://s.com/cart/"), 200))
    assert (cart["checkout_state"], cart["checkout_landing"], cart["checkout_status"]) == (
        "redirected", "https://s.com/cart/", 200)
    long = "https://s.com/cart/?" + "a" * 400
    assert len(_checkout_page(_load(1, url, "default", final_url=long))["checkout_landing"]) == 300
    # a 4xx wins over a differing path
    missing = _checkout_page(_with_status(_load(1, url, "default"), 404))
    assert (missing["checkout_state"], missing["checkout_landing"], missing["checkout_status"]) == ("not_found", None, 404)
    gone = _checkout_page(_with_status(_load(1, url, "default", final_url="https://s.com/shop/"), 410))
    assert gone["checkout_state"] == "not_found" and gone["checkout_status"] == 410
    # a 5xx is a page that loaded badly, not a missing checkout
    assert _checkout_page(_with_status(_load(1, url, "default"), 500))["checkout_state"] == "loaded"


def test_the_checkout_state_comes_from_the_first_usable_load_in_profile_order():
    from _support import _load

    url = "https://s.com/checkout/"
    dead = _load(1, url, "default", state="not_checked", reason="load_failed")
    dead.result = None
    cart = _with_status(_load(1, url, "mobile-ios", final_url="https://s.com/cart/"), 200)
    page = _checkout_page(cart, dead)
    assert page["checkout_state"] == "redirected" and page["checkout_landing"] == "https://s.com/cart/"
    blocked = _with_status(_load(1, url, "default", state="not_checked", reason="challenge"), 403)
    blocked.result.metadata["challenge"] = True
    page = _checkout_page(blocked)  # a bot check says nothing about the checkout
    assert (page["checkout_state"], page["checkout_landing"], page["checkout_status"]) == (None, None, None)
    assert _checkout_page(dead)["checkout_state"] is None


def test_the_404_probe_is_flagged_on_its_page_and_its_blocks():
    from _support import _load, _yara_hop
    from mandacaru.src.scanner.site_report import build_report

    probe = "https://s.com/mandacaru-0123456789ab/"
    own = "https://s.com/mandacaru-news/"  # an owner page with the same prefix: the probe is the last such page
    loads = [_load(0, "https://s.com/", "default"),
             _load(1, own, "default", [_yara_hop("served", own, "r1", 3, False, 0, "A")]),
             _load(2, probe, "default", [_yara_hop("served", probe, "r2", 3, False, 0, "B")])]
    r = build_report("s.com", "s.com", None, loads, 1, [], [])
    assert [(p["url"], p["probe"]) for p in r["checked"]["pages"]] == [("https://s.com/", False), (own, False), (probe, True)]
    assert {b["location"]: b["probe"] for b in r["blocks"]} == {own: False, probe: True}
    assert build_report("s.com", "s.com", None, loads[:1], 1, [], [])["checked"]["pages"][0]["probe"] is False


def test_offsite_homepage_landing_code_is_the_landings():
    from _support import _load, _yara_hop
    from mandacaru.src.scanner.site_report import build_report

    # The homepage default load lands on evil.net, whose HTML matches a weak rule.
    hop = _yara_hop("served", "https://evil.net/", "html_scam", 2, False, 10, "SCAMCODE")
    home = _load(0, "https://s.com/", "default", [hop], final_url="https://evil.net/",
                 script_requests=[{"url": "https://cdn.evil.net/x.js", "initiator": "parser", "main_frame": True}])
    others = [_load(0, "https://s.com/", p) for p in ("mobile-ios", "googlebot", "search-clicker")]
    r = build_report("s.com", "s.com", "evil.net", [home] + others, 1, [], [])
    found = {b["location"]: [(f["kind"], f["origin"], f["details"]["offsite"]) for f in b["findings"]] for b in r["blocks"]}
    assert found == {"https://s.com/": [("offsite_homepage", None, False)], "https://evil.net/": [("yara", None, True)]}
    assert r["external_scripts"]["hosts"] == []


def test_unchecked_loads_do_not_feed_scripts_or_counts():
    from _support import _load
    from mandacaru.src.scanner.site_report import build_report, external_scripts

    def rec(url, frame="https://s.com/", main=True):
        return {"url": url, "initiator": "parser", "initiator_url": None, "main_frame": main, "frame_url": frame}

    shared = rec("https://ads.net/a.js")
    ok = _load(0, "https://s.com/", "default", script_requests=[shared])
    # A load that failed after recording requests: it must not add scripts, frames or a profile.
    failed = _load(0, "https://s.com/", "googlebot", state="not_checked", reason="load_failed",
                   script_requests=[shared, rec("https://only-failed.net/x.js"), rec("https://ads.net/f.js", "https://fr.com/f", False)])
    [host] = external_scripts([ok, failed], "s.com", [])["hosts"]
    assert host["host"] == "ads.net" and [u["url"] for u in host["urls"]] == ["https://ads.net/a.js"]

    # With the failed googlebot load ignored, ads.net was seen by every visitor that was checked
    # (default and mobile-ios), so only zzz.net (mobile-ios alone) ranks as "some visitors".
    other = _load(0, "https://s.com/", "mobile-ios", script_requests=[rec("https://zzz.net/z.js"), shared])
    hosts = [h["host"] for h in external_scripts([ok, other, failed], "s.com", [])["hosts"]]
    assert hosts == ["zzz.net", "ads.net"]

    checked = build_report("s.com", "s.com", None, [ok, failed], 1, [], [])["checked"]
    assert (checked["scripts_scanned"], checked["frames_scanned"], checked["not_checked"]) == (1, 0, 1)


def _redirect_page(index, url, steered_profile, profiles, to="https://cheap-deals-shop.com/promo"):
    """Real scorer: `steered_profile` (or every profile, for "all") gets a 302 to `to`; the page's
    default result is folded with combine() as the site engine does."""
    from mandacaru.src.intelligence.scorer import MandacaruScorer
    from mandacaru.src.scanner.models import RedirectHop, ScanResult
    from mandacaru.src.scanner.site_findings import Load

    scorer = MandacaruScorer()
    loads = []
    for profile in profiles:
        steered = steered_profile in (profile, "all")
        hops = [RedirectHop(url=url, status_code=302, mechanism="http_3xx", headers={"location": to})] if steered else []
        r = ScanResult(target_url=url, final_url=to if steered else url, hops=hops)
        r.metadata = {"page_signals": {"title": "Deals", "password_inputs": 0, "forms": 0, "content_type": "text/html"},
                      "main_status": 200, "served_bytes": 1000, "script_requests": [], "injections": []}
        scorer.score(r, site_host="s.com")
        loads.append(Load(index, url, profile, "checked", None, r, None))
    scorer.combine(loads[0].result, "default", {l.profile: l.result for l in loads[1:]})
    return loads


def test_conditional_redirect_to_another_domain_is_suspicious_not_clean():
    from mandacaru.src.scanner.site_report import build_report

    home_profiles = ("default", "mobile-ios", "googlebot", "search-clicker")
    page_profiles = ("default", "mobile-ios", "googlebot")
    probe = _redirect_page(2, "https://s.com/mandacaru-abc/", None, page_profiles)
    for steered in ("mobile-ios", "search-clicker"):
        home = _redirect_page(0, "https://s.com/", steered, home_profiles)
        about = _redirect_page(1, "https://s.com/about/", "mobile-ios", page_profiles)
        assert home[0].result.metadata["cloaking"]["suspicious"] == []  # the landing alone isn't Suspicious
        r = build_report("s.com", "s.com", None, home + about + probe, 3, [], [])
        assert r["verdict"]["verdict"] == "suspicious"
        found = {b["location"]: b["findings"] for b in r["blocks"]}
        [f] = found["https://s.com/"]
        assert (f["kind"], f["severity"], f["visitors"]) == ("cloaking", "suspicious", [steered])
        assert f["message"] == "Some visitors are sent to a different website"
        assert "https://cheap-deals-shop.com/promo" in f["snippet"]["text"]
        assert any(s.startswith("Cloaking: ") for s in f["details"]["scoring"])
        assert found["https://s.com/about/"][0]["visitors"] == ["mobile-ios"]

    # Every visitor sent to the same other domain is not cloaking: no new finding.
    moved = _redirect_page(1, "https://s.com/old/", "all", page_profiles)
    assert moved[0].result.metadata["cloaking"] is None
    r = build_report("s.com", "s.com", None, _redirect_page(0, "https://s.com/", None, home_profiles) + moved, 3, [], [])
    assert r["blocks"] == [] and r["verdict"]["verdict"] == "clean"


def test_offsite_homepage_folds_in_its_non_decisive_cloaking():
    from _support import _load
    from mandacaru.src.scanner.site_report import build_report

    # Desktop visitors leave the site; Googlebot stays. One finding: the off-site homepage.
    home = [_load(0, "https://s.com/", p, final_url="https://s.com/" if p == "googlebot" else "https://elsewhere.net/")
            for p in ("default", "mobile-ios", "googlebot", "search-clicker")]
    home[0].result.malicious_score = 0.55  # combined; its own page scored 0.2
    home[0].result.metadata["variants"] = [{"profile": "default", "requested": True, "malicious_score": 0.2}]
    home[0].result.metadata["cloaking"] = {"landings": {}, "common": "elsewhere.net", "steered": ["googlebot"], "suspicious": []}
    home[0].result.metadata["scoring_findings"] = ["Cloaking: landing depends on the browser profile (y)"]
    [b] = build_report("s.com", "s.com", "elsewhere.net", home, 3, [], [])["blocks"]
    [f] = b["findings"]
    assert (f["kind"], f["severity"]) == ("offsite_homepage", "suspicious")
    assert "Cloaking: landing depends on the browser profile (y)" in f["details"]["scoring"]


def test_external_scripts_mark_a_script_blocked_as_malware_as_a_finding():
    from _support import _load
    from mandacaru.src.scanner.site_findings import build_blocks
    from mandacaru.src.scanner.site_report import external_scripts

    url = "https://r1.example/donation"
    rec = {"url": url, "main_frame": True, "frame_url": "https://s.com/p", "initiator": "script",
           "initiator_url": "https://s.com/p", "line": 0, "column": None}
    load = _load(0, "https://s.com/p", "default", [], script_requests=[rec])
    load.result.metadata["flagged_scripts"] = [{"url": url, "status": 403, "reason": "cloudflare_suspected_malware"}]
    blocks = build_blocks([load], "s.com", None)
    out = external_scripts([load], "s.com", blocks)
    [host] = out["hosts"]
    assert host["host"] == "r1.example"
    assert host["urls"][0]["finding"] is True and host["urls"][0]["injected_by"] == "inline on https://s.com/p"


def test_checked_pages_note_their_own_card_fields():
    """card_fields: a checked, on-site load of the page has card inputs (served, or inserted by
    the store's or a known vendor's code); card_fields_unchecked: whose code added them couldn't be
    checked on some load; card_fields_vendors: the known vendors whose code inserted them."""
    from _support import _card, _cards, _load
    from mandacaru.src.scanner.site_report import build_report

    page = "https://s.com/checkout/"
    loads = [
        _load(0, "https://s.com/", "default"),  # no card_inputs at all (an older result)
        _load(1, page, "default", card_inputs=_cards(_card("store", ["https://s.com/form.js"]))),
        _load(1, page, "mobile-ios", card_inputs=_cards(_card("vendor", ["https://static.hotjar.com/c.js"],
                                                              vendors=["Hotjar", "Not A Vendor"]))),
        _load(2, "https://s.com/served/", "default", card_inputs=_cards(present=1)),  # served with the page
        _load(3, "https://s.com/unchecked/", "default",
              card_inputs=_cards(_card(frames=["https://s.com/unchecked/"], verified=False))),
        _load(4, "https://s.com/none/", "default", card_inputs=_cards()),
    ]
    report = build_report("s.com", "s.com", None, loads, 1, [], [])
    assert report["blocks"] == []  # none of these is a finding
    pages = {p["url"]: p for p in report["checked"]["pages"]}
    flags = lambda p: (p["card_fields"], p["card_fields_unchecked"], p["card_fields_vendors"])
    assert flags(pages["https://s.com/"]) == (False, False, [])
    assert flags(pages[page]) == (True, False, ["Hotjar"])  # only names from the known-vendor list
    assert flags(pages["https://s.com/served/"]) == (True, False, [])
    assert flags(pages["https://s.com/unchecked/"]) == (True, True, [])
    assert flags(pages["https://s.com/none/"]) == (False, False, [])


def test_card_fields_skip_unusable_and_offsite_loads():
    from _support import _card, _cards, _load
    from mandacaru.src.scanner.site_report import build_report

    page = "https://s.com/checkout/"
    loads = [
        _load(0, "https://s.com/", "default"),
        _load(1, page, "default", final_url="https://evil.net/",
              card_inputs=_cards(_card("store", ["https://evil.net/f.js"]))),
        _load(1, page, "googlebot", state="not_checked", reason="challenge",
              card_inputs=_cards(_card(frames=[page], verified=False))),
    ]
    loads[2].result.metadata["challenge"] = True
    pages = {p["url"]: p for p in build_report("s.com", "s.com", None, loads, 1, [], [])["checked"]["pages"]}
    assert (pages[page]["card_fields"], pages[page]["card_fields_unchecked"]) == (False, False)


def test_unchecked_card_fields_keep_a_clean_site_from_reading_clean():
    """Unchecked must never read as Clean: card fields whose owner couldn't be checked make an
    otherwise clean site Partly checked; a Suspicious verdict is unaffected."""
    from _support import _card, _cards, _load
    from mandacaru.src.scanner.site_report import build_report

    home = [_load(0, "https://s.com/", p) for p in ("default", "mobile-ios")]
    unchecked = _load(1, "https://s.com/checkout/", "default",
                      card_inputs=_cards(_card(frames=[], via="unseen", verified=False)))
    v = build_report("s.com", "s.com", None, home + [unchecked], 1, [], [])["verdict"]
    assert v["verdict"] == "partly_checked"
    assert v["summary"] == "No malware found, but we couldn't check who added some card payment fields"
    checked = _load(1, "https://s.com/checkout/", "default", card_inputs=_cards(present=1))
    assert build_report("s.com", "s.com", None, home + [checked], 1, [], [])["verdict"]["verdict"] == "clean"
    skim = _load(2, "https://s.com/pay/", "default", card_inputs=_cards(_card(frames=["https://evil.example/s.js"])))
    assert build_report("s.com", "s.com", None, home + [unchecked, skim], 1, [], [])["verdict"]["verdict"] == "suspicious"


def test_unseen_card_fields_without_the_whole_served_body_are_unchecked_not_outside_code():
    """summarize's unseen insertion end to end: with no served body, or one cut at the cap, the
    page's card fields may be in the part we didn't get, so no finding and the page is unchecked;
    with the whole body and no card inputs in it, outside code it is."""
    from _support import _load
    from mandacaru.src.scanner.card_watch import summarize
    from mandacaru.src.scanner.site_report import build_report
    from mandacaru.src.scanner.yara_scan import MAX_BUFFER_BYTES

    page = "https://s.com/checkout/"
    whole = b"<html><body><form></form></body></html>"
    cut = (whole + b" " * MAX_BUFFER_BYTES)[:MAX_BUFFER_BYTES]
    for served, finding in ((None, False), (cut, False), (whole, True)):
        load = _load(0, page, "default", card_inputs=summarize([], 1, "s.com", page, served, parsed={}))
        report = build_report("s.com", "s.com", None, [load], 1, [], [])
        kinds = [f["kind"] for b in report["blocks"] for f in b["findings"]]
        assert kinds == (["card_inputs"] if finding else []), served is None
        [p] = report["checked"]["pages"]
        assert (p["card_fields"], p["card_fields_unchecked"]) == (True, not finding)
