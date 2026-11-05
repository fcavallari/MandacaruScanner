"""Load states, external scripts, verdict and report assembly (site_report), from hand-built loads."""


def test_verdict_rows():
    from _support import _load
    from pnakotic.src.scanner.site_report import site_verdict

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
    from pnakotic.src.scanner.site_report import site_verdict

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
    from pnakotic.src.scanner.site_report import classify_load

    assert classify_load(None, "budget") == ("not_checked", "budget")
    assert classify_load(_result(challenge=True), None) == ("not_checked", "challenge")
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=900, title="Home"), None) == ("partial", None)
    assert classify_load(_result(raw_error="Timeout 30000ms", served_bytes=0, title=""), None) == ("not_checked", "timeout")
    assert classify_load(_result(), None) == ("checked", None)


def test_classify_load_order_and_failures():
    from _support import _result
    from pnakotic.src.scanner.site_report import classify_load

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
    from pnakotic.src.scanner.site_report import external_scripts

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
    from pnakotic.src.scanner.site_report import external_scripts

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
    from pnakotic.src.scanner.site_report import external_scripts

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
    from pnakotic.src.scanner.site_report import external_scripts

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
    from pnakotic.src.scanner.site_report import build_report

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
        {"profile": "default", "state": "checked", "reason": None, "status": 200, "screenshot": "pages/0/default/landing_1.png", "score": 0.3},
        {"profile": "googlebot", "state": "not_checked", "reason": "challenge", "status": None, "screenshot": None, "score": None}]
    assert checked["pages"][1]["loads"][0]["status"] == 404
    assert report["notes"] == ["note"] and report["blocked_hosts"] == ["10.0.0.1"]

    same = build_report("s.com", "s.com", None, [_load(0, "https://s.com/", "default")], 0, [], [])
    assert same["redirected_from"] is None and same["verdict"]["summary"] == "Clean (no malware rules loaded)"
    assert same["blocks"] == [] and same["external_scripts"] == {"hosts": [], "hosts_more": 0, "urls_more": 0}
    assert same["checked"]["pages"][0]["loads"][0]["score"] == 0.0


def test_build_report_counts_blocks_past_the_cap():
    from _support import _load, _yara_hop
    from pnakotic.src.scanner.site_report import build_report

    loads = [_load(0, "https://s.com/", "default", [_yara_hop("script", f"https://s.com/{i}.js", f"r{i}", 5, True, 0, "X") for i in range(60)])]
    report = build_report("s.com", "s.com", None, loads, 1, [], [])
    assert len(report["blocks"]) == 50 and report["blocks_more"] == 10


def test_couldnt_check_summary_gives_the_reason():
    from _support import _load
    from pnakotic.src.scanner.site_report import site_verdict

    for reason, summary in [("challenge", "This site showed our scanner a bot check"),
                            ("budget", "We ran out of time before the homepage loaded"),
                            ("timeout", "The homepage took too long to load"),
                            ("load_failed", "We couldn't reach this site"), (None, "We couldn't reach this site")]:
        v = site_verdict([], [_load(0, "https://s.com/", "default", state="not_checked", reason=reason)], True)
        assert (v["verdict"], v["summary"]) == ("couldnt_check", summary)
    assert site_verdict([], [], True)["summary"] == "We couldn't reach this site"


def test_verdict_clean_paths_pinned():
    from _support import _load
    from pnakotic.src.scanner.site_report import site_verdict

    ok = lambda i, p, **kw: _load(i, f"https://s.com/{i}", p, **kw)
    # A homepage default load that only partly finished still counts as checked.
    loads = [ok(0, "default", state="partial"), ok(0, "googlebot"), ok(1, "default"), ok(2, "default")]
    assert site_verdict([], loads, True)["verdict"] == "clean"
    # A homepage-only run (no stage-2 loads) has nothing to be "more than half" of.
    assert site_verdict([], [ok(0, "default"), ok(0, "mobile-ios")], True)["verdict"] == "clean"


def test_unchecked_loads_do_not_feed_scripts_or_counts():
    from _support import _load
    from pnakotic.src.scanner.site_report import build_report, external_scripts

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
