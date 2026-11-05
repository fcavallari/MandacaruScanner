"""The site quick-check orchestrator (SiteScanner) against a local server: homepage in four
profiles, page picking, budgeted stage-2 loads, scoring and the report."""
import pytest

from _support import _site_engine, requires_browser, requires_yara, site_server, yara_rules_dir  # noqa: F401


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_site_scan_compromised_with_snippet_and_merged_footer(site_server, tmp_path, yara_rules_dir):
    from pnakotic.src.scanner.site_engine import SiteScanner

    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/")
    r = out.report
    assert r["verdict"]["verdict"] == "compromised"
    footer = [b for b in r["blocks"] if b["findings"][0]["details"]["rule"] == "js_skimmer_test_001" and b["location_kind"] == "page"]
    assert len(footer) == 1 and len(footer[0]["findings"][0]["pages"]) >= 3
    assert footer[0]["findings"][0]["snippet"]["line"] >= 1
    assert [p["index"] for p in r["checked"]["pages"]][-1] == len(r["checked"]["pages"]) - 1  # probe last
    assert any("/pnakotic-" in p["url"] for p in r["checked"]["pages"])
    # Homepage first, the probe last; the www-less loopback host is the site.
    pages = r["checked"]["pages"]
    assert pages[0]["url"] == f"{site_server}/" and "/pnakotic-" in pages[-1]["url"]
    assert [l["profile"] for l in pages[0]["loads"]] == ["default", "mobile-ios", "search-clicker", "googlebot"]
    assert all([l["profile"] for l in p["loads"]] == ["default", "mobile-ios", "googlebot"] for p in pages[1:])
    assert pages[0]["loads"][0]["landing"] == f"{site_server}/"
    assert pages[0]["loads"][0]["screenshot"].startswith("pages/0/default/landing_")
    assert out.worst_score == 1.0 and out.final_url == f"{site_server}/"
    assert any(a["rel_path"] == pages[0]["loads"][0]["screenshot"] for a in out.artifact_manifest["artifacts"])


@requires_browser
@requires_yara
@pytest.mark.asyncio
async def test_site_scan_googlebot_only_visitor(site_server, tmp_path, yara_rules_dir):
    from pnakotic.src.scanner.site_engine import SiteScanner

    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/g/")
    f = out.report["blocks"][0]["findings"][0]
    assert f["visitors"] == ["googlebot"]


@requires_browser
@pytest.mark.asyncio
async def test_site_scan_obfuscated_injector_is_suspicious_plain_loader_is_clean(site_server, tmp_path):
    from pnakotic.src.scanner.site_engine import SiteScanner

    assert (await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/obf/")).report["verdict"]["verdict"] == "suspicious"
    assert (await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/plain/")).report["verdict"]["verdict"] == "clean"


@requires_browser
@pytest.mark.asyncio
async def test_site_scan_phone_only_redirect_to_another_site_is_suspicious(site_server, tmp_path):
    from pnakotic.src.scanner.site_engine import SiteScanner

    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/m/")
    r = out.report
    assert r["verdict"]["verdict"] == "suspicious"
    [f] = [f for b in r["blocks"] for f in b["findings"] if f["kind"] == "cloaking"]
    assert f["severity"] == "suspicious" and f["visitors"] == ["mobile-ios"]
    assert f["message"] == "Some visitors are sent to a different website"
    assert "/plain/" in f["snippet"]["text"] and "localhost" in f["snippet"]["text"]


@requires_browser
@pytest.mark.asyncio
async def test_site_scan_budget_marks_not_checked(site_server, tmp_path):
    import time
    from pnakotic.src.scanner.site_engine import SiteScanner

    started = time.monotonic()
    out = await SiteScanner(_site_engine(tmp_path), budget_s=8, grace_s=1).scan(f"{site_server}/hang/")
    assert out.report["verdict"]["verdict"] == "couldnt_check"
    assert out.report["checked"]["not_checked"] >= 1
    loads = [l for p in out.report["checked"]["pages"] for l in p["loads"]]
    assert all((l["state"], l["reason"]) == ("not_checked", "budget") for l in loads)
    assert time.monotonic() - started < 15


@requires_browser
@pytest.mark.asyncio
async def test_site_scan_offsite_homepage_not_crawled(site_server, tmp_path):
    from pnakotic.src.scanner.site_engine import SiteScanner

    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{site_server}/to-other/")
    kinds = [f["kind"] for b in out.report["blocks"] for f in b["findings"]]
    assert "offsite_homepage" in kinds
    pages = [p["url"] for p in out.report["checked"]["pages"]]
    assert len(pages) == 2 and "/pnakotic-" in pages[1]   # only the probe after the homepage
    assert out.report["site"] == "127.0.0.1"
    assert out.report["notes"] == ["No pages could be picked because the homepage left the site"]
    assert out.redirect_chain is True


@requires_browser
@pytest.mark.asyncio
async def test_site_scan_falls_back_to_http_and_drops_the_https_set(site_server, tmp_path):
    from pnakotic.src.scanner.site_engine import SiteScanner

    https = site_server.replace("http://", "https://")  # the server speaks plain HTTP: TLS fails
    out = await SiteScanner(_site_engine(tmp_path)).scan(f"{https}/plain/")
    r = out.report
    assert out.homepage_url == f"{site_server}/plain/" and r["notes"] == ["Checked over http"]
    assert r["verdict"]["verdict"] == "clean"
    home = r["checked"]["pages"][0]
    assert home["url"] == f"{site_server}/plain/" and len(home["loads"]) == 4
    assert all(l["state"] == "checked" for l in home["loads"])
    listed = {a["rel_path"] for a in out.artifact_manifest["artifacts"]}
    shots = {l["screenshot"] for p in r["checked"]["pages"] for l in p["loads"] if l["screenshot"]}
    assert listed == shots  # the failed https loads' screenshots are gone
