HOME = "https://example.com/"


def test_pick_pages_fills_one_of_each_kind_in_order():
    from pnakotic.src.scanner.page_picker import pick_pages

    links = [HOME, "https://example.com/about/", "https://example.com/2024/05/lemon-tart/",
             "https://example.com/category/cakes/", "https://example.com/contact-us/",
             "https://example.com/shop/item/", "https://example.com/shop/other/"]
    assert pick_pages(links, "example.com", HOME) == [
        "https://example.com/2024/05/lemon-tart/", "https://example.com/about/",
        "https://example.com/category/cakes/", "https://example.com/contact-us/",
        "https://example.com/shop/item/"]


def test_pick_pages_drops_admin_feeds_media_and_offsite():
    from pnakotic.src.scanner.page_picker import pick_pages

    links = ["https://example.com/wp-admin/", "https://example.com/wp-login.php", "https://example.com/feed/",
             "https://example.com/wp-json/wp/v2/posts", "https://example.com/?replytocom=3",
             "https://example.com/a.pdf", "https://example.com/b.jpg", "https://blog.example.com/x/",
             "https://other.com/x/", "https://www.example.com/kept/"]
    assert pick_pages(links, "example.com", HOME) == ["https://example.com/kept/"]  # www twin rewritten


def test_extract_links_caps_and_filters():
    from pnakotic.src.scanner.page_picker import extract_links

    html = "".join(f'<a href="/p{i}/">x</a>' for i in range(100_000)) + '<a href="javascript:alert(1)">j</a>'
    links = extract_links(html, HOME)
    assert len(links) == 2000 and links[0] == "https://example.com/p0/"
    assert extract_links('<a href="data:text/html,x">d</a><a href="#top">t</a>', HOME) == ["https://example.com/"]


def test_probe_url():
    from pnakotic.src.scanner.page_picker import probe_url

    assert probe_url("https://example.com:8443/", "a1b2c3d4e5f6") == "https://example.com:8443/pnakotic-a1b2c3d4e5f6/"


def test_extract_links_resolves_normalises_and_dedupes():
    from pnakotic.src.scanner.page_picker import extract_links

    html = ('<a href="/About/#team">a</a><a href="HTTPS://Example.COM/About/">b</a>'
            '<a href="next?x=1">c</a><a href="mailto:a@b.c">m</a><a href="ftp://example.com/f">f</a>'
            '<a name="no-href">n</a><a href="//cdn.example.com/x/">p</a><a href="http://[bad">z</a>')
    assert extract_links(html, "https://example.com/blog/post/") == [
        "https://example.com/About/", "https://example.com/blog/post/next?x=1", "https://cdn.example.com/x/"]


def test_extract_links_keeps_port_and_drops_credentials():
    from pnakotic.src.scanner.page_picker import extract_links

    html = '<a href="http://user:pw@Example.com:8080/a">a</a>'
    assert extract_links(html, HOME) == ["http://example.com:8080/a"]


def test_extract_links_limit_counts_anchors_seen():
    from pnakotic.src.scanner.page_picker import extract_links

    html = '<a href="/a/">1</a><a href="/a/">2</a><a href="/b/">3</a><a href="/c/">4</a>'
    assert extract_links(html, HOME, limit=3) == ["https://example.com/a/", "https://example.com/b/"]


def test_pick_pages_post_shapes_and_deepest_fallback():
    from pnakotic.src.scanner.page_picker import pick_pages

    assert pick_pages([HOME + "x/", HOME + "?p=42"], "example.com", HOME)[0] == HOME + "?p=42"
    links = [HOME + "about/", HOME + "blog/2/deep/er/", HOME + "blog/short/"]
    assert pick_pages(links, "example.com", HOME)[:2] == [HOME + "blog/2/deep/er/", HOME + "about/"]


def test_pick_pages_homepage_never_counts_and_dedupes_twins():
    from pnakotic.src.scanner.page_picker import pick_pages

    links = ["https://example.com", "https://www.example.com/", "https://example.com/a/",
             "https://www.example.com/a/", "https://example.com/a"]
    assert pick_pages(links, "example.com", HOME) == ["https://example.com/a/"]
    assert pick_pages(["https://example.com/a/"], "www.example.com", "https://www.example.com/") == [
        "https://www.example.com/a/"]


def test_pick_pages_drops_action_urls_and_non_http():
    from pnakotic.src.scanner.page_picker import pick_pages

    links = ["https://example.com/logout/", "https://example.com/cart/?add-to-cart=7",
             "https://example.com/xmlrpc.php", "https://example.com/sitemap.xml", "https://example.com/a.zip",
             "javascript:alert(1)", "ftp://example.com/x/", "https://example.com/blog-outlook/"]
    assert pick_pages(links, "example.com", HOME) == ["https://example.com/blog-outlook/"]


def test_pick_pages_respects_limit_and_prefers_distinct_first_segment():
    from pnakotic.src.scanner.page_picker import pick_pages

    links = [HOME + "a/1/", HOME + "a/2/", HOME + "b/1/", HOME + "c/1/"]
    assert pick_pages(links, "example.com", HOME, limit=3) == [HOME + "a/1/", HOME + "b/1/", HOME + "c/1/"]
    assert pick_pages(links, "example.com", HOME, limit=0) == []


def test_extract_links_is_linear_on_hostile_markup():
    import time

    from pnakotic.src.scanner.page_picker import extract_links

    anchor = '<a href="/x/">x</a>'
    floods = ["<!--" * 100_000, "<![" * 100_000, "<a " * 100_000, "<a " + "x" * 3_000_000,
              '<a href="' * 100_000, "<" * 1_000_000]
    for flood in floods:
        start = time.monotonic()
        before = extract_links(anchor + flood, HOME)
        after = extract_links(flood + anchor, HOME)
        assert time.monotonic() - start < 2.0, flood[:12]
        assert before[0] == "https://example.com/x/"
        if not flood.startswith("<!--"):  # an unterminated comment swallows what follows it
            assert after[-1] == "https://example.com/x/"


def test_extract_links_attribute_forms_comments_and_entities():
    from pnakotic.src.scanner.page_picker import extract_links

    html = ("<A HREF='/single/'>1</A><a class=x href=/bare/ >2</a><a\nhref = \"/spaced/?a=1&amp;b=2\">3</a>"
            "<!-- <a href='/hidden/'>h</a> --><a href=\"/after-comment/\">4</a>"
            "<abbr href='/not-an-anchor/'>5</abbr><a data-href='/nope/'>6</a>")
    assert extract_links(html, HOME) == [
        "https://example.com/single/", "https://example.com/bare/",
        "https://example.com/spaced/?a=1&b=2", "https://example.com/after-comment/"]


def test_extract_links_unquoted_href_before_closing_bracket():
    from pnakotic.src.scanner.page_picker import extract_links

    assert extract_links("<a href=/x/>t</a><a href=/y/ >u</a><a href=/z/?a=1&amp;b=2>v</a>", HOME) == [
        "https://example.com/x/", "https://example.com/y/", "https://example.com/z/?a=1&b=2"]


def test_extract_links_empty_comments_do_not_swallow_the_document():
    from pnakotic.src.scanner.page_picker import extract_links

    assert extract_links('<!--><a href="/a/">a</a>', HOME) == ["https://example.com/a/"]
    assert extract_links('<!---><a href="/b/">b</a>', HOME) == ["https://example.com/b/"]
    assert extract_links('<!----><a href="/c/">c</a><!-- <a href="/h/"> --><a href="/d/">d</a>', HOME) == [
        "https://example.com/c/", "https://example.com/d/"]
