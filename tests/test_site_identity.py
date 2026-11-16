import pytest


def test_registrable_domain_uses_private_psl():
    from mandacaru.src.scanner.site_identity import registrable_domain

    assert registrable_domain("a.github.io") == "a.github.io"
    assert registrable_domain("www.example.co.uk") == "example.co.uk"
    assert registrable_domain("127.0.0.1") == ""


def test_same_domain_and_on_site():
    from mandacaru.src.scanner.site_identity import on_site, same_domain

    assert same_domain("www.example.com", "shop.example.com")
    assert not same_domain("a.github.io", "b.github.io")
    assert not same_domain("127.0.0.1", "localhost")
    assert on_site("www.example.com", "example.com") and on_site("example.com", "www.example.com")
    assert not on_site("blog.example.com", "example.com")


def test_same_domain_and_on_site_ignore_a_trailing_dot():
    from mandacaru.src.scanner.site_identity import on_site, same_domain

    assert on_site("example.com.", "example.com") and on_site("example.com", "example.com.")
    assert on_site("www.example.com.", "example.com") and on_site("example.com.", "www.example.com.")
    assert same_domain("www.example.com.", "shop.example.com") and same_domain("localhost.", "localhost")
    assert not on_site("blog.example.com.", "example.com") and not on_site(".", ".")
    assert not same_domain("127.0.0.1.", "localhost")


def test_normalize_site_input_messy():
    from mandacaru.src.scanner.site_identity import normalize_site_input

    assert normalize_site_input("Example.COM/blog?x=1") == "https://example.com/"
    assert normalize_site_input("http://example.com:8443/a") == "https://example.com:8443/"
    assert normalize_site_input("münchen.de") == "https://xn--mnchen-3ya.de/"
    for bad in ("", "   ", "ftp://x.com", "user:pw@example.com", "https://"):
        with pytest.raises(ValueError):
            normalize_site_input(bad)


def test_resolve_site_host_chain():
    from mandacaru.src.scanner.site_identity import resolve_site_host

    assert resolve_site_host("www.x.co.uk", "https://shop.x.co.uk/") == ("shop.x.co.uk", None)
    assert resolve_site_host("example.com", "https://example.com/home") == ("example.com", None)
    assert resolve_site_host("a.github.io", "https://b.github.io/") == ("a.github.io", "b.github.io")
    assert resolve_site_host("x.com", "") == ("x.com", None)
