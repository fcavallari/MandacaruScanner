import pytest


@pytest.mark.parametrize("addr, expected", [
    ("8.8.8.8", True),
    ("2606:4700:4700::1111", True),
    ("127.0.0.1", False),
    ("10.0.0.5", False),
    ("172.18.0.3", False),        # docker compose network
    ("192.168.1.1", False),
    ("169.254.169.254", False),   # cloud metadata
    ("100.64.0.1", False),        # CGNAT
    ("0.0.0.0", False),
    ("224.0.0.1", False),         # multicast
    ("::1", False),
    ("fe80::1%eth0", False),      # link-local with zone id
    ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback
    ("::ffff:8.8.8.8", True),
])
def test_is_public_ip(addr, expected):
    from pnakotic.src.scanner.netguard import is_public_ip

    assert is_public_ip(addr) is expected


@pytest.mark.asyncio
@pytest.mark.parametrize("host", [
    "localhost",
    "127.1",           # short form -> 127.0.0.1
    "2130706433",      # integer form -> 127.0.0.1
    "0x7f.1",          # hex form -> 127.0.0.1
    "[::1]",
    "169.254.169.254",
    "",
    "no-such-host.invalid",  # unresolvable: fail closed
])
async def test_host_is_public_blocks_internal(host):
    from pnakotic.src.scanner.netguard import host_is_public

    assert await host_is_public(host) is False


@pytest.mark.asyncio
async def test_host_is_public_allows_public_literal():
    from pnakotic.src.scanner.netguard import host_is_public

    assert await host_is_public("8.8.8.8") is True


@pytest.mark.asyncio
@pytest.mark.parametrize("url, expected", [
    ("data:text/html,hi", True),
    ("about:blank", True),
    ("blob:https://x.example/uuid", True),
    ("file:///etc/passwd", False),
    ("ftp://8.8.8.8/", False),
    ("http://8.8.8.8/", True),
    ("http://127.0.0.1:8000/", False),
    ("http://[::1]/", False),
    ("http://[not-an-ip/", False),  # urlparse ValueError
])
async def test_url_is_allowed(url, expected):
    from pnakotic.src.scanner.netguard import url_is_allowed

    assert await url_is_allowed(url) is expected


@pytest.mark.asyncio
async def test_resolve_public_addrs():
    from pnakotic.src.scanner.netguard import resolve_public_addrs

    assert await resolve_public_addrs("8.8.8.8") == ["8.8.8.8"]
    assert await resolve_public_addrs("localhost") is None
    assert await resolve_public_addrs("") is None
