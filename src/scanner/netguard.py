"""Egress guard: decide whether the scanner may contact a URL's host.

Used in three places:
  * the API rejects obviously internal targets up front (fast 400),
  * the engine checks browser HTTP requests (initial navigation, each redirect hop,
    subresources, iframes, dedicated-worker fetches) via CDP Fetch interception, and
  * egress_proxy.py enforces it on every connection the browser opens (WebSockets,
    SharedWorkers and everything else CDP cannot see), pinning the checked addresses.

A host is allowed only if every address it resolves to is globally routable.
Resolution goes through getaddrinfo, so hostnames (`localhost`, compose service
names like `db`), and alternate IPv4 spellings (`127.1`, `2130706433`, `0x7f.1`)
are all checked by the address they actually reach.
"""
import asyncio
import ipaddress
import socket
from typing import Awaitable, Callable, List, Optional
from urllib.parse import urlparse

HostCheck = Callable[[str], Awaitable[bool]]

# Schemes that never open a network connection.
LOCAL_SCHEMES = {"data", "blob", "about"}
NETWORK_SCHEMES = {"http", "https", "ws", "wss"}


def is_public_ip(addr: str) -> bool:
    ip = ipaddress.ip_address(addr.split("%", 1)[0])  # drop IPv6 zone id (fe80::1%eth0)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is 127.0.0.1
    # is_global excludes private, loopback, link-local, CGNAT, reserved, unspecified;
    # on Python < 3.11 it does not exclude multicast, so check that explicitly.
    return ip.is_global and not ip.is_multicast


async def resolve_addrs(host: str, port: Optional[int] = None) -> List[str]:
    """Every address `host` resolves to, deduplicated; empty if unresolvable."""
    host = (host or "").strip("[]")
    if not host:
        return []
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):  # socket.gaierror is an OSError
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


def all_public(addrs: List[str]) -> bool:
    """True for a non-empty list of public addresses (fails closed on unparsable ones)."""
    try:
        return bool(addrs) and all(is_public_ip(a) for a in addrs)
    except ValueError:
        return False


async def resolve_public_addrs(host: str) -> Optional[List[str]]:
    """Addresses `host` resolves to if every one is public, else None (also if unresolvable)."""
    addrs = await resolve_addrs(host)
    return addrs if all_public(addrs) else None


async def host_is_public(host: str) -> bool:
    """True only if `host` resolves and every resolved address is public."""
    return await resolve_public_addrs(host) is not None


async def url_is_allowed(url: str, host_allowed: HostCheck = host_is_public) -> bool:
    """Scheme + host check for a URL the browser is about to fetch."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        return False
    scheme = parsed.scheme.lower()
    if scheme in LOCAL_SCHEMES:
        return True
    if scheme not in NETWORK_SCHEMES or not host:
        return False
    return await host_allowed(host)
