"""Local SOCKS5 egress proxy: enforces the netguard policy on every connection Chromium opens.

CDP Fetch interception (EgressGuard) cannot see WebSockets or SharedWorker fetches, so
the browser is launched with this proxy as its only route out. Playwright's launch-level
SOCKS5 proxy also maps every hostname to NOTFOUND locally, so the name reaches the proxy,
which resolves it once, checks those exact addresses and connects to the first of them
(no second lookup, so DNS rebinding cannot swap the address after the check).
"""
import asyncio
import ipaddress
import struct
from typing import List, Optional, Set

from .netguard import HostCheck, all_public, host_is_public, resolve_addrs

REP_OK, REP_FAILURE, REP_NOT_ALLOWED, REP_CMD_UNSUPPORTED, REP_ATYP_UNSUPPORTED = 0, 1, 2, 7, 8
HANDSHAKE_TIMEOUT = 10  # seconds for the SOCKS handshake
CONNECT_TIMEOUT = 5     # seconds per upstream address; tried in order, so keep it short
IDLE_TIMEOUT = 120      # seconds without bytes in either direction before a tunnel is closed


class EgressProxy:
    def __init__(self, host_allowed: HostCheck = host_is_public):
        self.host_allowed = host_allowed
        self.blocked_hosts: List[str] = []
        self._server: Optional[asyncio.AbstractServer] = None
        self._tasks: Set[asyncio.Task] = set()

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._client, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        for task in list(self._tasks):  # open tunnels die with the scan
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        upstream = None  # (reader, writer) once the tunnel is open
        try:
            upstream = await self._handshake(reader, writer)
            if upstream is not None:
                up_reader, up_writer = upstream
                await asyncio.gather(self._pipe(reader, up_writer), self._pipe(up_reader, writer))
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            print(f"[egress-proxy] connection failed: {exc!r}")
        finally:
            self._tasks.discard(task)
            for w in (writer, upstream[1] if upstream else None):
                if w is not None:
                    w.close()

    async def _handshake(self, reader, writer):
        """Run SOCKS5 CONNECT; returns the upstream (reader, writer) once allowed, else None."""
        async def reply(rep: int) -> None:
            writer.write(struct.pack("!BBBBIH", 5, rep, 0, 1, 0, 0))
            await writer.drain()

        try:
            async def read_request():
                ver, nmethods = struct.unpack("!BB", await reader.readexactly(2))
                methods = await reader.readexactly(nmethods)
                if ver != 5 or 0 not in methods:
                    writer.write(b"\x05\xff")
                    return None
                writer.write(b"\x05\x00")
                ver, cmd, _, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
                if cmd != 1:
                    return REP_CMD_UNSUPPORTED
                if atyp == 1:
                    host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
                elif atyp == 4:
                    host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
                elif atyp == 3:
                    host = (await reader.readexactly((await reader.readexactly(1))[0])).decode("idna")
                else:
                    return REP_ATYP_UNSUPPORTED
                return host, struct.unpack("!H", await reader.readexactly(2))[0]

            request = await asyncio.wait_for(read_request(), HANDSHAKE_TIMEOUT)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, UnicodeError, ValueError, ConnectionError):
            return None  # malformed or stalled client
        if request is None:
            return None
        if isinstance(request, int):
            await reply(request)
            return None
        host, port = request

        addrs = await resolve_addrs(host, port)  # the only lookup: we connect to what we check
        try:
            # Identity check on purpose: only the unwrapped default policy takes the pinned
            # path. Wrapping it (partial, cache, decorator) would fall through to the
            # re-resolving branch below and silently lose rebinding protection.
            if self.host_allowed is host_is_public:
                allowed = all_public(addrs)
            else:  # injected test policy
                allowed = bool(addrs) and await self.host_allowed(host)
        except Exception as exc:
            print(f"[egress-proxy] check failed for {host!r}, blocking: {exc!r}")
            allowed = False
        if not allowed:
            if host not in self.blocked_hosts:
                self.blocked_hosts.append(host)
            await reply(REP_NOT_ALLOWED)
            return None
        # Every address in `addrs` passed the check, so trying them in order keeps the pin
        # while surviving an unreachable family (e.g. an AAAA record on a v4-only host).
        for addr in addrs:
            try:
                upstream = await asyncio.wait_for(asyncio.open_connection(addr, port), CONNECT_TIMEOUT)
                break
            except (OSError, asyncio.TimeoutError) as exc:
                print(f"[egress-proxy] connect to {host}:{port} via {addr} failed: {exc!r}")
        else:
            await reply(REP_FAILURE)
            return None
        await reply(REP_OK)
        return upstream

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        """Copy until EOF or idle timeout, then half-close so the other direction drains."""
        try:
            while True:
                data = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        finally:
            try:
                if dst.can_write_eof():
                    dst.write_eof()
                else:
                    dst.close()
            except Exception:
                pass
