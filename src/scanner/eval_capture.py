"""Code a page builds at runtime (``eval``, ``new Function``, an inserted inline ``<script>``),
captured through CDP ``Debugger.scriptParsed`` so YARA and the obfuscator markers can read it.

Skimmers unpack themselves this way: the file the page loads is a stub, and the code that
matters exists only after it has run. This module keeps the source of such scripts, bounded.

What Chromium 148 reports (observed with scratch pages against a local server, Debugger
enabled before navigation; ``hasSourceURL`` is false unless stated):

================================== ===================== ==============================================
script                             ``url``               ``stackTrace``
================================== ===================== ==============================================
the document's inline script       the document URL      none
a network script, ``<script src>``  its URL               none
an inline handler's own text       the document URL      none (the code it ``eval``s is a stage)
``eval(...)``                      ``""``                top frame = the calling page script
``new Function(...)``              ``""``                top frame = the calling page script
``eval`` ending in a sourceURL     the claimed URL       top frame = the calling page script
                                   (``hasSourceURL`` true)
inserted inline ``<script>``       ``""``                top frame = the inserting script
``setTimeout("code")``             ``""``                none
``setTimeout(eval, 0, "code")``    ``""``                none
``Promise.resolve(c).then(eval)``  ``""``                none
``setTimeout(Function, 0, "c")``   ``""``                none
``javascript:`` URL                ``""``                none
an ``eval`` inside a timer string  ``""``                top frame has an empty URL
================================== ===================== ==============================================

So ``url == ""`` or ``hasSourceURL`` selects every runtime-built script, with or without a
stack (a stage built from a timer or a promise has none, so ``caller`` is ``""`` for it, and
requiring a stack would give a loader a one-line bypass). The same selection also catches
everything Playwright injects into the page: its init scripts (ours included), its utility
script and wrapper, and every ``page.evaluate`` payload, in the main world and in an isolated
one. Those are told apart, not by a stack, but by what they are:

* a script in an isolated world (``executionContextAuxData.isDefault`` false) is Playwright's
  or a browser extension's: a page cannot create one;
* everything parsed *before* the capture is sealed is the harness. ``attach`` enables the
  debugger (which replays the init scripts of the blank page), runs a warm-up call so the
  utility script and the wrapper are parsed too, and records the ``hash`` of all of it. Later
  scripts with such a hash (the same init scripts in the real document and its frames, the
  wrapper at every call) are the harness, and so is any script whose top stack frame is one of
  them (a ``page.evaluate`` payload runs from the utility script). The page cannot get its code
  ignored this way without making it identical to the harness's own.

An inserted inline ``<script>`` (``s.text = ...; document.head.appendChild(s)``) is a stage: no
URL, and the stack of the code that built it. It is runtime-built code, so it is captured.
``Debugger.getScriptSource`` is called as soon as the event arrives (a script can be
garbage-collected before a later call: "No script for id"), as a background task, so the page
is never waited on; ``drain`` waits, bounded, for the calls still in flight.

Everything is page-supplied and bounded: ``MAX_STAGES`` stages, ``MAX_STAGE_CHARS`` characters
each (a longer one is cut, not dropped), ``MAX_STAGE_BYTES_TOTAL`` bytes in all; whatever does
not fit, or could not be read, is counted in ``dropped``. A ``debugger;`` loop cannot stall the
page: breakpoints are deactivated and any pause is resumed at once.
"""
import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

MAX_STAGES = 20
MAX_STAGE_CHARS = 200_000
MAX_STAGE_BYTES_TOTAL = 2_000_000
MAX_CALLER_CHARS = 300


@dataclass
class Stage:
    source: bytes
    caller_url: str  # the top frame of the stack that built it, or ""
    caller_line: Optional[int]  # 1-based


def _top_frame(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    stack = event.get("stackTrace")
    frames = stack.get("callFrames") if isinstance(stack, dict) else None
    if isinstance(frames, list) and frames and isinstance(frames[0], dict):
        return frames[0]
    return None


class EvalCapture:
    """Collects the source of scripts the page built at runtime (see the module docstring)."""

    def __init__(self) -> None:
        self.stages: List[Stage] = []
        self.dropped = 0
        self._accepted = 0  # stages kept or being fetched: the count budget
        self._bytes = 0
        self._sealed = False
        self._harness_hashes: Set[str] = set()  # what was parsed before attach() finished: not the page's
        self._harness_ids: Set[str] = set()
        self._tasks: Set["asyncio.Future[None]"] = set()
        self._cdp: Any = None

    async def attach(self, cdp: Any, warm_up: Optional[Callable[[], Awaitable[Any]]] = None) -> None:
        """Start listening. ``warm_up`` (optional) makes the harness parse the scripts it injects
        on first use (Playwright: any ``page.evaluate``), so they are known before the page runs."""
        self._cdp = cdp
        cdp.on("Debugger.scriptParsed", self._on_parsed)
        cdp.on("Debugger.paused", self._on_paused)
        try:
            await cdp.send("Debugger.enable")
            # A page can loop on `debugger;`: never stop for it, the load would wait for a resume.
            # Observed (Chromium 148): setSkipAllPauses alone does not stop a `debugger;` statement
            # from pausing the page, deactivating breakpoints does, and the paused handler is the
            # last line of defence. All three, since each costs nothing.
            await cdp.send("Debugger.setSkipAllPauses", {"skip": True})
            await cdp.send("Debugger.setBreakpointsActive", {"active": False})
        except Exception as exc:  # the scan is worth more than this signal
            print(f"[eval-capture] could not enable the debugger domain: {str(exc)[:200]}")
        try:
            if warm_up is not None:
                await warm_up()
            await cdp.send("Debugger.setSkipAllPauses", {"skip": True})  # a round trip: queued events arrive first
        except Exception as exc:
            print(f"[eval-capture] warm-up failed: {str(exc)[:200]}")
        self._sealed = True

    def _on_paused(self, _event: Dict[str, Any]) -> None:
        task = asyncio.ensure_future(self._resume())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _resume(self) -> None:
        try:
            await self._cdp.send("Debugger.resume")
        except Exception:
            pass  # the page is gone

    def _on_parsed(self, event: Dict[str, Any]) -> None:
        try:
            if not isinstance(event, dict):
                return
            script_id, digest = event.get("scriptId"), event.get("hash")
            if not isinstance(script_id, str):
                return
            if not self._sealed:  # before the page: the harness's own scripts
                if isinstance(digest, str):
                    self._harness_hashes.add(digest)
                self._harness_ids.add(script_id)
                return
            aux = event.get("executionContextAuxData")
            if isinstance(aux, dict) and aux.get("isDefault") is False:
                return  # an isolated world: Playwright's, never the page's
            if event.get("url") != "" and event.get("hasSourceURL") is not True:
                return  # a network script or the document's own inline script
            if isinstance(digest, str) and digest in self._harness_hashes:
                self._harness_ids.add(script_id)
                return  # the same script as one parsed before the page ran
            frame = _top_frame(event)
            if frame is not None and frame.get("scriptId") in self._harness_ids:
                return  # built by the harness (a page.evaluate payload)
            caller, line = "", None  # type: str, Optional[int]
            if frame is not None and isinstance(frame.get("url"), str):
                caller = frame["url"][:MAX_CALLER_CHARS]
                number = frame.get("lineNumber")
                line = number + 1 if isinstance(number, int) and not isinstance(number, bool) and number >= 0 else None
            if self._accepted >= MAX_STAGES:
                self.dropped += 1
                return
            self._accepted += 1
            task = asyncio.ensure_future(self._fetch(script_id, caller, line))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        except Exception as exc:  # an event handler must never raise into the CDP session
            print(f"[eval-capture] ignored an event: {str(exc)[:200]}")

    async def _fetch(self, script_id: str, caller: str, line: Optional[int]) -> None:
        try:
            reply = await self._cdp.send("Debugger.getScriptSource", {"scriptId": script_id})
            text = reply.get("scriptSource") if isinstance(reply, dict) else None
        except asyncio.CancelledError:
            self.dropped += 1  # drain() gave up on it
            raise
        except Exception:
            text = None  # collected before we asked, or the page is gone
        if not isinstance(text, str):
            self.dropped += 1
            return
        source = text[:MAX_STAGE_CHARS].encode("utf-8", "replace")
        if self._bytes + len(source) > MAX_STAGE_BYTES_TOTAL:
            self.dropped += 1
            return
        self._bytes += len(source)
        self.stages.append(Stage(source=source, caller_url=caller, caller_line=line))

    async def drain(self, timeout: float = 5.0) -> None:
        """Wait (bounded) for source fetches still in flight; call before the context closes."""
        pending = list(self._tasks)
        if pending:
            _done, still = await asyncio.wait(pending, timeout=timeout)
            for task in still:
                task.cancel()
