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
requiring a stack would give a loader a one-line bypass). ``data:`` and ``blob:`` URLs are
selected too: such a script has a URL, no sourceURL and no stack, and the page made it up.

The same selection also catches everything Playwright injects into the page: its init scripts
(ours included), its utility script and wrapper, and every ``page.evaluate`` payload, in the
main world and in an isolated one. Those are told apart by content alone:

* a script in an isolated world (``executionContextAuxData.isDefault`` false) is Playwright's
  or a browser extension's: a page cannot create one;
* the harness set is the CDP ``hash`` of everything parsed before the capture is sealed.
  ``attach`` enables the debugger (which replays the init scripts of the blank page), runs a
  warm-up that the caller builds from every main-world ``evaluate`` the engine will make (so the
  utility script, the wrapper and those payloads are parsed once) and records the hashes. A later
  script is skipped only when its own hash is in that set.

Nothing else excuses a script: not the stack it was built from, not being built by a harness
script. A page can copy Playwright's utility script and call it, or point ``String`` at ``eval``
and let a hook call it; what such code builds is still a stage. The only code a page can get
ignored is code byte-identical to one of the harness's own scripts.

An inserted inline ``<script>`` (``s.text = ...; document.head.appendChild(s)``) is a stage: no
URL, and the stack of the code that built it. It is runtime-built code, so it is captured.
``Debugger.getScriptSource`` is called as soon as the event arrives (a script can be
garbage-collected before a later call: "No script for id"), as a background task, so the page
is never waited on; ``drain`` waits, bounded, for the calls still in flight.

Everything is page-supplied and bounded: ``MAX_STAGES`` stages, ``MAX_STAGE_CHARS`` characters
each (a longer one is cut, not dropped), ``MAX_STAGE_BYTES_TOTAL`` bytes in all; whatever does
not fit, or could not be read, is counted in ``dropped``. A stage that repeats one already seen
(same ``hash``) takes no slot and is counted in ``repeated``. At most ``MAX_STAGE_FETCHES`` sources
are read per load, and none above ``MAX_STAGE_FETCH_CHARS`` characters (that stage is recorded
without source, ``oversized``). Once the slots are full, a stage with obfuscator markers replaces
a kept one that has none, so junk cannot crowd the payload out. A ``debugger;`` loop cannot stall the
page: breakpoints are deactivated and any pause is resumed at once.
"""
import asyncio
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urldefrag

from .obfuscation import obfuscator_markers

MAX_STAGES = 20
MAX_STAGE_CHARS = 200_000
MAX_STAGE_BYTES_TOTAL = 2_000_000
MAX_CALLER_CHARS = 300
MAX_STAGE_FETCHES = 100  # sources read per load
MAX_STAGE_FETCH_CHARS = 2_000_000  # a longer script is not read at all
MAX_TRACKED_HASHES = 10_000  # distinct stage hashes remembered for the repeat count
MAX_POSITIONS = 2_000  # (url, hash, start) entries kept for code_origin; beyond that, none counts


@dataclass
class Stage:
    source: bytes  # b"" for an oversized stage
    caller_url: str  # the top frame of the stack that built it, or ""
    caller_line: Optional[int]  # 1-based
    markers: List[str] = field(default_factory=list)  # obfuscator markers of the source
    oversized: bool = False  # longer than MAX_STAGE_FETCH_CHARS: never read
    length: int = 0  # characters, for an oversized stage


def _top_frame(event: Dict[str, Any], harness_ids: Set[str]) -> Optional[Dict[str, Any]]:
    """The top frame of the stack that built the script, passing over frames of the harness's
    own scripts (the card hooks wrap appendChild, so an inserted inline script compiles inside
    our wrapper). Chromium 148 gives scriptParsed only the top frame, so such a stage then has
    no caller rather than our hook's line."""
    stack = event.get("stackTrace")
    frames = stack.get("callFrames") if isinstance(stack, dict) else None
    if isinstance(frames, list):
        for frame in frames[:50]:
            if isinstance(frame, dict) and frame.get("scriptId") not in harness_ids:
                return frame
    return None


class EvalCapture:
    """Collects the source of scripts the page built at runtime (see the module docstring)."""

    def __init__(self) -> None:
        self.stages: List[Stage] = []
        self.dropped = 0
        self.repeated = 0
        self._fetches = 0
        self._bytes = 0
        self._sealed = False
        self._harness_hashes: Set[str] = set()  # what was parsed before attach() finished: not the page's
        # CDP script ids of the harness's scripts in every document (our hook scripts are parsed again
        # in each one): ScriptTracer passes over their frames, so a loader's appendChild going
        # through our hooks is still the loader's
        self.harness_script_ids: Set[str] = set()
        # where every page-world script with a URL started, by (URL, hash): code_origin trusts a
        # served inline block's hash only when every script with it starts at a served block
        self._positions: Dict[Tuple[str, str], Set[Tuple[int, int]]] = {}
        self._position_count = 0
        self.positions_dropped = 0
        self.debugger_on = False  # Debugger.enable succeeded: without it there is no parse record
        self._seen: Set[str] = set()  # hashes of stages already met
        self._tasks: Set["asyncio.Future[None]"] = set()
        self._cdp: Any = None

    async def attach(self, cdp: Any, warm_up: Optional[Callable[[], Awaitable[Any]]] = None) -> None:
        """Start listening. ``warm_up`` (optional) makes the harness parse everything it will inject
        or evaluate later (Playwright: the utility script and each main-world ``evaluate`` payload),
        so those are known by content before the page runs."""
        self._cdp = cdp
        cdp.on("Debugger.scriptParsed", self._on_parsed)
        cdp.on("Debugger.paused", self._on_paused)
        try:
            await cdp.send("Debugger.enable")
            self.debugger_on = True
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

    def _note_position(self, event: Dict[str, Any]) -> None:
        url, digest = event.get("url"), event.get("hash")
        line, column = event.get("startLine"), event.get("startColumn")
        if not (isinstance(url, str) and url.startswith(("http://", "https://")) and isinstance(digest, str)):
            return
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (line, column)):
            return
        key = (urldefrag(url)[0][:2048], digest[:128])
        where = self._positions.get(key)
        if where is not None and (line, column) in where:
            return
        if self._position_count >= MAX_POSITIONS:
            self.positions_dropped += 1
            return
        self._position_count += 1
        self._positions.setdefault(key, set()).add((line, column))

    def positions_at(self, url: str) -> Optional[Dict[str, Set[Tuple[int, int]]]]:
        """``{hash: {(startLine, startColumn)}}`` of the page-world scripts parsed at ``url``
        (fragment ignored), or None when there is no complete record: the record overflowed, or
        ``Debugger.enable`` failed (then nothing can be trusted, and ``card_watch.summarize``
        says page-URL frames couldn't be checked)."""
        if self.positions_dropped or not self.debugger_on:
            return None
        page = urldefrag(url or "")[0][:2048]
        return {digest: set(where) for (at, digest), where in self._positions.items() if at == page}

    def _note_harness(self, script_id: str) -> None:
        if len(self.harness_script_ids) < MAX_TRACKED_HASHES:
            self.harness_script_ids.add(script_id)

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
                self._note_harness(script_id)
                return
            aux = event.get("executionContextAuxData")
            if isinstance(aux, dict) and aux.get("isDefault") is False:
                return  # an isolated world: Playwright's, never the page's
            self._note_position(event)
            url = event.get("url")
            if not (url == "" or event.get("hasSourceURL") is True
                    or (isinstance(url, str) and url.startswith(("data:", "blob:")))):
                return  # a network script or the document's own inline script
            if isinstance(digest, str):
                if digest in self._harness_hashes:
                    self._note_harness(script_id)
                    return  # the same script as one parsed before the page ran
                if digest in self._seen:
                    self.repeated += 1  # the same code again: no slot, no fetch
                    return
                if len(self._seen) < MAX_TRACKED_HASHES:
                    self._seen.add(digest)
            frame = _top_frame(event, self.harness_script_ids)
            caller, line = "", None  # type: str, Optional[int]
            if frame is not None and isinstance(frame.get("url"), str):
                caller = frame["url"][:MAX_CALLER_CHARS]
                number = frame.get("lineNumber")
                line = number + 1 if isinstance(number, int) and not isinstance(number, bool) and number >= 0 else None
            length = event.get("length")
            if isinstance(length, int) and not isinstance(length, bool) and length > MAX_STAGE_FETCH_CHARS:
                self._keep(Stage(source=b"", caller_url=caller, caller_line=line, oversized=True, length=length))
                return
            if self._fetches >= MAX_STAGE_FETCHES:
                self.dropped += 1
                return
            self._fetches += 1
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
        text = text[:MAX_STAGE_CHARS]
        self._keep(Stage(source=text.encode("utf-8", "replace"), caller_url=caller, caller_line=line,
                         markers=obfuscator_markers(text)))

    def _keep(self, stage: Stage) -> None:
        """Take a slot for ``stage``, or, when the slots are gone, let a stage with obfuscator
        markers replace one without (the replaced one is counted as dropped)."""
        size = len(stage.source)
        if len(self.stages) < MAX_STAGES and self._bytes + size <= MAX_STAGE_BYTES_TOTAL:
            self.stages.append(stage)
            self._bytes += size
            return
        if stage.markers:
            for i, kept in enumerate(self.stages):
                if not kept.markers and self._bytes - len(kept.source) + size <= MAX_STAGE_BYTES_TOTAL:
                    self._bytes += size - len(kept.source)
                    self.stages[i] = stage
                    self.dropped += 1
                    return
        self.dropped += 1

    async def drain(self, timeout: float = 5.0) -> None:
        """Wait (bounded) for source fetches still in flight; call before the context closes."""
        pending = list(self._tasks)
        if pending:
            _done, still = await asyncio.wait(pending, timeout=timeout)
            for task in still:
                task.cancel()
