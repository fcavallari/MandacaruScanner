"""EvalCapture's bookkeeping, driven by hand-made CDP events (no browser)."""
import pytest

OBF = ("function _0x34e5(){var _0x18b8=['a','b'];_0x34e5=function(){return _0x18b8;};return _0x34e5();}"
       "(function(_0x44e7,_0x5d16){var _0x7eb7=_0x44e7();while(!![]){try{break;}catch(_0x1){"
       "_0x7eb7['push'](_0x7eb7['shift']());}}}(_0x34e5,0x1));")


class FakeCdp:
    def __init__(self, sources):
        self.sources = sources
        self.handlers = {}
        self.fetched = []

    def on(self, name, handler):
        self.handlers[name] = handler

    async def send(self, method, params=None):
        if method == "Debugger.getScriptSource":
            self.fetched.append(params["scriptId"])
            return {"scriptSource": self.sources[params["scriptId"]]}
        return {}

    def parsed(self, script_id, digest, source=None, length=None, url="", **extra):
        if source is not None:
            self.sources[script_id] = source
        event = {"scriptId": script_id, "hash": digest, "url": url, "hasSourceURL": False,
                 "length": length if length is not None else len(self.sources.get(script_id, "")),
                 "executionContextAuxData": {"isDefault": True}}
        event.update(extra)
        self.handlers["Debugger.scriptParsed"](event)


async def _capture(cdp):
    from pnakotic.src.scanner.eval_capture import EvalCapture

    capture = EvalCapture()
    await capture.attach(cdp)
    return capture


@pytest.mark.asyncio
async def test_a_script_is_skipped_only_by_its_own_content_hash():
    from pnakotic.src.scanner.eval_capture import EvalCapture

    cdp = FakeCdp({})
    capture = EvalCapture()

    async def warm_up():  # parsed before the seal: the harness
        cdp.parsed("1", "harness-hash", "harness code")
    await capture.attach(cdp, warm_up=warm_up)
    cdp.parsed("2", "harness-hash", "harness code")  # the same content again: skipped
    # built by the harness, but its own content is new: a stage (the stack is not an excuse)
    cdp.parsed("3", "page-hash", "page payload",
               stackTrace={"callFrames": [{"scriptId": "1", "url": "", "lineNumber": 0, "functionName": "evaluate"}]})
    await capture.drain()
    assert [s.source for s in capture.stages] == [b"page payload"]
    assert capture.stages[0].caller_url == "" and capture.dropped == 0


@pytest.mark.asyncio
async def test_data_and_blob_scripts_are_stages_network_scripts_are_not():
    cdp = FakeCdp({})
    capture = await _capture(cdp)
    cdp.parsed("1", "h1", "a = 1", url="data:text/javascript,a = 1")
    cdp.parsed("2", "h2", "b = 2", url="blob:http://shop.test/1234")
    cdp.parsed("3", "h3", "c = 3", url="http://shop.test/app.js")
    await capture.drain()
    assert sorted(s.source for s in capture.stages) == [b"a = 1", b"b = 2"]


@pytest.mark.asyncio
async def test_repeats_take_no_slot_and_no_fetch():
    cdp = FakeCdp({})
    capture = await _capture(cdp)
    for i in range(5):
        cdp.parsed(str(i), "same", "return 1")
    await capture.drain()
    assert len(capture.stages) == 1 and capture.repeated == 4 and cdp.fetched == ["0"]


@pytest.mark.asyncio
async def test_an_oversized_script_is_recorded_but_never_fetched():
    from pnakotic.src.scanner.eval_capture import MAX_STAGE_FETCH_CHARS
    from pnakotic.src.scanner.engine import _eval_stage_entry

    cdp = FakeCdp({})
    capture = await _capture(cdp)
    cdp.parsed("1", "big", length=MAX_STAGE_FETCH_CHARS + 1)
    await capture.drain()
    assert cdp.fetched == []
    [stage] = capture.stages
    assert stage.oversized and stage.source == b"" and stage.length == MAX_STAGE_FETCH_CHARS + 1
    entry = _eval_stage_entry(stage)
    assert entry["oversized"] is True and entry["length"] == MAX_STAGE_FETCH_CHARS + 1
    assert entry["markers"] == [] and entry["yara_matched"] is False


@pytest.mark.asyncio
async def test_at_most_100_sources_are_read_and_the_rest_counted():
    from pnakotic.src.scanner.eval_capture import MAX_STAGE_FETCHES, MAX_STAGES

    cdp = FakeCdp({})
    capture = await _capture(cdp)
    for i in range(MAX_STAGE_FETCHES + 50):
        cdp.parsed(str(i), f"h{i}", f"return {i}")
    await capture.drain()
    assert len(cdp.fetched) == MAX_STAGE_FETCHES
    assert len(capture.stages) == MAX_STAGES and capture.dropped == MAX_STAGE_FETCHES + 50 - MAX_STAGES


@pytest.mark.asyncio
async def test_a_marked_stage_replaces_an_unmarked_one_when_full_and_an_unmarked_one_does_not():
    from pnakotic.src.scanner.eval_capture import MAX_STAGES

    cdp = FakeCdp({})
    capture = await _capture(cdp)
    for i in range(MAX_STAGES):
        cdp.parsed(str(i), f"h{i}", f"return {i}")
    cdp.parsed("late-plain", "hp", "return 'late'")
    cdp.parsed("late-marked", "hm", OBF)
    await capture.drain()
    assert len(capture.stages) == MAX_STAGES and capture.dropped == 2
    assert [s.markers for s in capture.stages].count(["string_array_rotation"]) == 1
    assert b"return 'late'" not in [s.source for s in capture.stages]
    # a second marked stage replaces another unmarked one; a marked one is never replaced
    cdp.parsed("late-marked-2", "hm2", OBF + " ")
    await capture.drain()
    assert sum(1 for s in capture.stages if s.markers) == 2 and capture.dropped == 3


@pytest.mark.asyncio
async def test_a_stage_that_cannot_be_read_is_counted():
    cdp = FakeCdp({})
    capture = await _capture(cdp)
    cdp.parsed("gone", "hg", length=10)  # no source known: the fake raises KeyError like "No script for id"
    await capture.drain()
    assert capture.stages == [] and capture.dropped == 1


@pytest.mark.asyncio
async def test_parse_positions_are_none_when_they_cannot_be_trusted():
    """positions_at: the start of every page-world script with a URL, by hash; None when the
    record overflowed or the debugger domain never came on (then no page-URL frame can be checked)."""
    from pnakotic.src.scanner.eval_capture import MAX_POSITIONS, EvalCapture

    cdp = FakeCdp({})
    capture = await _capture(cdp)
    cdp.parsed("1", "h1", "x", url="https://s.com/p#a", startLine=3, startColumn=8)
    cdp.parsed("2", "h2", "x", url="https://s.com/other.js", startLine=0, startColumn=0)
    assert capture.positions_at("https://s.com/p") == {"h1": {(3, 8)}}
    for i in range(MAX_POSITIONS):
        cdp.parsed(str(10 + i), "h", "x", url="https://s.com/p", startLine=i, startColumn=0)
    assert capture.positions_at("https://s.com/p") is None

    class FailingCdp(FakeCdp):
        async def send(self, method, params=None):
            if method == "Debugger.enable":
                raise RuntimeError("no debugger")
            return await super().send(method, params)

    failing = FailingCdp({})
    capture = EvalCapture()
    await capture.attach(failing)
    assert capture.positions_at("https://s.com/p") is None


@pytest.mark.asyncio
async def test_a_source_url_block_is_recorded_at_the_document_that_embeds_it():
    """Chromium 148 reports a served block ending in ``//# sourceURL=<name>`` with ``url`` the
    name and ``embedderName`` the document URL, which is also what ``CallSite.getFileName`` gives
    its frames: its start is recorded at that document. A runtime script naming itself has an
    empty ``embedderName``: its start counts at every document, so a copy of a served block
    makes that hash untrusted."""
    cdp = FakeCdp({})
    capture = await _capture(cdp)
    page = "https://s.com/checkout/"
    loader = "https://s.com/wp-includes/js/wp-emoji-loader.min.js"
    cdp.parsed("1", "hb", "x", url="wc-checkout-js-extra", hasSourceURL=True, embedderName=page + "#x",
               startLine=4, startColumn=36)
    # a module whose sourceURL names a file: still the document's
    cdp.parsed("2", "hm", "x", url=loader, hasSourceURL=True, embedderName=page, startLine=9, startColumn=22)
    # a network file with a sourceURL: its own URL's
    cdp.parsed("3", "hn", "x", url="net-x", hasSourceURL=True, embedderName="https://s.com/app.js",
               startLine=0, startColumn=0)
    assert capture.positions_at(page) == {"hb": {(4, 36)}, "hm": {(9, 22)}}
    assert capture.positions_at(loader) == {}
    assert capture.positions_at("https://s.com/app.js") == {"hn": {(0, 0)}}
    # an eval of the block's exact text, and an eval naming itself after the page: no embedder
    cdp.parsed("4", "hb", "x", url="wc-checkout-js-extra", hasSourceURL=True, embedderName="",
               startLine=0, startColumn=0)
    cdp.parsed("5", "he", "x", url=page, hasSourceURL=True, embedderName="", startLine=0, startColumn=0)
    # a runtime script without a sourceURL has no file name in its frames either: not recorded
    cdp.parsed("6", "hr", "x", url="", embedderName="", startLine=0, startColumn=0)
    assert capture.positions_at(page) == {"hb": {(4, 36), (0, 0)}, "hm": {(9, 22)}, "he": {(0, 0)}}
    assert capture.positions_at("https://s.com/app.js") == {"hn": {(0, 0)}, "hb": {(0, 0)}, "he": {(0, 0)}}


@pytest.mark.asyncio
async def test_a_source_url_makes_a_stage_only_of_a_script_no_document_or_file_embeds():
    """A served block or a network file that ends in a sourceURL comment is not runtime-built; code
    built at runtime (no embedder) is, whatever it calls itself, and so is a blob: script or a
    script in a document the page wrote itself. Without ``embedderName`` (an older browser) every
    sourceURL script is a stage, as before."""
    cdp = FakeCdp({})
    capture = await _capture(cdp)
    sx = {"hasSourceURL": True}
    cdp.parsed("1", "h1", "served", url="wc-checkout-js-extra", embedderName="https://s.com/p", **sx)
    cdp.parsed("2", "h2", "network", url="net-x", embedderName="https://s.com/app.js", **sx)
    cdp.parsed("3", "h3", "eval", url="https://s.com/p", embedderName="", **sx)
    cdp.parsed("4", "h4", "blob", url="blob-x", embedderName="blob:https://s.com/1234", **sx)
    cdp.parsed("5", "h5", "srcdoc", url="srcdoc-x", embedderName="about:srcdoc", **sx)
    cdp.parsed("6", "h6", "older", url="name-x", **sx)
    await capture.drain()
    assert sorted(s.source for s in capture.stages) == [b"blob", b"eval", b"older", b"srcdoc"]


def _stage_event(script_id, digest, length="omit"):
    """A runtime stage's scriptParsed event; ``length`` "omit" leaves the field out."""
    event = {"scriptId": script_id, "hash": digest, "url": "", "hasSourceURL": False,
             "executionContextAuxData": {"isDefault": True}}
    if length != "omit":
        event["length"] = length
    return event


@pytest.mark.asyncio
async def test_sources_are_read_only_within_a_per_load_character_budget():
    """Six hostile loads at once each reading 100 sources of 2 000 000 characters took the worker
    past 1 GB: the characters read per load are budgeted by each event's ``length``, before the
    read. A stage over the budget is counted and not read; a smaller later one can still fit."""
    from pnakotic.src.scanner.eval_capture import MAX_STAGE_FETCH_CHARS, MAX_STAGE_FETCH_TOTAL_CHARS

    assert MAX_STAGE_FETCH_TOTAL_CHARS == 10_000_000
    cdp = FakeCdp({})
    capture = await _capture(cdp)
    size = 1_500_000  # under MAX_STAGE_FETCH_CHARS, so each is read, not recorded as oversized
    assert size <= MAX_STAGE_FETCH_CHARS
    for i in range(10):
        cdp.parsed(str(i), f"h{i}", f"return {i}", length=size)  # the source is small; the claim is what counts
    cdp.parsed("small", "hs", "return 's'", length=1_000)  # 6 * 1.5M + 1 000 still fits
    cdp.parsed("edge", "he", "return 'e'", length=MAX_STAGE_FETCH_TOTAL_CHARS - 6 * size - 1_000 + 1)
    await capture.drain()
    assert cdp.fetched == [str(i) for i in range(6)] + ["small"]
    assert len(capture.stages) == 7 and capture.dropped == 4 + 1


@pytest.mark.asyncio
async def test_a_stage_without_a_usable_length_is_counted_and_never_read():
    cdp = FakeCdp({"1": "a", "2": "b", "3": "c", "4": "d", "5": "e"})
    capture = await _capture(cdp)
    handler = cdp.handlers["Debugger.scriptParsed"]
    for script_id, length in (("1", "omit"), ("2", None), ("3", "12"), ("4", True), ("5", -1)):
        handler(_stage_event(script_id, "h" + script_id, length))
    await capture.drain()
    assert cdp.fetched == [] and capture.stages == [] and capture.dropped == 5


class SlowCdp(FakeCdp):
    """getScriptSource yields until released, recording how many reads were in flight at once."""

    def __init__(self, sources):
        super().__init__(sources)
        import asyncio
        self.release = asyncio.Event()
        self.in_flight = 0
        self.most = 0

    async def send(self, method, params=None):
        if method != "Debugger.getScriptSource":
            return {}
        self.in_flight += 1
        self.most = max(self.most, self.in_flight)
        try:
            await self.release.wait()
            return await super().send(method, params)
        finally:
            self.in_flight -= 1


@pytest.mark.asyncio
async def test_at_most_4_sources_are_read_at_once():
    import asyncio

    from pnakotic.src.scanner.eval_capture import MAX_FETCHES_IN_FLIGHT

    assert MAX_FETCHES_IN_FLIGHT == 4
    cdp = SlowCdp({})
    capture = await _capture(cdp)
    for i in range(10):
        cdp.parsed(str(i), f"h{i}", f"return {i}")
    for _ in range(20):
        await asyncio.sleep(0)
    assert cdp.in_flight == 4
    cdp.release.set()
    await capture.drain()
    assert cdp.most == 4 and len(cdp.fetched) == 10 and len(capture.stages) == 10 and capture.dropped == 0


@pytest.mark.asyncio
async def test_reads_still_queued_when_drain_gives_up_are_counted():
    cdp = SlowCdp({})
    capture = await _capture(cdp)
    for i in range(10):
        cdp.parsed(str(i), f"h{i}", f"return {i}")
    await capture.drain(timeout=0.05)  # never released: 4 in flight and 6 waiting are all cancelled
    assert capture.stages == [] and capture.dropped == 10
