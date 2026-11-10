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
