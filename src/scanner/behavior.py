"""What the landing page tries to do to the visitor, recorded while it runs.

Malvertising payloads are actions, not markup: a ClickFix page writes a shell command to
the clipboard, a drive-by page starts a download, a tech-support scam locks the browser
(fullscreen, keyboard lock, beforeunload trap, history stuffing, dialog loops). The
engine clicks once, on an empty spot after the landing is captured (its click probe);
events after that click carry trigger="click".

Page-side hooks are installed with an init script in every document and frame before any
page script runs. They report through a Playwright binding with a random per-scan name
that the init script removes from `window` right away, and wrapped functions keep their
native `toString()`, so a page can't trivially see that it is being watched. Dialogs and
downloads are observed from Playwright. Everything that crosses the binding is
attacker-controlled: only known event ids are kept, strings are truncated and the number
of events is capped. A page forging events can only raise its own score.
"""
import asyncio
import json
import re
import secrets
from typing import Any, Dict, List, Optional

from .models import RedirectHop

# Hop mechanism for every recorded behavior. Not a redirect (see REDIRECT_MECHANISMS).
BEHAVIOR_MECHANISM = "page_behavior"

# Event ids a page-side hook may report (anything else is dropped).
PAGE_EVENTS = {
    "clipboard_write",       # navigator.clipboard.writeText/write, execCommand('copy'), copy-event setData
    "fullscreen_request",    # Element.requestFullscreen (and the webkit alias)
    "keyboard_lock",         # navigator.keyboard.lock
    "notification_request",  # Notification.requestPermission
    "beforeunload_trap",     # a beforeunload handler was installed
    "history_flood",         # HISTORY_FLOOD_CALLS pushState calls in one document (the back-button trap;
                             # replaceState is left out: infinite-scroll pages call it constantly)
}
# window.open is not hooked here: the engine records every popup attempt from CDP
# (Page.windowOpen -> "popup_open"), which the page can't observe or forge.
# Recorded from Playwright, not from the page.
HOST_EVENTS = {"dialog", "download"}

# Behaviors that together make the tech-support-scam "browser lock". Two distinct ones are decisive.
LOCK_BEHAVIORS = {"fullscreen_request", "keyboard_lock", "beforeunload_trap", "history_flood", "dialog_flood"}
# This many alert/confirm/prompt dialogs in one scan count as a dialog loop.
DIALOG_FLOOD_COUNT = 3
HISTORY_FLOOD_CALLS = 10

MAX_EVENTS = 100      # per scan
MAX_PER_ID = 10       # per event id, so one noisy hook can't crowd out the others
MAX_TEXT = 300        # characters kept from any page-supplied string

# Downloads of these types are decisive: an installer, script or app nobody clicked for.
EXECUTABLE_EXTENSIONS = {
    "exe", "msi", "msix", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse",
    "wsf", "hta", "lnk", "jar", "apk", "xapk", "dmg", "pkg", "app", "iso", "img", "vhd", "vhdx",
    "appx", "appxbundle", "sh", "command", "deb", "rpm",
}

# A clipboard write that looks like a command for Win+R, a terminal or Run box (ClickFix).
# Bounded and linear: the text is already truncated to MAX_TEXT.
CLIPBOARD_COMMAND = re.compile(
    r"\b(?:powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|msiexec|"
    r"conhost|osascript|iex|invoke-expression|invoke-webrequest|iwr|start-process)\b"
    r"|\bcmd(?:\.exe)?\s{1,5}/[ck]\b"
    r"|\b(?:curl|wget)\b[^\n]{0,200}\|\s{0,5}(?:ba|z)?sh\b"
    r"|\bbase64\s{1,5}(?:-d|--decode)\b",
    re.IGNORECASE,
)

# The stealth prelude every hook script shares (behavior.py and card_watch.py). It runs inside
# the hook script's own function scope, right after the binding is taken and deleted, and defines:
#   nativeText   WeakMap: replacement function -> the native source text its toString() shows
#   fnToString   Function.prototype.toString as it was when the script ran
#   wrap(owner, key, before, nest)
#                replaces owner[key] with a function that calls before(...) (errors swallowed),
#                then the original; toString() and name stay native. Returns the wrapper (or
#                undefined), so a hook can cut its own frames off a stack with captureStackTrace.
#                With `nest` (an object), nest.depth counts the wrappers running the original
#                right now: page code the original runs (an inserted script, a custom element's
#                callback) has that many of our frames under it.
# Function.prototype.toString is patched to read nativeText. Each hook script installs its own
# prelude, so with two scripts the second patch delegates to the first and both stay native.
# Calls go through Reflect.apply saved here, so a page that redefines Function.prototype.apply
# neither sees nor breaks them. No "%" in here: _INIT_TEMPLATE is %-formatted.
HOOK_PRELUDE = r"""
  const nativeText = new WeakMap();
  const fnToString = Function.prototype.toString;
  const rApply = Reflect.apply;
  const patchedToString = function toString() {
    return nativeText.has(this) ? nativeText.get(this) : rApply(fnToString, this, []);
  };
  nativeText.set(patchedToString, rApply(fnToString, fnToString, []));
  Function.prototype.toString = patchedToString;

  const wrap = (owner, key, before, nest) => {
    if (!owner) return undefined;
    const orig = owner[key];
    if (typeof orig !== 'function') return undefined;
    const wrapped = function () {
      try { rApply(before, this, arguments); } catch (e) {}
      if (!nest) return rApply(orig, this, arguments);
      nest.depth += 1;
      try { return rApply(orig, this, arguments); } finally { nest.depth -= 1; }
    };
    nativeText.set(wrapped, rApply(fnToString, orig, []));
    try { Object.defineProperty(wrapped, 'name', { value: orig.name }); } catch (e) {}
    try { owner[key] = wrapped; } catch (e) {}
    return wrapped;
  };
"""

# The binding name is substituted in at runtime; the script must never run twice per document.
_INIT_TEMPLATE = r"""
(() => {
  const send = window[%(name)s];
  if (typeof send !== 'function') return;
  try { delete window[%(name)s]; } catch (e) {}
""" + HOOK_PRELUDE + r"""
  const report = (id, detail) => {
    try { send(Object.assign({ id: id }, detail || {})); } catch (e) {}
  };
  const str = (v) => { try { return String(v).slice(0, %(max_text)d); } catch (e) { return ''; } };

  // Clipboard: record the attempt before delegating (writes without a user gesture fail).
  if (window.Clipboard) {
    wrap(Clipboard.prototype, 'writeText', function (t) { report('clipboard_write', { via: 'writeText', text: str(t) }); });
    wrap(Clipboard.prototype, 'write', function () { report('clipboard_write', { via: 'write', text: '' }); });
  }
  wrap(Document.prototype, 'execCommand', function (cmd) {
    if (str(cmd).toLowerCase() !== 'copy') return;
    const el = document.activeElement;
    let text = '';
    try { text = (el && 'value' in el && el.value) ? el.value : String(getSelection()); } catch (e) {}
    report('clipboard_write', { via: 'execCommand', text: str(text) });
  });
  if (window.DataTransfer) {
    wrap(DataTransfer.prototype, 'setData', function (fmt, data) {
      report('clipboard_write', { via: 'setData', text: str(data) });
    });
  }

  wrap(Element.prototype, 'requestFullscreen', function () { report('fullscreen_request'); });
  wrap(Element.prototype, 'webkitRequestFullscreen', function () { report('fullscreen_request'); });
  wrap(Element.prototype, 'webkitRequestFullScreen', function () { report('fullscreen_request'); });
  if (window.Keyboard) wrap(Keyboard.prototype, 'lock', function () { report('keyboard_lock'); });
  if (window.Notification) wrap(Notification, 'requestPermission', function () { report('notification_request'); });

  wrap(EventTarget.prototype, 'addEventListener', function (type) {
    if (this === window && str(type).toLowerCase() === 'beforeunload') report('beforeunload_trap', { via: 'addEventListener' });
  });
  const obu = Object.getOwnPropertyDescriptor(Window.prototype, 'onbeforeunload')
           || Object.getOwnPropertyDescriptor(window, 'onbeforeunload');
  if (obu && obu.set && obu.configurable) {
    const setter = obu.set;
    const patched = function (v) {
      if (typeof v === 'function') report('beforeunload_trap', { via: 'onbeforeunload' });
      return setter.call(this, v);
    };
    nativeText.set(patched, rApply(fnToString, setter, []));
    try { Object.defineProperty(window, 'onbeforeunload', { get: obu.get, set: patched, configurable: true }); } catch (e) {}
  }

  let historyCalls = 0;
  const onHistory = function () {
    historyCalls += 1;
    if (historyCalls === %(history_flood)d) report('history_flood', { calls: historyCalls });
  };
  wrap(History.prototype, 'pushState', onHistory);
})();
"""


def _short(value: Any) -> str:
    return str(value).replace("\x00", "")[:MAX_TEXT]


def _extension(filename: str) -> str:
    name = filename.lower().rstrip(". ")
    return name.rsplit(".", 1)[-1] if "." in name else ""


def is_command(text: str) -> bool:
    return bool(text) and bool(CLIPBOARD_COMMAND.search(text[:MAX_TEXT]))


def is_executable(filename: str) -> bool:
    return _extension(filename) in EXECUTABLE_EXTENSIONS


class BehaviorRecorder:
    """Collects behavior events for one scan; `attach()` before `new_page()`, `watch()` after."""

    def __init__(self):
        self.binding = "__" + secrets.token_hex(8)
        self.events: List[Dict[str, Any]] = []
        self._per_id: Dict[str, int] = {}
        self.dialogs = 0
        # "load" until the engine's click probe, then "click": a clipboard write or download
        # right after a click is what a visitor's own click would have set off.
        self.trigger = "load"

    async def attach(self, ctx) -> None:
        await ctx.expose_binding(self.binding, self._on_page_event)
        await ctx.add_init_script(_INIT_TEMPLATE % {
            "name": json.dumps(self.binding),
            "max_text": MAX_TEXT,
            "history_flood": HISTORY_FLOOD_CALLS,
        })

    async def warm_up(self, page, wait_s: float = 2.0) -> None:
        """Fire one hook on the blank page and forget the event it records.

        A binding call makes Playwright run its delivery script in the page's main world
        (`arg => ...deliverBindingResult(arg)`), a script no other call parses. Running it once
        before the page's own code lets EvalCapture know it by content (the script does not
        depend on the binding's name, so this covers any recorder's binding).
        """
        before, per_id = len(self.events), dict(self._per_id)
        try:
            await page.evaluate("document.execCommand('copy')")
            waited = 0.0
            while len(self.events) == before and waited < wait_s:
                await asyncio.sleep(0.02)
                waited += 0.02
            await asyncio.sleep(0.05)  # the delivery script runs just after the handler returns
        finally:
            del self.events[before:]
            self._per_id = per_id

    def watch(self, page) -> None:
        page.on("dialog", self._on_dialog)
        page.on("download", self._on_download)

    # ---------- recording ----------

    def _record(self, event_id: str, url: str, detail: Dict[str, Any]) -> None:
        if len(self.events) >= MAX_EVENTS or self._per_id.get(event_id, 0) >= MAX_PER_ID:
            return
        self._per_id[event_id] = self._per_id.get(event_id, 0) + 1
        self.events.append({"id": event_id, "url": _short(url), "trigger": self.trigger, **detail})

    def _on_page_event(self, source: Dict[str, Any], payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        event_id = payload.get("id")
        if event_id not in PAGE_EVENTS:
            return
        frame = source.get("frame") if isinstance(source, dict) else None
        url = getattr(frame, "url", "") or ""
        page = source.get("page") if isinstance(source, dict) else None
        main = bool(page is not None and frame is not None and frame == page.main_frame)
        detail: Dict[str, Any] = {"main_frame": main}
        for key in ("via", "text"):
            if key in payload:
                detail[key] = _short(payload[key])
        if isinstance(payload.get("calls"), int) and not isinstance(payload.get("calls"), bool):
            detail["calls"] = payload["calls"]
        if event_id == "clipboard_write":
            detail["command"] = is_command(detail.get("text", ""))
        self._record(event_id, url, detail)

    async def _on_dialog(self, dialog) -> None:
        # A listener means Playwright no longer auto-dismisses: dismiss every one, or the page hangs.
        try:
            self.dialogs += 1
            self._record("dialog", getattr(dialog.page, "url", "") if dialog.page else "",
                         {"type": _short(dialog.type), "text": _short(dialog.message)})
        finally:
            try:
                await dialog.dismiss()
            except Exception:
                pass  # page already closed

    async def _on_download(self, download) -> None:
        # Never keep the file: record what was offered, then abort the transfer.
        try:
            name = _short(download.suggested_filename or "")
            self._record("download", _short(download.url), {
                "filename": name, "executable": is_executable(name), "page": _short(download.page.url),
            })
        finally:
            try:
                await download.cancel()
            except Exception:
                pass

    # ---------- output ----------

    def hops(self) -> List[RedirectHop]:
        out = []
        for event in self.events:
            out.append(RedirectHop(
                url=event.get("page") or event.get("url") or "",
                mechanism=BEHAVIOR_MECHANISM,
                evidence=json.dumps(event),
            ))
        if self.dialogs >= DIALOG_FLOOD_COUNT:
            out.append(RedirectHop(
                url=next((e["url"] for e in self.events if e["id"] == "dialog"), ""),
                mechanism=BEHAVIOR_MECHANISM,
                evidence=json.dumps({"id": "dialog_flood", "count": self.dialogs}),
            ))
        return out


def behavior_events(hops) -> List[Dict[str, Any]]:
    """The parsed evidence of every page_behavior hop (what the scorer reads)."""
    return evidence_of(hops, BEHAVIOR_MECHANISM)


def evidence_of(hops, mechanism: str) -> List[Dict[str, Any]]:
    """The parsed JSON evidence of every hop with this mechanism; malformed evidence is skipped."""
    events = []
    for hop in hops:
        if hop.mechanism != mechanism or not hop.evidence:
            continue
        try:
            event = json.loads(hop.evidence)
        except (TypeError, ValueError):
            continue
        if isinstance(event, dict):
            events.append(event)
    return events
