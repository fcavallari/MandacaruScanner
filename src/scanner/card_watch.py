"""Card inputs being inserted into the page, and whose code inserted them.

A checkout skimmer shows its own card form: it hides the payment provider's field and inserts
inputs for the card number, expiry and CVC into the store's page. This module watches for that
insertion from inside the page and records the JavaScript stack of the call that did it;
``code_origin`` then decides whose code that stack belongs to (the store's, a payment
provider's, a known vendor's, or unknown code).

Page side: an init script (installed before any page script, like ``behavior.py``'s, with the
same ``HOOK_PRELUDE`` so wrapped functions keep their native ``toString()``) wraps the DOM
insertion methods on their prototypes and the ``innerHTML`` / ``outerHTML`` setters. Each call
tests its argument: a node with ``matches`` / ``querySelector`` and ``CARD_SELECTOR``, an HTML
string with ``CARD_HTML_RE`` on its first 200 000 characters. Only a call that puts a card input
into this document (the target is connected to it) is reported, so a form built detached and then
attached is one insertion, and a template or a parsed document is none.

On a hit the hook takes the stack with the ``Error.captureStackTrace`` saved at start, cut at the
wrapper, so the hook's own frames above it are not on it. For that one call it sets
``Error.stackTraceLimit`` to 31 (not 30: a stack deeper than the 30 frames ``code_origin`` reads
then shows it was cut) and ``Error.prepareStackTrace`` to its own formatter, then restores both
exactly. The formatter writes each frame as ``at <url>:<line>:<column>`` with the script's real URL
(V8's own text shows a ``//# sourceURL`` name instead, which a cross-site script can set to a store
file), and any frame without a URL (eval, an inline script added at runtime, a builtin) as
``at <anonymous>``, which ``code_origin`` counts as unknown. Page code that a hooked call runs (a
custom element's callback, an inserted inline script) has our wrapper's URL-less frame under it;
the hook counts how many of its wrappers are running and leaves out that many of the deepest
URL-less frames, so every other one still shows. If the page has made either property an accessor
or read-only (to hide or forge the caller), or the stack is too deep to find our frames, the hook
reports an empty stack, which also counts as unknown. Every native the hook uses (CallSite methods
included) is saved when it starts, so a page that redefines them later is never called by it. Any
failure in the hook is swallowed.

The report goes through a randomly named Playwright binding that the script deletes from
``window`` at once. Only the main frame's reports are kept (a payment provider's iframe builds its
own card inputs; ``present`` counts the main frame's inputs only, too).

Everything that crosses the binding is page-supplied: ``via`` must be a known name, the stack is
cut to 4 000 characters, at most ``MAX_EVENTS`` events are kept and the rest are counted in
``dropped``. A page sends at most ``MAX_SENT_PER_DOCUMENT`` reports one by one, then one report per
1 000 further insertions, so a page inserting card inputs in a loop costs little and is still
counted.

What the hooks can't see (an input renamed after it was inserted, ``document.write``, a node
moved in from another frame's realm) is caught by ``summarize`` failing closed: card inputs on the
page, no insertion recorded and none in the served HTML gives an ``unseen`` insertion of unknown
code.
"""
import json
import re
import secrets
from typing import Any, Dict, List, Optional
from urllib.parse import urldefrag

from .behavior import HOOK_PRELUDE
from .code_origin import inline_line_ranges, parse_stack, stack_owner, stack_was_cut

MAX_EVENTS = 20  # card-insertion events kept per load
MAX_STACK_CHARS = 4000
MAX_FRAME_URLS = 10  # frame URLs kept per insertion in the summary
MAX_URL_CHARS = 300
MAX_HTML_CHARS = 200_000  # characters of an HTML string the page-side hook tests
MAX_SENT_PER_DOCUMENT = 1000  # one report per insertion up to here, then one per 1 000

# Names the page-side hook reports in "via"; anything else is dropped.
VIA = (
    "appendChild", "insertBefore", "replaceChild", "append", "prepend", "replaceWith",
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    # beyond the minimum: the other ways a script puts nodes or markup into the document
    "before", "after", "replaceChildren", "insertAdjacentElement", "setHTMLUnsafe",
)
_VIA = set(VIA)

# autocomplete tokens of card fields (the HTML standard's names)
CARD_AUTOCOMPLETE = ("cc-number", "cc-csc", "cc-exp", "cc-exp-month", "cc-exp-year")
# substrings of a card field's name or id (matched without case). Bare "cc", "code" or "exp"
# would match account_password, coupon_code and many others, so every part names the card.
CARD_NAME_PARTS = (
    # number
    "cardnum", "card_num", "card-num", "card[num", "ccnum", "cc_num", "cc-num", "cardno", "card_no",
    # CVC / CVV
    "cvc", "cvv", "cvn", "cardcode", "card_code", "card-code", "cc_csc", "cc-csc",
    # expiry
    "cardexp", "card_exp", "card-exp", "card[exp", "ccexp", "cc_exp", "cc-exp",
    "expiry", "expdate", "exp_date", "exp-date", "exp_month", "exp-month", "expmonth",
    "exp_year", "exp-year", "expyear",
)

CARD_SELECTOR = ":is(input,select):is({})".format(",".join(
    ['[autocomplete~="{}" i]'.format(token) for token in CARD_AUTOCOMPLETE]
    + ['[{}*="{}" i]'.format(attr, part) for part in CARD_NAME_PARTS for attr in ("name", "id")]))

# The same test for an HTML string, valid as a Python and a JavaScript regex (no inline flags,
# compiled case-insensitive on both sides). Linear in practice: one bounded window per tag start.
_NAME_ALTERNATION = "|".join(part.replace("[", "\\[") for part in CARD_NAME_PARTS)
CARD_HTML_PATTERN = (
    r"<(?:input|select)\b[^<>]{0,1000}?\b(?:"
    r"autocomplete\s{0,3}=\s{0,3}[\"']?(?:[a-z0-9-]{1,40}\s{1,3}){0,5}cc-(?:number|csc|exp)"
    r"|(?:name|id)\s{0,3}=\s{0,3}[\"']?[^\"'\s<>]{0,60}?(?:" + _NAME_ALTERNATION + r"))"
)
CARD_HTML_RE = re.compile(CARD_HTML_PATTERN, re.IGNORECASE)

# The served-HTML check reads a whole body (up to 2 MB) in the worker, where CARD_HTML_RE's
# per-tag window can backtrack for seconds on hostile markup: there, tags and attributes are
# read with two linear regexes and the values tested as CARD_SELECTOR tests them.
_TAG_RE = re.compile(r"<(?:input|select)\b[^<>]{0,1000}", re.IGNORECASE)
_ATTR_RE = re.compile(r"\b(autocomplete|name|id)\s{0,3}=\s{0,3}"
                      r"(?:\"([^\"]{0,200})\"|'([^']{0,200})'|([^\s\"'<>]{1,200}))", re.IGNORECASE)
_CARD_TOKENS = set(CARD_AUTOCOMPLETE)


def html_has_card_input(text: str) -> bool:
    """Whether ``text`` (HTML, any length) has an ``<input>`` / ``<select>`` tag that
    ``CARD_SELECTOR`` would match. Linear time."""
    for tag in _TAG_RE.finditer(text or ""):
        for attr in _ATTR_RE.finditer(tag.group()):
            value = (attr.group(2) or attr.group(3) or attr.group(4) or "").lower()
            if attr.group(1).lower() == "autocomplete":
                if _CARD_TOKENS.intersection(value.split()):
                    return True
            elif any(part in value for part in CARD_NAME_PARTS):
                return True
    return False

# __NAME__, __SELECTOR__, __HTML_RE__ and the limits are substituted by _init_script (no
# %-formatting: the script is full of regex text).
_INIT_SCRIPT = r"""
(() => {
  const send = window[__NAME__];
  if (typeof send !== 'function') return;
  try { delete window[__NAME__]; } catch (e) {}
""" + HOOK_PRELUDE + r"""
  try {
    const doc = document;
    const getDesc = Object.getOwnPropertyDescriptor;
    const defProp = Object.defineProperty;
    const ErrorCtor = Error;
    const capture = Error.captureStackTrace;
    const createNull = Object.create;
    const uncurry = (f) => (typeof f === 'function' ? (self, ...args) => rApply(f, self, args) : null);
    const getter = (proto, key) => {
      const d = proto ? getDesc(proto, key) : undefined;
      return d && typeof d.get === 'function' ? uncurry(d.get) : null;
    };
    const hasOwn = uncurry(Object.prototype.hasOwnProperty);
    const exec = uncurry(RegExp.prototype.exec);
    const slice = uncurry(String.prototype.slice);
    const matches = uncurry(Element.prototype.matches);
    const elementQuery = uncurry(Element.prototype.querySelector);
    const fragmentQuery = uncurry(DocumentFragment.prototype.querySelector);
    const nodeType = getter(Node.prototype, 'nodeType');
    const isConnected = getter(Node.prototype, 'isConnected');
    const ownerDocument = getter(Node.prototype, 'ownerDocument');
    const childCount = getter(Element.prototype, 'childElementCount');
    const SELECTOR = __SELECTOR__;
    const HTML_RE = new RegExp(__HTML_RE__, 'i');
    const nest = { depth: 0 };  // our wrappers running their original right now
    let hits = 0;
    let drop = 0;  // our wrapper frames under the stack being formatted

    // a stack property we may set: absent, or a plain writable and configurable value
    const settable = (d) => {
      if (!d) return true;
      if (hasOwn(d, 'get') || hasOwn(d, 'set')) return false;
      return d.writable === true && d.configurable === true;
    };
    const restore = (key, d) => {
      try { if (d) defProp(ErrorCtor, key, d); else delete ErrorCtor[key]; } catch (e) {}
    };

    // CallSite methods, saved before any page code runs (a page could reach CallSite.prototype
    // through its own prepareStackTrace later)
    let site = null;
    {
      const prep = getDesc(ErrorCtor, 'prepareStackTrace');
      try {
        defProp(ErrorCtor, 'prepareStackTrace', { value: (e, sites) => sites, writable: true, configurable: true });
        const holder = createNull(null);
        capture(holder);
        const sites = holder.stack;
        const proto = sites && sites[0] ? Object.getPrototypeOf(sites[0]) : null;
        if (proto) {
          site = {
            file: uncurry(proto.getFileName), line: uncurry(proto.getLineNumber),
            column: uncurry(proto.getColumnNumber), isEval: uncurry(proto.isEval),
          };
        }
      } catch (e) {}
      restore('prepareStackTrace', prep);
    }
    // The stack as text code_origin reads. Each frame is the script's real URL (getFileName, not
    // the //# sourceURL name V8's own text shows, which a script can set to anything); code
    // without a URL (eval, an inline script added at runtime, a builtin, our own wrappers) is
    // "<anonymous>". When `drop` of our wrappers are running under this call (page code that
    // a hooked call ran, such as a custom element's callback), the deepest `drop` script frames
    // without a URL are left out: ours are among them, and whichever are left out, every other
    // URL-less frame still shows. Only when the stack is whole (fewer frames than the limit) and
    // has that many; otherwise nothing is reported, which reads as unknown code.
    const format = (holder, sites) => {
      try {
        const count = sites.length;
        let keep = 0;  // URL-less script frames to keep, from the top, when some are ours
        if (drop > 0) {
          if (count >= __FRAMES__) return '';
          let blank = 0;
          for (let i = 0; i < count; i++) if (!site.isEval(sites[i]) && site.file(sites[i]) === '') blank += 1;
          if (blank < drop) return '';
          keep = blank - drop;
        }
        let out = 'Error';
        for (let i = 0; i < count; i++) {
          const s = sites[i];
          if (site.isEval(s)) { out += '\n    at eval (eval at <anonymous>)'; continue; }
          const file = site.file(s);
          if (typeof file === 'string' && file !== '') {
            out += '\n    at ' + slice(file, 0, 1000) + ':' + site.line(s) + ':' + site.column(s);
            continue;
          }
          if (drop > 0 && file === '') {
            if (keep === 0) continue;  // one of the deepest URL-less frames: ours
            keep -= 1;
          }
          out += '\n    at <anonymous>';
        }
        return out;
      } catch (e) {
        return '';
      }
    };
    // the stack of the caller of `fn` (the wrapper itself and our frames above it are cut off)
    const stackOf = (fn) => {
      if (site === null) return '';
      const prep = getDesc(ErrorCtor, 'prepareStackTrace');
      const limit = getDesc(ErrorCtor, 'stackTraceLimit');
      if (!settable(prep) || !settable(limit)) return '';  // the page is hiding or forging callers
      let out = '';
      try {
        drop = nest.depth;
        defProp(ErrorCtor, 'prepareStackTrace', { value: format, writable: true, configurable: true,
                                                  enumerable: prep ? prep.enumerable : true });
        defProp(ErrorCtor, 'stackTraceLimit', { value: __FRAMES__, writable: true, configurable: true,
                                                enumerable: limit ? limit.enumerable : true });
        const holder = createNull(null);
        capture(holder, fn);
        const stack = holder.stack;  // formatted now (V8 formats on first read), by ours
        out = typeof stack === 'string' ? slice(stack, 0, __STACK__) : '';
      } catch (e) {
        out = '';
      }
      restore('prepareStackTrace', prep);
      restore('stackTraceLimit', limit);
      return out;
    };
    const report = (via, fn) => {
      hits += 1;
      try {
        if (hits <= __EVENTS__) send({ via: via, stack: stackOf(fn) });
        else if (hits <= __SENT__) send({ via: via, over: 1 });
        else if (hits % __SENT__ === 0) send({ via: via, over: __SENT__ });
      } catch (e) {}
    };

    // the target is in this document (not detached, not a template's or a parsed document's)
    const live = (n) => {
      try { return !!isConnected(n) && (n === doc || ownerDocument(n) === doc); } catch (e) { return false; }
    };
    const hasCard = (n) => {
      try {
        if (n === null || typeof n !== 'object') return false;
        const type = nodeType(n);
        if (type === 1) return matches(n, SELECTOR) || (childCount(n) > 0 && elementQuery(n, SELECTOR) !== null);
        if (type === 11) return fragmentQuery(n, SELECTOR) !== null;
      } catch (e) {}
      return false;
    };
    const htmlHasCard = (v) => {
      try { return typeof v === 'string' && exec(HTML_RE, slice(v, 0, __HTML_CHARS__)) !== null; } catch (e) { return false; }
    };
    const anyCard = (args) => {
      for (let i = 0; i < args.length; i++) if (hasCard(args[i])) return true;
      return false;
    };

    const hook = (owner, key, test) => {
      if (!owner) return;
      const d = getDesc(owner, key);
      const length = d && typeof d.value === 'function' ? d.value.length : 0;
      let self;
      self = wrap(owner, key, function () { if (test(this, arguments)) report(key, self); }, nest);
      if (self) { try { defProp(self, 'length', { value: length }); } catch (e) {} }
    };
    const hookSetter = (proto, key) => {
      const d = proto ? getDesc(proto, key) : undefined;
      if (!d || typeof d.set !== 'function' || !d.configurable) return;
      const setter = d.set;
      const patched = function (v) {
        try { if (live(this) && htmlHasCard(v)) report(key, patched); } catch (e) {}
        nest.depth += 1;
        try { return rApply(setter, this, arguments); } finally { nest.depth -= 1; }
      };
      nativeText.set(patched, rApply(fnToString, setter, []));
      try { defProp(patched, 'name', { value: setter.name }); } catch (e) {}
      try { defProp(patched, 'length', { value: setter.length }); } catch (e) {}
      try { defProp(proto, key, { get: d.get, set: patched, enumerable: d.enumerable, configurable: true }); } catch (e) {}
    };

    const first = (target, args) => live(target) && hasCard(args[0]);
    const second = (target, args) => live(target) && hasCard(args[1]);
    const any = (target, args) => live(target) && anyCard(args);
    const markup = (index) => (target, args) => live(target) && htmlHasCard(args[index]);

    hook(Node.prototype, 'appendChild', first);
    hook(Node.prototype, 'insertBefore', first);
    hook(Node.prototype, 'replaceChild', first);
    for (const proto of [Element.prototype, Document.prototype, DocumentFragment.prototype]) {
      hook(proto, 'append', any);
      hook(proto, 'prepend', any);
      hook(proto, 'replaceChildren', any);
    }
    for (const proto of [Element.prototype, CharacterData.prototype, DocumentType.prototype]) {
      hook(proto, 'replaceWith', any);
      hook(proto, 'before', any);
      hook(proto, 'after', any);
    }
    hook(Element.prototype, 'insertAdjacentHTML', markup(1));
    hook(Element.prototype, 'insertAdjacentElement', second);
    hook(Element.prototype, 'setHTMLUnsafe', markup(0));
    if (window.ShadowRoot) hook(ShadowRoot.prototype, 'setHTMLUnsafe', markup(0));
    hookSetter(Element.prototype, 'innerHTML');
    hookSetter(Element.prototype, 'outerHTML');
    if (window.ShadowRoot) hookSetter(ShadowRoot.prototype, 'innerHTML');
  } catch (e) {}
})();
"""


def _init_script(binding: str) -> str:
    replacements = {
        "__NAME__": json.dumps(binding),
        "__SELECTOR__": json.dumps(CARD_SELECTOR),
        "__HTML_RE__": json.dumps(CARD_HTML_PATTERN),
        "__FRAMES__": "31",  # one more than code_origin reads, so a deeper stack shows it was cut
        "__STACK__": str(MAX_STACK_CHARS + 1),  # one more than kept, so a longer stack shows it was cut
        "__EVENTS__": str(MAX_EVENTS),
        "__SENT__": str(MAX_SENT_PER_DOCUMENT),
        "__HTML_CHARS__": str(MAX_HTML_CHARS),
    }
    script = _INIT_SCRIPT
    for key, value in replacements.items():
        script = script.replace(key, value)
    return script


class CardWatcher:
    """Records card-input insertions for one load; ``attach()`` before ``new_page()``."""

    def __init__(self) -> None:
        self.binding = "__" + secrets.token_hex(8)
        self.events: List[Dict[str, Any]] = []  # {"via", "stack", "cut"}
        self.dropped = 0

    async def attach(self, ctx) -> None:
        await ctx.expose_binding(self.binding, self._on_page_event)
        await ctx.add_init_script(_init_script(self.binding))

    def _on_page_event(self, source: Dict[str, Any], payload: Any) -> None:
        try:
            if not isinstance(payload, dict) or payload.get("via") not in _VIA:
                return
            frame = source.get("frame") if isinstance(source, dict) else None
            page = source.get("page") if isinstance(source, dict) else None
            if page is None or frame is None or frame != page.main_frame:
                return  # a subframe's own document (a payment provider's iframe builds card inputs)
            over = payload.get("over")
            if "over" in payload:
                if isinstance(over, int) and not isinstance(over, bool) and 0 < over <= MAX_SENT_PER_DOCUMENT:
                    self.dropped += over
                return
            if len(self.events) >= MAX_EVENTS:
                self.dropped += 1
                return
            stack = payload.get("stack")
            stack = stack[:MAX_STACK_CHARS + 1] if isinstance(stack, str) else ""
            self.events.append({"via": payload["via"], "stack": stack[:MAX_STACK_CHARS],
                                "cut": stack_was_cut(stack)})
        except Exception as exc:  # a binding handler must never raise into Playwright
            print(f"[card-watch] ignored an event: {str(exc)[:200]}")


def summarize(events: List[Dict[str, Any]], present: int, site_host: str, landing_url: str,
              served: Optional[bytes], *, dropped: int = 0) -> Dict[str, Any]:
    """``metadata["card_inputs"]``: how many card inputs the page has (``present``), each
    recorded insertion with its owner (``code_origin.stack_owner``) and up to 10 frame URLs (an
    unreadable frame is ``""``), and how many insertions were not kept (``dropped``).

    ``landing_url`` is the document the served HTML belongs to: a frame at that URL is the
    store's only inside a served inline script block. ``cut`` is true when part of the stack was
    left out (over 4 000 characters or over 30 frames); the owner is decided on what was kept.

    Fails closed: card inputs on the page, no insertion recorded and none in the served HTML
    means the inputs got there in a way the hooks can't see, so an ``unseen`` insertion of
    unknown code is added.
    """
    inline = inline_line_ranges(served)
    page_url = urldefrag(landing_url or "")[0]
    inserted = []  # type: List[Dict[str, Any]]
    for event in events[:MAX_EVENTS]:
        stack = event.get("stack") if isinstance(event.get("stack"), str) else ""
        frames = parse_stack(stack)
        owner, vendors = stack_owner(frames, site_host, page_url, inline)
        inserted.append({
            "via": event.get("via", ""),
            "owner": owner,
            "vendors": vendors,
            "frames": [frame.url[:MAX_URL_CHARS] for frame in frames[:MAX_FRAME_URLS]],
            "cut": bool(event.get("cut")) or stack_was_cut(stack),
        })
    if present > 0 and not events:
        text = served.decode("utf-8", "replace") if served else ""
        if not html_has_card_input(text):
            inserted.append({"via": "unseen", "owner": "unknown", "vendors": [], "frames": [], "cut": False})
    return {"present": present, "inserted": inserted, "dropped": dropped}
