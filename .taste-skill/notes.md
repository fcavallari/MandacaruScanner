# Mandacaru dashboard — design notes (tasteskill v2, app-screen run)

## Brief
Rebrand the dashboard (React + Vite, live API) from Pnakotic's cosmic-horror identity to
**Mandacaru**: Cosmic Sertão. The mandacaru is a cactus of the Caatinga; it survives a hostile, dry
place, protects itself with spines, and sertanejo folk wisdom reads its flowering as a sign that rain
is coming. A scanner does the same: it reads signs and tells you what is on the way. Its sibling
product Facheiro (another Caatinga cactus) does the cleanup, so Mandacaru detects and Facheiro cleans.
Sources: Brazilian northeastern dryland culture, punk DIY, woodcut (xilogravura / cordel)
illustration, and a thread of cosmic horror.

**Central principle: the Sertão looks empty, but it isn't empty.** Something ordinary can hide a
threat; no visible evidence is not evidence of absence; small details reveal larger structures. The
scanner is an instrument for looking closer, not a device that claims to know everything. This drives
the empty states, the waiting scene and the microcopy.

**Voice:** a field researcher in an unforgiving environment. Dry, concise, slightly sarcastic,
occasionally poetic but never theatrical, precise when reporting findings. It lives in the header,
empty states, errors and the waiting scene; finding text stays technical and the site report body
stays plain language.

**Anti-goals:** a postcard of the Northeast or a cangaceiro stereotype, a generic occult site, a neon
cyber palette, a cute cactus, atmosphere that costs clarity (no texture, animation or metaphor on
findings, tables, URLs or numbers), a waiting scene that pretends to report progress the API doesn't
(it only says queued or running), text under 4.5:1 or a meaning-carrying graphic under 3:1.

The layout, grid, panel order, type scale, 1px selection line, keyboard shortcuts and density are the
earlier redesign's and did not change. Colour, mark, wordmark, scene, empty states and copy did.

## 2.1 Data inventory
- Objects: ScanJob (id, target_url, profile, status queued/running/completed/failed, error, created_at)
  and ScanResult (final_url, malicious_score 0–1, is_redirect_chain_detected, hops[] {url,
  status_code, mechanism: http_3xx|meta_refresh|js_location|static_analysis, evidence},
  artifacts[] {rel_path png screenshots}, findings[] strings).
- Magnitudes: PoC account — single digits of scans (seeded to ~10), scores 0.0–1.0, chains 1–7 hops,
  profiles: default / mobile-ios / mobile-android / search-clicker.
- People: a security researcher or web dev pasting suspicious URLs; quick glances plus occasional
  deep dives, desktop-first (1440), phone for a glance.
- Jobs: submit a URL to scan (most frequent, one click); inspect the selected chain; open screenshot
  artifacts.
- Product's own things: name Mandacaru, the redirect chain itself (the trail), browser profiles as
  visitor types ("personas"), screenshot artifacts, the field-station vocabulary.

## 2.2 The screen's one question
"Where did that URL actually go, and how deep is it?"
- Biggest block: the selected scan — chain node graph + score depth gauge. Read first.
- One finding (computed, under the title): e.g. "2 of 5 completed scans ended on a high-value
  domain after redirect · 1 failed to load".
- Blocks: title row (h1 + finding + freshness) / KPI strip (scans, chains detected, highest score,
  median hops — one container, 1px dividers) / new-scan form (the job) / selected scan (lead) /
  intel panel (real aggregates: mechanisms, suspicious TLDs, landing domains) / recent scans table
  (capped rows + total). No block without a question.

## 2.3 Style, face, signature
- Style dealt: `data-terminal` (seed 1670938629), kept — Mandacaru is a monitoring tool read in long
  sessions (kind `markets`); its move, every selection a 1px accent line exactly as wide as its label,
  stays. Cards are darker than the ground. No glow, no glass, no entrance animations.
- Face: **Cosmic Sertão**, a charcoal ground warmed toward earth (not navy, not slate), flat woodcut
  ink, and a faint static paper grain on the page ground only (SVG `feTurbulence`, about 5.5% alpha;
  cards are opaque and stay clean; nothing on data).
- Palette: six hexes for fills, lines, marks and the logo, each with a lighter "reading twin" where
  the hex is too dark for text on charcoal. Tokens live in `frontend/src/index.css` `:root`.
  - Ground `#171512` charcoal (cards `#12100d`, raised `#1f1c18`, active `#1a1714`).
  - Ink `#D8D0BD` bone; muted `#b3aa96` (~8.2:1 on surface), faint `#958d79` (~5.8:1).
  - Accent, the one: rust `#A94B2A` (`--accent`: lines, fills, focus, icons, the mark; button fill
    `#93401F`) with the twin `#D2724F` (`--accent-ink`) for rust text.
  - Positive: mandacaru green `#65734B` (`--positive-fill`: bars, gauge fill), text and marks `#8E9C70`
    (`--positive`). Clean / Benign. No longer the accent.
  - Warning: dry sand `#C4A46A`. Suspicious / Watch.
  - Negative: dried blood `#733B43` (`--negative-fill`: only a block behind bone text, the
    Compromised and Malicious pills), text, marks and bars `#C46A72` (`--negative`). Rust and dried
    blood are both reds, so a critical result always carries its word plus a block or bar.
  - Status and data colours: running = muted text + rust dot; chain landing node and spine = accent
    (the trail is the signature, not a verdict); high-value-landing marker and a cloaking variant's
    differing landing = warning; benign gauge fill = positive-fill; Failed = neutral pill and text;
    error text and error dots = negative.
  - Contrast: text >= 4.5:1; meaning-carrying graphics (verdict and status dots, bars, gauge fill,
    focus and selection lines, chain nodes and spine) >= 3:1. Card borders, row rules and control
    outlines stay deliberately subtle (data-terminal's level, `--control` about 2.4:1 on surface, inputs also read by
    fill, placeholder and label); the dim scene art and unlit traces are decorative.
- Type: Public Sans (dealt) for text; IBM Plex Mono for every figure, ID and URL (the style's
  decision); **Alfa Slab One carved** for the wordmark only: "MANDACARU" at 30px (26px on a phone),
  letter-spacing ~0.05em, with an SVG `feTurbulence` + `feDisplacementMap` filter (about 2px) on the
  wordmark only, kept as real text in the `h1`. "Field Station" sits beside it in muted Public Sans.
- Mark: **A, the candelabra**: a woodcut mandacaru, one thick trunk with two raised arms at different
  heights (the left lower), exaggerated spines off every outer edge and tip, vertical carved ribs cut
  out of the trunk and arms with an SVG mask (not painted in a background colour), and a cracked-earth
  baseline. Resilient and sharp, not cute. Rust, 44px in the title row (36px on a phone), 32px at the
  top of the rail; `public/favicon.svg` is a simplified 24-unit redraw without ribs so it reads at 16px.
- Waiting scene: **Strata** (`FieldScene.tsx`), see Motion. Empty lead block: `EmptyGround`, see States.
- Signature element (only this product has): the redirect chain as the **Trail**, a node graph. Origin
  to stops (status code above, mechanism mark) to the final landing; each node is "stop N" (its index
  on the trail, so it never contradicts the heading's "N redirects"); plus the score as a depth gauge
  (0–1 track, true-ratio fill, both ends labelled).

## Grid arithmetic (1440)
Rail 56 + 1px edge. Canvas gutter 32 (dealt pad). Content = 1440 − 56 − 64 = 1320.
Main row, 12 cols gap 24: col = (1320 − 264)/12 = 88.
Left 8 cols: 8·88 + 7·24 = 872. Right 4 cols: 4·88 + 3·24 = 424. Check: 872 + 24 + 424 = 1320 ✓.
KPI strip and table run the full 1320.

## States
- Empty (no probe selected): frame + title kept; the lead block is `EmptyGround`, the waiting scene's
  ground static and dimmed (horizon, dimmed mark, strata, two barely visible unexamined traces) with
  "Nothing collected yet." / "Looks empty. It rarely is. Submit a site above to look closer."; the form
  stays (first action where data will appear). The smaller wells (probe list, intel panel) are text-only
  dashed wells with the same copy; no illustration in small containers.
- Loading: final layout with flat grey bars at real sizes, no shimmer.
- Error: per-block sentence ending "No signal." + Retry; negative colour only on a small mark.
  An unreachable API reads "No signal from the field station. No answer from <base>."; input the API
  rejects reads "Can't inspect that. <reason>"; a probe that failed without text reads "Analysis
  interrupted"; a missing scan answers "Scan not found". Never "No threats detected" for a rejection.
- Finding line: "No high-value landings, no failures. Quiet, for now." / "Probes in the field. Nothing
  back yet." / "Nothing collected yet."
- Zero printed as 0; missing as a grey dash.

## Motion (feedback only — app screens have no entrance floor)
Row hover = tone step; focus/selection = the 1px accent line (the move); running status = a pulsing
dot; chain nodes appear as data arrives. No entrance animations, no glow, no glass.
One deliberate exception: while a probe is queued or running, the lead block's body is **Strata**
(`FieldScene.tsx`, SVG): a carved horizon with the mandacaru on it in the left third, a few faint
stars, and three jagged soil strata with cracks below. Six buried traces (ring, cross,
diamond, triangle, dot) take their shape and position from the probe's own SHA-256 digests (target URL,
probe id, host, path, each visitor type), so each probe's ground differs and nothing is random.
Running: a faint rust band with a 1px rust leading line sinks from the horizon to the bottom in 7s,
looping; when it reaches a trace the trace flashes (rust-ink, then rust) and settles dim-rust, and a
tag shows for a few seconds (a 6-hex digest fragment, or the visitor type's name in clear). It is
feedback for the one long wait, never decoration on data, and not a progress bar: the API only says
queued or running. Queued: the ground dimmed, no band, traces unlit, "Waiting for a free worker…".
Running: "Checking <host>…" (site survey) or "Probing <host>…" and the mono line "inspecting specimen ·
probe a1b2c3d4" ("specimen" is used only here). prefers-reduced-motion gets one still frame, the band
halfway down and the traces above it lit and tagged.

## Sample content to confirm before launch
- Seeded scans are real (google, bing, duckduckgo, example.com, t.co, wikipedia + profiles); the
  intel panel and KPIs are computed from them. Nothing invented except the mark.
