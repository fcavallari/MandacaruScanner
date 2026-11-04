# Pnakotic dashboard — design notes (tasteskill v2, app-screen run)

## Brief
Redesign the Pnakotic dashboard (React + Vite, live API). User direction: Lovecraftian inspiration,
horror movies, cyberpunk. Existing brand voice in the codebase: "ritual", "abyss", "Summoning…",
"Intel Stream". The name Pnakotic is a play on Pnakotus — Lovecraft's sunken city of the Mi-Go.

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
- Product's own things: name Pnakotic (sunken city), the redirect chain itself, browser profiles as
  "personas", screenshot artifacts, ritual/abyss vocabulary.

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
- Style dealt: `data-terminal` (seed 1670938629) — chosen because Pnakotic is a monitoring tool read
  in long sessions (kind `markets`); its move — every selection is a 1px accent line exactly as wide
  as its label — is the most cyberpunk of the two dark styles dealt. No redraws: the user's
  Lovecraftian/cyberpunk direction is applied as the style's "face", not against it.
- Face (from the sheet's identity list):
  - Ground tinted from the product's world: abyssal green-black (the deep), keeping the dealt
    lightness steps (cards darker than ground — the style's move). Not navy, not slate.
  - The one accent in place of the dealt blue: phosphor teal (bioluminescence / terminal neon).
    --positive = the accent (green accent rule, §9.3). Negative stays the dealt blood red #e5566f
    (horror), warning the dealt sickly amber.
  - Type: Public Sans (dealt) for text; IBM Plex Mono for every figure/ID/URL (the style's decision,
    identity item 1 — reported); Chakra Petch for the wordmark only (a third face kept to the
    wordmark, allowed).
  - Mark: the Pnakotic sigil, a pentagon sealing a five-pointed star with one node at its heart
    (after the mythos' "Pnakotic pentagon", drawn fresh, not traced), in the accent at the top of
    the rail, in the title row and as public/favicon.svg. Never a black square with a letter.
- Signature element (only this product has): the redirect chain as a node graph — Pnakotic's order
  book. Origin → hops (status code above, mechanism mark) → final landing; plus the score as a depth
  gauge (0–1 track, true-ratio fill, both ends labelled).

## Grid arithmetic (1440)
Rail 56 + 1px edge. Canvas gutter 32 (dealt pad). Content = 1440 − 56 − 64 = 1320.
Main row, 12 cols gap 24: col = (1320 − 264)/12 = 88.
Left 8 cols: 8·88 + 7·24 = 872. Right 4 cols: 4·88 + 3·24 = 424. Check: 872 + 24 + 424 = 1320 ✓.
KPI strip and table run the full 1320.

## States
- Empty: frame + title kept; lead block a dashed well, "No probes yet. The deep is quiet."; form
  stays (first action where data will appear).
- Loading: final layout with flat grey bars at real sizes, no shimmer.
- Error: per-block sentence + Retry; negative colour only on a small mark.
- Zero printed as 0; missing as a grey dash.

## Motion (feedback only — app screens have no entrance floor)
Row hover = tone step; focus/selection = the 1px accent line (the move); running status = a pulsing
dot; chain nodes appear as data arrives. No entrance animations, no glow, no glass.

## Sample content to confirm before launch
- Seeded scans are real (google, bing, duckduckgo, example.com, t.co, wikipedia + profiles); the
  intel panel and KPIs are computed from them. Nothing invented except the wordmark glyph.
