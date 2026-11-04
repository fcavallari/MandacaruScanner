# Field test against urlscan.io submissions (2026-11-04)

## What was done

Thirty URLs were scanned with Pnakotic and the verdicts compared with how urlscan.io's community had tagged them. Twenty-two came from urlscan.io's public search API within the previous three days: ten tagged `phishing` (capped at four per free-hosting provider so one kit stream did not dominate), twelve tagged `scam` (seven of them crypto "AI trading platform" lead-generation sites). Eight well-known sites were added as benign controls. urlscan.io's result details (verdict scores, request chains) require a login, so the comparison uses the tag, the landing URL and status, and the domain and certificate ages that the free search results carry.

The scans ran inside the hardened worker image (`linux/amd64`, Google Chrome 157.0.8103.38, uid 1001, `cap_drop ALL`, `no-new-privileges`, the project seccomp profile, `init`, 1 GB shm) under CPU emulation on an Apple-silicon host, with no database or broker credentials in the container. The harness saved each landing page's HTML and screenshot alongside the verdict so misses could be diagnosed offline. Both runs used the same URL set; the "after" run used the image rebuilt from the tree after the changes below.

## Baseline: what the scanner found before the changes

| kind | Malicious | Suspicious | Watch | Benign |
|---|---|---|---|---|
| phishing (10) | 0 | 1 | 0 | 9 |
| scam (12) | 0 | 2 | 1 | 9 |
| benign (8) | 1 | 0 | 2 | 5 |

Eighteen of the twenty-two flagged URLs scored Benign, and the only Malicious verdict in the run was `www.amazon.com`. The reasons, from the captured pages:

- **Phishing pages do not redirect.** Nine of ten served their content on the submitted URL. A redirect-only scorer has nothing to grip.
- **Brand lookalikes live in the hostname**, not in a redirect: `sso-godaddy-….pages.dev`, `us05web-zoom-us8….pages.dev`, `googleplay.com`. The GoDaddy kit's JavaScript redirect was recorded (the first field confirmation of the CDP navigation hop added earlier in the day), but its destination was already down, so the engine analysed Chrome's error page as if it were the site.
- **Kits render late or behind a click.** The Zoom lookalike is a JavaScript bundle that shows "Preparing your meeting experience…" with the victim's email pre-seeded in `sessionStorage` as base64; no form exists in the DOM at the three-second settle.
- **Three "phishing" URLs served `audio/mpeg`**, which Chrome wrapped in a `<video>` element; there was no HTML to analyse and nothing said so.
- **Scams redirect across registrable domains**: `topbook-game.online` → `chinatownrestaurantau.com`, `investrixai.net` → `finazy6-….sbs`. The scorer had no rule for "landed somewhere else".
- **The crypto scams** (`valindexo.pro`, `nidio-rendomio.pro`, `zelantezza.pro`, `steadvestor-ie.net`) are plain marketing pages with a lead form posting to `/integration/send.php`. urlscan shows the domains were 0 to 2 days old. Nothing on the page is suspicious by itself; the signal is reputation and age, which the tool does not consult.
- **False positive on amazon.com**: its page performs a script navigation to its own URL, which was recorded as a JavaScript redirect (0.4), and its bundle contains `String.fromCharCode` (0.4). `stackoverflow.com` scored 0.1 from `<meta http-equiv="refresh" content="360">`, a reload timer with no URL. `b64_payload` fired on almost every site because of `data:` URIs.
- Several URLs tagged by one urlscan submitter as "possiblethreat" (`tampalandclearingservice.com`, `oasis-site-1up.pages.dev`, `vectorinnovation.group`) look like ordinary small-business sites using formsubmit.co; the scanner's Benign verdict is probably right and urlscan's tag probably not. Others (`guiavcenter.com`, `aguaducto.z15.web.core.windows.net`) rendered as benign Spanish-language "educational" pages; whether they cloak for scanners could not be determined.

## Changes made from this evidence

Engine (`src/scanner/engine.py`):
- `metadata["page_signals"]`: title, password-input count, form count, the main document's Content-Type, and whether the browser ended on `chrome-error://`. Static analysis is skipped for error pages and non-HTML documents, and `metadata["navigation_failed"]` records the destination that was unreachable.
- A script or meta navigation to the page's own URL (ignoring the fragment) is recorded as `client_navigation`, not as a redirect.

Scorer (`src/intelligence/scorer.py`), new rules, each applied once:

| Rule | Weight |
|---|---|
| Brand token in the hostname while the host is not the brand's own domain (exempt when the scan lands on the brand's own domain) | 0.4 |
| Credential form: a password input on a page whose title or hostname names a brand the host does not belong to | 0.4 |
| Observed JS / meta redirect scores only when it crossed registrable domains; same-site navigations are reported unweighted | (0.4 / 0.25 unchanged) |
| Obfuscation helpers score 0.4 only alongside a cross-site redirect, a brand hostname or a credential form; otherwise | 0.1 |
| Redirected to a different registrable domain (not a high-value brand) | 0.2 |
| Page title that leads with a brand name on a host that is not the brand's | 0.2 |
| Free-hosting platform in the hostname (`pages.dev`, `edgeone.dev`, `web.core.windows.net`, `netlify.app`, …) | 0.15 |
| Second-tier abuse-prone TLDs (`.pro`, `.online`, `.shop`, …); first tier extended (`.sbs`, `.cfd`, `.click`, …) | 0.15 / 0.3 |
| Unweighted: "Navigation failed: host unreachable", "Landing document is not HTML: type" | 0 |

Static analyzer: `meta_refresh` only counts with `url=`; base64 inside `data:` URIs is no longer reported as a payload.

In the same working tree, a second session added popup capture, a click probe (`popup_open`, `click_hijack`), new visitor personas and a client-hint user-agent override. The "after" run includes those.

## After

Same thirty URLs, image rebuilt from the changed tree:

| kind | Malicious | Suspicious | Watch | Benign |
|---|---|---|---|---|
| phishing (10) | 2 | 0 | 5 | 3 |
| scam (12) | 1 | 1 | 8 | 2 |
| benign (8) | 0 | 0 | 2 | 6 |

Per URL (score before → after, with the findings that produced the new score):

| URL | Tag | Before | After | Why |
|---|---|---|---|---|
| `sso-godaddy-….pages.dev` | phishing | 0.4 | **1.0** | JS redirect, brand `godaddy`, `pages.dev`, cross-domain |
| `us05web-zoom-us8….pages.dev` | phishing | 0.0 | **0.75** | brand `zoom` in hostname and title, `pages.dev` |
| `investrixai.net` → `finazy6-….sbs` | scam | 0.55 | **1.0** | JS redirect, `.sbs`, cross-domain |
| `plinkobonusplay.com` (title "Google Play") | scam | 0.0 | 0.2 | brand leads title |
| `googleplay.com` → `play.google.com` | scam (tag disputed) | 0.2 | 0.6 → 0.2 | first flagged as a `google` lookalike; the run exposed that Google's own redirector domain must be exempt when the landing is the brand's, fixed and re-verified in Chrome locally |
| `topbook-game.online` | scam | 0.4 | 0.15 | this time the site served a cloaking gate ("Loading", `window.__redirectUrl = 'https://chinatownrestaurantau.com/'`) and did not redirect within the scan; the first run saw the redirect |
| four `edgeone.dev` kits | phishing | 0.0 | 0.15 | free hosting; two served `audio/mpeg`, one `application/pdf`, now reported as non-HTML |
| `valindexo.pro`, `nidio-rendomio.pro`, `zelantezza.pro` | scam | 0.0 | 0.15 | `.pro` |
| `steadvestor-ie.net`, `guiavcenter.com` | scam | 0.0 | 0.0 | nothing on the page; needs reputation / domain age |
| `www.amazon.com` | benign | **0.8** | 0.1 | self-navigation no longer a redirect; obfuscation alone is 0.1 |
| `stackoverflow.com` | benign | 0.1 | 0.0 | refresh timer without `url=` ignored |
| `google.com` → `www.google.com` | benign | 0.2 | 0.2 | the "high-value landing after redirect" rule fires on Google's own redirect; left as is (review D8) |
| other controls | benign | 0.0 | 0.0 | |

What this shows: the phishing-specific rules catch the cases that give themselves away in the hostname or title (two of ten now Malicious, five more Watch), and the two false-positive classes on big sites are gone. Nothing in this run reached "Suspicious" wrongly on a control.

## What the scanner still cannot see

- **Reputation and age.** All seven crypto-scam domains were 0 to 4 days old per urlscan; two of them have no page-level signal at all. A WHOIS/RDAP age lookup and a reputation feed would catch what no amount of HTML inspection will (review D8).
- **Late-rendering and click-gated kits.** The Zoom kit draws its form after the settle window; the `topbook-game.online` gate decides after load. A longer dwell with interaction after the screenshot would see more of these (review D6; the peer session's click probe is a first step).
- **Cloaking.** The same URL served different content to the two runs. Several "scam"-tagged pages rendered as benign; the scanner cannot tell a cloaked page from a false tag.
- **External scripts** are still not analysed, so kits whose logic is in a bundle (`/assets/index-*.js`) leave no static finding (review D3).
- **Lookalike coverage is a list.** The brand list in `scorer.py` is short and English-centric; the test set's Spanish and Portuguese scams named no listed brand.
- **Ground truth is thin.** urlscan tags are community-applied; at least three "phishing" URLs appear to be ordinary small-business sites, and verdict scores were not available without a login.

## How to repeat

The harness, URL set and raw results are in this session's scratchpad (`urlscan/batch_scan.py`, `urlscan/urlset.json`, `urlscan/results_before.jsonl`, `urlscan/results_after.jsonl`, `urlscan/compare.py`). The harness mounts itself read-only into the worker image and writes JSONL, landing HTML and screenshots to a mounted output directory; it runs with the exact compose hardening flags and no credentials. Do not open these URLs in a browser on a workstation.
