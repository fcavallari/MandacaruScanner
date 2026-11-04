# What hacked-site owners can't get from today's scanners

Source: the WordPress.org support forum tag [`hacked`](https://wordpress.org/support/topic-tag/hacked/). It has 1,470 topics across 49 pages, from about 13 years ago to last week. I collected every title. I then read 65 threads in full, mostly ones about redirects, popups, search results and the visibility of an infection. Research date: 2026-11-04. Thread labels like #162 are positions in the tag listing, newest first; each one links to its thread.

> **Short version.** The incumbents (Wordfence, Sucuri, MalCare, Malcure, Quttera, hosts' scanners) mostly inspect files from inside the site, or fetch the page once from a datacenter with no referrer, no cookies and one user agent. The most frustrating cases in the forum are **conditional redirects**. They fire only for a visitor arriving from Google or Facebook, on a phone, on the first visit, when logged out, or only for Googlebot. Owners and the vendors' own support staff say they **can't reproduce it**, scans come back **clean**, and owners have **no way to check whether a fix worked**. A black-box prober that plays those visitor personas, and compares them, is exactly the missing tool. Pnakotic already has the base for it.

## 1. What the threads show

### 1.1 The redirect only fires for some visitors

The trigger condition shows up again and again. Each row links to threads where it is the defining symptom.

| Trigger | What owners report | Threads |
| --- | --- | --- |
| **Arrived from Google** | Typing the address works. Clicking the Google result goes to pharma, dating or "you won" pages. | [#155](https://wordpress.org/support/topic/unknown-url-opens-at-google-search-instead-of-my-site/), [#162](https://wordpress.org/support/topic/website-redirects-to-spam-from-google-search/), [#166](https://wordpress.org/support/topic/site-hacked-doesnt-load-from-search-please-help/), [#199](https://wordpress.org/support/topic/conditional-hack-on-website/), [#35](https://wordpress.org/support/topic/website-has-popup-saying-youre-a-winner-wordfence-scan-cant-detect-it/) |
| **Mobile only** | The desktop is clean; phones are redirected or see spam links. Owners fix it by swapping header.php or widgets one at a time. | [#569](https://wordpress.org/support/topic/wordpress-redirect-to-an-ip-on-mobile/), [#691](https://wordpress.org/support/topic/malware-redirect-on-mobile-only/), [#1254](https://wordpress.org/support/topic/wordpress-site-redirects-to-porn-on-ipad/), [#1272](https://wordpress.org/support/topic/hacked-website-viagracialis-code-only-showing-up-on-mobile-phone/), [#167](https://wordpress.org/support/topic/amp-version-of-blogposts-hacked/) (AMP pages only) |
| **Narrower device or browser** | Android only; Chrome on iPhone only. | [#452](https://wordpress.org/support/topic/spam-popups-on-android-devices-only/), [#1059](https://wordpress.org/support/topic/spam-content-on-load-from-chrome-on-iphone/) |
| **Arrived from Facebook or social** | Links shared on Facebook land on spam; the same links on Twitter or by email are fine. | [#1437](https://wordpress.org/support/topic/my-links-redirect-to-spam-sites-when-posted-to-facebook/), [#786](https://wordpress.org/support/topic/site-hacked-users-coming-from-facebook-get-pop-ups/), [#452](https://wordpress.org/support/topic/spam-popups-on-android-devices-only/) |
| **First visit only** | It redirects once, then never again for that browser. Clearing the cache doesn't bring it back, so the owner can't tell whether it's fixed. | [#162](https://wordpress.org/support/topic/website-redirects-to-spam-from-google-search/), [#1254](https://wordpress.org/support/topic/wordpress-site-redirects-to-porn-on-ipad/) |
| **Logged out only** | Admins never see it, because the malware hides itself from logged-in users. | [#340](https://wordpress.org/support/topic/hacked-by-redirection/), [#518](https://wordpress.org/support/topic/malicious-text-appears-when-i-am-logged-off/), [#51](https://wordpress.org/support/topic/adsmatcher-anti-adblock-plugin-was-hacked-and-now-opens-ads-on-clicks/) |
| **Googlebot only (cloaking)** | Visitors see the real site; Google sees a Chinese, Japanese or pharma site, and Search Console shows a render mismatch. Some owners used a third-party "view as Googlebot" page to see it. | [#595](https://wordpress.org/support/topic/search-console-googlebot-and-visitor-render-mismatch-after-hack-cleanup/), [#1120](https://wordpress.org/support/topic/page-only-googlebot-can-see-after-a-hack/), [#184](https://wordpress.org/support/topic/help-with-pharma-hack/), [#201](https://wordpress.org/support/topic/chinese-pages-in-my-sitemap/) (the sitemap differs when `?` is added) |
| **Intermittent or after interaction** | It happens sometimes, or after clicking around several pages. Some cases are click-triggered new tabs. | [#35](https://wordpress.org/support/topic/website-has-popup-saying-youre-a-winner-wordfence-scan-cant-detect-it/), [#614](https://wordpress.org/support/topic/hacked-site-intermittent-new-tab-advertising/), [#51](https://wordpress.org/support/topic/adsmatcher-anti-adblock-plugin-was-hacked-and-now-opens-ads-on-clicks/) |

### 1.2 The scanners come back clean

The same pattern runs through these threads: the visitor sees an attack, and every tool says the site is fine.

- **Wordfence support couldn't reproduce it.** In [#36](https://wordpress.org/support/topic/website-has-pop-up-doesnt-show-up-in-wordfence-scan/) the support rep clicked around the site and saw no popup, while the owner's customers were complaining. In [#18](https://wordpress.org/support/topic/hacked-got-no-warning-got-nothing-by-wordfence/), support explains that Wordfence is an endpoint firewall and the attack came from outside it.
- **Sucuri SiteCheck said clean while visitors were redirected:** [#569](https://wordpress.org/support/topic/wordpress-redirect-to-an-ip-on-mobile/) (every tool passed it), [#614](https://wordpress.org/support/topic/hacked-site-intermittent-new-tab-advertising/), [#646](https://wordpress.org/support/topic/website-isnt-hacked-but-readers-are-being-redirected-off-my-blog/) and [#1254](https://wordpress.org/support/topic/wordpress-site-redirects-to-porn-on-ipad/). In another thread, the owner notices that SiteCheck was showing an old, cached result.
- **Owners stack several scanners because each one's database is different.** In [#233](https://wordpress.org/support/topic/hacked-but-wordfecnce-does-not-pick-up-on-it/), 50+ sites had a homepage redirect. Wordfence found nothing, and only MalCare found the two scripts, at a price the owner called too high for 100 sites.
- **Hosts can't reproduce it either.** In [#614](https://wordpress.org/support/topic/hacked-site-intermittent-new-tab-advertising/) the host couldn't find where the injected script came from. In [#646](https://wordpress.org/support/topic/website-isnt-hacked-but-readers-are-being-redirected-off-my-blog/) the host couldn't replicate it, so it couldn't help.
- **Injected markup isn't in the PHP.** In [#1272](https://wordpress.org/support/topic/hacked-website-viagracialis-code-only-showing-up-on-mobile-phone/), a helper finds a class in view-source that the owner then can't find in any template. It was being added by script. In [#293](https://wordpress.org/support/topic/siteurl-hacked-to-redirect-to-another-site/), the redirect lived in `wp_options` and post content. There was no file for a file scanner to flag.

### 1.3 "How do I know it's fixed?"

The owner in [#162](https://wordpress.org/support/topic/website-redirects-to-spam-from-google-search/) asks directly for a way to check again and again whether the problem is fixed. This comes back after cleanup too:

- In [#595](https://wordpress.org/support/topic/search-console-googlebot-and-visitor-render-mismatch-after-hack-cleanup/), the homepage still renders differently for Googlebot after cleanup.
- In [#166](https://wordpress.org/support/topic/site-hacked-doesnt-load-from-search-please-help/), a Google click lands on a 404 for a deleted malware file.

Reinfection is common. About 38 titles mention the infection coming back ("keeps", "again", "revert"), for example [#3](https://wordpress.org/support/topic/reinfection-after-cleanup-craft-system-orb-backdoor-immutable-files/), [#42](https://wordpress.org/support/topic/index-php-and-htaccess-revert-to-hacked-version/) and [#291](https://wordpress.org/support/topic/malware-keeps-coming-back/). Owners find out from customers, not from a monitor.

### 1.4 Hack or bad ad?

In [#646](https://wordpress.org/support/topic/website-isnt-hacked-but-readers-are-being-redirected-off-my-blog/), iPhone readers on wifi were sent to "you won a prize" pages. The redirects stopped when ads were turned off, but came back with any ad network, even AdSense alone. The ad network blames the site, and the site blames the ad network. In [#786](https://wordpress.org/support/topic/site-hacked-users-coming-from-facebook-get-pop-ups/), the helpers' best guess is "mobile-only malvertising". Nobody can say which script started the navigation.

### 1.5 What the lure looks like

Recent lures, as the owners describe them:

- A fake CAPTCHA wall ([#72](https://wordpress.org/support/topic/fake-captcha-redirect-on-my-site/)).
- A fake "Windows Critical Update" popup, built with SweetAlert ([#185](https://wordpress.org/support/topic/possible-malware-pop-up-on-my-site/)).
- "You're a winner" popups ([#35](https://wordpress.org/support/topic/website-has-popup-saying-youre-a-winner-wordfence-scan-cant-detect-it/)).
- Ads opening in a new tab on every click ([#51](https://wordpress.org/support/topic/adsmatcher-anti-adblock-plugin-was-hacked-and-now-opens-ads-on-clicks/), [#614](https://wordpress.org/support/topic/hacked-site-intermittent-new-tab-advertising/)).

### 1.6 How often it comes up

These numbers come from matching words in the 1,470 titles, so read them as lower bounds. Most titles are just "Website hacked".

| Titles mentioning… | All 1,470 | Last ~5 years (263) |
| --- | ---: | ---: |
| Redirect / hijack / forward | 64 | 12 |
| Popup / ads / new tab / prize / captcha | 46 | 10 |
| Google / search / SEO / pharma / Japanese / sitemap | 77 | 15 |
| A trigger condition (mobile, Android, iPhone, Facebook, "only", logged off) | 24 | 3 |
| Scanner missed it ("didn't detect", "despite", "got nothing") | 28 | 12 |
| Reinfection ("again", "keeps", "coming back", "revert") | 38 | 10 |
| Lockout / rogue admin / password (broad match) | 194 | 44 |
| Tagged to a specific plugin's forum | 340 | — |

The "scanner missed it" share has gone up recently: 12 of 263 in the last ~5 years, against 28 of 1,470 overall.

## 2. Where Pnakotic stands today

Pnakotic is already a black-box, logged-out visitor. That alone avoids the logged-out-only blind spot and the problem of database-stored payloads with no file to flag. Section 1.2 shows how incumbents miss both. Here is what the engine does now, compared with what the threads need:

| Need from the threads | Pnakotic today | Gap |
| --- | --- | --- |
| Arrived from Google | `search-clicker` sends `Referer: https://www.google.com/` | Covered. Google's result links use referrer policy `origin`, so this is exactly what a real click sends. |
| Mobile (iOS / Android) | `mobile-ios`, `mobile-android` | Covered. **Built:** Chrome user agents now carry the scanning browser's real major version, instead of a fixed Chrome/120 that cloakers could treat as a bot. The client hints (`sec-ch-ua*`) match each persona; before this, they named `HeadlessChrome` on every request. The iOS persona still sends an empty `sec-ch-ua` where real Safari sends none. |
| Arrived from Facebook or social, and in-app browsers | `facebook-android` (**built**): the Facebook app's in-app browser, the `l.facebook.com` referrer and `X-Requested-With: com.facebook.katana` | `t.co` (X) and the Facebook iOS app are still missing. |
| Googlebot cloaking | `googlebot` (**built**): the Googlebot Smartphone user agent | This catches cloaking that checks only the user agent. Cloakers that verify Googlebot by reverse DNS still see our datacenter IP. |
| First visit vs. return visit | A new context every probe, so it always looks like a first visit | **Half covered.** Probing twice in the same context, with cookies kept, would show "fires once, then hides". It would also explain why the owner can't reproduce it. |
| Intermittent | One probe | **Missing.** N probes give a firing rate ("redirected 3 of 10 times"). |
| Click-triggered / new tab | **Built:** each blocked `window.open` / new-tab attempt becomes a `popup_open` hop, recorded from CDP `Page.windowOpen` and never loaded. After the landing is captured, one click on an empty spot of the page catches popunders (`trigger: click`) and click hijacks (`click_hijack`). | Cross-site popups score 0.3 and click hijacks 0.4, each applied once. |
| Compare personas | One profile per probe | **Missing, and this is the product.** "Probe as all personas, show where the landing pages differ" turns the owners' manual header.php swapping into one screen. |
| Did my fix work? / reinfection | Manual re-probe | **Missing.** Scheduled re-probes of a saved target, with an alert when the chain or landing page changes. |
| Hack vs. malvertising | Hops record which mechanism navigated | **Missing.** Use the CDP initiator (script URL and stack) for each navigation. Report "fired by `/wp-content/plugins/<slug>/…`" (a first-party compromise, with the plugin named) or "fired by a script from `<ad network>`" (malvertising). |
| A lure screenshot that helpers believe | A full-page screenshot | Covered. A shareable read-only probe link would let the owner hand evidence to the host, ad network or vendor who "can't reproduce". |
| Lure type | Regex signatures (atob, fromCharCode, location, meta refresh, b64) | **Missing.** Signatures for fake CAPTCHA, "paste this" clipboard lures and fake browser updates. |

## 3. Out of scope, on purpose

The largest categories in the tag are **lockouts, rogue admins and password changes** (194 titles), and **server-side persistence**:

- Immutable files and `.user.ini` prepends ([#3](https://wordpress.org/support/topic/reinfection-after-cleanup-craft-system-orb-backdoor-immutable-files/)).
- Self-regenerating droppers ([#13](https://wordpress.org/support/topic/malware-keeps-creating-wp-includes-capabilities-request-php-file/), [#42](https://wordpress.org/support/topic/index-php-and-htaccess-revert-to-hacked-version/)).

Neither is a URL prober's job. Pnakotic can't see inside the server, and it shouldn't claim to clean anything. It is still useful next to them: it is the outside view that confirms the visitor-facing symptom is gone, and keeps checking.

## 4. Suggested order

1. ~~**Popup-attempt capture.**~~ Built (2026-11-04), along with the click probe.
2. ~~**New personas.**~~ Built (2026-11-04): `facebook-android`, `googlebot`, and Chrome user agents that follow the real browser version.
3. **Multi-persona probe with a divergence view.** This is the headline feature: "Desktop and Google-arrival land in different places."
4. **Return-visit and repeat probes,** to measure first-visit-only and intermittent behaviour as a firing rate.
5. **Initiator attribution.** It names the plugin, theme or ad script that fired the redirect, which owners can't find on their own.
6. **Scheduled watch with change alerts,** for reinfection.
7. **Lure signatures** for fake CAPTCHA, clipboard lures and fake updates.

Caveat: Pnakotic scans from a datacenter IP. Some traffic-distribution systems filter by geography or a residential IP (in [#646](https://wordpress.org/support/topic/website-isnt-hacked-but-readers-are-being-redirected-off-my-blog/) it happened "only on wifi"). Egress location is a later concern, and the egress proxy is where it would go.
