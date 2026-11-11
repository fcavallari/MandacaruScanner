import React from 'react';
import type {
  ExternalScriptHost,
  LoadReason,
  ScanResultData,
  SiteBlock,
  SiteChallenge,
  SiteCheckedPage,
  SiteFinding,
  SiteLoad,
  SiteReportData,
  SiteVerdict,
  Snippet,
} from '../lib/api';
import { artifactUrl } from '../lib/api';
import { profileLabel } from '../lib/format';

/**
 * The site survey report, layout A (spec §6): grouped by where the code lives.
 * The reader is a worried site owner, so the body is plain language — no ritual words.
 * Everything in a finding is page-supplied text: it is rendered as text nodes only.
 */

/* ---------- verdict tone (shared with the list and the header) ---------- */

const PILL: Record<'negative' | 'warning' | 'neutral' | 'positive', React.CSSProperties> = {
  negative: { background: 'var(--pill-negative-bg)', color: 'var(--negative)' },
  warning: { background: 'var(--pill-warning-bg)', color: 'var(--warning)' },
  neutral: { background: 'var(--pill-neutral-bg)', color: 'var(--pill-neutral-ink)' },
  positive: { background: 'var(--pill-positive-bg)', color: 'var(--positive)' },
};

/** Clean without malware rules loaded is not a reassuring result, so it stays neutral. */
export function siteVerdictTone(verdict: SiteVerdict | undefined, rulesLoaded?: boolean): 'negative' | 'warning' | 'neutral' | 'positive' {
  if (verdict === 'compromised') return 'negative';
  if (verdict === 'suspicious') return 'warning';
  if (verdict === 'clean') return rulesLoaded === false ? 'neutral' : 'positive';
  return 'neutral';
}

export function SiteVerdictPill({ verdict, label, rulesLoaded }: { verdict: SiteVerdict | undefined; label: string; rulesLoaded?: boolean }) {
  return (
    <span className="px-2.5 py-1 text-[13px] leading-none font-medium rounded-full whitespace-nowrap" style={PILL[siteVerdictTone(verdict, rulesLoaded)]}>
      {label}
    </span>
  );
}

/* ---------- small pieces ---------- */

const REASONS: Record<LoadReason, string> = {
  budget: "not checked: we ran out of time",
  timeout: 'not checked: took too long to load',
  load_failed: "not checked: couldn't load",
  challenge: 'not checked: showed our scanner a bot check',
};

const ORIGINS: Record<string, string> = {
  served: 'Found in the HTML your server sent',
  rendered: 'Added by a script while the page loaded',
  frame: 'Inside a frame embedded in the page',
  script: 'In this script file',
  runtime: 'Built and run by code on this page while it loaded',
};

/** The 404 probe (/pnakotic-<hex>/) is shown by what it is, with its URL under it. */
const PROBE_LABEL = "Your 'page not found' page";
/** A WooCommerce store's checkout page, shown the same way. */
const CHECKOUT_LABEL = 'Your checkout page';

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? '' : 's'}`;
}

function SectionTitle({ children, meta }: { children: React.ReactNode; meta?: React.ReactNode }) {
  return (
    <p className="text-[15px] font-semibold text-ink m-0 mb-2.5">
      {children}
      {meta != null ? <span className="font-normal text-muted"> · {meta}</span> : null}
    </p>
  );
}

function More({ n, noun }: { n: number; noun: string }) {
  return n > 0 ? <li className="text-[12px] text-faint">and {plural(n, `more ${noun}`)}</li> : null;
}

function UrlList({ urls, more, noun }: { urls: string[]; more: number; noun: string }) {
  if (urls.length === 0 && more === 0) return null;
  return (
    <ul className="m-0 p-0 list-none space-y-0.5">
      {urls.map((u) => (
        <li key={u} className="font-mono text-[12px] text-muted break-all">
          {u}
        </li>
      ))}
      <More n={more} noun={noun} />
    </ul>
  );
}

/** Split by code points: the API's offsets count Python characters, not UTF-16 units. */
function SnippetView({ snippet }: { snippet: Snippet }) {
  const chars = Array.from(typeof snippet.text === 'string' ? snippet.text : '');
  const clamp = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? Math.min(chars.length, Math.max(0, Math.floor(v))) : 0);
  const start = clamp(snippet.match_start);
  const end = Math.max(start, clamp(snippet.match_end));
  return (
    <div>
      <pre className="m-0 bg-ground border border-line rounded-chip px-3 py-2 font-mono text-[12px] leading-[1.6] text-muted whitespace-pre-wrap break-all max-h-[180px] overflow-auto">
        {chars.slice(0, start).join('')}
        <mark className="bg-accent/25 text-ink rounded-[2px]">{chars.slice(start, end).join('')}</mark>
        {chars.slice(end).join('')}
      </pre>
      {typeof snippet.line === 'number' ? <p className="font-mono num text-[12px] text-faint m-0 mt-1">line {snippet.line}</p> : null}
    </div>
  );
}

/** pages/<n>/<profile>/landing_*.png → "homepage · googlebot" / "page 2 · mobile-ios". */
function shotLabel(rel: string): string {
  const m = /^pages\/(\d+)\/([^/]+)\//.exec(rel);
  if (!m) return rel;
  return `${m[1] === '0' ? 'homepage' : `page ${m[1]}`} · ${m[2]}`;
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[96px_minmax(0,1fr)] gap-3">
      <dt className="text-faint">{label}</dt>
      <dd className="m-0 min-w-0">{children}</dd>
    </div>
  );
}

function FindingDetails({ taskId, finding, block }: { taskId: string; finding: SiteFinding; block: SiteBlock }) {
  const d = finding.details;
  const profiles = d?.profiles ?? [];
  const screenshots = d?.screenshots ?? [];
  const scoring = d?.scoring ?? [];
  return (
    <details>
      <summary className="text-[13px] text-muted hover:text-ink cursor-pointer select-none w-fit">Details</summary>
      <dl className="m-0 mt-2 space-y-1.5 text-[13px]">
        {d?.rule ? (
          <DetailRow label="Rule">
            <span className="font-mono text-[12px] text-ink break-all">{d.rule}</span>
          </DetailRow>
        ) : null}
        {d?.signature_id != null ? (
          <DetailRow label="Signature ID">
            <span className="font-mono num text-[12px] text-ink">{d.signature_id}</span>
          </DetailRow>
        ) : null}
        {d?.mechanism ? (
          <DetailRow label="Mechanism">
            <span className="font-mono text-[12px] text-ink">{d.mechanism}</span>
          </DetailRow>
        ) : null}
        {profiles.length > 0 ? (
          <DetailRow label="Profiles">
            <span className="font-mono text-[12px] text-ink">{profiles.join(', ')}</span>
          </DetailRow>
        ) : null}
        {finding.origin === 'runtime' ? (
          // The builder's URL is what the page's own code calls itself, so it is named as the code that built
          // this, never as where the finding is: the finding is on the page.
          <DetailRow label="Built by">
            {d?.initiator ? (
              <span className="font-mono text-[12px] text-muted break-all">{d.initiator}</span>
            ) : (
              <span className="text-[12px] text-muted break-all">
                Built at runtime on <span className="font-mono">{block.location}</span>
              </span>
            )}
          </DetailRow>
        ) : d?.initiator ? (
          <DetailRow label="Added by">
            <span className="font-mono text-[12px] text-muted break-all">{d.initiator}</span>
          </DetailRow>
        ) : null}
        {(d?.frames ?? []).length > 0 ? (
          <DetailRow label="Added by code">
            <ul className="m-0 p-0 list-none space-y-0.5">
              {(d?.frames ?? []).map((u, i) =>
                u ? (
                  <li key={i} className="font-mono text-[12px] text-muted break-all">
                    {u}
                  </li>
                ) : (
                  <li key={i} className="text-[12px] text-muted">
                    Code with no file (built at runtime or hidden)
                  </li>
                ),
              )}
            </ul>
          </DetailRow>
        ) : null}
        {finding.loaded_by.length > 0 || finding.loaded_by_more > 0 ? (
          <DetailRow label="Loaded by">
            <UrlList urls={finding.loaded_by} more={finding.loaded_by_more} noun="source" />
          </DetailRow>
        ) : null}
        {finding.loaded.length > 0 || finding.loaded_more > 0 ? (
          <DetailRow label="Loads">
            <UrlList urls={finding.loaded} more={finding.loaded_more} noun="script" />
          </DetailRow>
        ) : null}
        {scoring.length > 0 ? (
          <DetailRow label="Evidence">
            <ul className="m-0 p-0 list-none space-y-0.5">
              {scoring.map((s, i) => (
                <li key={i} className="text-[12px] text-muted break-words">
                  {s}
                </li>
              ))}
            </ul>
          </DetailRow>
        ) : null}
        {screenshots.length > 0 ? (
          <DetailRow label="Screenshots">
            <span className="flex flex-wrap gap-1.5">
              {screenshots.map((rel) => (
                <a
                  key={rel}
                  href={artifactUrl(taskId, rel)}
                  target="_blank"
                  rel="noreferrer"
                  className="font-mono text-[12px] text-muted bg-ground border border-line rounded-full px-2.5 py-0.5 hover:border-accent hover:text-ink transition-colors"
                >
                  {shotLabel(rel)}
                </a>
              ))}
            </span>
          </DetailRow>
        ) : null}
      </dl>
    </details>
  );
}

function FindingView({ taskId, finding, block }: { taskId: string; finding: SiteFinding; block: SiteBlock }) {
  const compromised = finding.severity === 'compromised';
  const pages = finding.pages ?? [];
  const showPages = block.location_kind === 'script' || pages.length > 1 || (pages.length === 1 && pages[0] !== block.location) || finding.pages_more > 0;
  const offsite = finding.details?.offsite === true;
  const origin = offsite ? 'On the website these visitors were sent to, not on your site' : finding.origin ? ORIGINS[finding.origin] : null;
  const pagesLabel = offsite ? 'Visitors were sent there from' : block.location_kind === 'script' ? 'Loaded on' : 'Found on';
  return (
    <li className="py-3 first:pt-0 last:pb-0 border-b border-rule last:border-b-0 flex flex-col gap-2">
      <div className="flex items-baseline gap-2.5">
        <span
          className="px-2.5 py-1 text-[13px] leading-none font-medium rounded-full whitespace-nowrap flex-none"
          style={compromised ? PILL.negative : PILL.warning}
        >
          {compromised ? 'Compromised' : 'Suspicious'}
        </span>
        <p className="text-[14px] text-ink m-0 break-words min-w-0">{finding.message}</p>
      </div>
      {finding.snippet ? <SnippetView snippet={finding.snippet} /> : null}
      <div className="text-[13px] text-muted space-y-0.5">
        {origin ? <p className="m-0">{origin}</p> : null}
        {finding.all_visitors ? (
          <p className="m-0">Seen by every visitor type</p>
        ) : finding.visitors.length > 0 ? (
          <p className="m-0">Only: {finding.visitors.map((v) => profileLabel(v)).join(', ')}</p>
        ) : null}
      </div>
      {showPages ? (
        <div>
          <p className="text-[12px] text-faint m-0 mb-0.5">{pagesLabel}</p>
          <UrlList urls={pages} more={finding.pages_more} noun="page" />
        </div>
      ) : null}
      <FindingDetails taskId={taskId} finding={finding} block={block} />
    </li>
  );
}

function BlockView({ taskId, block }: { taskId: string; block: SiteBlock }) {
  return (
    <div className="border border-line rounded-card">
      {block.probe ? (
        <div className="px-4 py-2.5 border-b border-rule">
          <p className="text-[13px] text-ink m-0">{PROBE_LABEL}</p>
          <p className="font-mono text-[12px] text-faint m-0 break-all">{block.location}</p>
        </div>
      ) : (
        <div className="px-4 py-2.5 border-b border-rule flex items-baseline gap-2.5">
          <span className="text-[12px] text-faint flex-none">{block.location_kind === 'script' ? 'Script' : 'Page'}</span>
          <span className="font-mono text-[13px] text-ink break-all min-w-0">{block.location}</span>
        </div>
      )}
      <ul className="m-0 p-0 list-none px-4 py-3">
        {block.findings.map((f) => (
          <FindingView key={f.id} taskId={taskId} finding={f} block={block} />
        ))}
        {block.findings_more > 0 ? (
          <li className="pt-2 text-[12px] text-faint">and {plural(block.findings_more, 'more finding')} here</li>
        ) : null}
      </ul>
    </div>
  );
}

/* ---------- external scripts ---------- */

function HostView({ host }: { host: ExternalScriptHost }) {
  const tied = host.urls.some((u) => u.finding);
  return (
    <details className="border-b border-rule last:border-b-0">
      {/* the summary stays display:list-item so it keeps its disclosure marker */}
      <summary className={`px-4 py-2 cursor-pointer select-none text-faint hover:bg-raised/60 transition-colors ${tied ? 'shadow-[inset_1px_0_0_var(--accent)]' : ''}`}>
        <span className="inline-flex flex-wrap items-baseline gap-x-2.5 gap-y-0.5 max-w-[calc(100%-1.5rem)] align-baseline">
          <span className="font-mono text-[13px] text-ink break-all min-w-0">{host.host}</span>
          <span className="font-mono num text-[12px] text-faint whitespace-nowrap">
            {plural(host.urls.length, 'script')}
            {host.your_domain ? ' · your domain' : ''}
            {tied ? ' · tied to a finding' : ''}
          </span>
        </span>
      </summary>
      <ul className="m-0 p-0 list-none px-4 pb-3 pt-1 space-y-2">
        {host.urls.map((u) => (
          <li key={u.url} className="text-[12px]">
            <p className="font-mono text-muted m-0 break-all">{u.url}</p>
            <p className="text-faint m-0">
              {u.how === 'script' ? `Added by a script${u.injected_by ? ` (${u.injected_by})` : ''}` : 'In the page HTML'}
              {u.in_frame ? ` · inside a frame from ${u.in_frame}` : ''}
              {' · '}
              {u.profiles.map((p) => profileLabel(p)).join(', ')}
              {' · '}
              {plural(u.pages.length, 'page')}
            </p>
          </li>
        ))}
      </ul>
    </details>
  );
}

function ExternalScripts({ data }: { data: SiteReportData['external_scripts'] }) {
  const hosts = data?.hosts ?? [];
  return (
    <div>
      <SectionTitle meta={hosts.length === 0 ? 'none' : plural(hosts.length + (data.hosts_more ?? 0), 'other website')}>
        External scripts
      </SectionTitle>
      {hosts.length > 0 ? (
        <>
          <p className="text-[13px] text-faint m-0 mb-2">Scripts your pages load from other websites. Listed for you to recognise, not judged.</p>
          <div className="border border-line rounded-card overflow-hidden">
            {hosts.map((h) => (
              <HostView key={h.host} host={h} />
            ))}
          </div>
          {data.hosts_more > 0 || data.urls_more > 0 ? (
            <p className="text-[12px] text-faint m-0 mt-1.5">
              Not listed: {[data.hosts_more > 0 ? plural(data.hosts_more, 'more website') : '', data.urls_more > 0 ? plural(data.urls_more, 'more script') : '']
                .filter(Boolean)
                .join(', ')}
            </p>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

/* ---------- what was checked ---------- */

function LoadLine({ taskId, load }: { taskId: string; load: SiteLoad }) {
  const tone = load.state === 'checked' ? 'text-muted' : load.state === 'partial' ? 'text-warning' : 'text-negative';
  const words =
    load.state === 'checked'
      ? 'checked'
      : load.state === 'partial'
        ? "didn't finish loading; what loaded was checked"
        : (load.reason && REASONS[load.reason]) || 'not checked';
  return (
    <li className="flex items-baseline gap-2 text-[13px]">
      <span className="text-ink w-[120px] flex-none truncate">{profileLabel(load.profile)}</span>
      <span className={`${tone} min-w-0`}>{words}</span>
      {load.status != null ? <span className="font-mono num text-[12px] text-faint">{load.status}</span> : null}
      {load.screenshot ? (
        <a href={artifactUrl(taskId, load.screenshot)} target="_blank" rel="noreferrer" className="text-[12px] text-muted hover:text-accent transition-colors ml-auto flex-none">
          Screenshot
        </a>
      ) : null}
    </li>
  );
}

/** What the survey saw of the page's own card payment fields (never a finding). A page where
 *  outside code added card fields (a card_inputs finding) doesn't say it has its own. */
function CardFieldsNote({ page, skimmed }: { page: SiteCheckedPage; skimmed: boolean }) {
  const vendors = page.card_fields_vendors ?? [];
  if (!page.card_fields && !page.card_fields_unchecked) return null;
  return (
    <div className="mt-1 text-[13px] text-muted space-y-0.5">
      {page.card_fields && !page.card_fields_unchecked && !skimmed ? <p className="m-0">This page has its own card payment fields</p> : null}
      {vendors.length > 0 ? <p className="m-0">Some were added by {vendors.join(', ')}</p> : null}
      {page.card_fields_unchecked ? (
        <p className="m-0 text-warning">We couldn't check who added this page's card fields</p>
      ) : null}
    </div>
  );
}

function PageView({ taskId, page, skimmed }: { taskId: string; page: SiteCheckedPage; skimmed: boolean }) {
  return (
    <li className="px-4 py-2.5 border-b border-rule last:border-b-0">
      {page.probe || page.checkout ? (
        <div className="mb-1">
          <p className="text-[13px] text-ink m-0">{page.probe ? PROBE_LABEL : CHECKOUT_LABEL}</p>
          <p className="font-mono text-[12px] text-faint m-0 break-all">{page.url}</p>
        </div>
      ) : (
        <p className="font-mono text-[13px] text-ink m-0 mb-1 break-all">
          {page.url}
          {page.index === 0 ? <span className="font-sans text-[12px] text-faint"> · homepage</span> : null}
        </p>
      )}
      <ul className="m-0 p-0 list-none space-y-0.5">
        {page.loads.map((l) => (
          <LoadLine key={l.profile} taskId={taskId} load={l} />
        ))}
      </ul>
      <CardFieldsNote page={page} skimmed={skimmed} />
    </li>
  );
}

function pagesWithFindings(blocks: SiteBlock[]): Set<string> {
  const out = new Set<string>();
  for (const b of blocks) {
    if (b.location_kind === 'page') out.add(b.location);
    for (const f of b.findings) for (const p of f.pages ?? []) out.add(p);
  }
  return out;
}

/** Pages with a card_inputs finding: outside code added card fields there. */
function pagesWithCardFindings(blocks: SiteBlock[]): Set<string> {
  const out = new Set<string>();
  for (const b of blocks) {
    for (const f of b.findings) {
      if (f.kind !== 'card_inputs') continue;
      if (b.location_kind === 'page') out.add(b.location);
      for (const p of f.pages ?? []) out.add(p);
    }
  }
  return out;
}

function WhatWasChecked({ taskId, report }: { taskId: string; report: SiteReportData }) {
  const checked = report.checked;
  const pages = checked?.pages ?? [];
  const flagged = pagesWithFindings(report.blocks ?? []);
  const skimmed = pagesWithCardFindings(report.blocks ?? []);
  // Clean pages fold into "N other pages clean"; the homepage always stays as the anchor.
  // A page whose card fields couldn't be checked stays in view: unchecked must not read as clean.
  const isClean = (p: SiteCheckedPage) =>
    !flagged.has(p.url) && !p.card_fields_unchecked && p.loads.every((l) => l.state === 'checked');
  const shown = pages.filter((p) => p.index === 0 || !isClean(p));
  const folded = pages.filter((p) => p.index !== 0 && isClean(p));
  const blocked = report.blocked_hosts ?? [];

  return (
    <div>
      <SectionTitle meta={`${plural(pages.length, 'page')} · ${plural(checked?.total ?? 0, 'check')}`}>What was checked</SectionTitle>
      <div className="border border-line rounded-card overflow-hidden">
        <ul className="m-0 p-0 list-none">
          {shown.map((p) => (
            <PageView key={p.index} taskId={taskId} page={p} skimmed={skimmed.has(p.url)} />
          ))}
        </ul>
        {folded.length > 0 ? (
          <details className="border-t border-rule">
            <summary className="px-4 py-2 text-[13px] text-muted hover:text-ink cursor-pointer select-none">
              {plural(folded.length, shown.length > 0 ? 'other page' : 'page')} clean
            </summary>
            <ul className="m-0 p-0 list-none border-t border-rule">
              {folded.map((p) => (
                <PageView key={p.index} taskId={taskId} page={p} skimmed={skimmed.has(p.url)} />
              ))}
            </ul>
          </details>
        ) : null}
      </div>
      <ul className="m-0 mt-2 p-0 list-none text-[13px] text-muted space-y-0.5">
        <li>
          {checked && checked.rules > 0 ? (
            <>
              <span className="font-mono num">{checked.rules}</span> malware rule {checked.rules === 1 ? 'file' : 'files'} loaded
            </>
          ) : (
            <span className="text-warning">Malware rules not configured</span>
          )}
        </li>
        <li>
          <span className="font-mono num">{checked?.scripts_scanned ?? 0}</span> {checked?.scripts_scanned === 1 ? 'script' : 'scripts'} and{' '}
          <span className="font-mono num">{checked?.frames_scanned ?? 0}</span> {checked?.frames_scanned === 1 ? 'frame' : 'frames'} scanned
        </li>
        {checked && checked.not_checked > 0 ? (
          <li>
            <span className="font-mono num">{checked.not_checked}</span> of <span className="font-mono num">{checked.total}</span> checks couldn't run
          </li>
        ) : null}
        {blocked.length > 0 ? (
          <li className="text-faint">
            Requests to private addresses were blocked: <span className="font-mono text-[12px] break-all">{blocked.join(', ')}</span>
          </li>
        ) : null}
      </ul>
    </div>
  );
}

/* ---------- the report ---------- */

/* ---------- bot-check alert ---------- */

const VENDOR_NAMES: Record<NonNullable<SiteChallenge['vendor']>, string> = {
  cloudflare: 'Cloudflare',
  'ddos-guard': 'DDoS-Guard',
  incapsula: 'Imperva Incapsula',
};

/**
 * A CDN's bot check stood between the scanner and the site. Says so plainly, says it is not a
 * sign of a hack, and tells the owner how to let a re-check through.
 */
function ChallengeAlert({ data }: { data: SiteChallenge }) {
  const vendor = data.vendor ? VENDOR_NAMES[data.vendor] : null;
  const all = data.loads >= data.of;
  return (
    <div role="note" className="mt-3 rounded-card border border-warning/40 bg-warning/[0.06] px-4 py-3">
      <p className="text-[15px] font-semibold text-warning m-0">
        {vendor ? `${vendor}'s bot check blocked our scanner` : 'A bot check blocked our scanner'}
      </p>
      <p className="text-[14px] text-muted m-0 mt-1.5 leading-relaxed">
        {all ? 'It blocked every check' : `It blocked ${data.loads} of ${data.of} checks`}
        {data.homepage && !all ? ', including your homepage' : ''}, so we couldn't see what your visitors see
        {all || data.homepage ? '' : ' on those pages'}. A bot check is not a sign of a hack.
      </p>
      <p className="text-[14px] text-muted m-0 mt-2 leading-relaxed">
        {data.vendor === 'cloudflare' ? (
          <>
            To check your site, open your Cloudflare dashboard and, for a few minutes, turn off{' '}
            <span className="text-ink">I&apos;m Under Attack</span> mode and{' '}
            <span className="text-ink">Bot Fight Mode</span>, or add a WAF custom rule that skips the bot
            checks. Run the check again, then switch them back.
          </>
        ) : vendor ? (
          <>To check your site, relax {vendor}&apos;s bot protection for a few minutes, run the check again, then switch it back.</>
        ) : (
          <>To check your site, ask your host or CDN to relax its bot protection for a few minutes, then run the check again.</>
        )}
      </p>
    </div>
  );
}

export default function SiteReport({ taskId, result }: { taskId: string; result: ScanResultData }) {
  const report = result.site;
  if (!report) {
    return <p className="text-[14px] text-muted m-0">This site survey has no report.</p>;
  }
  const v = report.verdict;
  const rest = v.summary.startsWith(v.label) ? v.summary.slice(v.label.length) : ` · ${v.summary}`;
  const cleanup = (v.verdict === 'compromised' || v.verdict === 'suspicious') && result.cleanup_url;
  const blocks = report.blocks ?? [];
  const checked = <WhatWasChecked taskId={taskId} report={report} />;
  const external = <ExternalScripts data={report.external_scripts} />;

  return (
    <div className="flex flex-col gap-6">
      {/* 1. the verdict */}
      <div>
        <p className="text-[20px] leading-snug font-semibold text-ink m-0">
          <span className={{ negative: 'text-negative', warning: 'text-warning', neutral: 'text-ink', positive: 'text-positive' }[siteVerdictTone(v.verdict, v.rules_loaded)]}>
            {v.label}
          </span>
          <span className="text-muted font-normal">{rest}</span>
        </p>
        {report.redirected_from ? (
          <p className="text-[13px] text-muted m-0 mt-1">
            Scanned <span className="font-mono text-ink">{report.site}</span> (<span className="font-mono">{report.redirected_from}</span> redirects here)
          </p>
        ) : null}
        {(report.notes ?? []).map((n, i) => (
          <p key={i} className="text-[13px] text-faint m-0 mt-1">
            {n}
          </p>
        ))}
        {report.challenge ? <ChallengeAlert data={report.challenge} /> : null}

        {/* 2. the cleanup pointer */}
        {cleanup ? (
          <a
            href={result.cleanup_url}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 mt-3 text-[14px] font-medium text-accent hover:text-accent/85 border-b border-accent/40 hover:border-accent transition-colors"
          >
            {v.verdict === 'compromised' ? 'Clean it up with Elderward' : 'If you think this is a hack, Elderward can check and clean it'}
            <span aria-hidden="true">→</span>
          </a>
        ) : null}
      </div>

      {/* a clean site leads with what was checked (spec §6.3) */}
      {v.verdict === 'clean' ? checked : null}

      {/* 3. finding blocks */}
      {blocks.length > 0 ? (
        <div>
          <SectionTitle meta={plural(blocks.length + (report.blocks_more ?? 0), 'place')}>Where we found it</SectionTitle>
          <div className="flex flex-col gap-3">
            {blocks.map((b) => (
              <BlockView key={`${b.location_kind}:${b.location}`} taskId={taskId} block={b} />
            ))}
          </div>
          {report.blocks_more > 0 || (report.findings_more_total ?? 0) > 0 ? (
            <p className="text-[12px] text-faint m-0 mt-1.5">
              Not shown:{' '}
              {[report.blocks_more > 0 ? plural(report.blocks_more, 'more place') + ' with findings' : '',
                (report.findings_more_total ?? 0) > 0 ? `+${plural(report.findings_more_total ?? 0, 'more finding')}` : '']
                .filter(Boolean)
                .join(', ')}
            </p>
          ) : null}
        </div>
      ) : null}

      {/* 4. external scripts */}
      {external}

      {/* 5. what was checked */}
      {v.verdict === 'clean' ? null : checked}
    </div>
  );
}
