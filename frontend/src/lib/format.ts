import type { Hop, TaskState } from './api';

/* ---------- URL anatomy ---------- */

export function hostnameOf(raw: string | null | undefined): string {
  if (!raw) return '';
  try {
    return new URL(raw).hostname;
  } catch {
    return raw; // relative or malformed — print as-is, honestly
  }
}

export function isIpHost(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || host.includes(':');
}

/** registrable-ish apex: last two labels (mirrors the scorer's _apex). An IP stays whole. */
export function apexOf(raw: string | null | undefined): string {
  const host = hostnameOf(raw).toLowerCase();
  if (isIpHost(host)) return host;
  const parts = host.split('.');
  return parts.length >= 2 ? parts.slice(-2).join('.') : host;
}

export function tldOf(raw: string | null | undefined): string {
  const host = hostnameOf(raw).toLowerCase();
  return host.includes('.') ? host.split('.').pop()! : '';
}

/** Shorten a host from the left so its ending (apex and TLD, the telling part) survives. */
export function shortHost(host: string, max = 30): string {
  return host.length <= max ? host : `…${host.slice(host.length - (max - 1))}`;
}

/* ---------- hops (mirrors REDIRECT_MECHANISMS in src/scanner/models.py) ---------- */

export const REDIRECT_MECHANISMS = new Set(['http_3xx', 'meta_refresh', 'js_location']);

/** Real redirects only: obfuscation and static findings are evidence, not hops. */
export function redirectCount(hops: Hop[] | null | undefined): number {
  return (hops ?? []).filter((h) => REDIRECT_MECHANISMS.has(h.mechanism)).length;
}

export const MECHANISM_LABELS: Record<string, string> = {
  http_3xx: 'HTTP redirect',
  meta_refresh: 'Meta refresh',
  js_location: 'JS location',
  meta_refresh_code: 'Meta refresh code',
  js_location_code: 'JS location code',
  client_navigation: 'Navigation',
  js_obfuscation: 'Obfuscation',
  clickfix_lure: 'ClickFix lure',
  page_behavior: 'Page behavior',
  yara_match: 'YARA match',
  static_analysis: 'Static finding',
  popup_open: 'Popup',
  click_hijack: 'Click hijack',
};

const SIGNATURE_LABELS: Record<string, string> = {
  js_atob: 'atob() obfuscation',
  js_fromCharCode: 'fromCharCode obfuscation',
  js_location_assignment: 'JS location code',
  meta_refresh: 'Meta refresh code',
  b64_payload: 'Base64 payload',
  clickfix_lure: 'ClickFix lure text',
  // page_behavior event ids (src/scanner/behavior.py)
  clipboard_write: 'Clipboard write',
  download: 'Forced download',
  dialog: 'JS dialog',
  dialog_flood: 'Dialog loop',
  fullscreen_request: 'Fullscreen request',
  keyboard_lock: 'Keyboard lock',
  notification_request: 'Notification prompt',
  beforeunload_trap: 'Leave-page handler',
  history_flood: 'History stuffing',
};

/** Words for what a hop is; static hops carry the signature id in their JSON evidence.
 *  Observed redirects also carry an evidence id (equal to their mechanism, e.g. "meta_refresh"),
 *  which would collide with the signature ids above, so they skip the signature lookup. */
export function hopLabel(hop: Hop): string {
  // Popups and click hijacks: name where they tried to send the visitor, and what set them off.
  if ((hop.mechanism === 'popup_open' || hop.mechanism === 'click_hijack') && hop.evidence) {
    try {
      const ev = JSON.parse(hop.evidence);
      const to = typeof ev?.to === 'string' ? hostnameOf(new URL(ev.to, hop.url).toString()) : '';
      const base = MECHANISM_LABELS[hop.mechanism];
      const when = hop.mechanism === 'popup_open' && ev?.trigger === 'click' ? ' on click' : '';
      return to ? `${base}${when} → ${to}` : `${base}${when}`;
    } catch {
      /* fall through to the mechanism label */
    }
  }
  if (!REDIRECT_MECHANISMS.has(hop.mechanism) && hop.evidence) {
    try {
      const ev = JSON.parse(hop.evidence);
      const id = ev?.id;
      if (id === 'yara_match' && typeof ev.rule === 'string') return `YARA ${ev.rule}`;
      if (id && SIGNATURE_LABELS[id]) return SIGNATURE_LABELS[id];
    } catch {
      /* free-text evidence: fall back to the mechanism */
    }
  }
  return MECHANISM_LABELS[hop.mechanism] ?? hop.mechanism;
}

/* ---------- time ---------- */

/** Recency in words: "just now", "2m", "3h", "5d" — then a quiet date. */
export function relativeTime(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const s = Math.max(0, Math.floor((now - then) / 1000));
  if (s < 45) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  const d = Math.floor(h / 24);
  if (d < 7) return `${d}d`;
  const dt = new Date(then);
  return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function clockTime(d = new Date()): string {
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

/* ---------- verdict (mirrors the scorer's thresholds) ---------- */

export type Verdict = 'Malicious' | 'Suspicious' | 'Watch' | 'Benign';

export function verdictOf(score: number): Verdict {
  if (score >= 0.75) return 'Malicious';
  if (score >= 0.4) return 'Suspicious';
  if (score > 0) return 'Watch';
  return 'Benign';
}

/** polarity class for a score: colour says bad, not up. */
export function scoreTone(score: number): 'negative' | 'warning' | 'ink' {
  if (score >= 0.75) return 'negative';
  if (score >= 0.4) return 'warning';
  return 'ink';
}

/* ---------- the product's own knowledge (mirrors src/intelligence/scorer.py) ---------- */

export const SUSPICIOUS_TLDS = new Set(['xyz', 'top', 'icu', 'gq', 'tk', 'ml']);
export const HIGH_VALUE_APEXES = new Set(['google.com', 'x.com', 'twitter.com', 'apple.com', 'microsoft.com']);

export const PROFILE_LABELS: Record<string, string> = {
  default: 'Default desktop',
  'mobile-ios': 'Mobile iOS',
  'mobile-android': 'Mobile Android',
  'search-clicker': 'Search referrer',
  'facebook-android': 'Facebook app (Android)',
  googlebot: 'Googlebot',
};

/** Short persona names for the two-line list rows. */
export const PROFILE_SHORT: Record<string, string> = {
  default: 'Desktop',
  'mobile-ios': 'iOS',
  'mobile-android': 'Android',
  'search-clicker': 'Search ref.',
  'facebook-android': 'Facebook',
  googlebot: 'Googlebot',
};

export function profileShort(profile: string | null | undefined): string {
  return (profile && PROFILE_SHORT[profile]) || 'Desktop';
}

export function profileLabel(profile: string | null | undefined): string {
  return (profile && PROFILE_LABELS[profile]) || 'Default desktop';
}

/* ---------- aggregates computed from the rows (one source of truth) ---------- */

export interface Kpis {
  scans: number; // all jobs, any status
  completed: number;
  failed: number;
  chainsDetected: number; // completed with a redirect chain
  highestScore: number | null; // max malicious_score among completed (null = none)
  medianHops: number | null; // median hop count among completed (null = none)
  highValueLandings: number; // completed, chain detected, landed on a high-value apex
}

export function computeKpis(tasks: TaskState[]): Kpis {
  const completed = tasks.filter((t) => t.status === 'completed' && t.result);
  const scores = completed.map((t) => t.result!.malicious_score ?? 0);
  const hopCounts = completed.map((t) => redirectCount(t.result!.hops));
  const sorted = [...hopCounts].sort((a, b) => a - b);
  const median =
    sorted.length === 0
      ? null
      : sorted.length % 2
        ? sorted[(sorted.length - 1) / 2]
        : Math.round(((sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2) * 10) / 10;

  return {
    scans: tasks.length,
    completed: completed.length,
    failed: tasks.filter((t) => t.status === 'failed').length,
    chainsDetected: completed.filter((t) => t.result!.is_redirect_chain_detected).length,
    highestScore: scores.length ? Math.max(...scores) : null,
    medianHops: median,
    highValueLandings: completed.filter(
      (t) => t.result!.is_redirect_chain_detected && HIGH_VALUE_APEXES.has(apexOf(t.result!.final_url)),
    ).length,
  };
}

/** The one finding: the fact in this data that most needs attention. */
export function computeFinding(tasks: TaskState[]): string {
  const k = computeKpis(tasks);
  if (k.scans === 0) return 'Nothing collected yet.';
  const parts: string[] = [];
  if (k.highValueLandings > 0) {
    parts.push(
      `${k.highValueLandings} of ${k.completed} completed probe${k.completed === 1 ? '' : 's'} ended on a high-value domain after redirect`,
    );
  }
  if (k.failed > 0) parts.push(`${k.failed} failed to load`);
  if (parts.length === 0) {
    return k.completed > 0 ? 'No high-value landings, no failures. Quiet, for now.' : 'Probes in the field. Nothing back yet.';
  }
  return parts.join(' · ');
}

export interface IntelAggregates {
  mechanisms: Array<{ mechanism: string; count: number }>; // redirect hops by mechanism, desc
  suspiciousTlds: Array<{ tld: string; count: number }>; // landing TLDs in the suspicious set, desc
  landings: Array<{ apex: string; count: number; highValue: boolean }>; // top landing apexes, desc
}

export function computeIntel(tasks: TaskState[]): IntelAggregates {
  const completed = tasks.filter((t) => t.status === 'completed' && t.result);
  const mech = new Map<string, number>();
  const tlds = new Map<string, number>();
  const apexes = new Map<string, { count: number; highValue: boolean }>();

  for (const t of completed) {
    const r = t.result!;
    for (const h of r.hops ?? []) {
      if (REDIRECT_MECHANISMS.has(h.mechanism)) {
        mech.set(h.mechanism, (mech.get(h.mechanism) ?? 0) + 1);
      }
    }
    const tld = tldOf(r.final_url);
    if (tld && SUSPICIOUS_TLDS.has(tld)) tlds.set(tld, (tlds.get(tld) ?? 0) + 1);
    const apex = apexOf(r.final_url);
    if (apex) {
      const e = apexes.get(apex) ?? { count: 0, highValue: false };
      e.count += 1;
      e.highValue = HIGH_VALUE_APEXES.has(apex);
      apexes.set(apex, e);
    }
  }

  const byCount = <T extends { count: number }>(rows: T[]) => rows.sort((a, b) => b.count - a.count);

  return {
    mechanisms: byCount([...mech.entries()].map(([mechanism, count]) => ({ mechanism, count }))),
    suspiciousTlds: byCount([...tlds.entries()].map(([tld, count]) => ({ tld, count }))),
    landings: byCount(
      [...apexes.entries()].map(([apex, e]) => ({ apex, count: e.count, highValue: e.highValue })),
    ).slice(0, 5),
  };
}
