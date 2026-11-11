import axios from 'axios';

// Overridable at build time (frontend/Dockerfile ARG); defaults to the compose port mapping.
export const API_BASE: string = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000';

const http = axios.create({ baseURL: API_BASE });

/* ---------- shapes (mirror src/api/main.py) ---------- */

export type TaskStatus = 'queued' | 'running' | 'completed' | 'failed';

export interface Hop {
  url: string;
  status_code?: number | null;
  mechanism: string; // http_3xx | meta_refresh | js_location | client_navigation | meta_refresh_code | js_location_code | js_obfuscation | clickfix_lure | page_behavior | yara_match | static_analysis | origin
  headers?: Record<string, string>; // the engine stores response headers (Location etc.)
  evidence?: string | null;
}

export interface ArtifactEntry {
  name: string;
  rel_path: string; // relative to the task folder, e.g. screenshots/landing_*.png
}

/** One browser profile's own view of the URL (the requested one first). `error`: its page failed. */
export interface ProfileVariant {
  profile: string;
  requested?: boolean;
  final_url?: string | null;
  malicious_score?: number; // that profile's own score, before the job folds them together
  redirects?: number;
  decisive?: string[];
  raw_error?: string | null;
  error?: string;
}

/** Set when profiles landed on different registrable domains (src/intelligence/scorer.py combine). */
export interface Cloaking {
  landings: Record<string, string>; // profile -> landing apex ('' when its page never loaded)
  common: string; // the landing most profiles got
  steered: string[]; // profiles that landed elsewhere
  suspicious: string[]; // profiles whose own page scored Suspicious or worse
}

/* ---------- site quick check (mirror src/scanner/site_findings.py and site_report.py) ---------- */

export type SiteVerdict = 'compromised' | 'suspicious' | 'partly_checked' | 'clean' | 'couldnt_check';
export type FindingSeverity = 'compromised' | 'suspicious';
/** served: the HTML the server sent; rendered: added while the page loaded; frame: in an embedded frame;
 *  script: in a script file; null: unknown (no served HTML) or not a code finding. */
export type FindingOrigin = 'served' | 'rendered' | 'frame' | 'script' | 'runtime';
export type LoadState = 'checked' | 'partial' | 'not_checked';
export type LoadReason = 'budget' | 'timeout' | 'load_failed' | 'challenge';

/** A window of page-supplied text around a match; offsets are code points into `text`. */
export interface Snippet {
  text: string;
  match_start: number;
  match_end: number;
  line: number | null; // 1-based; null when the snippet is evidence, not code (e.g. where visitors land)
}

export interface SiteFindingDetails {
  rule: string | null;
  signature_id: number | null;
  mechanism: string;
  profiles: string[];
  screenshots: string[]; // rel paths under the task folder
  scoring: string[];
  initiator: string | null;
  offsite?: boolean; // code on the page a visitor was sent to on another site; `pages` are the owner's pages that sent them
  frames?: string[]; // card_inputs: the URLs of the code that inserted the card fields ("" = code with no file), at most 10
}

export interface SiteFinding {
  id: string;
  severity: FindingSeverity;
  kind: string; // yara | injection | flagged_script | runtime_code | card_inputs | clipboard | download | browser_lock | cloaking | offsite_homepage | page_score
  message: string;
  snippet: Snippet | null;
  origin: FindingOrigin | null;
  visitors: string[];
  all_visitors: boolean;
  pages: string[];
  pages_more: number;
  loaded_by: string[];
  loaded_by_more: number;
  loaded: string[];
  loaded_more: number;
  details: SiteFindingDetails;
}

/** One place the owner has to fix something: a page URL or a script URL. */
export interface SiteBlock {
  location: string;
  location_kind: 'page' | 'script';
  findings: SiteFinding[];
  findings_more: number;
  probe?: boolean; // located at the 404 probe URL (the site's "page not found" page)
}

export interface ExternalScriptUrl {
  url: string;
  pages: string[];
  profiles: string[];
  how: 'html' | 'script';
  injected_by: string | null; // the injecting script's URL, or "inline on <page>"
  in_frame: string | null; // the frame's host when requested inside a frame
  finding: boolean; // tied to a finding
}

export interface ExternalScriptHost {
  host: string;
  your_domain: boolean;
  urls: ExternalScriptUrl[];
}

export interface SiteLoad {
  profile: string;
  state: LoadState;
  reason: LoadReason | null;
  status: number | null;
  screenshot: string | null; // rel path under the task folder
  score: number | null;
  landing: string | null;
}

export interface SiteCheckedPage {
  index: number; // 0 = the homepage
  url: string;
  probe?: boolean; // the 404 probe (/pnakotic-<hex>/): the site's "page not found" page
  // src/scanner/site_report.py _card_fields; none of these is a finding
  card_fields?: boolean; // the page has card inputs of its own (served, or added by the store's or a known vendor's code)
  card_fields_unchecked?: boolean; // whose code added its card inputs couldn't be checked on some load
  card_fields_vendors?: string[]; // known vendors (Hotjar, ...) whose code added card inputs
  loads: SiteLoad[];
}

export interface SiteChecked {
  pages: SiteCheckedPage[];
  rules: number; // YARA rule files loaded; 0 = not configured
  scripts_scanned: number;
  frames_scanned: number;
  not_checked: number;
  total: number;
}

export interface SiteReportData {
  site: string;
  entered: string;
  redirected_from: string | null;
  verdict: { verdict: SiteVerdict; label: string; summary: string; rules_loaded: boolean };
  blocks: SiteBlock[];
  blocks_more: number; // blocks past the 50-block cap, plus blocks the 200-finding cap left empty
  findings_more_total?: number; // findings dropped by the report-wide 200-finding cap (not in any block's findings_more)
  external_scripts: { hosts: ExternalScriptHost[]; hosts_more: number; urls_more: number };
  checked: SiteChecked;
  blocked_hosts: string[];
  notes: string[];
  // a CDN bot check kept some loads out (src/scanner/site_report.py challenge_summary); null when none did
  challenge?: SiteChallenge | null;
}

export interface SiteChallenge {
  vendor: 'cloudflare' | 'ddos-guard' | 'incapsula' | null;
  loads: number; // loads the check kept out
  of: number; // loads in the whole check
  homepage: boolean; // one of them was the homepage
}

/** Identical in /tasks (list) and /tasks/{id}/results — the API returns one shape. */
export interface ScanResultData {
  kind?: 'url' | 'site';
  final_url: string | null;
  malicious_score: number; // 0..1
  is_redirect_chain_detected: boolean;
  hops: Hop[];
  artifacts: { artifacts?: ArtifactEntry[] };
  findings?: string[];
  decisive?: string[]; // findings that settle the verdict alone (score forced to 1); also first in findings
  variants?: ProfileVariant[]; // empty unless the probe compared profiles
  cloaking?: Cloaking | null;
  yara?: { rules: number; buffers: number; bytes: number; budget_exhausted: boolean; scripts_dropped?: number } | null;
  raw_error?: string | null;
  site?: SiteReportData | null; // site surveys only
  cleanup_url?: string; // site surveys only
}

export interface TaskState {
  task_id: string;
  status: TaskStatus;
  kind: 'url' | 'site';
  target_url: string;
  profile?: string | null;
  error?: string | null;
  created_at?: string | null; // ISO timestamp from the API
  result?: ScanResultData | null;
}

/* ---------- endpoints ---------- */

export async function listTasks(limit = 20): Promise<TaskState[]> {
  const res = await http.get('/tasks', { params: { limit } });
  return (res.data.tasks ?? []) as TaskState[];
}

export async function startScan(url: string, profile: string): Promise<string> {
  const res = await http.post('/scan', { url, profile });
  return res.data.task_id as string;
}

/** `site`: a bare host or a URL; the API normalises it to the homepage. */
export async function startSiteScan(site: string): Promise<string> {
  const res = await http.post('/site-scan', { site });
  return res.data.task_id as string;
}

export async function taskStatus(taskId: string): Promise<{ status: TaskStatus; error?: string | null }> {
  const res = await http.get(`/tasks/${taskId}/status`);
  return { status: res.data.status, error: res.data.error ?? null };
}

export async function taskResults(taskId: string): Promise<ScanResultData> {
  const res = await http.get(`/tasks/${taskId}/results`);
  return res.data.result as ScanResultData;
}

export function artifactUrl(taskId: string, relPath: string): string {
  return `${API_BASE}/tasks/${taskId}/artifacts/${relPath}`;
}
