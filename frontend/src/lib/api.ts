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

/** Identical in /tasks (list) and /tasks/{id}/results — the API returns one shape. */
export interface ScanResultData {
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
}

export interface TaskState {
  task_id: string;
  status: TaskStatus;
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
