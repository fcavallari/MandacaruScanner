import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import Mark from './Mark';
import KpiStrip from './KpiStrip';
import ScanForm from './ScanForm';
import SelectedScan from './SelectedScan';
import IntelPanel from './IntelPanel';
import ScanList from './ScanList';
import { API_BASE, listTasks, startScan, startSiteScan, taskResults, taskStatus } from '../lib/api';
import type { TaskState } from '../lib/api';
import { clockTime, computeFinding, computeIntel, computeKpis } from '../lib/format';

type Phase = 'loading' | 'ready' | 'error';

/**
 * The overview screen. One question: "Where did that URL actually go, and how
 * deep is it?" — answered first by the selected probe (chain graph + depth
 * gauge), with the job one click away and every figure computed from the rows.
 */

function FindingLine({ text }: { text: string }) {
  // red is a signal, not a texture: only the failure clause carries it
  return (
    <p className="text-[14px] text-muted m-0 mt-2">
      {text.split(' · ').map((part, i) => (
        <React.Fragment key={i}>
          {i > 0 ? <span className="text-faint"> · </span> : null}
          {/failed/i.test(part) ? <span className="text-negative">{part}</span> : part}
        </React.Fragment>
      ))}
    </p>
  );
}

export default function Dashboard() {
  const [tasks, setTasks] = useState<Record<string, TaskState>>({});
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('loading');
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [now, setNow] = useState(() => Date.now());

  /* ---------- data ---------- */

  const load = useCallback(async (initial: boolean) => {
    if (initial) setPhase('loading'); // a refresh keeps the old values and updates the stamp
    try {
      const list = await listTasks(20);
      setTasks((prev) => {
        const next = { ...prev };
        for (const t of list) next[t.task_id] = t; // the API is the source of truth
        return next;
      });
      setLastUpdated(new Date());
      setPhase('ready');
    } catch {
      // an error only replaces the screen if nothing is on it yet; otherwise keep the data
      setPhase((p) => (initial && p === 'loading' ? 'error' : p));
    }
  }, []);

  useEffect(() => {
    load(true);
  }, [load]);

  // keep relative times honest
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(t);
  }, []);

  // single polling loop for in-flight tasks; no interval while idle
  useEffect(() => {
    const inFlight = Object.values(tasks).filter((t) => t.status === 'queued' || t.status === 'running');
    if (inFlight.length === 0) return;

    const interval = setInterval(async () => {
      for (const task of inFlight) {
        try {
          const st = await taskStatus(task.task_id);
          if (st.status === task.status) continue;
          if (st.status === 'completed') {
            const result = await taskResults(task.task_id);
            setTasks((prev) => ({ ...prev, [task.task_id]: { ...prev[task.task_id], status: st.status, result } }));
          } else if (st.status === 'failed') {
            setTasks((prev) => ({ ...prev, [task.task_id]: { ...prev[task.task_id], status: st.status, error: st.error || 'The probe failed' } }));
          } else {
            setTasks((prev) => ({ ...prev, [task.task_id]: { ...prev[task.task_id], status: st.status } }));
          }
        } catch {
          /* API blip — the next tick retries */
        }
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [tasks]);

  /** Resolves to an error sentence for the form to show inline, or null once the probe is queued. */
  const handleScan = async (url: string, profile: string): Promise<string | null> => {
    try {
      const taskId = await startScan(url, profile);
      setTasks((prev) => ({ ...prev, [taskId]: { task_id: taskId, status: 'queued', kind: 'url', target_url: url, profile } }));
      setSelectedId(taskId); // the lead block follows the new probe
      return null;
    } catch (err) {
      const detail = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
        : null;
      // 400/503 carry the API's sentence; 422 carries pydantic's list of field errors.
      // The voice frames it, the real reason always follows.
      if (typeof detail === 'string') return `The gate is sealed. ${/[.!?]$/.test(detail) ? detail : `${detail}.`}`;
      if (Array.isArray(detail)) return 'The gate is sealed. Only http(s) URLs can be probed.';
      return `The observatory is unreachable. No answer from ${API_BASE}.`;
    }
  };

  /** Same contract for a site survey; polling and the list treat it like any other job. */
  const handleSiteScan = async (site: string): Promise<string | null> => {
    try {
      const taskId = await startSiteScan(site);
      setTasks((prev) => ({ ...prev, [taskId]: { task_id: taskId, status: 'queued', kind: 'site', target_url: site, profile: 'default' } }));
      setSelectedId(taskId);
      return null;
    } catch (err) {
      const detail = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
        : null;
      // 422 carries the normaliser's sentence (a string) or pydantic's list of field errors.
      if (typeof detail === 'string') return `The gate is sealed. ${/[.!?]$/.test(detail) ? detail : `${detail}.`}`;
      if (Array.isArray(detail)) {
        const msgs = detail
          .map((d) => (d && typeof d === 'object' && typeof (d as { msg?: unknown }).msg === 'string' ? (d as { msg: string }).msg : ''))
          .filter(Boolean);
        return `The gate is sealed. ${msgs.length ? `${msgs.join('; ')}.` : 'Enter a site such as example.com.'}`;
      }
      return `The observatory is unreachable. No answer from ${API_BASE}.`;
    }
  };

  /* ---------- derived (one source of truth: the rows) ---------- */

  const ordered = useMemo(() => {
    return Object.values(tasks).sort((a, b) => {
      const ta = a.created_at ? new Date(a.created_at).getTime() : Number.MAX_SAFE_INTEGER;
      const tb = b.created_at ? new Date(b.created_at).getTime() : Number.MAX_SAFE_INTEGER;
      return tb - ta; // newest first; optimistic (no timestamp) float to the top
    });
  }, [tasks]);

  const kpis = useMemo(() => computeKpis(ordered), [ordered]);
  const finding = useMemo(() => computeFinding(ordered), [ordered]);
  const intel = useMemo(() => computeIntel(ordered), [ordered]);

  // the lead block: prefer a completed probe (the deepest one); else the newest
  const selected = useMemo(() => {
    if (selectedId && tasks[selectedId]) return tasks[selectedId];
    const completed = ordered.filter((t) => t.status === 'completed' && t.result);
    if (completed.length > 0) {
      return completed.reduce((a, b) => ((b.result?.malicious_score ?? 0) > (a.result?.malicious_score ?? 0) ? b : a));
    }
    return ordered[0] ?? null;
  }, [selectedId, tasks, ordered]);

  const retry = useCallback(() => load(false), [load]);

  // Choosing a row shows its probe. Below xl the probe block sits above the list, so
  // bring it into view when it is off-screen; beside the list (xl) it already is.
  // The scroll waits for the render: the block changes height with the probe it shows.
  const scrollToProbe = useRef(false);
  const selectProbe = useCallback((id: string) => {
    const el = document.getElementById('selected-probe');
    const top = el ? el.getBoundingClientRect().top : 0;
    scrollToProbe.current = top < 0 || top > window.innerHeight * 0.6;
    setSelectedId(id);
  }, []);
  useEffect(() => {
    if (!scrollToProbe.current) return;
    scrollToProbe.current = false;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    document.getElementById('selected-probe')?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
  }, [selectedId]);

  // Terminal keys: "/" jumps to the prompt; j / k walk the probe list (the rows on screen).
  // Ignored while typing in a field or with a modifier held, so the browser's own keys still work.
  const visibleIds = useMemo(() => ordered.slice(0, 10).map((t) => t.task_id), [ordered]);
  const selectedRef = useRef<string | null>(null);
  selectedRef.current = selected?.task_id ?? null;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const el = e.target as HTMLElement | null;
      if (el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName))) return;
      if (e.key === '/') {
        e.preventDefault();
        document.getElementById('probe-target')?.focus();
      } else if ((e.key === 'j' || e.key === 'k') && visibleIds.length > 0) {
        e.preventDefault();
        const at = visibleIds.indexOf(selectedRef.current ?? '');
        const next = e.key === 'j' ? Math.min(visibleIds.length - 1, at + 1) : Math.max(0, at - 1);
        selectProbe(visibleIds[at === -1 ? 0 : next]);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [visibleIds, selectProbe]);

  /* ---------- layout: rail is in App; canvas gutter 32, one gap of 24 ---------- */

  return (
    <div className="max-w-[1408px] mx-auto px-4 sm:px-8 pt-6 sm:pt-7 pb-12">
      {/* title row: the product is named, then a noun, then the finding */}
      <div className="flex items-start justify-between gap-4 mb-7">
        {/* the lockup: the sigil and the wordmark are the title; the screen's noun sits beside it */}
        <div className="min-w-0 flex items-center gap-3.5 sm:gap-4">
          <Mark size={44} className="text-accent flex-none hidden sm:block" />
          <Mark size={36} className="text-accent flex-none sm:hidden" />
          <div className="min-w-0">
            <h1 className="m-0 flex items-baseline gap-x-3 gap-y-0.5 flex-wrap leading-none">
              <span className="font-display text-[26px] sm:text-[30px] font-semibold tracking-[0.06em] text-ink">PNAKOTIC</span>
              <span className="text-[17px] sm:text-[18px] font-medium text-muted">Observatory</span>
            </h1>
            {phase === 'ready' ? <FindingLine text={finding} /> : null}
          </div>
        </div>

        {lastUpdated ? (
          <div className="flex items-center gap-2.5 flex-none pt-2">
            <span className="hidden sm:inline font-mono num text-[13px] text-muted whitespace-nowrap">Updated {clockTime(lastUpdated)}</span>
            <button
              type="button"
              onClick={() => load(false)}
              aria-label="Refresh"
              title="Refresh"
              className="w-[32px] h-[32px] flex items-center justify-center rounded-full border border-control bg-transparent text-muted hover:text-ink hover:border-faint transition-colors cursor-pointer"
            >
              <RefreshCw size={15} strokeWidth={1.5} />
            </button>
          </div>
        ) : null}
      </div>

      <ScanForm onSubmit={handleScan} onSubmitSite={handleSiteScan} />

      {/* main row: 12 cols, gap 24 — left 8 (the selected probe) + right 4 (the list that
          picks it); sums to the canvas. Intel's aggregates and the totals run full width beneath. */}
      <div className="mt-6 grid grid-cols-1 xl:grid-cols-12 gap-6 items-stretch">
        <div className="xl:col-span-8 min-w-0">
          <SelectedScan task={selected} phase={phase} onRetry={retry} now={now} />
        </div>
        <div className="xl:col-span-4 min-w-0">
          <ScanList tasks={ordered} selectedId={selected?.task_id ?? null} onSelect={selectProbe} phase={phase} onRetry={retry} now={now} />
        </div>
      </div>

      <div className="mt-6">
        <IntelPanel intel={intel} phase={phase} onRetry={retry} />
      </div>

      {/* running totals across every probe: useful for a team watching many sites over time,
          not for the one-off check, so they close the page instead of opening it */}
      <div className="mt-6">
        <KpiStrip kpis={kpis} phase={phase} onRetry={retry} />
      </div>
    </div>
  );
}
