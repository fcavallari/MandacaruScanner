import React from 'react';
import type { TaskState } from '../lib/api';
import { hostnameOf, profileLabel, profileShort, redirectCount, relativeTime, scoreTone, shortHost, verdictOf } from '../lib/format';
import { siteVerdictTone } from './SiteReport';
import { Bar, EmptyWell, ErrorNote } from './states';

/**
 * Recent probes as two-line rows, beside the selected probe on wide screens and under it
 * on narrow ones (one component, so no width loses a field):
 *   line 1  target host ................................ score
 *   line 2  status · persona · → landing host ........ redirects · age
 * Rules between rows, no zebra; numbers right-aligned in the mono. The selected row is
 * marked by a 1px accent line exactly as tall as the row (the style's move).
 */

const MAX_ROWS = 10;

function Status({ task }: { task: TaskState }) {
  switch (task.status) {
    case 'queued':
      return <span className="text-faint">Queued</span>;
    case 'running':
      return (
        <span className="inline-flex items-center gap-1.5 text-accent">
          <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-accent pulse-dot" />
          Probing
        </span>
      );
    case 'failed':
      return (
        <span className="inline-flex items-center gap-1.5 text-negative">
          <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-negative" />
          Failed
        </span>
      );
    default: {
      if (task.kind === 'site') {
        // a site's verdict is its own, never derived from the score (Couldn't check scores 0)
        const sv = task.result?.site?.verdict;
        const t = siteVerdictTone(sv?.verdict);
        return (
          <span className={`inline-flex items-center gap-1.5 ${t === 'negative' ? 'text-negative' : t === 'warning' ? 'text-warning' : 'text-muted'}`}>
            <span aria-hidden="true" className={`w-1.5 h-1.5 rounded-full flex-none ${t === 'negative' ? 'bg-negative' : t === 'warning' ? 'bg-warning' : t === 'positive' ? 'bg-positive' : 'bg-faint'}`} />
            {sv?.label ?? 'No report'}
          </span>
        );
      }
      const s = task.result?.malicious_score ?? 0;
      const tone = scoreTone(s);
      return (
        <span className={`inline-flex items-center gap-1.5 ${tone === 'negative' ? 'text-negative' : tone === 'warning' ? 'text-warning' : 'text-muted'}`}>
          <span aria-hidden="true" className={`w-1.5 h-1.5 rounded-full flex-none ${tone === 'negative' ? 'bg-negative' : tone === 'warning' ? 'bg-warning' : 'bg-positive'}`} />
          {verdictOf(s)}
        </span>
      );
    }
  }
}

function Key({ children }: { children: React.ReactNode }) {
  return (
    <kbd className="inline-flex h-[18px] min-w-[18px] px-1 items-center justify-center font-mono text-[11px] leading-none text-faint border border-control rounded-[4px]">
      {children}
    </kbd>
  );
}

/** "→ host": when it must cut, it cuts the start (rtl box, ltr text) and keeps the apex/TLD. */
function Landing({ landing, finalUrl }: { landing: string; finalUrl: string }) {
  return (
    <>
      <span aria-hidden="true" className="font-mono text-[11px] text-muted">→</span>
      <span className="sr-only">landed on </span>
      <span className="font-mono text-[11px] text-muted truncate min-w-0 [direction:rtl] text-left" title={finalUrl}>
        <bdi dir="ltr">{shortHost(landing, 40)}</bdi>
      </span>
    </>
  );
}

/** Which kind of job a row is: a whole-site check or a single-URL probe. */
function KindTag({ kind }: { kind: TaskState['kind'] }) {
  return (
    <span
      className="font-mono text-[10px] leading-none tracking-[0.06em] px-1.5 py-[3px] rounded-chip flex-none translate-y-[-1px]"
      style={{ background: 'var(--pill-neutral-bg)', color: 'var(--pill-neutral-ink)' }}
    >
      {kind === 'site' ? 'SITE' : 'URL'}
    </span>
  );
}

function Row({ task, selected, onSelect, now }: { task: TaskState; selected: boolean; onSelect: (id: string) => void; now: number }) {
  const site = task.kind === 'site';
  const host = (site && task.result?.site?.site) || hostnameOf(task.target_url) || task.target_url;
  const done = task.status === 'completed' && task.result;
  // a site check has a verdict, not a score, persona, landing or hop count
  const score = done && !site ? task.result!.malicious_score ?? 0 : null;
  const tone = score != null ? scoreTone(score) : 'ink';
  const landing = done && !site ? hostnameOf(task.result!.final_url) : '';
  const redirects = done && !site ? redirectCount(task.result!.hops) : null;

  return (
    <li className="border-b border-rule last:border-b-0">
      <button
        type="button"
        aria-current={selected ? 'true' : undefined}
        onClick={() => onSelect(task.task_id)}
        title={task.target_url}
        className={`w-full text-left px-5 py-2.5 cursor-pointer transition-colors border-0 block
          ${selected ? 'bg-active shadow-[inset_1px_0_0_var(--accent)]' : 'bg-transparent hover:bg-raised/60'}`}
      >
        <span className="flex items-baseline justify-between gap-3">
          <span className="flex items-baseline gap-2 min-w-0">
            <KindTag kind={task.kind} />
            <span className={`text-[13px] truncate min-w-0 ${selected ? 'text-ink font-medium' : 'text-ink'}`}>{shortHost(host, 40)}</span>
          </span>
          <span className={`font-mono num text-[13px] flex-none ${tone === 'negative' ? 'text-negative' : tone === 'warning' ? 'text-warning' : score != null ? 'text-ink' : 'text-faint'}`}>
            {score != null ? score.toFixed(2) : '—'}
          </span>
        </span>
        <span className="flex items-baseline justify-between gap-3 mt-1 text-[12px]">
          <span className="flex items-baseline gap-1.5 min-w-0 whitespace-nowrap">
            <Status task={task} />
            {site ? null : (
              <>
                <span className="text-faint" aria-hidden="true">·</span>
                <span className="text-faint" title={profileLabel(task.profile)}>{profileShort(task.profile)}</span>
              </>
            )}
            {landing ? (
              <span className="hidden sm:contents">
                <span className="text-faint" aria-hidden="true">·</span>
                <Landing landing={landing} finalUrl={task.result?.final_url ?? ''} />
              </span>
            ) : null}
          </span>
          <span className="font-mono num text-[11px] text-faint whitespace-nowrap flex-none">
            {redirects != null ? `${redirects} hop${redirects === 1 ? '' : 's'} · ` : null}
            {relativeTime(task.created_at, now)}
          </span>
        </span>
        {landing ? (
          <span className="flex items-baseline gap-1.5 mt-1 sm:hidden">
            <Landing landing={landing} finalUrl={task.result?.final_url ?? ''} />
          </span>
        ) : null}
      </button>
    </li>
  );
}

export default function ScanList({
  tasks,
  selectedId,
  onSelect,
  phase,
  onRetry,
  now = Date.now(),
}: {
  tasks: TaskState[]; // newest first
  selectedId: string | null;
  onSelect: (id: string) => void;
  phase: 'loading' | 'ready' | 'error';
  onRetry?: () => void;
  now?: number;
}) {
  const visible = tasks.slice(0, MAX_ROWS);

  return (
    <section aria-label="Recent probes" className="bg-surface border border-line rounded-card overflow-hidden h-full flex flex-col">
      <div className="flex items-baseline justify-between px-5 pt-5 pb-3 border-b border-rule">
        <h2 className="text-[16px] font-semibold text-ink m-0">
          Recent probes{phase === 'ready' ? <span className="font-mono num text-[13px] font-normal text-faint"> · {tasks.length}</span> : null}
        </h2>
        {phase === 'ready' && tasks.length > 0 ? (
          <span className="flex items-center gap-3 text-[11px] text-faint">
            {tasks.length > MAX_ROWS ? <span>showing {MAX_ROWS} of {tasks.length}</span> : null}
            {/* keyboard hint; phones have no keyboard */}
            <span className="hidden md:flex items-center gap-1" title="Move through the list with j and k">
              <Key>j</Key>
              <Key>k</Key>
              <span className="ml-0.5">to move</span>
            </span>
          </span>
        ) : null}
      </div>

      {phase === 'loading' ? (
        <div className="px-5 py-3 space-y-4">
          {[0, 1, 2, 3, 4].map((i) => (
            <div key={i} className="space-y-1.5">
              <div className="flex justify-between">
                <Bar h={13} w="45%" />
                <Bar h={13} w="32px" />
              </div>
              <Bar h={12} w="70%" />
            </div>
          ))}
        </div>
      ) : phase === 'error' ? (
        <div className="px-5 py-4">
          <ErrorNote message="Couldn't load recent probes. The deep is silent." onRetry={onRetry} />
        </div>
      ) : tasks.length === 0 ? (
        <EmptyWell title="No probes yet. The deep is quiet." sub="Submit a URL above to start peering into the abyss." className="m-5 min-h-[120px] flex-1" />
      ) : (
        <ul className="m-0 p-0 list-none">
          {visible.map((t) => (
            <Row key={t.task_id} task={t} selected={t.task_id === selectedId} onSelect={onSelect} now={now} />
          ))}
        </ul>
      )}
    </section>
  );
}
