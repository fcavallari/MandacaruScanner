import React, { useEffect, useState } from 'react';
import type { ArtifactEntry, TaskState } from '../lib/api';
import { artifactUrl } from '../lib/api';
import { hostnameOf, redirectCount, relativeTime, verdictOf } from '../lib/format';
import DepthGauge from './DepthGauge';
import ProfileSplit from './ProfileSplit';
import RedirectChain from './RedirectChain';
import { Bar, EmptyWell, ErrorNote } from './states';

/**
 * The lead block: the selected probe. Answers the screen's one question —
 * "Where did that URL actually go, and how deep is it?" — with the chain node
 * graph (the signature) and the score as a depth gauge.
 */

function StatusMark({ task }: { task: TaskState }) {
  switch (task.status) {
    case 'queued':
      return <span className="text-[12px] text-faint whitespace-nowrap">Queued</span>;
    case 'running':
      return (
        <span className="flex items-center gap-1.5 text-[12px] text-accent whitespace-nowrap">
          <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-accent pulse-dot" />
          Probing
        </span>
      );
    case 'failed':
      return (
        <span className="px-2 py-[3px] text-[11px] font-medium rounded-full whitespace-nowrap" style={{ background: 'var(--pill-negative-bg)', color: 'var(--negative)' }}>
          Failed
        </span>
      );
    default: {
      const v = verdictOf(task.result?.malicious_score ?? 0);
      const style =
        v === 'Malicious'
          ? { background: 'var(--pill-negative-bg)', color: 'var(--negative)' }
          : v === 'Suspicious'
            ? { background: 'var(--pill-warning-bg)', color: 'var(--warning)' }
            : v === 'Watch'
              ? { background: 'var(--pill-neutral-bg)', color: 'var(--pill-neutral-ink)' }
              : { background: 'var(--pill-positive-bg)', color: 'var(--positive)' };
      return (
        <span className="px-2 py-[3px] text-[11px] font-medium rounded-full whitespace-nowrap" style={style}>
          {v}
        </span>
      );
    }
  }
}

/** The landing screenshot: the newest PNG under screenshots/ (names carry a timestamp). */
function pickShot(artifacts: ArtifactEntry[]): ArtifactEntry | null {
  const shots = artifacts.filter((a) => a.rel_path.startsWith('screenshots/') && /\.png$/i.test(a.rel_path));
  return shots.length ? [...shots].sort((a, b) => a.rel_path.localeCompare(b.rel_path))[shots.length - 1] : null;
}

/**
 * Where the browser surfaced, as a picture: the strongest evidence the product has.
 * Cropped from the top (the page is captured full length); the whole capture opens in a tab.
 */
function LandingShot({ taskId, shot, host }: { taskId: string; shot: ArtifactEntry | null; host: string }) {
  const [failed, setFailed] = useState(false);
  useEffect(() => setFailed(false), [taskId, shot?.rel_path]);

  if (!shot || failed) {
    return (
      <div className="aspect-[4/3] border border-dashed border-control rounded-chip flex items-center justify-center px-4 text-center">
        <p className="text-[12px] text-faint m-0">{shot ? 'The screenshot could not be loaded.' : 'No screenshot was taken.'}</p>
      </div>
    );
  }
  const href = artifactUrl(taskId, shot.rel_path);
  return (
    <figure className="m-0">
      <a href={href} target="_blank" rel="noreferrer" className="block group rounded-chip overflow-hidden border border-line hover:border-accent transition-colors">
        <img
          src={href}
          alt={`Screenshot of the landing page${host ? ` on ${host}` : ''}`}
          loading="lazy"
          onError={() => setFailed(true)}
          className="block w-full aspect-[4/3] object-cover object-top bg-ground"
        />
      </a>
      <figcaption className="flex items-center justify-between gap-2 mt-1.5 text-[11px] text-faint">
        <span>Landing screenshot</span>
        <a href={href} target="_blank" rel="noreferrer" className="text-muted hover:text-accent transition-colors">
          Open full page
        </a>
      </figcaption>
    </figure>
  );
}

export default function SelectedScan({ task, phase, onRetry, now = Date.now() }: { task: TaskState | null; phase: 'loading' | 'ready' | 'error'; onRetry?: () => void; now?: number }) {
  const artifacts = task?.result?.artifacts?.artifacts ?? [];
  const shot = pickShot(artifacts);
  // per-profile shots are linked from the Profiles table instead
  const otherArtifacts = artifacts.filter((a) => a !== shot && !a.rel_path.startsWith('profiles/'));

  return (
    <section id="selected-probe" aria-label="Selected probe" className="bg-surface border border-line rounded-card p-5 flex flex-col gap-5 min-h-[380px] h-full">
      {/* header: identity + status */}
      {phase === 'loading' ? (
        <div className="flex items-center justify-between gap-4">
          <div className="space-y-2 min-w-0">
            <Bar h={16} w="38%" />
            <Bar h={12} w="55%" className="mt-2" />
          </div>
          <Bar h={20} w="72px" />
        </div>
      ) : phase === 'error' ? (
        <ErrorNote message="Couldn't load the probe. The deep is silent." onRetry={onRetry} />
      ) : !task ? (
        <div className="flex items-center justify-between gap-4">
          <p className="text-[16px] font-semibold text-muted m-0">No probe selected</p>
        </div>
      ) : (
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0 max-w-full">
            <p className="text-[16px] font-semibold text-ink m-0 truncate" title={task.target_url}>
              {hostnameOf(task.target_url) || task.target_url}
            </p>
            <p className="font-mono text-[11px] text-faint m-0 mt-1 truncate max-w-full" title={task.target_url}>
              {task.target_url}
            </p>
          </div>
          <StatusMark task={task} />
        </div>
      )}

      {/* body */}
      {phase === 'loading' ? (
        <div className="space-y-4">
          <Bar h={32} w="180px" />
          <Bar h={40} w="100%" />
          <div className="flex gap-3">
            <Bar h={12} w="90px" />
            <Bar h={12} w="70px" />
          </div>
        </div>
      ) : phase === 'error' ? null : !task ? (
        <EmptyWell
          title="No probes yet. The deep is quiet."
          sub="Submit a URL above to send the first probe."
          className="flex-1"
        />
      ) : task.status === 'queued' || task.status === 'running' ? (
        <div className="flex-1 flex flex-col justify-center gap-2">
          <p className="flex items-center gap-2 text-[13px] text-muted m-0">
            <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-accent pulse-dot" />
            {task.status === 'running' ? `Probing ${hostnameOf(task.target_url) || task.target_url}…` : 'Waiting for a worker in the dark…'}
          </p>
          <p className="font-mono text-[11px] text-faint m-0">
            {task.status === 'running' ? 'the deep is listening' : 'queued'} · probe {task.task_id.slice(0, 8)}
          </p>
        </div>
      ) : task.status === 'failed' ? (
        <div className="flex-1 flex flex-col justify-center gap-2">
          <p className="text-[13px] text-negative m-0 break-all">{task.error || 'The probe failed'}</p>
          <p className="font-mono text-[11px] text-faint m-0">probe {task.task_id.slice(0, 8)}</p>
        </div>
      ) : (
        <>
          {task.result ? (
            <DepthGauge score={task.result.malicious_score ?? 0} />
          ) : null}

          {task.result ? (
            <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_minmax(0,272px)] gap-6 items-start">
              <div className="min-w-0">
                <p className="text-[12px] text-muted m-0 mb-3">
                  Descent
                  <span className="text-faint">
                    {' · '}
                    <span className="font-mono num">{redirectCount(task.result.hops)}</span>
                    {redirectCount(task.result.hops) === 1 ? ' redirect' : ' redirects'}
                  </span>
                </p>
                <RedirectChain
                  target={task.target_url}
                  hops={task.result.hops ?? []}
                  finalUrl={task.result.final_url ?? null}
                  chainDetected={task.result.is_redirect_chain_detected ?? false}
                />
              </div>
              <LandingShot taskId={task.task_id} shot={shot} host={hostnameOf(task.result.final_url) || hostnameOf(task.target_url)} />
            </div>
          ) : null}

          {task.result?.raw_error ? (
            <p className="text-[12px] text-warning m-0 break-all">Page did not load: {task.result.raw_error}</p>
          ) : null}

          {task.result?.findings && task.result.findings.length > 0 ? (
            <div>
              <p className="text-[12px] text-muted m-0 mb-2">Findings</p>
              <ul className="m-0 p-0 list-none space-y-1.5">
                {task.result.findings.map((f, i) => {
                  const decisive = task.result?.decisive?.includes(f) ?? false;
                  return (
                  <li key={i} className={`flex items-baseline gap-2 text-[13px] ${decisive ? 'text-negative' : 'text-ink'}`}>
                    <span aria-hidden="true" className={`w-1 h-1 flex-none translate-y-[-2px] ${decisive ? 'bg-negative' : 'bg-faint'}`} />
                    <span className="break-words min-w-0">{f}</span>
                  </li>
                  );
                })}
              </ul>
            </div>
          ) : null}

          {task.result?.variants && task.result.variants.length > 1 ? (
            <ProfileSplit
              taskId={task.task_id}
              variants={task.result.variants}
              cloaking={task.result.cloaking}
              artifacts={artifacts}
            />
          ) : null}

          {otherArtifacts.length > 0 ? (
            <div>
              <p className="text-[12px] text-muted m-0 mb-2">Other artifacts</p>
              <div className="flex flex-wrap gap-1.5">
                {otherArtifacts.map((a) => (
                  <a
                    key={a.rel_path}
                    href={artifactUrl(task.task_id, a.rel_path)}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-[11px] text-muted bg-ground border border-line rounded-full px-2.5 py-1 hover:border-accent hover:text-ink transition-colors"
                  >
                    {a.name}
                  </a>
                ))}
              </div>
            </div>
          ) : null}

          <p className="font-mono text-[11px] text-faint m-0 mt-auto pt-2 border-t border-rule">
            probe {task.task_id.slice(0, 8)} · {relativeTime(task.created_at, now)}
          </p>
        </>
      )}
    </section>
  );
}
