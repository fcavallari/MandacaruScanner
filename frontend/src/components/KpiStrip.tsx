import React from 'react';
import type { Kpis } from '../lib/format';
import { Bar, ErrorNote } from './states';

/**
 * KPIs as type, not tiles: one container split by 1px hairlines into four equal
 * cells. Label above value, sentence case; values in the mono at the dealt size.
 */

function Cell({ label, value, sub, tone = 'ink' }: { label: string; value: string; sub?: string; tone?: 'ink' | 'negative' | 'warning' }) {
  const valueClass = tone === 'negative' ? 'text-negative' : tone === 'warning' ? 'text-warning' : 'text-ink';
  return (
    <div className="px-6 py-4 min-w-0">
      <p className="text-[13px] text-muted m-0">{label}</p>
      <div className="flex items-baseline gap-2.5 mt-2">
        <span className={`font-mono num text-[28px] leading-none font-medium ${valueClass}`}>{value}</span>
        {sub ? <span className="text-[13px] text-muted leading-none">{sub}</span> : null}
      </div>
    </div>
  );
}

/** hairline placement: 2-up on phone, 4-across at lg — borders land on the seams */
const SEAMS = [
  '',
  'border-l border-rule',
  'max-lg:border-t max-lg:border-rule lg:border-l lg:border-rule',
  'border-l border-rule max-lg:border-t max-lg:border-rule',
];

export default function KpiStrip({ kpis, phase, onRetry }: { kpis: Kpis; phase: 'loading' | 'ready' | 'error'; onRetry?: () => void }) {
  return (
    <section aria-label="Probe totals" className="bg-surface border border-line rounded-card overflow-hidden grid grid-cols-2 lg:grid-cols-4">
      {phase === 'loading' ? (
        <>
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className={`px-6 py-4 ${SEAMS[i]}`}>
              <Bar h={12} w="70%" />
              <div className="mt-3">
                <Bar h={20} w="45%" />
              </div>
            </div>
          ))}
        </>
      ) : phase === 'error' ? (
        <div className="col-span-2 lg:col-span-4">
          <ErrorNote message="Couldn't reach the field station. No signal." onRetry={onRetry} />
        </div>
      ) : (
        <>
          <div className={SEAMS[0]}>
            <Cell label="Probes" value={String(kpis.scans)} sub={`${kpis.completed} completed`} />
          </div>
          <div className={SEAMS[1]}>
            <Cell label="Chains detected" value={String(kpis.chainsDetected)} sub={`of ${kpis.completed} completed`} />
          </div>
          <div className={SEAMS[2]}>
            <Cell
              label="Highest score"
              value={kpis.highestScore != null ? kpis.highestScore.toFixed(2) : '—'}
              tone={kpis.highestScore != null && kpis.highestScore >= 0.75 ? 'negative' : 'ink'}
            />
          </div>
          <div className={SEAMS[3]}>
            <Cell label="Median hops" value={kpis.medianHops != null ? String(kpis.medianHops) : '—'} />
          </div>
        </>
      )}
    </section>
  );
}
