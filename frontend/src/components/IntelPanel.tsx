import React from 'react';
import type { IntelAggregates } from '../lib/format';
import { MECHANISM_LABELS } from '../lib/format';
import { Bar, ErrorNote } from './states';

/**
 * Intel: aggregates computed from the probes on screen — redirect mechanisms,
 * suspicious landing TLDs, top landing domains. Nothing invented; when there is
 * nothing, each section says so in one sentence.
 */


function SectionTitle({ children }: { children: React.ReactNode }) {
  return <p className="text-[15px] font-semibold text-ink m-0 mb-3">{children}</p>;
}

/** one-figure ranking: the row's fill is the bar (share of the largest) */
function BarList({ rows }: { rows: Array<{ label: string; count: number; mark?: 'warning' | 'accent' }> }) {
  const max = Math.max(...rows.map((r) => r.count), 1);
  return (
    <div className="space-y-1">
      {rows.map((r, i) => (
        <div key={r.label} className="relative rounded-[4px] overflow-hidden" style={{ height: 26 }}>
          <div
            className="absolute inset-y-0 left-0 rounded-[4px] bg-raised"
            style={{ width: `${((r.count / max) * 100).toFixed(2)}%` }}
          />
          <div className="relative flex items-center justify-between h-full px-2.5">
            <span className={`text-[13px] truncate ${i === 0 ? 'text-ink' : 'text-muted'}`}>{r.label}</span>
            <span className="font-mono num text-[13px] text-muted flex items-center gap-1.5">
              {r.mark === 'accent' ? <span aria-hidden="true" className="w-1.5 h-1.5 bg-accent flex-none" /> : null}
              {r.mark === 'warning' ? <span aria-hidden="true" className="w-1.5 h-1.5 bg-warning flex-none" /> : null}
              {r.count}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

function Quiet({ children }: { children: React.ReactNode }) {
  return <p className="text-[13px] text-faint m-0">{children}</p>;
}

export default function IntelPanel({ intel, phase, onRetry }: { intel: IntelAggregates; phase: 'loading' | 'ready' | 'error'; onRetry?: () => void }) {
  return (
    <section aria-label="Intel" className="bg-surface border border-line rounded-card p-5 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <h2 className="text-[18px] font-semibold text-ink m-0">Intel</h2>
        <span className="text-[12px] text-faint">computed from probes</span>
      </div>

      {phase === 'loading' ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-x-8 gap-y-4">
          {[0, 1, 2].map((s) => (
            <div key={s} className="space-y-2">
              <Bar h={12} w="45%" />
              {[0, 1].map((i) => (
                <Bar key={i} h={26} w="100%" />
              ))}
            </div>
          ))}
        </div>
      ) : phase === 'error' ? (
        <ErrorNote message="Couldn't compute intel. The deep is silent." onRetry={onRetry} />
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-x-8 gap-y-4">
          <div>
            <SectionTitle>Redirect mechanisms</SectionTitle>
            {intel.mechanisms.length > 0 ? (
              <BarList rows={intel.mechanisms.map((m) => ({ label: MECHANISM_LABELS[m.mechanism] ?? m.mechanism, count: m.count }))} />
            ) : (
              <Quiet>No redirects observed yet.</Quiet>
            )}
          </div>

          <div className="border-t border-rule pt-4 lg:border-t-0 lg:pt-0">
            <SectionTitle>Suspicious TLDs</SectionTitle>
            {intel.suspiciousTlds.length > 0 ? (
              <BarList rows={intel.suspiciousTlds.map((t) => ({ label: `.${t.tld}`, count: t.count, mark: 'warning' as const }))} />
            ) : (
              <Quiet>None observed.</Quiet>
            )}
          </div>

          <div className="border-t border-rule pt-4 lg:border-t-0 lg:pt-0">
            <SectionTitle>Landing domains</SectionTitle>
            {intel.landings.length > 0 ? (
              <BarList rows={intel.landings.map((l) => ({ label: l.apex, count: l.count, mark: (l.highValue ? 'accent' : undefined) as 'accent' | undefined }))} />
            ) : (
              <Quiet>No probes have landed yet.</Quiet>
            )}
          </div>

          </div>

          <p className="text-[12px] text-faint m-0 pt-3 border-t border-rule">
            <span aria-hidden="true" className="inline-block w-1.5 h-1.5 bg-accent mr-1.5 -mt-[2px]" />
            high-value landing after redirect
          </p>
        </>
      )}
    </section>
  );
}
