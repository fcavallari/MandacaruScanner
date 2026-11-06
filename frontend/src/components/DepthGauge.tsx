import React from 'react';
import { scoreTone } from '../lib/format';

/** The verdict cut-offs (mirror verdictOf in lib/format.ts). */
const THRESHOLDS = [
  { at: 0.4, name: 'Suspicious' },
  { at: 0.75, name: 'Malicious' },
];

/**
 * The score as a gauge: a 0–1 track, the fill at its true ratio, notched at the two
 * verdict cut-offs so the pill beside the title can be read off the bar. The one hue
 * on the main data element; polarity colour only when it is bad.
 */
export default function DepthGauge({ score }: { score: number }) {
  const clamped = Math.min(1, Math.max(0, score));
  const tone = scoreTone(score);
  const fillClass = tone === 'negative' ? 'bg-negative' : tone === 'warning' ? 'bg-warning' : 'bg-accent';
  const valueClass = tone === 'negative' ? 'text-negative' : tone === 'warning' ? 'text-warning' : 'text-ink';

  return (
    <div>
      <div className="flex items-end justify-between mb-2">
        <span className="text-[15px] font-semibold text-ink">Maliciousness</span>
        <span className={`font-mono num text-[24px] leading-none font-medium ${valueClass}`}>
          {score.toFixed(2)}
        </span>
      </div>

      <div
        className="relative"
        role="meter"
        aria-valuemin={0}
        aria-valuemax={1}
        aria-valuenow={Number(clamped.toFixed(2))}
        aria-label="Maliciousness"
      >
        <div className="relative h-2.5 rounded-full bg-raised border border-line overflow-hidden">
          <div className={`h-full rounded-full ${fillClass}`} style={{ width: `${(clamped * 100).toFixed(2)}%` }} />
          {/* notches at the cut-offs, cut through the fill in the card's colour */}
          {THRESHOLDS.map((t) => (
            <span key={t.at} aria-hidden="true" className="absolute top-0 bottom-0 w-[2px] -ml-px bg-surface" style={{ left: `${t.at * 100}%` }} />
          ))}
        </div>
        <div className="relative h-[16px] mt-2 font-mono num text-[12px] text-muted leading-none">
          <span className="absolute left-0">0.0</span>
          {THRESHOLDS.map((t) => (
            <span key={t.at} title={`${t.name} from ${t.at}`} className="absolute -translate-x-1/2" style={{ left: `${t.at * 100}%` }}>
              {t.at}
            </span>
          ))}
          <span className="absolute right-0">1.0</span>
        </div>
      </div>
    </div>
  );
}
