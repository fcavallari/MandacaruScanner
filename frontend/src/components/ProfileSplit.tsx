import React from 'react';
import type { ArtifactEntry, Cloaking, ProfileVariant } from '../lib/api';
import { artifactUrl } from '../lib/api';
import { hostnameOf, profileLabel, shortHost, verdictOf } from '../lib/format';

/**
 * Where each browser persona was sent. A cloaker shows its payload only to the visitor it
 * wants (a phone, a search click) and something harmless to everyone else, so a split here
 * is the tell. Rows that were steered off the common landing carry a warning line.
 */
export default function ProfileSplit({
  taskId,
  variants,
  cloaking,
  artifacts,
}: {
  taskId: string;
  variants: ProfileVariant[];
  cloaking: Cloaking | null | undefined;
  artifacts: ArtifactEntry[];
}) {
  if (variants.length < 2) return null;
  const steered = new Set(cloaking?.steered ?? []);
  const shotFor = (profile: string) =>
    artifacts.filter((a) => a.rel_path.startsWith(`profiles/${profile}/`) && /\.png$/i.test(a.rel_path)).pop();

  return (
    <div>
      <p className="text-[15px] font-semibold text-ink m-0 mb-2.5">
        Profiles
        <span className="font-normal text-muted">
          {' · '}
          {cloaking ? `${steered.size} of ${variants.length} sent elsewhere` : 'same landing for every profile'}
        </span>
      </p>
      <div className="border border-line rounded-card overflow-hidden">
        <table className="w-full text-[13px] border-collapse">
          <thead>
            <tr className="text-faint text-left">
              <th className="font-normal px-3 py-1.5">Profile</th>
              <th className="font-normal px-3 py-1.5">Landing</th>
              <th className="font-normal px-3 py-1.5 text-right">Redirects</th>
              <th className="font-normal px-3 py-1.5 text-right">Score</th>
            </tr>
          </thead>
          <tbody>
            {variants.map((v) => {
              const off = steered.has(v.profile);
              const shot = v.requested ? undefined : shotFor(v.profile);
              const host = hostnameOf(v.final_url);
              const score = v.malicious_score ?? 0;
              return (
                <tr key={v.profile} className={`border-t border-rule ${off ? 'shadow-[inset_1px_0_0_0_var(--warning)]' : ''}`}>
                  <td className="px-3 py-1.5 text-ink whitespace-nowrap">
                    {profileLabel(v.profile)}
                    {v.requested ? <span className="text-faint"> · requested</span> : null}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[12px] min-w-0 break-all">
                    {v.error ? (
                      <span className="text-warning">did not load</span>
                    ) : (
                      <span className={off ? 'text-warning' : 'text-muted'} title={v.final_url ?? ''}>
                        {shortHost(host || '—', 34)}
                      </span>
                    )}
                    {shot ? (
                      <a
                        href={artifactUrl(taskId, shot.rel_path)}
                        target="_blank"
                        rel="noreferrer"
                        className="ml-2 text-faint hover:text-ink"
                      >
                        shot
                      </a>
                    ) : null}
                  </td>
                  <td className="px-3 py-1.5 font-mono num text-right text-muted">{v.error ? '—' : (v.redirects ?? 0)}</td>
                  <td className="px-3 py-1.5 font-mono num text-right whitespace-nowrap">
                    {v.error ? (
                      <span className="text-faint">—</span>
                    ) : (
                      <span className={score >= 0.75 ? 'text-negative' : score >= 0.4 ? 'text-warning' : 'text-ink'}>
                        {score.toFixed(2)} <span className="text-faint font-sans">{verdictOf(score)}</span>
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
