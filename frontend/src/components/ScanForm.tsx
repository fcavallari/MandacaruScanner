import React, { useState } from 'react';

const PROFILES = [
  { value: 'default', label: 'Default desktop' },
  { value: 'mobile-ios', label: 'Mobile iOS (iPhone)' },
  { value: 'mobile-android', label: 'Mobile Android' },
  { value: 'search-clicker', label: 'Search referrer (Google)' },
];

/**
 * The job the screen exists for: paste a URL, pick a persona, summon.
 * One row from sm up; on a phone the URL takes its own row and the controls
 * grow to 44px. `onSubmit` resolves to an error sentence, or null on success.
 * The URL is cleared only once the probe was accepted, so a rejected URL can be fixed.
 */
export default function ScanForm({
  onSubmit,
}: {
  onSubmit: (url: string, profile: string) => Promise<string | null>;
}) {
  const [url, setUrl] = useState('');
  const [profile, setProfile] = useState('default');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const control = 'h-[44px] sm:h-[34px] bg-ground border rounded-full outline-none focus:border-accent transition-colors';

  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        const target = url.trim();
        if (!target || busy) return;
        setBusy(true);
        setError(null);
        const err = await onSubmit(target, profile);
        setBusy(false);
        if (err) setError(err);
        else setUrl('');
      }}
      className="bg-surface border border-line rounded-card p-3"
    >
      <div className="flex flex-wrap sm:flex-nowrap gap-2.5 items-center">
        <div className="relative basis-full sm:basis-auto sm:flex-1 min-w-0">
          {/* a prompt, not a search: this field launches a probe */}
          <span aria-hidden="true" className="absolute left-3.5 top-1/2 -translate-y-1/2 font-mono text-[14px] leading-none text-accent pointer-events-none select-none">
            &gt;
          </span>
          <input
            id="probe-target"
            type="url"
            spellCheck={false}
            autoComplete="off"
            onKeyDown={(e) => {
              if (e.key === 'Escape') e.currentTarget.blur();
            }}
            required
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (error) setError(null);
            }}
            placeholder="paste a suspicious URL to probe — https://…"
            aria-label="Target URL"
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? 'scan-form-error' : undefined}
            className={`${control} peer w-full pl-9 pr-10 font-mono text-[14px] sm:text-[13px] text-ink placeholder:text-faint ${error ? 'border-negative' : 'border-control'}`}
          />
          {url ? null : (
            <kbd
              title="Press / to focus"
              className="hidden sm:flex absolute right-3 top-1/2 -translate-y-1/2 h-[18px] min-w-[18px] px-1 items-center justify-center font-mono text-[11px] leading-none text-faint border border-control rounded-[4px] pointer-events-none peer-focus:hidden"
            >
              /
            </kbd>
          )}
        </div>

        <div className="relative flex-1 sm:flex-none min-w-0">
          <select
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            aria-label="Browser profile"
            className={`${control} w-full px-3.5 pr-9 border-control text-[13px] sm:text-[12px] text-muted cursor-pointer appearance-none`}
          >
            {PROFILES.map((p) => (
              <option key={p.value} value={p.value} className="bg-surface text-ink">
                {p.label}
              </option>
            ))}
          </select>
          <svg
            aria-hidden="true"
            viewBox="0 0 10 6"
            className="absolute right-3.5 top-1/2 -translate-y-1/2 w-[10px] h-[6px] text-faint pointer-events-none"
          >
            <path d="M1 1l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>

        <button
          type="submit"
          disabled={busy}
          aria-busy={busy}
          className={`h-[44px] sm:h-[34px] px-5 rounded-full text-[13px] sm:text-[12px] font-semibold tracking-wide flex items-center justify-center gap-2 whitespace-nowrap transition-colors
            ${busy ? 'bg-accent/60 text-ground cursor-wait' : 'bg-accent text-[#08120d] hover:bg-accent/85 active:bg-accent/75 cursor-pointer'}`}
        >
          {busy ? (
            <>
              <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-ground pulse-dot" />
              Summoning…
            </>
          ) : (
            'Summon'
          )}
        </button>
      </div>

      {error ? (
        <p id="scan-form-error" role="alert" className="flex items-baseline gap-2 text-[12px] text-ink m-0 mt-2.5 px-1">
          <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-negative flex-none translate-y-[-1px]" />
          {error}
        </p>
      ) : null}
    </form>
  );
}
