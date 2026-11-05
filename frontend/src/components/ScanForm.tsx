import React, { useState } from 'react';

const PROFILES = [
  { value: 'default', label: 'Default desktop' },
  { value: 'mobile-ios', label: 'Mobile iOS (iPhone)' },
  { value: 'mobile-android', label: 'Mobile Android' },
  { value: 'search-clicker', label: 'Search referrer (Google)' },
  { value: 'facebook-android', label: 'Facebook app link (Android)' },
  { value: 'googlebot', label: 'Googlebot (cloaking check)' },
];

type Mode = 'site' | 'url';

const MODES: Array<{ value: Mode; label: string }> = [
  { value: 'site', label: 'Site check' },
  { value: 'url', label: 'URL probe' },
];

const control = 'h-[44px] sm:h-[34px] bg-ground border rounded-full outline-none focus:border-accent transition-colors';

/**
 * The job the screen exists for. Two kinds: Site check (the default) quick-checks a whole
 * site from its homepage; URL probe is the single-URL descent. The chosen kind carries the
 * 1px accent line exactly as wide as its label (the style's move). Each form clears its
 * field only once the job was accepted, so a rejected input can be fixed.
 */
export default function ScanForm({
  onSubmit,
  onSubmitSite,
}: {
  onSubmit: (url: string, profile: string) => Promise<string | null>;
  onSubmitSite: (site: string) => Promise<string | null>;
}) {
  const [mode, setMode] = useState<Mode>('site');

  return (
    <div className="bg-surface border border-line rounded-card p-3">
      <div role="radiogroup" aria-label="Kind of scan" className="flex items-center gap-5 px-1 mb-2.5">
        {MODES.map((m) => {
          const on = m.value === mode;
          return (
            <button
              key={m.value}
              type="button"
              role="radio"
              aria-checked={on}
              onClick={() => setMode(m.value)}
              className={`bg-transparent border-0 p-0 pb-1 text-[12px] cursor-pointer transition-colors
                ${on ? 'text-ink font-medium shadow-[inset_0_-1px_0_var(--accent)]' : 'text-muted hover:text-ink'}`}
            >
              {m.label}
            </button>
          );
        })}
      </div>
      {mode === 'site' ? <SiteForm onSubmit={onSubmitSite} /> : <ProbeForm onSubmit={onSubmit} />}
    </div>
  );
}

/**
 * Site check: one field, a bare host or a URL; the API normalises it to the homepage.
 * The field is text, not url (a bare host like example.com is the expected input), and it
 * keeps the #probe-target id so "/" focuses whichever prompt is shown.
 */
function SiteForm({ onSubmit }: { onSubmit: (site: string) => Promise<string | null> }) {
  const [site, setSite] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        const target = site.trim();
        if (!target || busy) return;
        setBusy(true);
        setError(null);
        const err = await onSubmit(target);
        setBusy(false);
        if (err) setError(err);
        else setSite('');
      }}
    >
      <div className="flex flex-wrap sm:flex-nowrap gap-2.5 items-center">
        <div className="relative basis-full sm:basis-auto sm:flex-1 min-w-0">
          <span aria-hidden="true" className="absolute left-3.5 top-1/2 -translate-y-1/2 font-mono text-[14px] leading-none text-accent pointer-events-none select-none">
            &gt;
          </span>
          <input
            id="probe-target"
            type="text"
            inputMode="url"
            spellCheck={false}
            autoComplete="off"
            autoCapitalize="off"
            onKeyDown={(e) => {
              if (e.key === 'Escape') e.currentTarget.blur();
            }}
            required
            value={site}
            onChange={(e) => {
              setSite(e.target.value);
              if (error) setError(null);
            }}
            placeholder="example.com"
            aria-label="Site to check"
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? 'scan-form-error' : undefined}
            className={`${control} peer w-full pl-9 pr-10 font-mono text-[14px] sm:text-[13px] text-ink placeholder:text-faint ${error ? 'border-negative' : 'border-control'}`}
          />
          {site ? null : <SlashHint />}
        </div>
        <SummonButton busy={busy} className="basis-full sm:basis-auto" />
      </div>
      {error ? <FormError error={error} /> : null}
    </form>
  );
}

function SlashHint() {
  return (
    <kbd
      title="Press / to focus"
      className="hidden sm:flex absolute right-3 top-1/2 -translate-y-1/2 h-[18px] min-w-[18px] px-1 items-center justify-center font-mono text-[11px] leading-none text-faint border border-control rounded-[4px] pointer-events-none peer-focus:hidden"
    >
      /
    </kbd>
  );
}

function SummonButton({ busy, className = '' }: { busy: boolean; className?: string }) {
  return (
    <button
      type="submit"
      disabled={busy}
      aria-busy={busy}
      className={`${className} h-[44px] sm:h-[34px] px-5 rounded-full text-[13px] sm:text-[12px] font-semibold tracking-wide flex items-center justify-center gap-2 whitespace-nowrap transition-colors
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
  );
}

function FormError({ error }: { error: string }) {
  return (
    <p id="scan-form-error" role="alert" className="flex items-baseline gap-2 text-[12px] text-ink m-0 mt-2.5 px-1">
      <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-negative flex-none translate-y-[-1px]" />
      {error}
    </p>
  );
}

/**
 * URL probe (today's form): paste a URL, pick a persona, summon.
 * One row from sm up; on a phone the URL takes its own row and the controls
 * grow to 44px. `onSubmit` resolves to an error sentence, or null on success.
 */
function ProbeForm({
  onSubmit,
}: {
  onSubmit: (url: string, profile: string) => Promise<string | null>;
}) {
  const [url, setUrl] = useState('');
  const [profile, setProfile] = useState('default');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    >
      <div className="flex flex-wrap sm:flex-nowrap gap-2.5 items-center">
        <div className="relative basis-full sm:basis-auto sm:flex-1 min-w-0">
          {/* a prompt, not a search: this field launches a probe */}
          <span aria-hidden="true" className="absolute left-3.5 top-1/2 -translate-y-1/2 font-mono text-[14px] leading-none text-accent pointer-events-none select-none">
            &gt;
          </span>
          <input
            id="probe-target"
            type="text"
            inputMode="url"
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
            placeholder="paste a suspicious URL to probe — example.com/…"
            aria-label="Target URL"
            aria-invalid={error ? true : undefined}
            aria-describedby={error ? 'scan-form-error' : undefined}
            className={`${control} peer w-full pl-9 pr-10 font-mono text-[14px] sm:text-[13px] text-ink placeholder:text-faint ${error ? 'border-negative' : 'border-control'}`}
          />
          {url ? null : <SlashHint />}
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

        <SummonButton busy={busy} />
      </div>

      {error ? <FormError error={error} /> : null}
    </form>
  );
}
