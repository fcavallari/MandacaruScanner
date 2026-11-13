import { useEffect, useId, useMemo, useState } from 'react';
import type { TaskState } from '../lib/api';
import { hostnameOf } from '../lib/format';
import { MarkGlyph } from './Mark';

/**
 * The waiting scene for a queued or running probe ("Strata"): a carved horizon with the
 * mandacaru on it and cracked layers of soil beneath. While the probe runs, a faint rust band
 * sinks through the layers and each buried trace flashes and gets tagged as the band passes.
 * The Sertão looks empty, but it isn't.
 *
 * A deliberate exception to the "no glow, no entrance animation" rule (.taste-skill/notes.md):
 * it is feedback for the one long wait on this screen, not decoration on data.
 *
 * Every mark is about this probe: star and trace positions, trace shapes and strata jitter are
 * bytes of digests of its URL, id, host, path and each visitor type it runs as, and every tag
 * is a 6-hex fragment of one of those digests or a visitor-type name in clear. Nothing is
 * random, and nothing claims progress the API doesn't report (it only says queued / running):
 * the band loops, it is not a progress bar. Under prefers-reduced-motion it is one still frame
 * (index.css, `.field-*`).
 */

const URL_PROFILES = ['default', 'mobile-ios', 'mobile-android', 'search-clicker', 'facebook-android', 'googlebot'];
const SITE_PROFILES = ['default', 'mobile-ios', 'googlebot', 'search-clicker'];

/** What the probe is made of: the strings its hashes are taken from. */
function probeSeeds(task: TaskState): { seeds: string[]; tokens: string[] } {
  const host = hostnameOf(task.target_url) || task.target_url;
  const profiles = task.kind === 'site' ? SITE_PROFILES : [task.profile || 'default', ...URL_PROFILES.filter((p) => p !== (task.profile || 'default'))];
  let path = '/';
  try {
    path = new URL(task.target_url).pathname || '/';
  } catch {
    /* keep "/" */
  }
  const seeds = [task.target_url, task.task_id, host, path, ...profiles.map((p) => `${p}|${task.target_url}`)];
  for (let i = 0; seeds.length < 24; i++) seeds.push(`${task.task_id}#${i}`);
  return { seeds, tokens: [host, ...profiles, task.task_id.slice(0, 8), path] };
}

/** A fast stand-in (FNV-1a, 64 hex chars) until SHA-256 resolves, or where crypto.subtle is absent (plain http). */
function fnvHex(s: string): string {
  let out = '';
  for (let round = 0; round < 8; round++) {
    let h = 0x811c9dc5 ^ round;
    for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
    out += (h >>> 0).toString(16).padStart(8, '0');
  }
  return out;
}

async function sha256Hex(s: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

/* ---------- the ground (600 × 270 viewBox) ---------- */

const W = 600;
const HORIZON = 'M0 121L38 118L77 121L129 120L183 120L240 117L298 121L352 118L407 122L466 117L520 120L600 118';
// The mark: 66 units, left third, its own cracked baseline (y 60.5 of 64) laid on the horizon.
const MARK_SIZE = 66;
const MARK_X = 92;
const MARK_Y = 120 - 60.5 * (MARK_SIZE / 64);
// Strata at y≈152/186/220: the reference vertices; a probe's digest bytes nudge each one ±3.
const STRATA: Array<Array<[number, number]>> = [
  [[0, 152], [60, 149], [131, 154], [210, 150], [288, 153], [371, 148], [452, 152], [530, 149], [600, 151]],
  [[0, 186], [72, 189], [150, 184], [236, 188], [318, 183], [402, 187], [489, 184], [600, 188]],
  [[0, 220], [55, 217], [141, 222], [229, 218], [310, 221], [398, 216], [470, 220], [600, 218]],
];
// Cracks run down from these [stratum, vertex] points.
const CRACKS: Array<[number, number]> = [[0, 2], [0, 4], [0, 6], [1, 3], [1, 5], [2, 2], [2, 5]];
// The band sinks 132 units in 7 s; its line starts at y 122.
const BAND_TOP = 122;
const BAND_TRAVEL = 132;
const BAND_SECONDS = 7;
const HALFWAY = BAND_TOP + BAND_TRAVEL / 2;

const byteAt = (hex: string, i: number) => parseInt(hex.slice((i % 32) * 2, (i % 32) * 2 + 2), 16) || 0;
const unit = (hex: string, i: number) => byteAt(hex, i) / 255;
const poly = (pts: Array<[number, number]>) => 'M' + pts.map(([x, y]) => `${x} ${y.toFixed(1)}`).join('L');

type Shape = 'ring' | 'cross' | 'diamond' | 'triangle' | 'dot';
const SHAPES: Shape[] = ['ring', 'cross', 'diamond', 'triangle', 'dot'];

interface Trace {
  shape: Shape;
  x: number;
  y: number;
  tag: string;
  delay: string; // when the band's line reaches y
  above: boolean; // above the still frame's halfway band
}

interface Ground {
  stars: Array<{ x: number; y: number; r: number }>;
  strata: string[];
  cracks: string;
  traces: Trace[];
}

/**
 * Digest bytes → geometry. d[0] (target URL): stars. d[1] (task id): strata jitter.
 * d[2] (host): crack shapes. d[4..9] (each visitor type with the URL, then task id #k): one
 * trace each, byte 0 shape, byte 1 x, byte 2 depth, chars 6–11 the hex tag.
 */
function groundOf(digests: string[], tokens: string[]): Ground {
  const stars = Array.from({ length: 6 }, (_, i) => ({
    x: 190 + unit(digests[0], i * 3) * 400,
    y: 10 + unit(digests[0], i * 3 + 1) * 88,
    r: 0.6 + unit(digests[0], i * 3 + 2) * 0.6,
  }));
  let k = 0;
  const jittered = STRATA.map((line) => line.map(([x, y]): [number, number] => [x, y + (unit(digests[1], k++) - 0.5) * 6]));
  const cracks = CRACKS.map(([s, v], i) => {
    const [x, y] = jittered[s][v];
    const b = (j: number) => byteAt(digests[2], i * 4 + j);
    return `M${x} ${y.toFixed(1)}l${(b(0) % 11) - 5} ${9 + (b(1) % 6)}l${(b(2) % 9) - 4} ${5 + (b(3) % 5)}`;
  }).join('');
  const profiles = tokens.slice(1, -2);
  const traces = Array.from({ length: 6 }, (_, i): Trace => {
    const d = digests[4 + i];
    const y = 130 + unit(d, 2) * 125;
    return {
      shape: SHAPES[byteAt(d, 0) % SHAPES.length],
      x: 24 + unit(d, 1) * 552,
      y,
      // two of the six carry their visitor type's name in clear, when that digest is one
      tag: i % 3 === 2 && profiles[i] ? profiles[i] : d.slice(6, 12),
      delay: `${(((y - BAND_TOP) / BAND_TRAVEL) * BAND_SECONDS).toFixed(2)}s`,
      above: y < HALFWAY,
    };
  });
  return { stars, strata: jittered.map(poly), cracks, traces };
}

function TraceMark({ shape, x, y }: { shape: Shape; x: number; y: number }) {
  switch (shape) {
    case 'ring':
      return <circle cx={x} cy={y} r={3} fill="none" />;
    case 'cross':
      return <path d={`M${x - 2.5} ${y - 2.5}l5 5M${x + 2.5} ${y - 2.5}l-5 5`} fill="none" />;
    case 'diamond':
      return <path d={`M${x} ${y - 3.5}L${x + 3.5} ${y}L${x} ${y + 3.5}L${x - 3.5} ${y}Z`} />;
    case 'triangle':
      return <path d={`M${x - 4} ${y + 3.5}L${x} ${y - 3.5}L${x + 4} ${y + 3.5}Z`} />;
    default:
      return <circle cx={x} cy={y} r={2.4} />;
  }
}

/** A unique, url(#…)-safe id (useId yields colons or guillemets depending on React). */
function useSvgId(prefix: string) {
  return `${prefix}-${useId().replace(/[^A-Za-z0-9_-]/g, '')}`;
}

function Mandacaru({ color }: { color: string }) {
  const maskId = useSvgId('field-mark');
  return (
    <g transform={`translate(${MARK_X} ${MARK_Y.toFixed(2)}) scale(${MARK_SIZE / 64})`} style={{ color }}>
      <MarkGlyph maskId={maskId} />
    </g>
  );
}

const SCENE_SVG = 'block w-full h-auto aspect-[600/270]';

export default function FieldScene({ task }: { task: TaskState }) {
  const bandId = useSvgId('field-band');
  const { seeds, tokens } = useMemo(
    () => probeSeeds(task),
    // the seeds are the probe's identity; a poll's fresh task object must not recompute them
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [task.task_id, task.target_url, task.kind, task.profile],
  );
  const [digests, setDigests] = useState(() => seeds.map(fnvHex));
  useEffect(() => {
    let alive = true;
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      Promise.all(seeds.map(sha256Hex))
        .then((real) => {
          if (alive) setDigests(real);
        })
        .catch(() => {});
    }
    return () => {
      alive = false;
    };
  }, [seeds]);
  const ground = useMemo(() => groundOf(digests, tokens), [digests, tokens]);

  const host = hostnameOf(task.target_url) || task.target_url;
  const running = task.status === 'running';
  return (
    <div className="relative flex-1 min-h-[300px] -mx-6 -mb-6 overflow-hidden rounded-b-card flex flex-col">
      <div className="flex-1 flex items-center">
        <svg
          viewBox={`0 0 ${W} 270`}
          preserveAspectRatio="xMidYMid slice"
          aria-hidden="true"
          className={`field-scene ${running ? 'is-running' : 'is-queued'} ${SCENE_SVG}`}
        >
          <defs>
            <linearGradient id={bandId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0" style={{ stopColor: 'var(--accent)', stopOpacity: 0 }} />
              <stop offset="1" style={{ stopColor: 'var(--accent)', stopOpacity: 0.16 }} />
            </linearGradient>
          </defs>
          <g fill="var(--faint)" opacity={0.55}>
            {ground.stars.map((s, i) => (
              <circle key={i} cx={s.x} cy={s.y} r={s.r} />
            ))}
          </g>
          <path d={HORIZON} stroke="var(--faint)" strokeWidth={1.6} fill="none" />
          <Mandacaru color="var(--accent)" />
          <g stroke="var(--border)" strokeWidth={1.2} fill="none">
            {ground.strata.map((d, i) => (
              <path key={i} d={d} />
            ))}
            <path d={ground.cracks} />
          </g>
          <g stroke="currentColor" fill="currentColor" strokeWidth={1.3}>
            {ground.traces.map((t, i) => (
              <g key={i} className={`field-trace${t.above ? ' is-above' : ''}`} style={{ animationDelay: t.delay }}>
                <TraceMark shape={t.shape} x={t.x} y={t.y} />
              </g>
            ))}
          </g>
          <g fontFamily='"IBM Plex Mono", ui-monospace, monospace' fontSize={10} fill="var(--accent-ink)">
            {ground.traces.map((t, i) => {
              // keep the tag inside the box: past x 470 it reads leftwards
              const flip = t.x > 470;
              return (
                <text
                  key={i}
                  className={`field-tag${t.above ? ' is-above' : ''}`}
                  x={flip ? t.x - 8 : t.x + 8}
                  y={t.y + 3}
                  textAnchor={flip ? 'end' : 'start'}
                  style={{ animationDelay: t.delay }}
                >
                  {t.tag}
                </text>
              );
            })}
          </g>
          {running ? (
            <g className="field-band">
              <rect x={0} y={BAND_TOP - 22} width={W} height={22} fill={`url(#${bandId})`} />
              <path d={`M0 ${BAND_TOP}H${W}`} stroke="var(--accent)" strokeWidth={1} opacity={0.7} />
            </g>
          ) : null}
        </svg>
      </div>
      <div role="status" className="relative -mt-8 px-6 pb-6 pt-10 text-center bg-gradient-to-t from-surface via-surface/80 to-transparent">
        <p className="text-[14px] text-muted m-0 truncate" title={running ? host : undefined}>
          {running ? `${task.kind === 'site' ? 'Checking' : 'Probing'} ${host}…` : 'Waiting for a free worker…'}
        </p>
        <p className="font-mono text-[12px] text-faint m-0 mt-1 truncate">
          {running ? 'inspecting specimen' : 'queued'} · {task.kind === 'site' ? 'site survey' : 'probe'} {task.task_id.slice(0, 8)}
        </p>
      </div>
    </div>
  );
}

/** The lead block with no probe at all: the same ground, static and dimmed, with two traces nobody has examined. */
export function EmptyGround() {
  return (
    <div className="flex-1 flex flex-col justify-center -mx-6 -mb-6 overflow-hidden rounded-b-card">
      <svg viewBox={`0 0 ${W} 270`} preserveAspectRatio="xMidYMid slice" aria-hidden="true" className={SCENE_SVG}>
        <g fill="var(--faint)" opacity={0.45}>
          <circle cx={420} cy={28} r={1} />
          <circle cx={520} cy={20} r={1.2} />
          <circle cx={250} cy={22} r={0.7} />
        </g>
        <path d={HORIZON} stroke="var(--faint)" strokeWidth={1.6} fill="none" opacity={0.8} />
        <Mandacaru color="var(--trace-settled)" />
        <g stroke="var(--grid)" strokeWidth={1.2} fill="none">
          {STRATA.map((line, i) => (
            <path key={i} d={poly(line)} />
          ))}
        </g>
        <circle cx={381} cy={168} r={2.4} fill="none" stroke="var(--border)" strokeWidth={1.2} />
        <path d="M268 236l4-7l4 7Z" fill="var(--border)" />
      </svg>
      <div role="status" className="px-6 pb-6 pt-1 text-center">
        <p className="text-[14px] text-muted m-0">Nothing collected yet.</p>
        <p className="text-[13px] text-faint m-0 mt-1">Looks empty. It rarely is. Submit a site above to look closer.</p>
      </div>
    </div>
  );
}
