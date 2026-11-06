import { useEffect, useRef } from 'react';
import type { TaskState } from '../lib/api';
import { hostnameOf } from '../lib/format';

/**
 * The waiting scene for a queued or running probe: the sigil glows in the middle of the pane
 * while columns of hash characters fall around it, and now and then it seizes a fragment, pulls
 * it into its origin node and runs it down the redirect path into the landing node.
 *
 * A deliberate exception to the "no glow, no entrance animation" rule (.taste-skill/notes.md):
 * it is feedback for the one long wait on this screen, not decoration on data.
 *
 * Every string is about this probe: SHA-256 digests of the target URL, the probe id, its host
 * and path, and each visitor type it runs as, plus those names in clear. Nothing is random text.
 * Under prefers-reduced-motion it draws one still frame (a lit sigil, frozen rain).
 */

const URL_PROFILES = ['default', 'mobile-ios', 'mobile-android', 'search-clicker', 'facebook-android', 'googlebot'];
const SITE_PROFILES = ['default', 'mobile-ios', 'googlebot', 'search-clicker'];

// The sigil, in Mark.tsx's 24-unit viewBox.
const SEAL = 'M12 22.2 1.92 14.88 5.77 3.02H18.23L22.08 14.88Z';
const CHAIN = 'M9.27 7.65 18.15 16.38 14.2 4.15 12.2 17';
const ORIGIN: [number, number] = [8.2, 6.6];
const LANDING: [number, number] = [12.2, 17];
// A captured fragment's route: into the hollow origin, then the chain to the solid landing.
const ROUTE: Array<[number, number]> = [ORIGIN, [9.27, 7.65], [18.15, 16.38], [14.2, 4.15], LANDING];
const CENTER: [number, number] = [12, 11.6];

const FONT_PX = 13;
const MONO = '"IBM Plex Mono", ui-monospace, SFMono-Regular, monospace';
const MAX_CAPTIVES = 6;

type RGB = [number, number, number];

function parseColor(value: string, fallback: RGB): RGB {
  const hex = value.trim().match(/^#([0-9a-f]{6})$/i);
  if (!hex) return fallback;
  const n = parseInt(hex[1], 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

const rgba = ([r, g, b]: RGB, a: number) => `rgba(${r},${g},${b},${Math.max(0, Math.min(1, a))})`;
const mix = (a: RGB, b: RGB, t: number): RGB => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];

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

interface Column {
  x: number;
  y: number; // head, px
  speed: number; // px/s
  len: number; // trail, chars
  src: number; // digest index
  off: number; // offset into it
}

interface Captive {
  text: string;
  start: [number, number]; // screen px
  t: number; // seconds alive
  pull: number; // seconds to reach the origin
}

function easeIn(t: number) {
  return t * t * t;
}

export default function ProbeRitual({ task }: { task: TaskState }) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const runningRef = useRef(task.status === 'running');
  runningRef.current = task.status === 'running';
  // under reduced motion nothing loops, so a status change has to redraw the still frame itself
  const redrawStillRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    const wrap = wrapRef.current;
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!wrap || !canvas || !ctx) return;

    const { seeds, tokens } = probeSeeds(task);
    const digests = seeds.map(fnvHex);
    let alive = true;
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      Promise.all(seeds.map(sha256Hex))
        .then((real) => {
          if (alive) real.forEach((d, i) => (digests[i] = d));
        })
        .catch(() => {});
    }

    const css = getComputedStyle(document.documentElement);
    const accent = parseColor(css.getPropertyValue('--accent'), [64, 224, 180]);
    const faint = parseColor(css.getPropertyValue('--faint'), [122, 141, 131]);
    const white: RGB = [236, 255, 248];
    const seal = new Path2D(SEAL);
    const chain = new Path2D(CHAIN);

    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
    let w = 0;
    let h = 0;
    let dpr = 1;
    let cols: Column[] = [];
    let captives: Captive[] = [];
    let intensity = runningRef.current ? 1 : 0.25;
    let flash = 0; // landing node, after a captive arrives
    let nextCapture = 0.6;
    let clock = 0;
    let last = performance.now();
    let raf = 0;

    const rand = (a: number, b: number) => a + Math.random() * (b - a);
    const newColumn = (x: number, fresh: boolean): Column => ({
      x,
      y: fresh ? rand(-h, h) : rand(-h * 0.6, 0),
      speed: rand(38, 120),
      len: Math.floor(rand(8, 26)),
      src: Math.floor(Math.random() * digests.length),
      off: Math.floor(Math.random() * 64),
    });

    // Sigil placement: centred a little above the middle, leaving the status lines room below.
    const sigil = () => {
      const size = Math.max(110, Math.min(260, Math.min(w, h) * 0.46));
      const s = size / 24;
      const ox = w / 2 - CENTER[0] * s;
      const oy = h * 0.44 - CENTER[1] * s;
      return { s, ox, oy, cx: w / 2, cy: h * 0.44, r: size * 0.5 };
    };
    const toScreen = (p: [number, number]): [number, number] => {
      const { s, ox, oy } = sigil();
      return [ox + p[0] * s, oy + p[1] * s];
    };

    const layout = () => {
      const rect = wrap.getBoundingClientRect();
      w = Math.max(1, rect.width);
      h = Math.max(1, rect.height);
      dpr = Math.min(2, window.devicePixelRatio || 1);
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      const cw = FONT_PX * 0.95;
      cols = Array.from({ length: Math.ceil(w / cw) }, (_, i) => newColumn(i * cw + cw / 2, true));
      captives = [];
    };

    const drawRain = (k: number) => {
      const { cx, cy, r } = sigil();
      const lens = r * 1.7;
      ctx.font = `${FONT_PX}px ${MONO}`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.shadowBlur = 0;
      for (const c of cols) {
        const head = Math.floor(c.y / FONT_PX);
        const d = digests[c.src];
        for (let i = 0; i < c.len; i++) {
          const row = head - i;
          const y = row * FONT_PX;
          if (y < -FONT_PX || y > h + FONT_PX) continue;
          // the sigil bends the rain towards itself, and the rain thins over its face
          const dx = cx - c.x;
          const dy = cy - y;
          const dist = Math.hypot(dx, dy);
          let x = c.x;
          let yy = y;
          let a = (1 - i / c.len) * 0.55 * (0.35 + 0.65 * k);
          if (dist < lens) {
            const pull = Math.pow(1 - dist / lens, 2) * 0.32 * k;
            x += dx * pull;
            yy += dy * pull * 0.45;
            if (dist < r * 0.85) a *= 0.22;
          }
          const ch = d[(c.off + ((row % 64) + 64)) % 64];
          ctx.fillStyle = i === 0 ? rgba(mix(accent, white, 0.6 * k), Math.min(1, a * 1.8)) : rgba(mix(faint, accent, k * 0.8), a);
          ctx.fillText(ch, x, yy);
        }
      }
    };

    const routePoint = (u: number): [number, number] => {
      // u in [0,1] along ROUTE, by length
      const pts = ROUTE.map(toScreen);
      const lens = pts.slice(1).map((p, i) => Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1]));
      const total = lens.reduce((x, y) => x + y, 0);
      let left = u * total;
      for (let i = 0; i < lens.length; i++) {
        if (left <= lens[i]) {
          const t = lens[i] ? left / lens[i] : 0;
          return [pts[i][0] + (pts[i + 1][0] - pts[i][0]) * t, pts[i][1] + (pts[i + 1][1] - pts[i][1]) * t];
        }
        left -= lens[i];
      }
      return pts[pts.length - 1];
    };

    const spawnCaptive = () => {
      const { cx, cy, r } = sigil();
      // seize from a column head that is visible and not under the sigil itself
      const near = cols.filter((c) => c.y > 0 && c.y < h && Math.hypot(c.x - cx, c.y - cy) > r * 1.1);
      if (!near.length) return;
      const c = near[Math.floor(Math.random() * near.length)];
      const d = digests[Math.floor(Math.random() * digests.length)];
      const at = Math.floor(Math.random() * 52);
      const text = Math.random() < 0.3 ? tokens[Math.floor(Math.random() * tokens.length)].slice(0, 22) : d.slice(at, at + 12);
      captives.push({ text, start: [c.x, Math.floor(c.y / FONT_PX) * FONT_PX], t: 0, pull: rand(0.9, 1.4) });
    };

    const RUN = 1.1; // seconds along the chain

    const drawCaptives = (dt: number) => {
      const o = toScreen(ORIGIN);
      ctx.font = `500 ${FONT_PX - 1}px ${MONO}`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      captives = captives.filter((cap) => {
        cap.t += dt;
        let x: number;
        let y: number;
        let text = cap.text;
        if (cap.t < cap.pull) {
          // dragged in, accelerating, along a curve that swings past the centre
          const u = easeIn(cap.t / cap.pull);
          const { cx, cy } = sigil();
          const mx = (cap.start[0] + cx) / 2;
          const my = (cap.start[1] + cy) / 2 - 40;
          x = (1 - u) * (1 - u) * cap.start[0] + 2 * (1 - u) * u * mx + u * u * o[0];
          y = (1 - u) * (1 - u) * cap.start[1] + 2 * (1 - u) * u * my + u * u * o[1];
        } else {
          const u = (cap.t - cap.pull) / RUN;
          if (u >= 1) {
            flash = 1;
            return false;
          }
          [x, y] = routePoint(u);
          // consumed as it runs: the fragment loses characters from its front
          text = text.slice(Math.floor(text.length * u));
          // the stretch of path it has just lit
          ctx.save();
          ctx.strokeStyle = rgba(white, 0.85);
          ctx.lineWidth = 2;
          ctx.lineCap = 'round';
          ctx.shadowColor = rgba(accent, 1);
          ctx.shadowBlur = 14 * dpr;
          ctx.beginPath();
          const steps = 8;
          for (let i = 0; i <= steps; i++) {
            const p = routePoint(Math.max(0, u - 0.12 + (0.12 * i) / steps));
            if (i === 0) ctx.moveTo(p[0], p[1]);
            else ctx.lineTo(p[0], p[1]);
          }
          ctx.stroke();
          ctx.restore();
        }
        ctx.shadowColor = rgba(accent, 0.9);
        ctx.shadowBlur = 10 * dpr;
        ctx.fillStyle = rgba(mix(accent, white, 0.35), 0.95);
        ctx.fillText(text, x, y - (cap.t >= cap.pull ? 12 : 0));
        ctx.shadowBlur = 0;
        return true;
      });
    };

    const drawSigil = (k: number, breath: number) => {
      const { s, ox, oy } = sigil();
      const glow = k * (0.45 + 0.55 * breath) + flash * 0.7;
      const ink = mix(faint, accent, Math.min(1, k * 1.1));
      ctx.save();
      ctx.translate(ox, oy);
      ctx.scale(s, s);
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.shadowColor = rgba(accent, Math.min(1, glow));
      // the seal, twice: a wide halo, then the line itself
      ctx.shadowBlur = 42 * glow * dpr;
      ctx.strokeStyle = rgba(ink, 0.35 + 0.65 * k);
      ctx.lineWidth = 2.1;
      ctx.stroke(seal);
      ctx.shadowBlur = 16 * glow * dpr;
      ctx.stroke(seal);
      ctx.lineWidth = 1.15;
      ctx.strokeStyle = rgba(ink, (0.35 + 0.65 * k) * 0.75);
      ctx.stroke(chain);
      ctx.beginPath();
      ctx.arc(ORIGIN[0], ORIGIN[1], 1.5, 0, Math.PI * 2);
      ctx.stroke();
      ctx.beginPath();
      ctx.arc(LANDING[0], LANDING[1], 1.75 + flash * 0.5, 0, Math.PI * 2);
      ctx.fillStyle = rgba(mix(ink, white, flash * 0.7), 0.4 + 0.6 * k);
      ctx.shadowBlur = (18 * glow + 30 * flash) * dpr;
      ctx.fill();
      ctx.restore();
      if (flash > 0.02) {
        // a ring off the landing node as it swallows a fragment
        const [lx, ly] = toScreen(LANDING);
        ctx.beginPath();
        ctx.arc(lx, ly, (1 - flash) * s * 5 + s * 1.8, 0, Math.PI * 2);
        ctx.strokeStyle = rgba(accent, flash * 0.6);
        ctx.lineWidth = 1.5;
        ctx.stroke();
      }
    };

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;
      clock += dt;
      const target = runningRef.current ? 1 : 0.25;
      intensity += (target - intensity) * Math.min(1, dt * 1.6);
      flash = Math.max(0, flash - dt * 1.6);

      for (const c of cols) {
        c.y += c.speed * dt * (0.45 + 0.55 * intensity);
        if (c.y - c.len * FONT_PX > h) Object.assign(c, newColumn(c.x, false));
      }
      if (intensity > 0.6) {
        nextCapture -= dt;
        if (nextCapture <= 0 && captives.length < MAX_CAPTIVES) {
          spawnCaptive();
          nextCapture = rand(0.35, 0.9);
        }
      }

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      drawRain(intensity);
      drawSigil(intensity, 0.5 + 0.5 * Math.sin((clock * Math.PI * 2) / 3.2));
      drawCaptives(dt);
      raf = requestAnimationFrame(frame);
    };

    const still = () => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      const k = runningRef.current ? 1 : 0.25;
      drawRain(k);
      drawSigil(k, 0.7);
    };

    const start = () => {
      cancelAnimationFrame(raf);
      if (reduced.matches) {
        still();
      } else {
        last = performance.now();
        raf = requestAnimationFrame(frame);
      }
    };

    redrawStillRef.current = () => {
      if (reduced.matches) still();
    };
    layout();
    start();
    const ro = new ResizeObserver(() => {
      layout();
      if (reduced.matches) still();
    });
    ro.observe(wrap);
    reduced.addEventListener('change', start);
    return () => {
      alive = false;
      redrawStillRef.current = null;
      cancelAnimationFrame(raf);
      ro.disconnect();
      reduced.removeEventListener('change', start);
    };
    // restart only for a different probe; status changes are read through runningRef
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [task.task_id]);

  useEffect(() => {
    redrawStillRef.current?.();
  }, [task.status]);

  const host = hostnameOf(task.target_url) || task.target_url;
  const running = task.status === 'running';
  return (
    <div ref={wrapRef} className="relative flex-1 min-h-[300px] -mx-5 -mb-5 overflow-hidden rounded-b-card">
      {/* the rain fades in under the header instead of starting on a hard edge */}
      <canvas
        ref={canvasRef}
        aria-hidden="true"
        className="absolute inset-0"
        style={{ maskImage: 'linear-gradient(to bottom, transparent, black 18%)', WebkitMaskImage: 'linear-gradient(to bottom, transparent, black 18%)' }}
      />
      <div role="status" className="absolute inset-x-0 bottom-0 px-5 pb-5 pt-10 text-center bg-gradient-to-t from-surface via-surface/80 to-transparent">
        <p className="text-[14px] text-muted m-0">
          {running ? `${task.kind === 'site' ? 'Checking' : 'Probing'} ${host}…` : 'Waiting for a worker in the dark…'}
        </p>
        <p className="font-mono text-[12px] text-faint m-0 mt-1">
          {running ? 'the deep is listening' : 'queued'} · {task.kind === 'site' ? 'site survey' : 'probe'} {task.task_id.slice(0, 8)}
        </p>
      </div>
    </div>
  );
}
