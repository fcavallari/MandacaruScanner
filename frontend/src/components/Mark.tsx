import { useId } from 'react';

/**
 * The Mandacaru mark: a woodcut candelabra cactus, drawn on a 64-unit grid in
 * `currentColor` (the carved ribs are cut out of the body, so it works on any surface).
 *
 * - Trunk and two raised arms: heavy round-capped strokes. The trunk runs off the bottom
 *   edge on purpose; the mask below clips it at 64.
 * - Ribs: thin vertical gouges cut through trunk and arms by an SVG mask (white field,
 *   black strokes), not painted in a background colour.
 * - Spines: short, exaggerated strokes jutting off every edge and crowning each tip.
 * - Baseline: cracked earth, a ground line with two fissures splitting downward.
 *
 * `MarkGlyph` is the bare 64-unit group plus its mask, so a larger scene can embed it
 * inside its own SVG; the `maskId` must be unique within the document.
 */
export function MarkGlyph({ maskId }: { maskId: string }) {
  return (
    <>
      <mask id={maskId} maskUnits="userSpaceOnUse" x="0" y="0" width="64" height="64">
        <rect x="0" y="0" width="64" height="64" fill="white" />
        <g stroke="black" strokeWidth="1.3" strokeLinecap="round" fill="none">
          <path d="M29.6 13V24M29.6 28V44M29.6 48V58M34.4 11V20M34.4 24V38M34.4 42V58" />
          <path d="M17 21V33M47 14V26" />
        </g>
      </mask>
      <g stroke="currentColor" fill="none" strokeLinecap="round" strokeLinejoin="round">
        {/* trunk and arms, ribs cut out */}
        <g mask={`url(#${maskId})`}>
          <path d="M32 66V10" strokeWidth="11" />
          <path d="M32 40H21Q17 40 17 36V20" strokeWidth="8" />
          <path d="M32 33H43Q47 33 47 29V13" strokeWidth="8" />
        </g>
        {/* spines */}
        <g strokeWidth="1.7">
          <path d="M26.5 14l-4-3M26.5 22l-4-3M26.5 50l-4-3M26.5 56l-4-3" />
          <path d="M37.5 16l4-3M37.5 24l4-3M37.5 44l4-3M37.5 52l4-3" />
          <path d="M32 4V0.5M28 6l-2.5-3M36 6l2.5-3" />
          <path d="M13 23l-4-3M13 29l-4-3M13 35l-4-3M17 16V12.5M14 17.5l-2.5-3M20 17.5l2.5-3M22 44l-2 3.5" />
          <path d="M51 17l4-3M51 23l4-3M51 29l4-3M47 9V5.5M44 10.5l-2.5-3M50 10.5l2.5-3M42 37l2 3.5" />
        </g>
        {/* cracked-earth baseline */}
        <path d="M3 60.5H61M15 60.5l2 3.5M45 60.5l-2.5 3.5" strokeWidth="2" />
      </g>
    </>
  );
}

export default function Mark({ size = 24, className = '' }: { size?: number; className?: string }) {
  // useId() yields colons or guillemets depending on the React version; url(#…) needs a plain id.
  const maskId = `mandacaru-ribs-${useId().replace(/[^A-Za-z0-9_-]/g, '')}`;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      aria-hidden="true"
      className={className}
    >
      <MarkGlyph maskId={maskId} />
    </svg>
  );
}
