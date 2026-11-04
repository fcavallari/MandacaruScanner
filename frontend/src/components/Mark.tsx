/**
 * The Pnakotic sigil, after the mythos' "Pnakotic pentagon" (drawn fresh for this
 * product, not traced from any artwork): a heavy pentagon standing on its point, and
 * inside it the product's own figure — a redirect chain. A hollow node (the origin)
 * sends a line that strikes the walls twice and crosses its own path before it ends
 * in a solid node (the landing). Kept to a thick seal, three segments and two nodes so it holds at 14px.
 *
 * Geometry: a regular pentagon of radius 10.6 around (12, 11.6), point down
 * (vertices at 90°, 162°, 234°, 306°, 18° in screen coordinates).
 */
export default function Mark({ size = 24, className = '' }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
      className={className}
    >
      {/* the seal */}
      <path
        d="M12 22.2 1.92 14.88 5.77 3.02H18.23L22.08 14.88Z"
        stroke="currentColor"
        strokeWidth="2.1"
        strokeLinejoin="round"
      />
      {/* the chain: origin → wall → wall → landing, crossing itself once */}
      <path
        d="M9.27 7.65 18.15 16.38 14.2 4.15 12.2 17"
        stroke="currentColor"
        strokeWidth="1.15"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.75"
      />
      {/* the origin: hollow */}
      <circle cx="8.2" cy="6.6" r="1.5" stroke="currentColor" strokeWidth="1.15" />
      {/* the landing: solid */}
      <circle cx="12.2" cy="17" r="1.75" fill="currentColor" />
    </svg>
  );
}
