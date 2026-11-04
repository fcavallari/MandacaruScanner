import React from 'react';

/**
 * Honest states, per the app-screen rules:
 * - loading = a flat grey bar at the value's real size (no shimmer, no shift)
 * - empty   = the frame and header kept, one sentence in a dashed well
 * - error   = one sentence + Retry inside the block; negative colour on a small mark only
 */

/** Flat grey bar at a real size. `w` is a CSS width (e.g. "40%"). */
export function Bar({ h = 12, w = '100%', className = '' }: { h?: number; w?: string | number; className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`bg-raised rounded-[3px] ${className}`}
      style={{ height: h, width: w }}
    />
  );
}

/** Dashed well that keeps a block's frame while it holds nothing. */
export function EmptyWell({ title, sub, className = '' }: { title: string; sub?: string; className?: string }) {
  return (
    <div
      role="status"
      className={`border border-dashed border-control rounded-card flex flex-col items-center justify-center text-center px-6 ${className}`}
    >
      <p className="text-[13px] text-muted m-0">{title}</p>
      {sub ? <p className="text-[12px] text-faint m-0 mt-1">{sub}</p> : null}
    </div>
  );
}

/** Per-block failure: one sentence, a small negative mark, and a Retry. */
export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div role="alert" className="flex items-center gap-2.5 px-1 py-1">
      <span aria-hidden="true" className="w-1.5 h-1.5 rounded-full bg-negative flex-none" />
      <p className="text-[12px] text-muted m-0 flex-1">{message}</p>
      {onRetry ? (
        <button
          type="button"
          onClick={onRetry}
          className="text-[12px] font-medium text-accent bg-transparent border-0 p-0 cursor-pointer"
        >
          Retry
        </button>
      ) : null}
    </div>
  );
}
