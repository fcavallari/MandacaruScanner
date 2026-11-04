import React from 'react';
import { Radar } from 'lucide-react';
import Dashboard from './components/Dashboard';
import Mark from './components/Mark';

/**
 * Shell: an unlabelled 56px icon rail on the page ground with a 1px edge —
 * the product's mark at top, one destination (this is a single-screen tool),
 * and the active item marked by icon colour plus a 1px accent line on the
 * rail's edge (the style's move). On a phone the rail goes:
 * with one destination there is nothing to navigate, and the title row names the product.
 */

function Rail() {
  return (
    <nav
      aria-label="Primary"
      className="hidden md:flex fixed left-0 top-0 bottom-0 w-[56px] border-r border-line bg-ground flex-col items-center py-4 z-20"
    >
      <a href="#" aria-label="Pnakotic" title="Pnakotic" className="text-accent block mb-6">
        <Mark size={24} />
      </a>

      {/* the one destination: this screen */}
      <button
        type="button"
        aria-label="Observatory"
        aria-current="page"
        title="Observatory"
        className="relative w-9 h-9 flex items-center justify-center text-ink cursor-default"
      >
        {/* the move: a 1px accent line exactly as tall as the icon, on the rail's edge */}
        <span aria-hidden="true" className="absolute -right-[10px] top-1/2 -translate-y-1/2 w-px h-[18px] bg-accent" />
        <Radar size={18} strokeWidth={1.5} className="text-accent" />
      </button>
    </nav>
  );
}

export default function App() {
  return (
    <div className="min-h-screen bg-ground text-ink">
      <Rail />
      <main className="md:pl-[57px]">
        <Dashboard />
      </main>
    </div>
  );
}
