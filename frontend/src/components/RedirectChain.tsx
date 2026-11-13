import React, { useMemo } from 'react';
import type { Hop } from '../lib/api';
import { REDIRECT_MECHANISMS, hopLabel, hostnameOf } from '../lib/format';

/**
 * The signature element: the redirect chain as a trail. One row per distinct host
 * in visit order, origin at the top, each step one stop further, the landing at the bottom; between rows, how the
 * browser got there in words ("302 · HTTP redirect"). Hosts print whole — the end of a
 * host (apex, TLD) is the telling part, so it is never truncated. A 1px accent spine
 * means the scorer called it a real chain.
 *
 * Static hops carry url = the page they were found on, so their labels attach to that
 * node ("found here"), not to the edge that left it.
 */

interface GNode {
  url: string;
  host: string;
  isLanding?: boolean;
  selfStatus?: number | null; // a same-host redirect that happened at this node
  marks: string[]; // static findings observed on this page, in words
}

interface GEdge {
  status?: number | null;
  label: string; // how the browser moved; '' = it moved without a recorded redirect
}

function resolveDest(hop: Hop): string | null {
  const loc = hop.headers?.location;
  if (!loc) return null;
  try {
    return new URL(loc, hop.url).toString();
  } catch {
    return null;
  }
}

/** A client-side redirect the browser performed carries its destination in JSON evidence ("to"). */
function clientDest(hop: Hop): string | null {
  if (!REDIRECT_MECHANISMS.has(hop.mechanism) || !hop.evidence) return null;
  try {
    const to = JSON.parse(hop.evidence)?.to;
    return typeof to === 'string' && to ? new URL(to, hop.url).toString() : null;
  } catch {
    return null;
  }
}

/** Evidence about a page, not a move: never a depth of its own. */
const MARK_ONLY = new Set(['page_behavior', 'yara_match']);

function buildGraph(target: string, hops: Hop[], finalUrl: string | null) {
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  let lastHost = '';

  const pushNode = (url: string, edge?: GEdge) => {
    const host = hostnameOf(url) || url; // unparseable — print as-is
    if (host === lastHost) return false;
    if (edge && nodes.length > 0) edges.push(edge);
    nodes.push({ url, host, marks: [] });
    lastHost = host;
    return true;
  };

  pushNode(target);

  for (const hop of hops) {
    if (hop.mechanism === 'origin') continue; // the first node already is it
    if (MARK_ONLY.has(hop.mechanism)) continue; // marked below, once the landing exists
    if (hop.mechanism === 'http_3xx') {
      const dest = resolveDest(hop);
      const moved = dest ? pushNode(dest, { status: hop.status_code ?? null, label: 'HTTP redirect' }) : false;
      if (!moved && nodes.length > 0) {
        // a 3xx with no usable Location, or back to the same host: mark the node it happened at
        nodes[nodes.length - 1].selfStatus = hop.status_code ?? null;
      }
    } else {
      const label = hopLabel(hop);
      const host = hostnameOf(hop.url) || hop.url;
      if (host !== lastHost) pushNode(hop.url, { status: null, label: '' });
      const n = nodes[nodes.length - 1];
      if (!n.marks.includes(label)) n.marks.push(label);
      // an observed JS / meta redirect moves the browser: draw where it went as the next depth
      const dest = clientDest(hop);
      if (dest) pushNode(dest, { status: null, label });
    }
  }

  // the landing: where the browser actually ended up
  if (finalUrl) {
    const host = hostnameOf(finalUrl);
    if (host && host !== lastHost) pushNode(finalUrl, { status: null, label: '' });
    if (nodes.length > 0) nodes[nodes.length - 1].url = finalUrl;
  }
  if (nodes.length > 0) nodes[nodes.length - 1].isLanding = true;

  // Behaviors and YARA hits are recorded for the whole scan (a YARA hit's url is often a
  // script on a CDN): mark the depth on that host, else the landing, never add a depth.
  for (const hop of hops) {
    if (!MARK_ONLY.has(hop.mechanism)) continue;
    const host = hostnameOf(hop.url) || hop.url;
    const n = [...nodes].reverse().find((node) => node.host === host) ?? nodes[nodes.length - 1];
    const label = hopLabel(hop);
    if (n && !n.marks.includes(label)) n.marks.push(label);
  }

  return { nodes, edges };
}

function Marks({ marks }: { marks: string[] }) {
  if (marks.length === 0) return null;
  return (
    <span className="flex flex-wrap gap-1.5 mt-1.5">
      {marks.map((m) => (
        <span
          key={m}
          className="px-2.5 py-[3px] text-[13px] rounded-full whitespace-nowrap"
          style={{ background: 'var(--pill-warning-bg)', color: 'var(--warning)' }}
        >
          {m}
        </span>
      ))}
    </span>
  );
}

function NodeRow({ node, depth, live, hasNext }: { node: GNode; depth: number; live: boolean; hasNext: boolean }) {
  const first = depth === 0;
  const marker = node.isLanding
    ? 'bg-accent border-accent'
    : live
      ? 'bg-surface border-accent'
      : 'bg-surface border-control';
  return (
    <li className="relative grid grid-cols-[20px_minmax(0,1fr)] gap-x-2.5">
      {/* the spine runs from this marker down to the next */}
      {hasNext ? (
        <span aria-hidden="true" className={`absolute left-[9.5px] top-[14px] bottom-0 w-px ${live ? 'bg-accent/60' : 'bg-control'}`} />
      ) : null}
      <span aria-hidden="true" className="flex justify-center pt-[5px]">
        <span className={`relative w-[9px] h-[9px] rounded-[2px] border ${marker}`} />
      </span>
      <div className="min-w-0 pb-0.5">
        <div className="flex items-baseline justify-between gap-3">
          <span
            title={node.url}
            className={`font-mono text-[14px] leading-[19px] break-all ${node.isLanding ? 'text-ink font-medium' : 'text-muted'}`}
          >
            {node.host}
          </span>
          <span className="text-[12px] text-faint whitespace-nowrap flex-none">
            {first ? (node.isLanding ? 'Origin · landed' : 'Origin') : (
              <>
                {node.isLanding ? 'Landed · ' : null}
                stop <span className="font-mono num">{depth}</span>
              </>
            )}
            {node.selfStatus != null ? <span className="font-mono num"> · {node.selfStatus} in place</span> : null}
          </span>
        </div>
        {node.isLanding && !first ? (
          <p className="font-mono text-[12px] text-faint m-0 mt-0.5 truncate" title={node.url}>
            {node.url}
          </p>
        ) : null}
        <Marks marks={node.marks} />
      </div>
    </li>
  );
}

function EdgeRow({ edge, live }: { edge: GEdge; live: boolean }) {
  return (
    <li className="relative grid grid-cols-[20px_minmax(0,1fr)] gap-x-2.5">
      <span aria-hidden="true" className={`absolute left-[9.5px] top-0 bottom-0 w-px ${live ? 'bg-accent/60' : 'bg-control'}`} />
      <span />
      <p className="text-[12px] leading-none text-faint m-0 py-2">
        {edge.status != null ? <span className="font-mono num text-muted">{edge.status}</span> : null}
        {edge.status != null && edge.label ? ' · ' : null}
        {edge.label || 'Navigated without a 3xx'}
      </p>
    </li>
  );
}

export default function RedirectChain({
  target,
  hops,
  finalUrl,
  chainDetected,
}: {
  target: string;
  hops: Hop[];
  finalUrl: string | null;
  chainDetected: boolean;
}) {
  const graph = useMemo(() => buildGraph(target, hops, finalUrl), [target, hops, finalUrl]);

  if (graph.nodes.length === 0) return null;

  const live = chainDetected;
  const summary = graph.nodes.map((n) => n.host).join(' to ');

  return (
    <div>
      <ol className="m-0 p-0 list-none" aria-label={`Redirect chain: ${summary}`}>
        {graph.nodes.map((node, i) => (
          <React.Fragment key={`${node.host}-${i}`}>
            {i > 0 ? <EdgeRow edge={graph.edges[i - 1]} live={live} /> : null}
            <NodeRow node={node} depth={i} live={live} hasNext={i < graph.nodes.length - 1} />
          </React.Fragment>
        ))}
      </ol>
      {graph.nodes.length === 1 ? (
        <p className="text-[13px] text-faint m-0 mt-2 pl-[30px]">No redirect observed: it landed where it started.</p>
      ) : null}
    </div>
  );
}
