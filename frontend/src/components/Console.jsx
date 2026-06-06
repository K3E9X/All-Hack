import { useEffect, useMemo, useRef, useState } from 'react';

/**
 * A self-contained live log console: toolbar (search, type filter, autoscroll,
 * copy, clear-view) + colour-coded event lines. "Smart" autoscroll sticks to
 * the bottom only while the operator is already at the bottom, so scrolling up
 * to read isn't interrupted by incoming events.
 *
 * Props:
 *   title       header label
 *   events      [{ id, ts, type, message, level }]
 *   accent      optional accent class for the title dot
 *   emptyText   shown when there are no (matching) events
 *   live        boolean, drives the pulsing "connected" dot
 */
export default function Console({ title, events = [], accent = '', emptyText = 'No events yet.', live = false }) {
  const [query, setQuery] = useState('');
  const [type, setType] = useState('all');
  const [autoscroll, setAutoscroll] = useState(true);
  const [clearedBeforeId, setClearedBeforeId] = useState(0);
  const bodyRef = useRef(null);

  const types = useMemo(() => {
    const s = new Set();
    for (const ev of events) s.add(ev.type);
    return Array.from(s).sort();
  }, [events]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return events.filter((ev) => {
      if (ev.id <= clearedBeforeId) return false;
      if (type !== 'all' && ev.type !== type) return false;
      if (q && !(`${ev.type} ${ev.message}`.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [events, query, type, clearedBeforeId]);

  // Stick to bottom only when already at (or near) the bottom.
  useEffect(() => {
    if (!autoscroll || !bodyRef.current) return;
    bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [filtered, autoscroll]);

  function onScroll() {
    const el = bodyRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    if (atBottom !== autoscroll) setAutoscroll(atBottom);
  }

  function copyAll() {
    const text = filtered
      .map((ev) => `${fmtTime(ev.ts)} [${ev.type}] ${ev.message}`)
      .join('\n');
    navigator.clipboard?.writeText(text).catch(() => {});
  }

  return (
    <div className="console-panel">
      <div className="console-bar">
        <div className="console-title">
          <span className={`dot ${live ? 'dot-live' : ''} ${accent}`} />
          {title}
          <span className="tab-count">{filtered.length}</span>
        </div>
        <div className="console-tools">
          <input
            className="console-search"
            placeholder="filter…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <select value={type} onChange={(e) => setType(e.target.value)}>
            <option value="all">all types</option>
            {types.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <button
            className={`console-btn ${autoscroll ? 'on' : ''}`}
            title="Auto-scroll to newest"
            onClick={() => setAutoscroll((v) => !v)}
          >
            ↓ auto
          </button>
          <button className="console-btn" title="Copy visible lines" onClick={copyAll}>copy</button>
          <button
            className="console-btn"
            title="Clear view (hides current lines)"
            onClick={() => setClearedBeforeId(events.length ? events[events.length - 1].id : 0)}
          >
            clear
          </button>
        </div>
      </div>
      <div className="console" ref={bodyRef} onScroll={onScroll}>
        {filtered.length === 0 && <div className="muted small console-empty">{emptyText}</div>}
        {filtered.map((ev) => (
          <div key={ev.id} className={`logline log-${ev.type}`}>
            <span className="log-ts">{fmtTime(ev.ts)}</span>
            <span className={`log-badge badge-${badgeKind(ev.type)}`}>{ev.type}</span>
            <span className="log-msg">{ev.message}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
}

// Map an event type to a small set of semantic colour buckets.
function badgeKind(type) {
  switch (type) {
    case 'error': return 'error';
    case 'finding':
    case 'approval_required': return 'warn';
    case 'validated':
    case 'chain_built':
    case 'run_finished': return 'ok';
    case 'phase_changed':
    case 'run_started':
    case 'task_launched': return 'info';
    case 'command': return 'cmd';
    case 'fingerprint': return 'tech';
    default: return 'muted';
  }
}
