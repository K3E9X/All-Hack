import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../lib/api.js';

const PHASES = ['recon', 'mapping', 'vuln_analysis', 'exploitation', 'validation'];

export default function LiveView() {
  const { id } = useParams();
  const [state, setState] = useState(null);
  const [eventsList, setEventsList] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [err, setErr] = useState(null);
  const wsRef = useRef(null);
  const lastIdRef = useRef(0);
  const consoleRef = useRef(null);

  const loadState = useCallback(async () => {
    try {
      const [s, a] = await Promise.all([api.engagements.state(id), api.engagements.approvals(id)]);
      setState(s);
      setApprovals((a.items || []).filter((x) => x.decision === null));
    } catch (e) {
      setErr(e.message);
    }
  }, [id]);

  useEffect(() => { loadState(); }, [loadState]);
  useEffect(() => {
    const t = setInterval(loadState, 3000);
    return () => clearInterval(t);
  }, [loadState]);

  // Event stream over WebSocket, with REST backfill first.
  useEffect(() => {
    let closed = false;
    (async () => {
      try {
        const back = await api.engagements.events(id, 0);
        if (closed) return;
        setEventsList(back.items || []);
        lastIdRef.current = (back.items || []).reduce((m, e) => Math.max(m, e.id), 0);
      } catch { /* ignore backfill errors */ }

      const proto = location.protocol === 'https:' ? 'wss' : 'ws';
      const ws = new WebSocket(`${proto}://${location.host}/ws/engagements/${id}/stream?after=${lastIdRef.current}`);
      wsRef.current = ws;
      ws.onmessage = (msg) => {
        try {
          const ev = JSON.parse(msg.data);
          lastIdRef.current = Math.max(lastIdRef.current, ev.id || 0);
          setEventsList((prev) => [...prev.slice(-400), ev]);
        } catch { /* ignore */ }
      };
      ws.onerror = () => { /* fall back to polling state */ };
    })();
    return () => { closed = true; if (wsRef.current) wsRef.current.close(); };
  }, [id]);

  useEffect(() => {
    consoleRef.current?.scrollTo(0, consoleRef.current.scrollHeight);
  }, [eventsList]);

  async function decide(approvalId, decision) {
    try { await api.engagements.decideApproval(id, approvalId, decision); await loadState(); }
    catch (e) { setErr(e.message); }
  }
  async function run() {
    try { await api.engagements.run(id); await loadState(); } catch (e) { setErr(e.message); }
  }
  async function stop() {
    try { await api.engagements.stop(id); await loadState(); } catch (e) { setErr(e.message); }
  }

  const e = state?.engagement;
  const r = state?.run;
  const active = r && (r.status === 'queued' || r.status === 'running');
  const vsum = state?.validation_summary || {};
  const chains = state?.chains || [];
  const validated = state?.validated_findings || [];

  return (
    <div className="stack">
      <div className="row-between">
        <h2>Live view {e ? `· ${e.target_host}` : ''}</h2>
        <div className="btn-row">
          <Link className="btn ghost" to="/engagements">Back</Link>
          {!active && <button className="btn" onClick={run}>Run</button>}
          {active && <button className="btn ghost danger" onClick={stop}>Stop</button>}
          <a className="btn ghost" href={`/api/engagements/${id}/report.md`} target="_blank" rel="noreferrer">Report .md</a>
          <a className="btn ghost" href={`/api/engagements/${id}/report.html`} target="_blank" rel="noreferrer">Report (print)</a>
        </div>
      </div>
      {err && <p className="result error small">{err}</p>}

      {/* Phase timeline */}
      <section className="card">
        <div className="phase-timeline">
          {PHASES.map((p) => {
            const isCurrent = r?.phase === p;
            const idx = PHASES.indexOf(r?.phase);
            const done = idx > PHASES.indexOf(p);
            return (
              <div key={p} className={`phase ${isCurrent ? 'phase-current' : ''} ${done ? 'phase-done' : ''}`}>
                {p}
              </div>
            );
          })}
        </div>
        <div className="muted small">
          Run: <span className={`run-${r?.status || 'none'}`}>{r?.status || 'not started'}</span>
          {r ? ` · iteration ${r.iterations} · ${r.jobs_launched} jobs` : ''}
        </div>
      </section>

      {/* Pending approvals */}
      {approvals.map((a) => (
        <section key={a.id} className="card approval-card">
          <h3 className="msg-h">Approval required</h3>
          <p className="small">{a.summary}</p>
          <p className="muted small mono">tools: {a.tools.join(', ')} · targets: {a.targets.join(', ')}</p>
          <div className="btn-row">
            <button className="btn" onClick={() => decide(a.id, 'approved')}>Approve exploitation</button>
            <button className="btn ghost danger" onClick={() => decide(a.id, 'denied')}>Deny</button>
          </div>
        </section>
      ))}

      <div className="live-grid">
        {/* Agent reasoning console */}
        <section className="card">
          <h3 className="msg-h">Agent console</h3>
          <div className="console" ref={consoleRef}>
            {eventsList.length === 0 && <div className="muted small">No events yet.</div>}
            {eventsList.map((ev) => (
              <div key={ev.id} className={`logline log-${ev.type}`}>
                <span className="log-ts">{new Date(ev.ts * 1000).toLocaleTimeString()}</span>
                <span className="log-type">[{ev.type}]</span>
                <span className="log-msg">{ev.message}</span>
              </div>
            ))}
          </div>
        </section>

        {/* Stats + tech */}
        <section className="card">
          <h3 className="msg-h">Surface</h3>
          <div className="grid-stats">
            <div className="stat"><div className="muted small">Assets</div><div className="mono">{state?.assets?.length || 0}</div></div>
            <div className="stat"><div className="muted small">Tech</div><div className="mono">{state?.technologies?.length || 0}</div></div>
            <div className="stat"><div className="muted small">Confirmed</div><div className="mono sev-high">{vsum.confirmed || 0}</div></div>
            <div className="stat"><div className="muted small">FP rate</div><div className="mono">{vsum.false_positive_rate_pct != null ? `${vsum.false_positive_rate_pct}%` : '-'}</div></div>
          </div>
          {state?.technologies?.length > 0 && (
            <p className="small"><strong>Tech:</strong> <span className="mono">{state.technologies.join(', ')}</span></p>
          )}
        </section>
      </div>

      {/* Kill-chains */}
      {chains.length > 0 && (
        <section className="card">
          <h3 className="msg-h">Kill-chains ({chains.length})</h3>
          <div className="stack-sm">
            {chains.map((c) => (
              <div key={c.id} className="suggestion-card">
                <div className="row-between">
                  <span className={`sev sev-${(c.severity || 'medium').toLowerCase()}`}>{c.severity}</span>
                  <span className="muted small mono">{c.source || 'deterministic'}</span>
                </div>
                <div className="finding-title">{c.title}</div>
                {c.summary && <div className="finding-desc">{c.summary}</div>}
                <ol className="small chain-steps">
                  {(c.steps || []).map((s, i) => (
                    <li key={i}><strong>{s.action}</strong>{s.reason ? ` - ${s.reason}` : ''}</li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* Validated findings */}
      {validated.length > 0 && (
        <section className="card">
          <h3 className="msg-h">Validated findings ({validated.length})</h3>
          <div className="stack-sm">
            {validated.slice(0, 80).map((f) => (
              <div key={f.id} className="finding">
                <div className="row-between">
                  <span className={`sev sev-${(f.severity || 'info').toLowerCase()}`}>{f.severity}</span>
                  <span className={`mono small vstatus-${f.status}`}>{f.status} ({Math.round((f.confidence || 0) * 100)}%)</span>
                </div>
                <div className="finding-title">{f.title}</div>
                <div className="mono small truncate" title={f.target}>{f.target}</div>
                <div className="muted small">{f.tool} · {f.method}</div>
                {f.poc && <pre className="body mono small">{f.poc}</pre>}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
