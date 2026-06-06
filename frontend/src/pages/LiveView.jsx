import { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../lib/api.js';

const PHASES = ['recon', 'mapping', 'vuln_analysis', 'exploitation', 'validation'];

// Fallback category taxonomy (the backend sends the authoritative one in state).
const DEFAULT_CATEGORIES = [
  { key: 'recon', label: 'Reconnaissance' },
  { key: 'enumeration', label: 'Mapping & enumeration' },
  { key: 'access_control', label: 'Access control' },
  { key: 'injection', label: 'Injection & exploitation' },
  { key: 'auth_secrets', label: 'Auth & secrets' },
  { key: 'config', label: 'Server & config' },
  { key: 'other', label: 'Other' },
];

export default function LiveView() {
  const { id } = useParams();
  const [state, setState] = useState(null);
  const [eventsList, setEventsList] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [err, setErr] = useState(null);
  const wsRef = useRef(null);
  const lastIdRef = useRef(0);
  const consoleRef = useRef(null);
  const verboseRef = useRef(null);
  const [activeCat, setActiveCat] = useState('all');
  const [analyzing, setAnalyzing] = useState(false);
  const [tab, setTab] = useState('console');
  const [openJob, setOpenJob] = useState(null);
  const [jobDetail, setJobDetail] = useState(null);

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
    verboseRef.current?.scrollTo(0, verboseRef.current.scrollHeight);
  }, [eventsList, tab]);

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
  // Open a job to see exactly what ran in the backend: command, exit code,
  // error and the tool's stdout/stderr.
  async function toggleJob(jid) {
    if (openJob === jid) { setOpenJob(null); setJobDetail(null); return; }
    setOpenJob(jid); setJobDetail(null);
    try { setJobDetail(await api.scans.get(jid)); } catch (e) { setErr(e.message); }
  }
  async function analyzeTraffic() {
    setAnalyzing(true);
    try {
      const r = await api.engagements.analyzeTraffic(id);
      await loadState();
      const lg = r.logic || {}, js = r.js_recon || {}, jw = r.jwt || {}, ac = r.access_control || {}, co = r.cors || {};
      alert(
        `Deep analysis complete:\n` +
        `· Logic: ${lg.idor || 0} IDOR, ${lg.csrf || 0} CSRF, ${lg.bfla || 0} BFLA/privesc\n` +
        `· JS mining: ${js.secrets || 0} secret(s), ${js.endpoints || 0} endpoint(s)\n` +
        `· JWT: ${jw.findings || 0} issue(s) on ${jw.jwt_tokens || 0} token(s)\n` +
        `· Access control: ${ac.broken_access_control || 0} broken, ${ac.flagged || 0} to review\n` +
        `· CORS: ${co.findings || 0} finding(s) on ${co.probed || 0} endpoint(s)`
      );
    } catch (e) { setErr(e.message); }
    finally { setAnalyzing(false); }
  }

  const e = state?.engagement;
  const r = state?.run;
  const active = r && (r.status === 'queued' || r.status === 'running');
  const vsum = state?.validation_summary || {};
  const chains = state?.chains || [];
  const validated = state?.validated_findings || [];
  const assets = state?.assets || [];
  const jobs = state?.jobs || [];
  const coverage = state?.coverage || [];
  const covSummary = state?.coverage_summary || {};
  const llm = state?.llm_usage || {};
  const infoEvents = eventsList.filter((ev) => ev.level !== 'verbose');
  const verboseEvents = eventsList.filter((ev) => ev.level === 'verbose');

  // Partition validated findings by the backend's canonical category taxonomy.
  const catMeta = state?.categories || DEFAULT_CATEGORIES;
  const byCategory = {};
  for (const f of validated) {
    const c = f.category || 'other';
    (byCategory[c] = byCategory[c] || []).push(f);
  }
  const activeCats = catMeta.filter((c) => (byCategory[c.key] || []).length > 0);
  const shownFindings = activeCat === 'all' ? validated : (byCategory[activeCat] || []);

  const TABS = [
    { key: 'console', label: 'Console' },
    { key: 'assets', label: 'Assets', count: assets.length },
    { key: 'coverage', label: 'Coverage', count: coverage.length },
    { key: 'jobs', label: 'Jobs', count: jobs.length },
    { key: 'findings', label: 'Findings', count: validated.length },
    { key: 'chains', label: 'Chains', count: chains.length },
  ];

  return (
    <div className="stack">
      <div className="row-between">
        <h2>Live view {e ? `· ${e.target_host}` : ''}</h2>
        <div className="btn-row">
          <Link className="btn ghost" to="/engagements">Back</Link>
          {!active && <button className="btn" onClick={run}>Run</button>}
          {active && <button className="btn ghost danger" onClick={stop}>Stop</button>}
          <button className="btn ghost" onClick={analyzeTraffic} disabled={analyzing}>
            {analyzing ? 'Analyzing...' : 'Deep analysis (logic / JS / JWT)'}
          </button>
          <a className="btn ghost" href={`/api/engagements/${id}/report.md`} target="_blank" rel="noreferrer">Report .md</a>
          <a className="btn ghost" href={`/api/engagements/${id}/report.html`} target="_blank" rel="noreferrer">Report (print)</a>
        </div>
      </div>
      {err && <p className="result error small">{err}</p>}

      {/* Phase timeline (always visible) */}
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

      {/* Pending approvals (always visible, action required) */}
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

      {/* Page-level tabs */}
      <div className="tabs">
        {TABS.map((t) => (
          <button key={t.key} className={tab === t.key ? 'active' : ''} onClick={() => setTab(t.key)}>
            {t.label}{t.count != null ? <span className="tab-count">{t.count}</span> : null}
          </button>
        ))}
      </div>

      {/* ---- Console tab ---- */}
      {tab === 'console' && (
        <>
          <section className="card">
            <h3 className="msg-h">Agent console</h3>
            <div className="console" ref={consoleRef}>
              {infoEvents.length === 0 && <div className="muted small">No events yet.</div>}
              {infoEvents.map((ev) => (
                <div key={ev.id} className={`logline log-${ev.type}`}>
                  <span className="log-ts">{new Date(ev.ts * 1000).toLocaleTimeString()}</span>
                  <span className="log-type">[{ev.type}]</span>
                  <span className="log-msg">{ev.message}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="card">
            <h3 className="msg-h">Verbose console</h3>
            <div className="console" ref={verboseRef}>
              {verboseEvents.length === 0 && <div className="muted small">No detail yet.</div>}
              {verboseEvents.map((ev) => (
                <div key={ev.id} className={`logline log-${ev.type}`}>
                  <span className="log-ts">{new Date(ev.ts * 1000).toLocaleTimeString()}</span>
                  <span className="log-type">[{ev.type}]</span>
                  <span className="log-msg">{ev.message}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="card">
            <h3 className="msg-h">Surface &amp; cost</h3>
            <div className="grid-stats">
              <div className="stat"><div className="muted small">Assets</div><div className="mono">{assets.length}</div></div>
              <div className="stat"><div className="muted small">Tech</div><div className="mono">{state?.technologies?.length || 0}</div></div>
              <div className="stat"><div className="muted small">Confirmed</div><div className="mono sev-high">{vsum.confirmed || 0}</div></div>
              <div className="stat"><div className="muted small">FP rate</div><div className="mono">{vsum.false_positive_rate_pct != null ? `${vsum.false_positive_rate_pct}%` : '-'}</div></div>
              <div className="stat"><div className="muted small">LLM calls</div><div className="mono">{llm.calls || 0}</div></div>
              <div className="stat"><div className="muted small">Tokens</div><div className="mono">{(llm.total_tokens || 0).toLocaleString()}</div></div>
              <div className="stat"><div className="muted small">API cost</div><div className="mono">${(llm.cost_usd || 0).toFixed(4)}</div></div>
            </div>
            {state?.technologies?.length > 0 && (
              <p className="small"><strong>Tech:</strong> <span className="mono">{state.technologies.join(', ')}</span></p>
            )}
          </section>
        </>
      )}

      {/* ---- Assets tab ---- */}
      {tab === 'assets' && (
        <section className="card">
          <h3 className="msg-h">Discovered assets ({assets.length})</h3>
          {assets.length === 0 ? (
            <div className="muted small">No assets discovered yet.</div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr><th>Kind</th><th>Value</th><th>Source</th><th>Params</th><th>HTTPS</th></tr>
                </thead>
                <tbody>
                  {assets.map((a, i) => (
                    <tr key={i}>
                      <td>{a.kind}</td>
                      <td className="mono truncate" title={a.value}>{a.value}</td>
                      <td className="muted">{a.source || '-'}</td>
                      <td>{a.has_params ? 'yes' : '-'}</td>
                      <td>{a.is_https ? 'yes' : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* ---- Coverage tab ---- */}
      {tab === 'coverage' && (
        <section className="card">
          <h3 className="msg-h">Methodology coverage ({coverage.length})</h3>
          <div className="cov-chips">
            {Object.entries(covSummary).map(([s, n]) => (
              <span key={s} className="cov-chip">{s} <span className="tab-count">{n}</span></span>
            ))}
            {Object.keys(covSummary).length === 0 && <span className="muted small">Nothing run yet.</span>}
          </div>
          {coverage.length > 0 && (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr><th>Catalog item</th><th>Asset</th><th>Status</th><th>When</th></tr>
                </thead>
                <tbody>
                  {coverage.map((c, i) => (
                    <tr key={i}>
                      <td className="mono">{c.catalog_item_id}</td>
                      <td className="mono truncate" title={c.asset_value}>{c.asset_value}</td>
                      <td>{c.status}</td>
                      <td className="muted">{c.updated_at ? new Date(c.updated_at * 1000).toLocaleTimeString() : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* ---- Jobs tab ---- */}
      {tab === 'jobs' && (
        <section className="card">
          <h3 className="msg-h">Scan jobs ({jobs.length})</h3>
          <p className="muted small">Click a job to see the exact backend command and its output.</p>
          {jobs.length === 0 ? (
            <div className="muted small">No jobs launched yet.</div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr><th>Tool</th><th>Target</th><th>Status</th><th>Findings</th><th>Duration</th></tr>
                </thead>
                <tbody>
                  {jobs.map((j) => (
                    <tr key={j.id} className={openJob === j.id ? 'selected' : ''} onClick={() => toggleJob(j.id)}>
                      <td className="mono">{j.tool}</td>
                      <td className="mono truncate" title={j.target}>{j.target}</td>
                      <td><span className={`status-${j.status}`}>{j.status}</span></td>
                      <td>{j.findings_count}</td>
                      <td className="muted">{j.duration_ms != null ? `${(j.duration_ms / 1000).toFixed(1)}s` : '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {openJob && (
            <div className="job-detail">
              {!jobDetail ? (
                <div className="muted small">Loading…</div>
              ) : (
                <>
                  <div className="row-between">
                    <span className="mono small">
                      {jobDetail.tool} · <span className={`status-${jobDetail.status}`}>{jobDetail.status}</span>
                      {jobDetail.exit_code != null ? ` · exit ${jobDetail.exit_code}` : ''}
                      {jobDetail.duration_ms != null ? ` · ${(jobDetail.duration_ms / 1000).toFixed(1)}s` : ''}
                    </span>
                    <button className="btn ghost" onClick={() => toggleJob(openJob)}>Close</button>
                  </div>
                  <h4 className="msg-h">Command</h4>
                  <pre className="body mono small">{[jobDetail.tool, ...(jobDetail.args || [])].join(' ')} {jobDetail.target}</pre>
                  {jobDetail.error && <p className="result error small">error: {jobDetail.error}</p>}
                  {jobDetail.stdout_tail && (<><h4 className="msg-h">stdout</h4><pre className="body mono small">{jobDetail.stdout_tail}</pre></>)}
                  {jobDetail.stderr_tail && (<><h4 className="msg-h">stderr</h4><pre className="body mono small">{jobDetail.stderr_tail}</pre></>)}
                  {!jobDetail.stdout_tail && !jobDetail.stderr_tail && !jobDetail.error && (
                    <div className="muted small">No output captured.</div>
                  )}
                </>
              )}
            </div>
          )}
        </section>
      )}

      {/* ---- Findings tab ---- */}
      {tab === 'findings' && (
        <section className="card">
          <h3 className="msg-h">Findings by category ({validated.length})</h3>
          {validated.length === 0 ? (
            <div className="muted small">No validated findings yet.</div>
          ) : (
            <>
              <div className="tabs">
                <button className={activeCat === 'all' ? 'active' : ''} onClick={() => setActiveCat('all')}>
                  All <span className="tab-count">{validated.length}</span>
                </button>
                {activeCats.map((c) => (
                  <button key={c.key} className={activeCat === c.key ? 'active' : ''} onClick={() => setActiveCat(c.key)}>
                    {c.label} <span className="tab-count">{byCategory[c.key].length}</span>
                  </button>
                ))}
              </div>
              <div className="stack-sm">
                {shownFindings.slice(0, 120).map((f) => (
                  <div key={f.id} className="finding">
                    <div className="row-between">
                      <span className={`sev sev-${(f.severity || 'info').toLowerCase()}`}>{f.severity}</span>
                      <span className={`mono small vstatus-${f.status}`}>{f.status} ({Math.round((f.confidence || 0) * 100)}%)</span>
                    </div>
                    <div className="finding-title">{f.title}</div>
                    <div className="mono small truncate" title={f.target}>{f.target}</div>
                    <div className="muted small">{f.tool} · {f.vuln_class}{f.method ? ` · ${f.method}` : ''}</div>
                    {f.poc && <pre className="body mono small">{f.poc}</pre>}
                  </div>
                ))}
                {shownFindings.length === 0 && <div className="muted small">No findings in this category.</div>}
              </div>
            </>
          )}
        </section>
      )}

      {/* ---- Chains tab ---- */}
      {tab === 'chains' && (
        <section className="card">
          <h3 className="msg-h">Kill-chains ({chains.length})</h3>
          {chains.length === 0 ? (
            <div className="muted small">No multi-step attack chains identified.</div>
          ) : (
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
          )}
        </section>
      )}
    </div>
  );
}
