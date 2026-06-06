import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const POLL_MS = 5000;

export default function Engagements() {
  const [items, setItems] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [form, setForm] = useState({ target_url: '', scope_hosts: '', attest: false });
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const res = await api.engagements.list();
      setItems(res.items);
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load]);

  async function onCreate(e) {
    e.preventDefault();
    setError(null);
    if (!form.target_url) { setError('Target URL is required.'); return; }
    if (!form.attest) { setError('You must attest you are authorized to test this target.'); return; }
    setCreating(true);
    try {
      const scope = form.scope_hosts
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      const res = await api.engagements.create({
        target_url: form.target_url,
        scope_hosts: scope.length ? scope : undefined,
        attest_authorized: true,
      });
      setForm({ target_url: '', scope_hosts: '', attest: false });
      setSelectedId(res.engagement.id);
      load();
    } catch (err) {
      setError(err.message);
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>New engagement</h2>
        <p className="muted small">
          A scan can only run against a target you have proven you control.
          Create an engagement, prove ownership (DNS TXT or a .well-known file),
          then launch scans from the Scans page.
        </p>
        <form onSubmit={onCreate} className="stack-sm">
          <label className="grow">
            <span className="muted small">Target URL</span>
            <input
              type="text"
              placeholder="https://app.example.com"
              value={form.target_url}
              onChange={(e) => setForm((f) => ({ ...f, target_url: e.target.value }))}
            />
          </label>
          <label className="grow">
            <span className="muted small">
              Extra in-scope hosts (comma-separated, optional). Prefix with '.' to allow subdomains.
            </span>
            <input
              type="text"
              placeholder="api.example.com, .example.com"
              value={form.scope_hosts}
              onChange={(e) => setForm((f) => ({ ...f, scope_hosts: e.target.value }))}
            />
          </label>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={form.attest}
              onChange={(e) => setForm((f) => ({ ...f, attest: e.target.checked }))}
            />
            <span className="small">
              I am authorized to perform security testing against this target.
            </span>
          </label>
          <div>
            <button type="submit" className="btn" disabled={creating}>
              {creating ? 'Creating...' : 'Create engagement'}
            </button>
          </div>
        </form>
        {error && <p className="result error">{error}</p>}
      </section>

      <section className="card">
        <div className="row-between">
          <h2>Engagements ({items.length})</h2>
          <button className="btn ghost" onClick={load}>Refresh</button>
        </div>
        {items.length === 0 ? (
          <p className="muted small">No engagements yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="table mono">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Scope</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr
                    key={e.id}
                    className={e.id === selectedId ? 'selected' : ''}
                    onClick={() => setSelectedId(e.id)}
                  >
                    <td>{e.id}</td>
                    <td className="truncate" title={e.target_url}>{e.target_url}</td>
                    <td className={`eng-${e.status}`}>{e.status}</td>
                    <td className="truncate">{(e.scope_hosts || []).join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selectedId && (
        <EngagementInspector engagementId={selectedId} onChange={load} />
      )}
    </div>
  );
}

function EngagementInspector({ engagementId, onChange }) {
  const [data, setData] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    try {
      const res = await api.engagements.get(engagementId);
      setData(res);
      setErr(null);
    } catch (e) {
      setErr(e.message);
    }
  }, [engagementId]);

  useEffect(() => { load(); }, [load]);

  async function onVerify() {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await api.engagements.verify(engagementId);
      setVerifyResult(res);
      await load();
      onChange && onChange();
    } catch (e) {
      setErr(e.message);
    } finally {
      setVerifying(false);
    }
  }

  async function onClose() {
    if (!confirm('Close this engagement? No further scans will be allowed.')) return;
    try { await api.engagements.close(engagementId); await load(); onChange && onChange(); }
    catch (e) { setErr(e.message); }
  }

  if (err) return <section className="card"><p className="result error">{err}</p></section>;
  if (!data) return <section className="card"><p className="muted small">Loading...</p></section>;

  const e = data.engagement;
  const challenge = data.challenge;

  return (
    <section className="card">
      <div className="row-between">
        <h2>Engagement {e.id}</h2>
        <div className="btn-row">
          {e.status === 'pending_authorization' && (
            <button className="btn" onClick={onVerify} disabled={verifying}>
              {verifying ? 'Verifying...' : 'Verify ownership'}
            </button>
          )}
          {e.status === 'authorized' && (
            <button className="btn ghost danger" onClick={onClose}>Close</button>
          )}
        </div>
      </div>

      <dl className="kv">
        <dt>Target</dt><dd className="mono">{e.target_url}</dd>
        <dt>Host</dt><dd className="mono">{e.target_host}</dd>
        <dt>Status</dt><dd className={`mono eng-${e.status}`}>{e.status}</dd>
        <dt>Scope</dt><dd className="mono">{(e.scope_hosts || []).join(', ')}</dd>
        {e.verification_method && (<><dt>Verified via</dt><dd className="mono">{e.verification_method}</dd></>)}
      </dl>

      {verifyResult && !verifyResult.verified && (
        <p className="result error small">Not verified yet: {verifyResult.detail}</p>
      )}
      {verifyResult && verifyResult.verified && (
        <p className="result ok small">Authorized. You can now run scans against this scope.</p>
      )}

      {challenge && e.status === 'pending_authorization' && (
        <div className="stack-sm">
          <h3 className="msg-h">Prove ownership (either method)</h3>

          <div className="suggestion-card">
            <div className="suggestion-tool mono">DNS TXT</div>
            <div className="small">Add this TXT record on <code>{challenge.methods.dns_txt.record_name}</code>:</div>
            <pre className="body mono small">{challenge.methods.dns_txt.record_value}</pre>
          </div>

          <div className="suggestion-card">
            <div className="suggestion-tool mono">.well-known file</div>
            <div className="small">Serve this URL returning exactly the token:</div>
            <pre className="body mono small">{challenge.methods.well_known.url}
{'\n'}body: {challenge.methods.well_known.file_content}</pre>
          </div>
        </div>
      )}

      {e.status === 'authorized' && <AutonomousPanel engagementId={engagementId} />}
    </section>
  );
}

function AutonomousPanel({ engagementId }) {
  const [state, setState] = useState(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    try {
      setState(await api.engagements.state(engagementId));
      setErr(null);
    } catch (e) {
      setErr(e.message);
    }
  }, [engagementId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const t = setInterval(load, 3000);
    return () => clearInterval(t);
  }, [load]);

  const run = state?.run;
  const active = run && (run.status === 'queued' || run.status === 'running');

  async function start() {
    setBusy(true); setErr(null);
    try { await api.engagements.run(engagementId); await load(); }
    catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }
  async function stop() {
    setBusy(true); setErr(null);
    try { await api.engagements.stop(engagementId); await load(); }
    catch (e) { setErr(e.message); }
    finally { setBusy(false); }
  }

  const cov = state?.coverage_summary || {};

  return (
    <div className="autonomous-wrap stack-sm">
      <div className="row-between">
        <h3 className="msg-h">Autonomous test</h3>
        <div className="btn-row">
          {!active && <button className="btn" onClick={start} disabled={busy}>Run autonomous test</button>}
          {active && <button className="btn ghost danger" onClick={stop} disabled={busy}>Stop</button>}
        </div>
      </div>

      {err && <p className="result error small">{err}</p>}

      {run ? (
        <dl className="kv">
          <dt>Run status</dt><dd className={`mono run-${run.status}`}>{run.status}</dd>
          <dt>Phase</dt><dd className="mono">{run.phase || '-'}</dd>
          <dt>Iterations</dt><dd className="mono">{run.iterations}</dd>
          <dt>Jobs launched</dt><dd className="mono">{run.jobs_launched}</dd>
          {run.error && (<><dt>Error</dt><dd className="mono error">{run.error}</dd></>)}
        </dl>
      ) : (
        <p className="muted small">No run yet. Launch one to start autonomous coverage.</p>
      )}

      {(() => {
        const vsum = state?.validation_summary || {};
        const validated = state?.validated_findings || [];
        const chains = state?.chains || [];
        const fpRate = vsum.false_positive_rate_pct;
        return (
          <>
            <div className="grid-stats">
              <div className="stat"><div className="muted small">Assets</div><div className="mono">{state?.assets?.length || 0}</div></div>
              <div className="stat"><div className="muted small">Technologies</div><div className="mono">{state?.technologies?.length || 0}</div></div>
              <div className="stat"><div className="muted small">Raw findings</div><div className="mono">{state?.findings_count || 0}</div></div>
              <div className="stat"><div className="muted small">Coverage done</div><div className="mono">{cov.done || 0}</div></div>
            </div>

            {state?.technologies?.length > 0 && (
              <p className="small"><strong>Tech:</strong> <span className="mono">{state.technologies.join(', ')}</span></p>
            )}

            {validated.length > 0 && (
              <div className="grid-stats">
                <div className="stat"><div className="muted small">Confirmed</div><div className="mono sev-high">{vsum.confirmed || 0}</div></div>
                <div className="stat"><div className="muted small">Likely</div><div className="mono">{vsum.likely || 0}</div></div>
                <div className="stat"><div className="muted small">False positive</div><div className="mono">{vsum.false_positive || 0}</div></div>
                <div className="stat"><div className="muted small">FP rate</div><div className="mono">{fpRate != null ? `${fpRate}%` : '-'}</div></div>
              </div>
            )}

            {chains.length > 0 && (
              <div className="stack-sm">
                <div className="msg-h">Kill-chains ({chains.length})</div>
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

            {validated.length > 0 ? (
              <div className="stack-sm">
                <div className="msg-h">Validated findings ({validated.length})</div>
                {validated.slice(0, 60).map((f) => (
                  <div key={f.id} className="finding">
                    <div className="row-between">
                      <span className={`sev sev-${(f.severity || 'info').toLowerCase()}`}>{f.severity}</span>
                      <span className={`mono small vstatus-${f.status}`}>
                        {f.status} ({Math.round((f.confidence || 0) * 100)}%)
                      </span>
                    </div>
                    <div className="finding-title">{f.title}</div>
                    <div className="mono small truncate" title={f.target}>{f.target}</div>
                    <div className="muted small">{f.tool} · {f.method}</div>
                    {f.poc && <pre className="body mono small">{f.poc}</pre>}
                  </div>
                ))}
              </div>
            ) : (
              state?.findings?.length > 0 && (
                <div className="stack-sm">
                  <div className="msg-h">Findings ({state.findings.length}) — not yet validated</div>
                  {state.findings.slice(0, 50).map((f, i) => (
                    <div key={i} className="finding">
                      <div className="row-between">
                        <span className={`sev sev-${(f.severity || 'info').toLowerCase()}`}>{f.severity}</span>
                        <span className="muted small mono">{f.tool}</span>
                      </div>
                      <div className="finding-title">{f.title}</div>
                      <div className="mono small truncate" title={f.target}>{f.target}</div>
                    </div>
                  ))}
                </div>
              )
            )}
          </>
        );
      })()}
    </div>
  );
}
