import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const POLL_MS = 2000;

export default function Scans() {
  const [tools, setTools] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [total, setTotal] = useState(0);
  const [selectedId, setSelectedId] = useState(null);
  const [form, setForm] = useState({ tool: '', target: '', options: '' });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const loadAll = useCallback(async () => {
    try {
      const [t, j] = await Promise.all([api.scans.tools(), api.scans.list({ limit: 100 })]);
      setTools(t);
      setJobs(j.items);
      setTotal(j.total);
      setForm((f) => (f.tool ? f : { ...f, tool: t.find((x) => x.available)?.name || '' }));
    } catch (err) {
      setError(err.message);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  useEffect(() => {
    const t = setInterval(loadAll, POLL_MS);
    return () => clearInterval(t);
  }, [loadAll]);

  async function onSubmit(e) {
    e.preventDefault();
    setError(null);
    if (!form.tool || !form.target) {
      setError('Tool and target are required.');
      return;
    }
    setSubmitting(true);
    try {
      const opts = form.options
        .split(' ')
        .map((s) => s.trim())
        .filter(Boolean);
      const job = await api.scans.submit({
        tool: form.tool,
        target: form.target,
        options: opts,
      });
      setSelectedId(job.id);
      setForm((f) => ({ ...f, target: '' }));
      loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Launch a scan</h2>
        <form onSubmit={onSubmit} className="scan-form">
          <label>
            <span className="muted small">Tool</span>
            <select
              value={form.tool}
              onChange={(e) => setForm((f) => ({ ...f, tool: e.target.value }))}
            >
              {tools.map((t) => (
                <option key={t.name} value={t.name} disabled={!t.available}>
                  {t.name}{!t.available ? ' (not installed)' : ''}
                </option>
              ))}
            </select>
          </label>
          <label className="grow">
            <span className="muted small">Target URL or host</span>
            <input
              type="text"
              placeholder="https://example.com   (ffuf: use FUZZ, e.g. https://example.com/FUZZ)"
              value={form.target}
              onChange={(e) => setForm((f) => ({ ...f, target: e.target.value }))}
            />
          </label>
          <label className="grow">
            <span className="muted small">Extra CLI options (optional)</span>
            <input
              type="text"
              placeholder="e.g. --level=3 --risk=3"
              value={form.options}
              onChange={(e) => setForm((f) => ({ ...f, options: e.target.value }))}
            />
          </label>
          <button type="submit" className="btn" disabled={submitting}>
            {submitting ? 'Launching...' : 'Run'}
          </button>
        </form>
        {error && <p className="result error">{error}</p>}
        <p className="muted small">
          {tools.filter((t) => t.available).length}/{tools.length} tools available in this container.
        </p>
      </section>

      <section className="card">
        <div className="row-between">
          <h2>Jobs ({total})</h2>
          <button className="btn ghost" onClick={loadAll}>Refresh</button>
        </div>
        <JobsTable
          jobs={jobs}
          selectedId={selectedId}
          onSelect={setSelectedId}
        />
      </section>

      {selectedId && (
        <JobInspector
          jobId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

function JobsTable({ jobs, selectedId, onSelect }) {
  if (!jobs.length) return <p className="muted small">No jobs yet.</p>;
  return (
    <div className="table-wrap">
      <table className="table mono">
        <thead>
          <tr>
            <th style={{ width: 160 }}>ID</th>
            <th style={{ width: 80 }}>Tool</th>
            <th>Target</th>
            <th style={{ width: 100 }}>Status</th>
            <th style={{ width: 80 }}>Findings</th>
            <th style={{ width: 100 }}>Duration</th>
          </tr>
        </thead>
        <tbody>
          {jobs.map((j) => (
            <tr
              key={j.id}
              className={j.id === selectedId ? 'selected' : ''}
              onClick={() => onSelect(j.id)}
            >
              <td>{j.id}</td>
              <td>{j.tool}</td>
              <td className="truncate" title={j.target}>{j.target}</td>
              <td className={`status-${j.status}`}>{j.status}</td>
              <td>{j.findings_count}</td>
              <td>{j.duration_ms != null ? `${(j.duration_ms / 1000).toFixed(1)}s` : '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function JobInspector({ jobId, onClose }) {
  const [job, setJob] = useState(null);
  const [tab, setTab] = useState('findings');
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    try {
      const data = await api.scans.get(jobId);
      setJob(data);
      setErr(null);
    } catch (e) {
      setErr(e.message);
    }
  }, [jobId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    // Poll while running.
    const t = setInterval(() => {
      if (!job || job.status === 'running' || job.status === 'queued') load();
    }, POLL_MS);
    return () => clearInterval(t);
  }, [load, job]);

  async function onCancel() {
    try { await api.scans.cancel(jobId); load(); } catch (e) { setErr(e.message); }
  }
  async function onDelete() {
    if (!confirm('Delete this job?')) return;
    try { await api.scans.delete(jobId); onClose(); } catch (e) { setErr(e.message); }
  }

  return (
    <section className="card">
      <div className="row-between">
        <h2>Job inspector</h2>
        <div className="btn-row">
          {job && (job.status === 'queued' || job.status === 'running') && (
            <button className="btn ghost" onClick={onCancel}>Cancel</button>
          )}
          <button className="btn ghost danger" onClick={onDelete}>Delete</button>
          <button className="btn ghost" onClick={onClose}>Close</button>
        </div>
      </div>
      {err && <p className="result error">{err}</p>}
      {!job ? (
        <p className="muted small">Loading...</p>
      ) : (
        <>
          <div className="inspect-head mono">
            <div><strong>{job.tool}</strong> {job.target}</div>
            <div className="muted small">
              id {job.id} &middot;
              {' '}status <span className={`status-${job.status}`}>{job.status}</span> &middot;
              {' '}exit {job.exit_code ?? '-'} &middot;
              {' '}{job.duration_ms != null ? `${(job.duration_ms / 1000).toFixed(1)}s` : '-'}
              {job.args?.length ? ` · args: ${job.args.join(' ')}` : ''}
            </div>
            {job.error && <div className="error small">error: {job.error}</div>}
          </div>

          <div className="tabs">
            <button className={tab === 'findings' ? 'active' : ''} onClick={() => setTab('findings')}>
              Findings ({job.findings_count})
            </button>
            <button className={tab === 'stdout' ? 'active' : ''} onClick={() => setTab('stdout')}>stdout</button>
            <button className={tab === 'stderr' ? 'active' : ''} onClick={() => setTab('stderr')}>stderr</button>
          </div>

          {tab === 'findings' && <FindingsList findings={job.findings} />}
          {tab === 'stdout' && <pre className="body mono">{job.stdout_tail || '(empty)'}</pre>}
          {tab === 'stderr' && <pre className="body mono">{job.stderr_tail || '(empty)'}</pre>}
        </>
      )}
    </section>
  );
}

function FindingsList({ findings }) {
  if (!findings?.length) return <p className="muted small">No findings.</p>;
  return (
    <div className="stack">
      {findings.map((f, i) => (
        <div key={i} className="finding">
          <div className="row-between">
            <span className={`sev sev-${(f.severity || 'info').toLowerCase()}`}>{f.severity}</span>
            <span className="muted small mono truncate" title={f.target}>{f.target}</span>
          </div>
          <div className="finding-title">{f.title}</div>
          {f.description && <div className="finding-desc">{f.description}</div>}
          {f.evidence && <pre className="body mono small">{f.evidence}</pre>}
          {f.metadata && Object.keys(f.metadata).length > 0 && (
            <details className="finding-meta">
              <summary className="muted small">metadata</summary>
              <pre className="body mono small">{JSON.stringify(f.metadata, null, 2)}</pre>
            </details>
          )}
        </div>
      ))}
    </div>
  );
}
