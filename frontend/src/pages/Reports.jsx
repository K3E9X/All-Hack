import { useCallback, useEffect, useState } from 'react';
import { api } from '../lib/api.js';

export default function Reports() {
  const [jobs, setJobs] = useState([]);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [title, setTitle] = useState('Penetration Test Report');
  const [scope, setScope] = useState('');
  const [gen, setGen] = useState({ loading: false, markdown: null, meta: null, error: null });

  const loadJobs = useCallback(async () => {
    try {
      const res = await api.scans.list({ limit: 200 });
      setJobs(res.items);
    } catch (err) {
      setGen((g) => ({ ...g, error: err.message }));
    }
  }, []);

  useEffect(() => { loadJobs(); }, [loadJobs]);

  function toggle(id) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }
  function selectAll(checked) {
    setSelectedIds(checked ? new Set(jobs.map((j) => j.id)) : new Set());
  }

  async function generate() {
    setGen({ loading: true, markdown: null, meta: null, error: null });
    try {
      const payload = {
        title,
        scope,
        job_ids: selectedIds.size > 0 ? Array.from(selectedIds) : undefined,
      };
      const res = await api.llm.report(payload);
      setGen({
        loading: false,
        markdown: res.markdown,
        meta: { jobs_included: res.jobs_included, hosts_included: res.hosts_included },
        error: null,
      });
    } catch (err) {
      setGen({ loading: false, markdown: null, meta: null, error: err.message });
    }
  }

  function download() {
    if (!gen.markdown) return;
    const blob = new Blob([gen.markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    a.href = url;
    a.download = `pentest-report-${stamp}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function copyMarkdown() {
    try {
      await navigator.clipboard.writeText(gen.markdown || '');
    } catch (err) {
      alert('Copy failed: ' + err.message);
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Generate pentest report</h2>

        <div className="stack-sm">
          <label className="grow">
            <span className="muted small">Title</span>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Penetration Test Report"
            />
          </label>
          <label className="grow">
            <span className="muted small">Scope / notes</span>
            <textarea
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              placeholder="e.g. Black-box test of the customer portal, week of ..."
              rows={3}
            />
          </label>
        </div>

        <div className="row-between report-jobs-head">
          <div className="muted small">
            Jobs to include ({selectedIds.size === 0 ? 'all' : selectedIds.size})
          </div>
          <div className="btn-row">
            <button className="btn ghost" onClick={() => selectAll(true)}>Select all</button>
            <button className="btn ghost" onClick={() => selectAll(false)}>Clear</button>
            <button className="btn ghost" onClick={loadJobs}>Refresh</button>
          </div>
        </div>

        <div className="table-wrap" style={{ maxHeight: 260 }}>
          <table className="table mono">
            <thead>
              <tr>
                <th style={{ width: 32 }}></th>
                <th style={{ width: 160 }}>ID</th>
                <th style={{ width: 80 }}>Tool</th>
                <th>Target</th>
                <th style={{ width: 90 }}>Status</th>
                <th style={{ width: 80 }}>Findings</th>
              </tr>
            </thead>
            <tbody>
              {jobs.length === 0 && (
                <tr><td colSpan="6" className="muted">No jobs to include yet.</td></tr>
              )}
              {jobs.map((j) => (
                <tr key={j.id} className={selectedIds.has(j.id) ? 'selected' : ''}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedIds.has(j.id)}
                      onChange={() => toggle(j.id)}
                    />
                  </td>
                  <td>{j.id}</td>
                  <td>{j.tool}</td>
                  <td className="truncate" title={j.target}>{j.target}</td>
                  <td className={`status-${j.status}`}>{j.status}</td>
                  <td>{j.findings_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="btn-row" style={{ marginTop: 12 }}>
          <button className="btn" onClick={generate} disabled={gen.loading}>
            {gen.loading ? 'Generating...' : 'Generate report'}
          </button>
          {gen.markdown && (
            <>
              <button className="btn ghost" onClick={download}>Download .md</button>
              <button className="btn ghost" onClick={copyMarkdown}>Copy to clipboard</button>
            </>
          )}
        </div>
        {gen.error && <p className="result error">{gen.error}</p>}
        {gen.meta && (
          <p className="muted small">
            Report covers {gen.meta.jobs_included} jobs and {gen.meta.hosts_included} captured hosts.
          </p>
        )}
      </section>

      {gen.markdown && (
        <section className="card">
          <h2>Report preview (markdown source)</h2>
          <pre className="body mono report-preview">{gen.markdown}</pre>
        </section>
      )}
    </div>
  );
}
