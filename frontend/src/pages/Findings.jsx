import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';

// Global, cross-engagement findings view. The deduped backend
// (GET /api/findings + status/retest/export) is wired in the next milestone;
// for now this aggregates each engagement's validated findings client-side.
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function Findings() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [sev, setSev] = useState('');
  const [q, setQ] = useState('');

  useEffect(() => {
    (async () => {
      try {
        const r = await api.engagements.list();
        const engs = r.items || [];
        const all = [];
        for (const e of engs) {
          try {
            const s = await api.engagements.state(e.id);
            for (const f of (s.validated_findings || [])) {
              if (f.status === 'false_positive') continue;
              all.push({ ...f, engagement: e.target_host || e.target_url, engagement_id: e.id });
            }
          } catch { /* ignore */ }
        }
        all.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
        setRows(all);
      } finally { setLoading(false); }
    })();
  }, []);

  const shown = rows.filter((f) =>
    (!sev || f.severity === sev) &&
    (!q || (`${f.title} ${f.target} ${f.vuln_class}`).toLowerCase().includes(q.toLowerCase())));

  return (
    <div className="page">
      <div className="card">
        <div className="card__head"><span className="card__title">Findings</span><span className="card__meta">{shown.length} shown &middot; cross-engagement</span></div>
        <div className="card__body" style={{ paddingBottom: 12 }}>
          <div className="px-filters">
            <div className="select-box"><select className="select" value={sev} onChange={(e) => setSev(e.target.value)}>
              <option value="">All severities</option>{['critical', 'high', 'medium', 'low', 'info'].map((s) => <option key={s} value={s}>{s}</option>)}
            </select></div>
            <input className="px-search" placeholder="filter title / target / class..." value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
        </div>
        <div className="tbl-scroll">
          <table className="tbl">
            <thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Class</th><th>Tool</th><th>Status</th><th>Engagement</th></tr></thead>
            <tbody>
              {shown.map((f) => (
                <tr key={f.id}>
                  <td><span className={'sev sev--' + (f.severity || 'info')}>{f.severity}</span></td>
                  <td>{f.title}</td>
                  <td className="mono truncate" style={{ maxWidth: 240, color: 'var(--text-secondary)' }} title={f.target}>{f.target}</td>
                  <td className="mono" style={{ color: 'var(--text-secondary)' }}>{f.vuln_class}</td>
                  <td className="mono">{f.tool}</td>
                  <td><span className={'vstatus vstatus--' + f.status}>{f.status}</span></td>
                  <td className="mono" style={{ color: 'var(--text-faint)' }}>{f.engagement}</td>
                </tr>
              ))}
              {!loading && shown.length === 0 && <tr><td colSpan={7}><div className="empty">No findings match.</div></td></tr>}
              {loading && <tr><td colSpan={7}><div className="empty">Loading findings...</div></td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
