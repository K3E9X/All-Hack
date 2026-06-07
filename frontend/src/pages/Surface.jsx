import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';

// Attack surface. The aggregated GET /api/engagements/{id}/surface endpoint
// (hosts -> ports/tech/endpoints) is wired in a later milestone; for now this
// derives hosts and endpoints from the live engagement state assets.
export default function Surface() {
  const [engagements, setEngagements] = useState([]);
  const [engId, setEngId] = useState('');
  const [assets, setAssets] = useState([]);

  useEffect(() => {
    api.engagements.list().then((r) => {
      const items = r.items || [];
      setEngagements(items);
      if (items.length) setEngId(items[0].id);
    }).catch(() => {});
  }, []);
  useEffect(() => {
    if (!engId) return;
    api.engagements.state(engId).then((s) => setAssets(s.assets || [])).catch(() => setAssets([]));
  }, [engId]);

  const hosts = assets.filter((a) => a.kind === 'host');
  const endpoints = assets.filter((a) => a.kind === 'endpoint');
  const ports = assets.filter((a) => a.kind === 'port');

  return (
    <div className="page">
      <div className="card">
        <div className="card__head"><span className="card__title">Attack surface</span>
          <div className="select-box"><select className="select" value={engId} onChange={(e) => setEngId(e.target.value)}>
            {engagements.length === 0 && <option value="">no engagements</option>}
            {engagements.map((e) => <option key={e.id} value={e.id}>{e.target_host || e.target_url}</option>)}
          </select></div>
        </div>
        <div className="card__body">
          <div className="cov-summary">
            <span>hosts<b>{hosts.length}</b></span>
            <span>endpoints<b>{endpoints.length}</b></span>
            <span>ports<b>{ports.length}</b></span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card__head"><span className="card__title">Hosts &amp; endpoints</span><span className="card__meta">{assets.length} assets</span></div>
        <div className="tbl-scroll">
          <table className="tbl">
            <thead><tr><th>Kind</th><th>Value</th><th>Source</th><th>Params</th><th>HTTPS</th></tr></thead>
            <tbody>
              {assets.map((a, i) => (
                <tr key={i}>
                  <td><span className="st">{a.kind}</span></td>
                  <td className="mono truncate" style={{ maxWidth: 420 }} title={a.value}>{a.value}</td>
                  <td className="mono" style={{ color: 'var(--text-faint)' }}>{a.source}</td>
                  <td>{a.has_params ? <span className="st">yes</span> : <span style={{ color: 'var(--text-faint)' }}>-</span>}</td>
                  <td>{a.is_https ? <span className="st st--succeeded">yes</span> : <span style={{ color: 'var(--text-faint)' }}>-</span>}</td>
                </tr>
              ))}
              {assets.length === 0 && <tr><td colSpan={5}><div className="empty">No surface mapped yet. Run the engagement to discover hosts, ports and endpoints.</div></td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
