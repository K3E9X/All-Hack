import { useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api.js';

const PHASE_LABEL = { recon: 'Reconnaissance', mapping: 'Mapping & enumeration', vuln_analysis: 'Vulnerability analysis', exploitation: 'Exploitation' };

export default function Methodology() {
  const [catalog, setCatalog] = useState([]);
  useEffect(() => {
    api.methodology.catalog().then((r) => setCatalog(r.items || r || [])).catch(() => {});
  }, []);

  const byPhase = useMemo(() => {
    const m = {};
    for (const it of catalog) (m[it.phase] = m[it.phase] || []).push(it);
    return m;
  }, [catalog]);
  const phases = Object.keys(PHASE_LABEL).filter((p) => byPhase[p]);

  return (
    <div className="page">
      <div className="card">
        <div className="card__head"><span className="card__title">Methodology catalog</span><span className="card__meta">OWASP WSTG &middot; MITRE ATT&amp;CK &middot; {catalog.length} tests</span></div>
        <div className="card__body">
          {catalog.length === 0 && <div className="empty">Loading catalog...</div>}
          {phases.map((p) => (
            <div key={p} style={{ marginBottom: 18 }}>
              <div className="sbom-phase__t">{PHASE_LABEL[p]}</div>
              <table className="tbl">
                <thead><tr><th>Test</th><th>WSTG</th><th>ATT&amp;CK</th><th>Tool</th><th>Class</th></tr></thead>
                <tbody>
                  {byPhase[p].map((it) => (
                    <tr key={it.id}>
                      <td>{it.description}</td>
                      <td className="mono" style={{ color: 'var(--text-faint)' }}>{it.wstg_id}</td>
                      <td className="mono" style={{ color: 'var(--text-faint)' }}>{(it.attack_techniques || []).join(', ')}</td>
                      <td className="mono">{it.tool}</td>
                      <td className="mono" style={{ color: 'var(--text-secondary)' }}>{it.vuln_class}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
          <p className="intro" style={{ marginTop: 10 }}>Per-engagement coverage (which tests ran against which assets, with hits) is wired to <code>GET /api/engagements/&#123;id&#125;/coverage</code> next.</p>
        </div>
      </div>
    </div>
  );
}
