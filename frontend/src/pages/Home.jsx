import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const PHASE_ORDER = ['Reconnaissance', 'Scanning & enumeration', 'Exploitation', 'Capture & analysis', 'Other'];

export default function Home() {
  const [config, setConfig] = useState(null);
  const [dash, setDash] = useState(null);
  const [tools, setTools] = useState([]);
  const [ping, setPing] = useState({ state: 'idle', text: '' });

  useEffect(() => {
    api.config().then(setConfig).catch(() => {});
    api.dashboard().then(setDash).catch(() => {});
    api.tools().then((t) => setTools(Array.isArray(t) ? t : [])).catch(() => {});
  }, []);

  async function testLlm() {
    setPing({ state: 'pending', text: 'Pinging LLM...' });
    try {
      const r = await api.llmPing('planner');
      setPing({ state: 'ok', text: `${r.model_used} replied: ${r.reply}` });
    } catch (e) {
      setPing({ state: 'err', text: e.message });
    }
  }

  const roles = config?.llm_roles || {};
  const usage = dash?.llm_usage || { calls: 0, total_tokens: 0, cost_usd: 0, by_model: [] };
  const conf = dash?.confirmed_findings || {};
  const confTotal = Object.values(conf).reduce((a, b) => a + b, 0);

  const byPhase = {};
  for (const t of tools) (byPhase[t.phase] = byPhase[t.phase] || []).push(t);
  const phases = PHASE_ORDER.filter((p) => byPhase[p]);
  const okTools = tools.filter((t) => t.available).length;

  return (
    <div className="page">
      <div className="metrics">
        <div className="metric">
          <div className="metric__l">Active engagements</div>
          <div className="metric__v">{dash?.active_engagements ?? '-'}</div>
          <div className="metric__sub">authorized</div>
        </div>
        <div className="metric metric--ok">
          <div className="metric__l">Jobs running</div>
          <div className="metric__v">{dash?.running_jobs ?? '-'}</div>
          <div className="metric__sub">queued + running</div>
        </div>
        <div className="metric metric--alert">
          <div className="metric__l">Confirmed findings</div>
          <div className="metric__v">{confTotal}</div>
          <div className="metric__sub">{conf.critical || 0} critical &middot; {conf.high || 0} high</div>
        </div>
        <div className="metric">
          <div className="metric__l">API spend</div>
          <div className="metric__v"><small>$</small>{(usage.cost_usd || 0).toFixed(2)}</div>
          <div className="metric__sub">{(usage.total_tokens / 1e6).toFixed(2)}M tokens &middot; {usage.calls} calls</div>
        </div>
      </div>

      <div className="dash-grid">
        <div>
          <div className="card">
            <div className="card__head"><span className="card__title">Backend status</span></div>
            <div className="card__body">
              <dl className="kv">
                <dt>LLM configured</dt><dd className={config?.llm_configured ? 'kv-yes' : ''}>{config?.llm_configured ? 'yes' : 'no'}</dd>
                <dt>Model router</dt>
                <dd className="mono">
                  {Object.keys(roles).length
                    ? Object.entries(roles).map(([r, v]) => `${r}: ${(v && v.model) || v}`).join('  ·  ')
                    : (config?.llm_model || '-')}
                </dd>
                <dt>MITM proxy</dt><dd className="mono kv-yes">:{config?.mitm_port ?? '-'} listening</dd>
                <dt>Data directory</dt><dd className="mono">{config?.data_dir || '-'}</dd>
              </dl>
            </div>
          </div>

          <div className="card">
            <div className="card__head"><span className="card__title">Model usage</span><span className="card__meta">${(usage.cost_usd || 0).toFixed(2)}</span></div>
            <div className="card__body">
              <div className="usage">
                {(usage.by_model || []).length === 0 && <div className="empty">No LLM calls yet.</div>}
                {(usage.by_model || []).map((m) => (
                  <div key={m.model} className="usage__row">
                    <span className="usage__l">{m.model}</span>
                    <span className="usage__bar"><span className="usage__fill" style={{ width: m.pct + '%' }}></span></span>
                    <span className="usage__n">{(m.tokens / 1000).toFixed(0)}k</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="card">
            <div className="card__head"><span className="card__title">LLM sanity check</span></div>
            <div className="card__body">
              <p className="home-intro">Send a tiny request to the model provider to verify the key and model work.</p>
              <button className="btn btn--solid" onClick={testLlm} disabled={ping.state === 'pending'}>{ping.state === 'pending' ? 'Pinging...' : 'Ping LLM'}</button>
              {ping.text && <p className={'ping-result ping-result--' + ping.state}>{ping.text}</p>}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card__head"><span className="card__title">Toolchain / SBOM</span><span className="card__meta">{okTools}/{tools.length} available &middot; container image</span></div>
          <div className="card__body" style={{ paddingTop: 4 }}>
            {phases.length === 0 && <div className="empty">Loading tools...</div>}
            {phases.map((p) => (
              <div key={p} className="sbom-phase">
                <div className="sbom-phase__t">{p}</div>
                <table className="sbom">
                  <tbody>
                    {byPhase[p].map((t) => (
                      <tr key={t.name}>
                        <td className="sbom__name">{t.name}</td>
                        <td className="sbom__ver">{t.version ? 'v' + t.version : '-'}</td>
                        <td className="sbom__src">{t.source}</td>
                        <td className={t.available ? 'sbom__ok' : 'sbom__missing'}>{t.available ? 'ready' : 'missing'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
