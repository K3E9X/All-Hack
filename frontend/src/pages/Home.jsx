import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';

const PHASE_ORDER = ['Reconnaissance', 'Scanning & enumeration', 'Exploitation', 'Capture & analysis', 'Other'];
const LLM_ROLES = ['planner', 'executor', 'validator'];

export default function Home() {
  const [config, setConfig] = useState(null);
  const [dash, setDash] = useState(null);
  const [tools, setTools] = useState([]);
  const [pinging, setPinging] = useState(false);
  const [pings, setPings] = useState([]);
  const [net, setNet] = useState(null);
  const [proxyUrl, setProxyUrl] = useState('');
  const [netBusy, setNetBusy] = useState(false);
  const [netError, setNetError] = useState(null);

  useEffect(() => {
    api.config().then(setConfig).catch(() => {});
    api.dashboard().then(setDash).catch(() => {});
    api.tools().then((t) => setTools(Array.isArray(t) ? t : [])).catch(() => {});
    api.network.status().then(setNet).catch(() => {});
  }, []);

  // Ping every role, not just the planner: they can sit on different
  // providers, so one answering says nothing about the other two.
  async function testLlm() {
    setPinging(true);
    setPings(LLM_ROLES.map((role) => ({ role, state: 'pending' })));
    const results = await Promise.all(
      LLM_ROLES.map(async (role) => {
        try {
          const r = await api.llmPing(role);
          return {
            role,
            state: 'ok',
            model: r.model_used,
            latency: r.latency_ms,
            tokens: (r.prompt_tokens || 0) + (r.completion_tokens || 0),
            fallback: r.fallback_used,
            reply: r.reply,
          };
        } catch (e) {
          return { role, state: 'err', error: e.message };
        }
      })
    );
    setPings(results);
    setPinging(false);
  }

  async function refreshNetwork() {
    setNetBusy(true);
    setNetError(null);
    try {
      const r = await api.network.check();
      if (!r.safe && r.reason) setNetError(r.reason);
      setNet(await api.network.status());
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
  }

  async function applyProxy() {
    setNetBusy(true);
    setNetError(null);
    try {
      setNet(await api.network.setProxy(proxyUrl));
      setProxyUrl('');
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
  }

  async function dropTunnel() {
    setNetBusy(true);
    setNetError(null);
    try {
      setNet(await api.network.disconnect());
    } catch (e) {
      setNetError(e.message);
    }
    setNetBusy(false);
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
            <div className="card__head">
              <span className="card__title">Exit route</span>
              <span className={'card__meta ' + (net?.mode !== 'off' && !net?.ip_changed ? 'kv-no' : '')}>
                {net?.mode === 'off' ? 'direct connection' : net?.mode || '-'}
              </span>
            </div>
            <div className="card__body">
              <dl className="kv">
                <dt>Exit IP</dt>
                <dd className={'mono ' + (net?.ip_changed ? 'kv-yes' : '')}>{net?.current_ip || 'unknown'}</dd>
                {net?.baseline_ip && (<><dt>Real IP</dt><dd className="mono">{net.baseline_ip}</dd></>)}
                <dt>Block scans without VPN</dt>
                <dd className={net?.require_vpn ? 'kv-yes' : ''}>{net?.require_vpn ? 'yes' : 'no'}</dd>
                <dt>User-Agent</dt>
                <dd className="mono">{net?.user_agent_mode || '-'}{net?.pentest_id ? ` · id ${net.pentest_id}` : ''}</dd>
              </dl>

              {net && net.mode !== 'off' && !net.ip_changed && (
                <p className="ping-result ping-result--err">
                  Traffic is NOT going through the tunnel. Scans run from your real IP
                  unless REQUIRE_VPN is on, in which case they are blocked.
                </p>
              )}

              <div className="key-row" style={{ marginTop: 8 }}>
                <input
                  className="input"
                  placeholder="socks5://127.0.0.1:9050"
                  value={proxyUrl}
                  onChange={(e) => setProxyUrl(e.target.value)}
                />
                <button className="btn btn--solid" onClick={applyProxy} disabled={!proxyUrl || netBusy}>Route</button>
              </div>
              <div className="form-actions" style={{ marginTop: 6 }}>
                <button className="btn" onClick={refreshNetwork} disabled={netBusy}>{netBusy ? 'Checking...' : 'Check IP'}</button>
                <button className="btn" onClick={dropTunnel} disabled={netBusy}>Direct</button>
              </div>
              {netError && <p className="ping-result ping-result--err">{netError}</p>}
              <p className="home-intro" style={{ marginTop: 8 }}>
                Turn this on before creating an engagement. A proxy needs no privileges;
                for WireGuard/OpenVPN set VPN_CONFIG_PATH in .env.
              </p>
            </div>
          </div>

          <div className="card">
            <div className="card__head"><span className="card__title">LLM sanity check</span><span className="card__meta">all roles</span></div>
            <div className="card__body">
              <p className="home-intro">Send a tiny request to each role's provider to verify the key, the model and how slow it answers.</p>
              <button className="btn btn--solid" onClick={testLlm} disabled={pinging}>{pinging ? 'Pinging...' : 'Ping LLM'}</button>
              {pings.map((p) => (
                <p key={p.role} className={'ping-result ping-result--' + p.state}>
                  <strong>{p.role}</strong>{' '}
                  {p.state === 'pending' && 'pinging...'}
                  {p.state === 'ok' && `${p.model} · ${p.latency}ms${p.tokens ? ` · ${p.tokens} tok` : ''}${p.fallback ? ' · fallback' : ''}`}
                  {p.state === 'err' && p.error}
                </p>
              ))}
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
