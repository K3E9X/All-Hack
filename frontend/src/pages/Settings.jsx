import { useEffect, useState } from 'react';
import { api } from '../lib/api.js';

// Custom toggle (no icon).
function Toggle({ on, onChange }) {
  return (
    <button type="button" className={'toggle' + (on ? ' toggle--on' : '')} onClick={() => onChange(!on)} aria-pressed={on}>
      <span className="toggle__track"></span>
      <span className="toggle__knob"></span>
    </button>
  );
}

// Settings. GET/PUT /api/settings (persisted, keys masked) is wired in the
// settings milestone. This reads live config now and posts changes when the
// endpoint is available.
export default function Settings() {
  const [config, setConfig] = useState(null);
  const [settings, setSettings] = useState(null);
  const [saved, setSaved] = useState(null);

  useEffect(() => {
    api.config().then(setConfig).catch(() => {});
    api.settings.get().then(setSettings).catch(() => setSettings(null));
  }, []);

  const safety = settings?.safety || {};
  const setSafety = (k, v) => setSettings((s) => ({ ...(s || {}), safety: { ...(s?.safety || {}), [k]: v } }));

  async function save() {
    try { await api.settings.save(settings || {}); setSaved('Saved'); }
    catch (e) { setSaved('Pending: ' + e.message); }
    setTimeout(() => setSaved(null), 2500);
  }

  const roles = config?.llm_roles || {};

  return (
    <div className="page">
      <div className="card">
        <div className="card__head"><span className="card__title">Model router</span></div>
        <div className="card__body">
          <dl className="kv">
            {Object.keys(roles).length === 0 && <><dt>Model</dt><dd className="mono">{config?.llm_model || '-'}</dd></>}
            {Object.entries(roles).map(([r, v]) => (
              <span key={r} style={{ display: 'contents' }}><dt>{r}</dt><dd className="mono">{(v && v.model) || String(v)}</dd></span>
            ))}
          </dl>
          <p className="intro" style={{ marginTop: 10 }}>Provider keys are write-only and never returned to the UI (masked set/unset). Editing the per-role router + keys is wired to <code>PUT /api/settings</code> next.</p>
        </div>
      </div>

      <div className="card">
        <div className="card__head"><span className="card__title">Safety</span></div>
        <div className="card__body">
          <div className="toggle-row"><span className="toggle-row__txt">Safe-PoC only (read-only proofs)</span><Toggle on={safety.safe_mode !== false} onChange={(v) => setSafety('safe_mode', v)} /></div>
          <div className="toggle-row"><span className="toggle-row__txt">Require approval before exploitation</span><Toggle on={!!safety.require_approval} onChange={(v) => setSafety('require_approval', v)} /></div>
          <div className="toggle-row"><span className="toggle-row__txt">Auto-validate findings</span><Toggle on={safety.auto_validate !== false} onChange={(v) => setSafety('auto_validate', v)} /></div>
          <div className="toggle-row"><span className="toggle-row__txt">Out-of-band (interactsh) enabled</span><Toggle on={!!safety.oob_enabled} onChange={(v) => setSafety('oob_enabled', v)} /></div>
          <div className="form-actions" style={{ marginTop: 14 }}>
            <button className="btn btn--solid" onClick={save}>Save settings</button>
            {saved && <span className="form-error" style={{ color: 'var(--text-secondary)' }}>{saved}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}
