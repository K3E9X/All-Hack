import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../lib/api.js';

const POLL_MS = 5000;

export default function Engagements() {
  const [items, setItems] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [form, setForm] = useState({ target_url: '', scope_hosts: '', attest: false, require_approval: false });
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
        require_exploit_approval: form.require_approval,
      });
      setForm({ target_url: '', scope_hosts: '', attest: false, require_approval: false });
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
          Enter a target you own, tick the authorization box, and create. The
          engagement is authorized immediately - open its live view to run the
          autonomous test. The scope list limits what will be touched.
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
              checked={form.require_approval}
              onChange={(e) => setForm((f) => ({ ...f, require_approval: e.target.checked }))}
            />
            <span className="small">
              Require my approval before the exploitation phase.
            </span>
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
                  <th></th>
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
                    <td onClick={(ev) => ev.stopPropagation()}>
                      {e.status === 'authorized' && (
                        <Link className="text-link" to={`/engagements/${e.id}/live`}>live view</Link>
                      )}
                    </td>
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
  const [err, setErr] = useState(null);
  const [verifying, setVerifying] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api.engagements.get(engagementId));
      setErr(null);
    } catch (e) {
      setErr(e.message);
    }
  }, [engagementId]);

  useEffect(() => { load(); }, [load]);

  async function onClose() {
    if (!confirm('Close this engagement? No further scans will be allowed.')) return;
    try { await api.engagements.close(engagementId); await load(); onChange && onChange(); }
    catch (e) { setErr(e.message); }
  }

  // Fallback only: an engagement created without attestation stays pending and
  // can be authorized via DNS/.well-known. The normal flow auto-authorizes.
  async function onVerify() {
    setVerifying(true);
    try { await api.engagements.verify(engagementId); await load(); onChange && onChange(); }
    catch (e) { setErr(e.message); }
    finally { setVerifying(false); }
  }

  if (err) return <section className="card"><p className="result error">{err}</p></section>;
  if (!data) return <section className="card"><p className="muted small">Loading...</p></section>;

  const e = data.engagement;

  return (
    <section className="card">
      <div className="row-between">
        <h2>Engagement {e.id}</h2>
        <div className="btn-row">
          {e.status === 'authorized' && (
            <Link className="btn" to={`/engagements/${e.id}/live`}>Open live view</Link>
          )}
          {e.status === 'pending_authorization' && (
            <button className="btn" onClick={onVerify} disabled={verifying}>
              {verifying ? 'Verifying...' : 'Verify ownership'}
            </button>
          )}
          <button className="btn ghost danger" onClick={onClose}>Close</button>
        </div>
      </div>

      <dl className="kv">
        <dt>Target</dt><dd className="mono">{e.target_url}</dd>
        <dt>Status</dt><dd className={`mono eng-${e.status}`}>{e.status}</dd>
        <dt>Scope</dt><dd className="mono">{(e.scope_hosts || []).join(', ')}</dd>
        {e.verification_method && (<><dt>Authorized via</dt><dd className="mono">{e.verification_method}</dd></>)}
      </dl>

      {e.status === 'authorized' && (
        <p className="muted small">
          Authorized. Open the live view to run the autonomous test and watch
          recon, findings, kill-chains and the report build in real time.
        </p>
      )}
      {e.status === 'pending_authorization' && data.challenge && (
        <p className="muted small">
          Not authorized. Either re-create with the authorization checkbox, or
          prove ownership: add DNS TXT
          <code> {data.challenge.methods.dns_txt.record_value}</code> on
          <code> {e.target_host}</code> and click Verify.
        </p>
      )}
    </section>
  );
}
