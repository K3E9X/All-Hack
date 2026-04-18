import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../lib/api.js';

const POLL_MS = 2000;

export default function Proxy() {
  const [status, setStatus] = useState(null);
  const [flows, setFlows] = useState([]);
  const [total, setTotal] = useState(0);
  const [hosts, setHosts] = useState([]);
  const [filters, setFilters] = useState({ host: '', method: '', search: '' });
  const [selectedId, setSelectedId] = useState(null);
  const [paused, setPaused] = useState(false);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    try {
      const [statusRes, flowsRes, hostsRes] = await Promise.all([
        api.proxy.status(),
        api.proxy.flows({
          limit: 300,
          host: filters.host || undefined,
          method: filters.method || undefined,
          search: filters.search || undefined,
        }),
        api.proxy.hosts(),
      ]);
      setStatus(statusRes);
      setFlows(flowsRes.items);
      setTotal(flowsRes.total);
      setHosts(hostsRes);
      setError(null);
    } catch (err) {
      setError(err.message);
    }
  }, [filters.host, filters.method, filters.search]);

  // Initial + on-filter reload
  useEffect(() => { load(); }, [load]);

  // Polling
  useEffect(() => {
    if (paused) return undefined;
    const t = setInterval(load, POLL_MS);
    return () => clearInterval(t);
  }, [load, paused]);

  async function onClear() {
    if (!confirm('Delete all captured flows?')) return;
    await api.proxy.clear();
    setSelectedId(null);
    load();
  }

  return (
    <div className="stack">
      <section className="card">
        <div className="row-between">
          <h2>Proxy capture</h2>
          <div className="btn-row">
            <button className="btn ghost" onClick={() => setPaused((p) => !p)}>
              {paused ? 'Resume polling' : 'Pause polling'}
            </button>
            <button className="btn ghost" onClick={load}>Refresh</button>
            <button className="btn ghost danger" onClick={onClear}>Clear</button>
          </div>
        </div>
        <dl className="kv">
          <dt>Listen port</dt>
          <dd className="mono">{status?.listen_port ?? '-'}</dd>
          <dt>Flows captured</dt>
          <dd className="mono">{total}</dd>
          <dt>CA certificate</dt>
          <dd>
            {status?.ca_available ? (
              <a href={api.proxy.caUrl()} download>Download allhack-mitmproxy-ca.pem</a>
            ) : (
              <span className="muted">Not generated yet. Send any HTTPS request through the proxy first.</span>
            )}
          </dd>
        </dl>
        {error && <p className="result error">{error}</p>}
      </section>

      <section className="card">
        <div className="filters">
          <select
            value={filters.host}
            onChange={(e) => setFilters((f) => ({ ...f, host: e.target.value }))}
          >
            <option value="">All hosts ({hosts.reduce((n, h) => n + h.count, 0)})</option>
            {hosts.map((h) => (
              <option key={h.host} value={h.host}>{h.host} ({h.count})</option>
            ))}
          </select>
          <select
            value={filters.method}
            onChange={(e) => setFilters((f) => ({ ...f, method: e.target.value }))}
          >
            <option value="">All methods</option>
            {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <input
            type="text"
            placeholder="Filter URL..."
            value={filters.search}
            onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
          />
        </div>

        <FlowTable
          flows={flows}
          selectedId={selectedId}
          onSelect={setSelectedId}
        />
      </section>

      {selectedId && (
        <FlowInspector
          flowId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  );
}

function FlowTable({ flows, selectedId, onSelect }) {
  if (flows.length === 0) {
    return <p className="muted small">No captured flows yet.</p>;
  }
  return (
    <div className="table-wrap">
      <table className="table mono">
        <thead>
          <tr>
            <th style={{ width: 80 }}>Time</th>
            <th style={{ width: 60 }}>Method</th>
            <th style={{ width: 60 }}>Status</th>
            <th>Host</th>
            <th>Path</th>
            <th style={{ width: 80 }}>Size</th>
            <th style={{ width: 70 }}>Time (ms)</th>
          </tr>
        </thead>
        <tbody>
          {flows.map((f) => (
            <tr
              key={f.id}
              className={f.id === selectedId ? 'selected' : ''}
              onClick={() => onSelect(f.id)}
            >
              <td>{formatTime(f.timestamp)}</td>
              <td>{f.method}</td>
              <td className={statusClass(f.status_code)}>{f.status_code ?? '-'}</td>
              <td>{f.host}</td>
              <td className="truncate" title={f.path}>{f.path}</td>
              <td>{f.response_size != null ? formatBytes(f.response_size) : '-'}</td>
              <td>{f.duration_ms ?? '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FlowInspector({ flowId, onClose }) {
  const [flow, setFlow] = useState(null);
  const [tab, setTab] = useState('request');
  const [err, setErr] = useState(null);
  const reqId = useRef(flowId);

  useEffect(() => {
    reqId.current = flowId;
    setFlow(null);
    setErr(null);
    api.proxy.flow(flowId)
      .then((data) => { if (reqId.current === flowId) setFlow(data); })
      .catch((e) => setErr(e.message));
  }, [flowId]);

  return (
    <section className="card">
      <div className="row-between">
        <h2>Inspector</h2>
        <button className="btn ghost" onClick={onClose}>Close</button>
      </div>
      {err && <p className="result error">{err}</p>}
      {!flow && !err && <p className="muted small">Loading...</p>}
      {flow && (
        <>
          <div className="inspect-head mono">
            <div><strong>{flow.method}</strong> {flow.url}</div>
            <div className="muted small">
              {formatTime(flow.timestamp)} &middot;{' '}
              status {flow.status_code ?? '-'} &middot;{' '}
              {flow.response_size != null ? formatBytes(flow.response_size) : '-'} &middot;{' '}
              {flow.duration_ms ?? '-'} ms
            </div>
          </div>

          <div className="tabs">
            <button className={tab === 'request' ? 'active' : ''} onClick={() => setTab('request')}>Request</button>
            <button className={tab === 'response' ? 'active' : ''} onClick={() => setTab('response')}>Response</button>
          </div>

          {tab === 'request' ? (
            <MessageView
              headers={flow.request_headers}
              body={flow.request_body_preview}
              contentType={flow.request_content_type}
            />
          ) : (
            <MessageView
              headers={flow.response_headers}
              body={flow.response_body_preview}
              contentType={flow.response_content_type}
            />
          )}
        </>
      )}
    </section>
  );
}

function MessageView({ headers, body, contentType }) {
  return (
    <div className="msg">
      <h3 className="msg-h">Headers</h3>
      {headers && headers.length ? (
        <table className="headers-table mono">
          <tbody>
            {headers.map((pair, i) => (
              <tr key={i}>
                <td className="header-key">{pair[0]}</td>
                <td className="header-val">{pair[1]}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted small">No headers.</p>
      )}

      <h3 className="msg-h">Body</h3>
      <BodyView body={body} contentType={contentType} />
    </div>
  );
}

function BodyView({ body, contentType }) {
  if (!body || !body.present) return <p className="muted small">Empty body.</p>;
  const meta = (
    <p className="muted small">
      {contentType || '(no content-type)'} &middot; {formatBytes(body.size)}
      {body.truncated && ' (truncated)'}
    </p>
  );
  if (body.encoding === 'text') {
    return (<>{meta}<pre className="body mono">{body.text}</pre></>);
  }
  return (<>{meta}<pre className="body mono">{body.hex}{body.hex_truncated ? '\n...' : ''}</pre></>);
}

// --- utils ---

function formatTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function statusClass(code) {
  if (code == null) return '';
  if (code >= 500) return 'status-5xx';
  if (code >= 400) return 'status-4xx';
  if (code >= 300) return 'status-3xx';
  if (code >= 200) return 'status-2xx';
  return '';
}
