// Thin fetch wrappers for the FastAPI backend. Paths are relative so they
// work behind the nginx proxy in production and the Vite dev proxy locally.

async function request(path, opts = {}) {
  const res = await fetch(path, opts);
  const text = await res.text();
  const body = text ? safeJson(text) : null;
  if (!res.ok) {
    const msg = body?.detail || body?.error || text || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return body;
}

function safeJson(text) {
  try { return JSON.parse(text); } catch { return text; }
}

export const api = {
  config: () => request('/api/config'),
  llmPing: () => request('/api/llm/ping', { method: 'POST' }),

  proxy: {
    status: () => request('/api/proxy/status'),
    hosts: () => request('/api/proxy/hosts'),
    flows: (params = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== null)
      ).toString();
      return request(`/api/proxy/flows${qs ? `?${qs}` : ''}`);
    },
    flow: (id) => request(`/api/proxy/flows/${id}`),
    clear: () => request('/api/proxy/flows', { method: 'DELETE' }),
    caUrl: () => '/api/proxy/ca.pem',
  },

  scans: {
    tools: () => request('/api/scans/tools'),
    list: (params = {}) => {
      const qs = new URLSearchParams(
        Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== null)
      ).toString();
      return request(`/api/scans${qs ? `?${qs}` : ''}`);
    },
    submit: (payload) => request('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
    get: (id) => request(`/api/scans/${id}`),
    cancel: (id) => request(`/api/scans/${id}/cancel`, { method: 'POST' }),
    delete: (id) => request(`/api/scans/${id}`, { method: 'DELETE' }),
  },

  llm: {
    suggestForFlow: (flowId) => request(`/api/llm/flows/${flowId}/suggest`, { method: 'POST' }),
    explainJob: (jobId) => request(`/api/llm/jobs/${jobId}/explain`, { method: 'POST' }),
    report: (payload) => request('/api/llm/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }),
  },
};
