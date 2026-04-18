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
};
