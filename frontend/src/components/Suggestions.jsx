import { useState } from 'react';
import { api } from '../lib/api.js';

/**
 * Renders LLM-proposed scans for a given captured flow. A click on "Run"
 * submits the scan via /api/scans and calls onLaunched(jobId) so the parent
 * can redirect/select the new job.
 */
export default function Suggestions({ flowId, onLaunched }) {
  const [state, setState] = useState({ loading: false, data: null, error: null });
  const [launching, setLaunching] = useState(null); // index of running suggestion

  async function fetchSuggestions() {
    setState({ loading: true, data: null, error: null });
    try {
      const res = await api.llm.suggestForFlow(flowId);
      setState({ loading: false, data: res, error: null });
    } catch (err) {
      setState({ loading: false, data: null, error: err.message });
    }
  }

  async function runSuggestion(idx, suggestion) {
    setLaunching(idx);
    try {
      const job = await api.scans.submit({
        tool: suggestion.tool,
        target: suggestion.target,
        options: suggestion.options,
        flow_id: flowId,
      });
      if (onLaunched) onLaunched(job.id);
    } catch (err) {
      alert('Launch failed: ' + err.message);
    } finally {
      setLaunching(null);
    }
  }

  const parsed = state.data?.parsed;

  return (
    <div className="suggestions">
      <div className="row-between">
        <h3 className="msg-h">LLM suggestions</h3>
        <button className="btn ghost" onClick={fetchSuggestions} disabled={state.loading}>
          {state.loading ? 'Analyzing...' : 'Suggest attacks'}
        </button>
      </div>

      {state.error && <p className="result error">{state.error}</p>}

      {state.data && !parsed && (
        <>
          <p className="result error small">
            The model did not return valid JSON. Raw response below.
          </p>
          <pre className="body mono small">{state.data.raw}</pre>
        </>
      )}

      {parsed && (
        <div className="stack-sm">
          {parsed.summary && <p className="small">{parsed.summary}</p>}
          {parsed.auth_scheme && (
            <p className="small muted"><strong>Auth:</strong> {parsed.auth_scheme}</p>
          )}

          {parsed.suspicious_parameters?.length > 0 && (
            <div>
              <div className="msg-h">Suspicious parameters</div>
              <ul className="small">
                {parsed.suspicious_parameters.map((p, i) => (
                  <li key={i}>
                    <code>{p.name}</code> <span className="muted">({p.location})</span> - {p.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {parsed.suggested_scans?.length > 0 ? (
            <div>
              <div className="msg-h">Suggested scans</div>
              <div className="stack-sm">
                {parsed.suggested_scans.map((s, i) => (
                  <div key={i} className="suggestion-card">
                    <div className="row-between">
                      <span className="suggestion-tool mono">{s.tool}</span>
                      <button
                        className="btn"
                        disabled={launching === i}
                        onClick={() => runSuggestion(i, s)}
                      >
                        {launching === i ? 'Launching...' : 'Run'}
                      </button>
                    </div>
                    <div className="mono small truncate" title={s.target}>{s.target}</div>
                    {s.options?.length > 0 && (
                      <div className="mono small muted">options: {s.options.join(' ')}</div>
                    )}
                    <div className="small">{s.rationale}</div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <p className="muted small">No scans suggested for this flow.</p>
          )}
        </div>
      )}
    </div>
  );
}
