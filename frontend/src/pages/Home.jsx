import { useEffect, useState } from 'react';

export default function Home() {
  const [config, setConfig] = useState(null);
  const [pingStatus, setPingStatus] = useState({ state: 'idle', text: '' });

  useEffect(() => {
    fetch('/api/config')
      .then((r) => r.json())
      .then(setConfig)
      .catch(() => setConfig({ error: true }));
  }, []);

  async function testLlm() {
    setPingStatus({ state: 'pending', text: 'Pinging LLM...' });
    try {
      const r = await fetch('/api/llm/ping', { method: 'POST' });
      const body = await r.json();
      if (!r.ok) {
        setPingStatus({ state: 'error', text: body.detail || 'Error' });
      } else {
        const note = body.fallback_used
          ? ` (fallback from ${body.primary_model})`
          : '';
        setPingStatus({
          state: 'ok',
          text: `${body.model_used} replied: ${body.reply}${note}`,
        });
      }
    } catch (err) {
      setPingStatus({ state: 'error', text: String(err) });
    }
  }

  return (
    <div className="stack">
      <section className="card">
        <h2>Backend status</h2>
        {config === null && <p className="muted">Loading...</p>}
        {config?.error && <p className="error">Cannot reach backend.</p>}
        {config && !config.error && (
          <dl className="kv">
            <dt>LLM configured</dt>
            <dd>{config.llm_configured ? 'yes' : 'no (set OPENROUTER_API_KEY)'}</dd>
            <dt>LLM model</dt>
            <dd className="mono">{config.llm_model}</dd>
            <dt>LLM fallbacks</dt>
            <dd className="mono">
              {config.llm_fallback_models?.length
                ? config.llm_fallback_models.join(', ')
                : '(none)'}
            </dd>
            <dt>MITM proxy port</dt>
            <dd className="mono">{config.mitm_port}</dd>
            <dt>Data directory</dt>
            <dd className="mono">{config.data_dir}</dd>
          </dl>
        )}
      </section>

      <section className="card">
        <h2>LLM sanity check</h2>
        <p className="muted">Send a tiny request to OpenRouter to verify the key and model work.</p>
        <button className="btn" onClick={testLlm} disabled={pingStatus.state === 'pending'}>
          {pingStatus.state === 'pending' ? 'Pinging...' : 'Ping LLM'}
        </button>
        {pingStatus.text && (
          <p className={`result ${pingStatus.state}`}>{pingStatus.text}</p>
        )}
      </section>
    </div>
  );
}
