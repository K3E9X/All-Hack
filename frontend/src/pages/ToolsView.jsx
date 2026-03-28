import { useState, useEffect } from 'react';
import {
  Database,
  Scan,
  Zap,
  Play,
  Loader,
  Copy,
  Check,
  AlertTriangle,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import clsx from 'clsx';
import { useActiveScans } from '../contexts/ActiveScansContext';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

const VULN_TYPES = ['sqli', 'xss', 'rce', 'lfi', 'ssti', 'xxe', 'nosql', 'ssrf'];

export default function ToolsView() {
  const { moduleStates, updateModuleState, addEvent } = useActiveScans();
  const [activeTab, setActiveTab] = useState('sqlmap');

  // Restore state from context on mount
  const toolsState = moduleStates.tools;

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-4 h-10 border-b border-border bg-surface">
        <h1 className="text-xs font-medium tracking-wider uppercase">TOOLS</h1>
      </header>

      {/* Tabs */}
      <div className="flex border-b border-border bg-surface px-4">
        {[
          { id: 'sqlmap', name: 'SQLMAP', icon: Database },
          { id: 'nuclei', name: 'NUCLEI', icon: Scan },
          { id: 'payloads', name: 'PAYLOADS', icon: Zap },
          { id: 'exploit-assist', name: 'EXPLOIT', icon: AlertTriangle }
        ].map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={clsx(
                'flex items-center gap-2 px-3 py-2 text-xs tracking-wide border-b -mb-px transition-colors',
                activeTab === tab.id
                  ? 'border-accent text-accent'
                  : 'border-transparent text-secondary hover:text-primary'
              )}
            >
              <Icon className="w-3 h-3" strokeWidth={1.5} />
              {tab.name}
            </button>
          );
        })}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 bg-background">
        <div className="max-w-3xl">
          {activeTab === 'sqlmap' && <SQLMapTool />}
          {activeTab === 'nuclei' && <NucleiTool />}
          {activeTab === 'payloads' && <PayloadsTool />}
          {activeTab === 'exploit-assist' && <ExploitAssistTool />}
        </div>
      </div>
    </div>
  );
}

function SQLMapTool() {
  const { moduleStates, updateModuleState, addEvent } = useActiveScans();
  const savedState = moduleStates.tools?.sqlmap || {};

  const [target, setTarget] = useState(savedState.target || '');
  const [level, setLevel] = useState(savedState.level || 1);
  const [risk, setRisk] = useState(savedState.risk || 1);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(savedState.result || null);

  // Persist state changes
  useEffect(() => {
    updateModuleState('tools', {
      ...moduleStates.tools,
      sqlmap: { target, level, risk, result }
    });
  }, [target, level, risk, result]);

  const runSQLMap = async () => {
    setRunning(true);
    setResult(null);
    addEvent('tools', 'sqlmap', `Running SQLMap on ${target}`, 'info');

    try {
      const response = await fetch(`${API_URL}/api/v1/tools/sqlmap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, level, risk })
      });
      const data = await response.json();
      setResult(data);
      addEvent('tools', 'sqlmap', data.vulnerable ? 'SQL Injection found!' : 'No SQLi detected', data.vulnerable ? 'warning' : 'success');
    } catch (error) {
      setResult({ error: error.message });
      addEvent('tools', 'sqlmap', `SQLMap error: ${error.message}`, 'error');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <h2 className="text-lg font-semibold mb-4">SQLMap Integration</h2>
        <p className="text-sm text-secondary mb-4">
          Automated SQL injection detection and exploitation tool.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com/page?id=1"
              className="w-full px-4 py-2 rounded-lg border border-border bg-surface"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1.5">Level (1-5)</label>
              <input
                type="number"
                min={1}
                max={5}
                value={level}
                onChange={(e) => setLevel(parseInt(e.target.value))}
                className="w-full px-4 py-2 rounded-lg border border-border bg-surface"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5">Risk (1-3)</label>
              <input
                type="number"
                min={1}
                max={3}
                value={risk}
                onChange={(e) => setRisk(parseInt(e.target.value))}
                className="w-full px-4 py-2 rounded-lg border border-border bg-surface"
              />
            </div>
          </div>

          <button
            onClick={runSQLMap}
            disabled={!target || running}
            className="btn btn-primary w-full disabled:opacity-50"
          >
            {running ? <Loader className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            Run SQLMap
          </button>
        </div>
      </div>

      {result && (
        <div className="card p-6">
          <h3 className="font-medium mb-4">Results</h3>
          {result.error ? (
            <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg text-yellow-400">
              {result.error}
              {result.install_hint && (
                <p className="mt-2 text-sm font-mono">{result.install_hint}</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className={clsx(
                'p-4 rounded-lg',
                result.vulnerable ? 'bg-red-500/10 border border-red-500/20' : 'bg-green-500/10 border border-green-500/20'
              )}>
                <span className={result.vulnerable ? 'text-red-400' : 'text-green-400'}>
                  {result.vulnerable ? 'Vulnerable to SQL Injection' : 'No SQL Injection found'}
                </span>
              </div>

              {result.injection_points?.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Injection Points</div>
                  {result.injection_points.map((point, i) => (
                    <div key={i} className="p-2 bg-surface rounded border border-border text-sm font-mono">
                      {point}
                    </div>
                  ))}
                </div>
              )}

              {result.databases?.length > 0 && (
                <div>
                  <div className="text-sm font-medium mb-2">Databases</div>
                  <div className="flex flex-wrap gap-2">
                    {result.databases.map((db, i) => (
                      <span key={i} className="px-2 py-1 bg-accent/10 text-accent rounded text-sm">
                        {db}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function NucleiTool() {
  const { moduleStates, updateModuleState, addEvent } = useActiveScans();
  const savedState = moduleStates.tools?.nuclei || {};

  const [target, setTarget] = useState(savedState.target || '');
  const [severity, setSeverity] = useState(savedState.severity || ['critical', 'high']);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(savedState.result || null);

  // Persist state changes
  useEffect(() => {
    updateModuleState('tools', {
      ...moduleStates.tools,
      nuclei: { target, severity, result }
    });
  }, [target, severity, result]);

  const runNuclei = async () => {
    setRunning(true);
    setResult(null);
    addEvent('tools', 'nuclei', `Running Nuclei templates on ${target}`, 'info');

    try {
      const response = await fetch(`${API_URL}/api/v1/tools/nuclei`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, severity })
      });
      const data = await response.json();
      setResult(data);
      addEvent('tools', 'nuclei', `Nuclei completed: ${data.vulnerabilities_found || 0} findings`, data.vulnerabilities_found > 0 ? 'warning' : 'success');
    } catch (error) {
      setResult({ error: error.message });
      addEvent('tools', 'nuclei', `Nuclei error: ${error.message}`, 'error');
    } finally {
      setRunning(false);
    }
  };

  const toggleSeverity = (sev) => {
    setSeverity(prev =>
      prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
    );
  };

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <h2 className="text-lg font-semibold mb-4">Nuclei Scanner</h2>
        <p className="text-sm text-secondary mb-4">
          Template-based vulnerability scanner with thousands of community templates.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1.5">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com"
              className="w-full px-4 py-2 rounded-lg border border-border bg-surface"
            />
          </div>

          <div>
            <label className="block text-sm font-medium mb-2">Severity Filter</label>
            <div className="flex gap-2">
              {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
                <button
                  key={sev}
                  onClick={() => toggleSeverity(sev)}
                  className={clsx(
                    'px-3 py-1.5 rounded text-sm font-medium capitalize border transition-colors',
                    severity.includes(sev)
                      ? `severity-${sev} border-current`
                      : 'border-border text-secondary hover:border-accent'
                  )}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          <button
            onClick={runNuclei}
            disabled={!target || running}
            className="btn btn-primary w-full disabled:opacity-50"
          >
            {running ? <Loader className="w-4 h-4 animate-spin mr-2" /> : <Scan className="w-4 h-4 mr-2" />}
            Run Nuclei
          </button>
        </div>
      </div>

      {result && (
        <div className="card p-6">
          <h3 className="font-medium mb-4">Results</h3>
          {result.error ? (
            <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg text-yellow-400">
              {result.error}
              {result.install_hint && (
                <p className="mt-2 text-sm font-mono">{result.install_hint}</p>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-surface rounded border border-border">
                  <div className="text-sm text-secondary">Templates Run</div>
                  <div className="text-2xl font-semibold">{result.templates_run || 0}</div>
                </div>
                <div className="p-3 bg-surface rounded border border-border">
                  <div className="text-sm text-secondary">Vulnerabilities</div>
                  <div className="text-2xl font-semibold text-critical">{result.vulnerabilities_found || 0}</div>
                </div>
              </div>

              {result.findings?.length > 0 && (
                <div className="space-y-2">
                  {result.findings.map((finding, i) => (
                    <div key={i} className={clsx('p-3 rounded border', `severity-${finding.severity || 'info'}`)}>
                      <div className="font-medium">{finding.name || finding.template}</div>
                      <div className="text-sm opacity-80">{finding.description}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function PayloadsTool() {
  const { moduleStates, updateModuleState, addEvent } = useActiveScans();
  const savedState = moduleStates.tools?.payloads || {};

  const [vulnType, setVulnType] = useState(savedState.vulnType || 'sqli');
  const [count, setCount] = useState(savedState.count || 20);
  const [loading, setLoading] = useState(false);
  const [payloads, setPayloads] = useState(savedState.payloads || []);
  const [copied, setCopied] = useState(null);

  // Persist state changes
  useEffect(() => {
    updateModuleState('tools', {
      ...moduleStates.tools,
      payloads: { vulnType, count, payloads }
    });
  }, [vulnType, count, payloads]);

  const fetchPayloads = async () => {
    setLoading(true);
    addEvent('tools', 'payloads', `Loading ${vulnType} payloads`, 'info');
    try {
      const response = await fetch(`${API_URL}/api/v1/tools/payloads/${vulnType}?limit=${count}`);
      const data = await response.json();
      setPayloads(data.payloads || []);
      addEvent('tools', 'payloads', `Loaded ${data.payloads?.length || 0} ${vulnType} payloads`, 'success');
    } catch (error) {
      console.error('Failed to fetch payloads:', error);
      addEvent('tools', 'payloads', `Failed to load payloads: ${error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const generatePayloads = async () => {
    setLoading(true);
    addEvent('tools', 'payloads', `Generating AI ${vulnType} payloads`, 'info');
    try {
      const response = await fetch(`${API_URL}/api/v1/tools/payloads`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vuln_type: vulnType, count })
      });
      const data = await response.json();
      setPayloads(data.payloads || []);
      addEvent('tools', 'payloads', `Generated ${data.payloads?.length || 0} AI payloads`, 'success');
    } catch (error) {
      console.error('Failed to generate payloads:', error);
      addEvent('tools', 'payloads', `Failed to generate payloads: ${error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  const copyPayload = async (payload, index) => {
    await navigator.clipboard.writeText(payload);
    setCopied(index);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <h2 className="text-lg font-semibold mb-4">Payload Generator</h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Vulnerability Type</label>
            <div className="flex flex-wrap gap-2">
              {VULN_TYPES.map(type => (
                <button
                  key={type}
                  onClick={() => setVulnType(type)}
                  className={clsx(
                    'px-3 py-1.5 rounded text-sm font-medium uppercase border transition-colors',
                    vulnType === type
                      ? 'border-accent bg-accent/10 text-accent'
                      : 'border-border text-secondary hover:border-accent'
                  )}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1.5">Count</label>
            <input
              type="number"
              min={5}
              max={100}
              value={count}
              onChange={(e) => setCount(parseInt(e.target.value))}
              className="w-32 px-4 py-2 rounded-lg border border-border bg-surface"
            />
          </div>

          <div className="flex gap-3">
            <button
              onClick={fetchPayloads}
              disabled={loading}
              className="btn btn-secondary flex-1 disabled:opacity-50"
            >
              {loading ? <Loader className="w-4 h-4 animate-spin mr-2" /> : null}
              Load Static Payloads
            </button>
            <button
              onClick={generatePayloads}
              disabled={loading}
              className="btn btn-primary flex-1 disabled:opacity-50"
            >
              {loading ? <Loader className="w-4 h-4 animate-spin mr-2" /> : <Zap className="w-4 h-4 mr-2" />}
              Generate AI Payloads
            </button>
          </div>
        </div>
      </div>

      {payloads.length > 0 && (
        <div className="card p-6">
          <h3 className="font-medium mb-4">Payloads ({payloads.length})</h3>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {payloads.map((payload, i) => (
              <div
                key={i}
                className="flex items-center justify-between p-2 bg-surface rounded border border-border group"
              >
                <code className="text-sm font-mono truncate flex-1 mr-2">
                  {typeof payload === 'string' ? payload : payload.payload || JSON.stringify(payload)}
                </code>
                <button
                  onClick={() => copyPayload(typeof payload === 'string' ? payload : payload.payload, i)}
                  className="p-1.5 rounded hover:bg-hover opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  {copied === i ? (
                    <Check className="w-4 h-4 text-green-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ExploitAssistTool() {
  const { moduleStates, updateModuleState, addEvent } = useActiveScans();
  const savedState = moduleStates.tools?.exploitAssist || {};

  const [vulnType, setVulnType] = useState(savedState.vulnType || 'sqli');
  const [target, setTarget] = useState(savedState.target || '');
  const [loading, setLoading] = useState(false);
  const [guidance, setGuidance] = useState(savedState.guidance || null);

  // Persist state changes
  useEffect(() => {
    updateModuleState('tools', {
      ...moduleStates.tools,
      exploitAssist: { vulnType, target, guidance }
    });
  }, [vulnType, target, guidance]);

  const getGuidance = async () => {
    setLoading(true);
    addEvent('tools', 'exploit-assist', `Getting exploitation guidance for ${vulnType}`, 'info');
    try {
      const response = await fetch(`${API_URL}/api/v1/tools/exploit-assist?vuln_type=${vulnType}&target=${encodeURIComponent(target)}`, {
        method: 'POST'
      });
      const data = await response.json();
      setGuidance(data.guidance);
      addEvent('tools', 'exploit-assist', `Received ${vulnType} exploitation guide`, 'success');
    } catch (error) {
      console.error('Failed to get guidance:', error);
      addEvent('tools', 'exploit-assist', `Failed to get guidance: ${error.message}`, 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="card p-6">
        <h2 className="text-lg font-semibold mb-4">Exploitation Assistant</h2>
        <p className="text-sm text-secondary mb-4">
          Get AI-powered guidance for exploiting discovered vulnerabilities.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Vulnerability Type</label>
            <div className="flex flex-wrap gap-2">
              {VULN_TYPES.map(type => (
                <button
                  key={type}
                  onClick={() => setVulnType(type)}
                  className={clsx(
                    'px-3 py-1.5 rounded text-sm font-medium uppercase border transition-colors',
                    vulnType === type
                      ? 'border-accent bg-accent/10 text-accent'
                      : 'border-border text-secondary hover:border-accent'
                  )}
                >
                  {type}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1.5">Target URL</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com/vulnerable?param=value"
              className="w-full px-4 py-2 rounded-lg border border-border bg-surface"
            />
          </div>

          <button
            onClick={getGuidance}
            disabled={loading}
            className="btn btn-primary w-full disabled:opacity-50"
          >
            {loading ? <Loader className="w-4 h-4 animate-spin mr-2" /> : <AlertTriangle className="w-4 h-4 mr-2" />}
            Get Exploitation Guidance
          </button>
        </div>
      </div>

      {guidance && (
        <div className="card p-6">
          <h3 className="font-medium mb-4">Exploitation Guide</h3>

          {guidance.steps && (
            <div className="mb-6">
              <div className="text-sm font-medium mb-2">Steps</div>
              <ol className="space-y-2">
                {guidance.steps.map((step, i) => (
                  <li key={i} className="flex gap-3 p-3 bg-surface rounded border border-border">
                    <span className="w-6 h-6 rounded-full bg-accent/10 text-accent flex items-center justify-center text-sm font-medium shrink-0">
                      {i + 1}
                    </span>
                    <span className="text-sm">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}

          {guidance.tools && (
            <div className="mb-6">
              <div className="text-sm font-medium mb-2">Recommended Tools</div>
              <div className="flex flex-wrap gap-2">
                {guidance.tools.map((tool, i) => (
                  <span key={i} className="px-3 py-1 bg-surface rounded border border-border text-sm">
                    {tool}
                  </span>
                ))}
              </div>
            </div>
          )}

          {guidance.payloads && (
            <div>
              <div className="text-sm font-medium mb-2">Example Payloads</div>
              <div className="space-y-2">
                {guidance.payloads.map((payload, i) => (
                  <code key={i} className="block p-2 bg-surface rounded border border-border text-sm font-mono">
                    {payload}
                  </code>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
