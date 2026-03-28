import { useState, useEffect } from 'react';
import {
  Globe,
  Server,
  Lock,
  FolderSearch,
  Play,
  Loader,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import clsx from 'clsx';
import { useActiveScans } from '../contexts/ActiveScansContext';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

const SCAN_TYPES = [
  {
    id: 'ports',
    name: 'Port Scan',
    description: 'Scan for open ports and services',
    icon: Server,
    endpoint: '/api/v1/recon/ports'
  },
  {
    id: 'subdomains',
    name: 'Subdomain Enum',
    description: 'Enumerate subdomains for target domain',
    icon: Globe,
    endpoint: '/api/v1/recon/subdomains'
  },
  {
    id: 'ssl',
    name: 'SSL/TLS Analysis',
    description: 'Analyze SSL/TLS configuration and vulnerabilities',
    icon: Lock,
    endpoint: '/api/v1/recon/ssl'
  },
  {
    id: 'directories',
    name: 'Directory Fuzzing',
    description: 'Discover hidden directories and files',
    icon: FolderSearch,
    endpoint: '/api/v1/recon/directories'
  }
];

export default function ReconView() {
  const { moduleStates, updateModuleState, addEvent } = useActiveScans();
  const savedState = moduleStates.recon || {};

  // Restore state from context
  const [target, setTarget] = useState(savedState.target || '');
  const [selectedScans, setSelectedScans] = useState(savedState.selectedScans || ['ports', 'ssl']);
  const [running, setRunning] = useState({});
  const [results, setResults] = useState(savedState.results || {});
  const [expanded, setExpanded] = useState(savedState.expanded || {});

  // Persist state changes to context
  useEffect(() => {
    updateModuleState('recon', { target, selectedScans, results, expanded });
  }, [target, selectedScans, results, expanded]);

  const toggleScan = (id) => {
    setSelectedScans(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    );
  };

  const runScan = async (scanType) => {
    if (!target) return;

    setRunning(prev => ({ ...prev, [scanType.id]: true }));
    setResults(prev => ({ ...prev, [scanType.id]: null }));
    addEvent('recon', scanType.id, `Running ${scanType.name} on ${target}`, 'info');

    try {
      const response = await fetch(`${API_URL}${scanType.endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      });

      const data = await response.json();
      setResults(prev => ({ ...prev, [scanType.id]: { success: true, data } }));
      setExpanded(prev => ({ ...prev, [scanType.id]: true }));
      addEvent('recon', scanType.id, `${scanType.name} completed`, 'success', data);
    } catch (error) {
      setResults(prev => ({
        ...prev,
        [scanType.id]: { success: false, error: error.message }
      }));
      addEvent('recon', scanType.id, `${scanType.name} failed: ${error.message}`, 'error');
    } finally {
      setRunning(prev => ({ ...prev, [scanType.id]: false }));
    }
  };

  const runAllSelected = async () => {
    addEvent('recon', 'batch', `Running ${selectedScans.length} recon scans`, 'info');
    // Run in parallel instead of sequential
    const promises = selectedScans.map(id => {
      const scanType = SCAN_TYPES.find(s => s.id === id);
      return scanType ? runScan(scanType) : Promise.resolve();
    });
    await Promise.all(promises);
  };

  const toggleExpand = (id) => {
    setExpanded(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const renderResult = (scanId, result) => {
    if (!result) return null;

    if (!result.success) {
      return (
        <div className="p-4 bg-red-500/10 border border-red-500/20 rounded-lg text-red-400">
          Error: {result.error}
        </div>
      );
    }

    const data = result.data;

    switch (scanId) {
      case 'ports':
        return (
          <div className="space-y-2">
            <div className="text-sm text-secondary">
              Found {data.open_ports?.length || 0} open ports
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {data.open_ports?.map((port, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-surface border border-border text-sm font-mono"
                >
                  <span className="text-accent">{port.port}</span>
                  <span className="text-secondary ml-2">{port.service || 'unknown'}</span>
                </div>
              ))}
            </div>
            {data.vulnerabilities?.length > 0 && (
              <div className="mt-4">
                <div className="text-sm font-medium mb-2">Vulnerabilities</div>
                {data.vulnerabilities.map((v, i) => (
                  <div key={i} className="p-2 rounded bg-red-500/10 border border-red-500/20 text-sm">
                    {v.title || v.description}
                  </div>
                ))}
              </div>
            )}
          </div>
        );

      case 'subdomains':
        return (
          <div className="space-y-2">
            <div className="text-sm text-secondary">
              Found {data.count || 0} subdomains
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
              {data.subdomains?.map((sub, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-surface border border-border text-sm font-mono flex justify-between"
                >
                  <span>{sub.subdomain || sub}</span>
                  {sub.ip && <span className="text-secondary">{sub.ip}</span>}
                </div>
              ))}
            </div>
          </div>
        );

      case 'ssl':
        return (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 rounded bg-surface border border-border">
                <div className="text-sm text-secondary">Vulnerabilities</div>
                <div className="text-2xl font-semibold text-critical">
                  {data.summary?.vulnerabilities_count || 0}
                </div>
              </div>
              <div className="p-3 rounded bg-surface border border-border">
                <div className="text-sm text-secondary">Misconfigurations</div>
                <div className="text-2xl font-semibold text-medium">
                  {data.summary?.misconfigurations_count || 0}
                </div>
              </div>
            </div>
            {data.vulnerabilities?.length > 0 && (
              <div>
                <div className="text-sm font-medium mb-2">Issues Found</div>
                <div className="space-y-2">
                  {data.vulnerabilities.map((v, i) => (
                    <div key={i} className="p-2 rounded bg-red-500/10 border border-red-500/20 text-sm">
                      {v.title || v.name || JSON.stringify(v)}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );

      case 'directories':
        return (
          <div className="space-y-2">
            <div className="text-sm text-secondary">
              Found {data.count || 0} paths
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
              {data.directories?.map((dir, i) => (
                <div
                  key={i}
                  className="p-2 rounded bg-surface border border-border text-sm font-mono flex justify-between"
                >
                  <span>{dir.path || dir}</span>
                  {dir.status && (
                    <span className={clsx(
                      dir.status === 200 && 'text-green-400',
                      dir.status === 403 && 'text-yellow-400',
                      dir.status === 301 && 'text-blue-400'
                    )}>
                      {dir.status}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        );

      default:
        return (
          <pre className="p-4 bg-surface rounded text-sm overflow-auto max-h-64">
            {JSON.stringify(data, null, 2)}
          </pre>
        );
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-6 h-14 border-b border-border bg-background">
        <h1 className="text-lg font-semibold">Reconnaissance</h1>
      </header>

      <div className="flex-1 overflow-y-auto p-6 bg-surface">
        <div className="max-w-4xl mx-auto space-y-6">
          {/* Target Input */}
          <div className="card p-4">
            <label className="block text-sm font-medium mb-2">Target</label>
            <div className="flex gap-3">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or https://example.com"
                className="flex-1 px-4 py-2 rounded-lg border border-border bg-surface"
              />
              <button
                onClick={runAllSelected}
                disabled={!target || selectedScans.length === 0}
                className="btn btn-primary disabled:opacity-50"
              >
                <Play className="w-4 h-4 mr-2" />
                Run Selected
              </button>
            </div>
          </div>

          {/* Scan Types */}
          <div className="space-y-3">
            {SCAN_TYPES.map((scanType) => {
              const Icon = scanType.icon;
              const isSelected = selectedScans.includes(scanType.id);
              const isRunning = running[scanType.id];
              const result = results[scanType.id];
              const isExpanded = expanded[scanType.id];

              return (
                <div key={scanType.id} className="card">
                  <div className="flex items-center justify-between p-4">
                    <div className="flex items-center gap-4">
                      <button
                        onClick={() => toggleScan(scanType.id)}
                        className={clsx(
                          'w-5 h-5 rounded border-2 flex items-center justify-center transition-colors',
                          isSelected
                            ? 'bg-accent border-accent'
                            : 'border-border hover:border-accent'
                        )}
                      >
                        {isSelected && <CheckCircle className="w-3 h-3 text-white" />}
                      </button>

                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center">
                          <Icon className="w-5 h-5 text-accent" />
                        </div>
                        <div>
                          <div className="font-medium">{scanType.name}</div>
                          <div className="text-sm text-secondary">{scanType.description}</div>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {result && (
                        <button
                          onClick={() => toggleExpand(scanType.id)}
                          className="p-2 rounded hover:bg-hover"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-5 h-5" />
                          ) : (
                            <ChevronRight className="w-5 h-5" />
                          )}
                        </button>
                      )}

                      <button
                        onClick={() => runScan(scanType)}
                        disabled={!target || isRunning}
                        className="btn btn-secondary disabled:opacity-50"
                      >
                        {isRunning ? (
                          <Loader className="w-4 h-4 animate-spin" />
                        ) : result?.success ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : result && !result.success ? (
                          <XCircle className="w-4 h-4 text-red-400" />
                        ) : (
                          <Play className="w-4 h-4" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Results */}
                  {isExpanded && result && (
                    <div className="px-4 pb-4 border-t border-border pt-4">
                      {renderResult(scanType.id, result)}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
