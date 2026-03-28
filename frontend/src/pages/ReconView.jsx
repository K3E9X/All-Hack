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
        <div className="p-2 bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
          Error: {result.error}
        </div>
      );
    }

    const data = result.data;

    switch (scanId) {
      case 'ports':
        return (
          <div className="space-y-2">
            <div className="text-xs text-secondary uppercase">
              {data.open_ports?.length || 0} open ports
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-1">
              {data.open_ports?.map((port, i) => (
                <div
                  key={i}
                  className="p-1.5 bg-background border border-border text-xs font-mono"
                >
                  <span className="text-accent">{port.port}</span>
                  <span className="text-secondary ml-2">{port.service || '?'}</span>
                </div>
              ))}
            </div>
            {data.vulnerabilities?.length > 0 && (
              <div className="mt-3">
                <div className="text-xs font-medium mb-1 uppercase">Vulnerabilities</div>
                {data.vulnerabilities.map((v, i) => (
                  <div key={i} className="p-1.5 bg-red-500/10 border border-red-500/30 text-xs">
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
            <div className="text-xs text-secondary uppercase">
              {data.count || 0} subdomains
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-1 max-h-48 overflow-y-auto">
              {data.subdomains?.map((sub, i) => (
                <div
                  key={i}
                  className="p-1.5 bg-background border border-border text-xs font-mono flex justify-between"
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
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-2">
              <div className="p-2 bg-background border border-border">
                <div className="text-xs text-secondary uppercase">Vulns</div>
                <div className="text-xl font-mono text-critical">
                  {data.summary?.vulnerabilities_count || 0}
                </div>
              </div>
              <div className="p-2 bg-background border border-border">
                <div className="text-xs text-secondary uppercase">Misconfig</div>
                <div className="text-xl font-mono text-medium">
                  {data.summary?.misconfigurations_count || 0}
                </div>
              </div>
            </div>
            {data.vulnerabilities?.length > 0 && (
              <div>
                <div className="text-xs font-medium mb-1 uppercase">Issues</div>
                <div className="space-y-1">
                  {data.vulnerabilities.map((v, i) => (
                    <div key={i} className="p-1.5 bg-red-500/10 border border-red-500/30 text-xs">
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
            <div className="text-xs text-secondary uppercase">
              {data.count || 0} paths
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-1 max-h-48 overflow-y-auto">
              {data.directories?.map((dir, i) => (
                <div
                  key={i}
                  className="p-1.5 bg-background border border-border text-xs font-mono flex justify-between"
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
          <pre className="p-2 bg-background border border-border text-xs overflow-auto max-h-48 font-mono">
            {JSON.stringify(data, null, 2)}
          </pre>
        );
    }
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-4 h-10 border-b border-border bg-surface">
        <h1 className="text-xs font-medium tracking-wider uppercase">RECON</h1>
      </header>

      <div className="flex-1 overflow-y-auto p-4 bg-background">
        <div className="max-w-4xl mx-auto space-y-4">
          {/* Target Input */}
          <div className="p-3 border border-border bg-surface">
            <label className="block text-xs font-medium mb-2 uppercase tracking-wider">TARGET</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="example.com or https://example.com"
                className="flex-1 px-3 py-2 border border-border bg-background text-sm font-mono"
              />
              <button
                onClick={runAllSelected}
                disabled={!target || selectedScans.length === 0}
                className="btn btn-primary disabled:opacity-50 text-xs"
              >
                <Play className="w-3 h-3 mr-1" />
                RUN
              </button>
            </div>
          </div>

          {/* Scan Types */}
          <div className="space-y-2">
            {SCAN_TYPES.map((scanType) => {
              const Icon = scanType.icon;
              const isSelected = selectedScans.includes(scanType.id);
              const isRunning = running[scanType.id];
              const result = results[scanType.id];
              const isExpanded = expanded[scanType.id];

              return (
                <div key={scanType.id} className="border border-border bg-surface">
                  <div className="flex items-center justify-between p-3">
                    <div className="flex items-center gap-3">
                      <button
                        onClick={() => toggleScan(scanType.id)}
                        className={clsx(
                          'w-4 h-4 border flex items-center justify-center transition-colors',
                          isSelected
                            ? 'bg-accent border-accent'
                            : 'border-border hover:border-accent'
                        )}
                      >
                        {isSelected && <CheckCircle className="w-2.5 h-2.5 text-background" />}
                      </button>

                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 text-accent" />
                        <div>
                          <div className="text-sm font-medium uppercase">{scanType.name}</div>
                          <div className="text-xs text-secondary">{scanType.description}</div>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      {result && (
                        <button
                          onClick={() => toggleExpand(scanType.id)}
                          className="p-1 hover:bg-hover"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-4 h-4" />
                          ) : (
                            <ChevronRight className="w-4 h-4" />
                          )}
                        </button>
                      )}

                      <button
                        onClick={() => runScan(scanType)}
                        disabled={!target || isRunning}
                        className="btn btn-secondary disabled:opacity-50 p-1.5"
                      >
                        {isRunning ? (
                          <Loader className="w-3 h-3 animate-spin" />
                        ) : result?.success ? (
                          <CheckCircle className="w-3 h-3 text-green-400" />
                        ) : result && !result.success ? (
                          <XCircle className="w-3 h-3 text-red-400" />
                        ) : (
                          <Play className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </div>

                  {/* Results */}
                  {isExpanded && result && (
                    <div className="px-3 pb-3 border-t border-border pt-3">
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
