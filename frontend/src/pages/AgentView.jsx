import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Play,
  Square,
  Loader,
  CheckCircle,
  XCircle,
  ChevronDown,
  ChevronRight,
  Zap,
  Brain,
  Wrench,
  AlertTriangle,
  Cpu,
  RefreshCw
} from 'lucide-react';
import clsx from 'clsx';
import { useActiveScans } from '../contexts/ActiveScansContext';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

export default function AgentView() {
  const { moduleStates, updateModuleState, addEvent: addGlobalEvent } = useActiveScans();
  const savedState = moduleStates.agent || {};

  // Restore state from context
  const [target, setTarget] = useState(savedState.target || '');
  const [request, setRequest] = useState(savedState.request || '');
  const [isRunning, setIsRunning] = useState(savedState.running || false);
  const [events, setEvents] = useState(savedState.events || []);
  const [decisionEngine, setDecisionEngine] = useState(savedState.decisionEngine || null);
  const [loadingEngine, setLoadingEngine] = useState(false);
  const [expandedSections, setExpandedSections] = useState(savedState.expandedSections || {
    decisionEngine: false,
    reasoning: true,
    tools: true,
    findings: true
  });

  const wsRef = useRef(null);
  const eventsEndRef = useRef(null);

  // Persist state changes to context
  useEffect(() => {
    updateModuleState('agent', {
      target,
      request,
      running: isRunning,
      events,
      decisionEngine,
      expandedSections
    });
  }, [target, request, isRunning, events, decisionEngine, expandedSections]);

  useEffect(() => {
    eventsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const loadDecisionEngine = useCallback(async () => {
    setLoadingEngine(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/agent/decision-engine`);
      if (res.ok) {
        const data = await res.json();
        setDecisionEngine(data);
      }
    } catch (err) {
      console.error('Failed to load DecisionEngine:', err);
    } finally {
      setLoadingEngine(false);
    }
  }, []);

  useEffect(() => {
    if (!decisionEngine) {
      loadDecisionEngine();
    }
  }, [loadDecisionEngine, decisionEngine]);

  const startAgent = () => {
    if (!target || !request) return;

    setIsRunning(true);
    setEvents([]);
    addGlobalEvent('agent', 'start', `Starting OpenClaw agent on ${target}`, 'info');

    // Connect via WebSocket
    const wsUrl = `${API_URL.replace('http', 'ws')}/api/v1/agent/ws/${encodeURIComponent(target)}`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      ws.send(JSON.stringify({ request, context: {} }));
      addGlobalEvent('agent', 'connected', 'WebSocket connected', 'info');
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      setEvents(prev => [...prev, data]);

      // Log findings to global events
      if (data.type === 'finding') {
        addGlobalEvent('agent', 'finding', `Found: ${data.data?.title || data.data?.type}`, 'warning', data.data);
      }

      if (data.type === 'status' && data.data?.phase === 'completed') {
        setIsRunning(false);
        addGlobalEvent('agent', 'complete', 'Agent scan completed', 'success');
      }
    };

    ws.onerror = () => {
      setIsRunning(false);
      setEvents(prev => [...prev, {
        type: 'error',
        data: { message: 'Connection failed' },
        timestamp: new Date().toISOString()
      }]);
      addGlobalEvent('agent', 'error', 'WebSocket connection failed', 'error');
    };

    ws.onclose = () => {
      setIsRunning(false);
    };
  };

  const stopAgent = () => {
    if (wsRef.current) {
      wsRef.current.close();
    }
    setIsRunning(false);
    addGlobalEvent('agent', 'stop', 'Agent stopped by user', 'warning');
  };

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const reasoning = events.filter(e => e.type === 'reasoning');
  const toolCalls = events.filter(e => e.type === 'tool_start' || e.type === 'tool_complete');
  const findings = events.filter(e => e.type === 'finding');

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-4 h-10 border-b border-border bg-surface">
        <div className="flex items-center gap-3">
          <h1 className="text-xs font-medium tracking-wider uppercase">OPENCLAW</h1>
          {events.length > 0 && !isRunning && (
            <span className="text-xs px-2 py-0.5 border border-accent text-accent">
              {findings.length} findings
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {isRunning && (
            <span className="flex items-center gap-2 text-xs text-accent">
              <span className="w-1.5 h-1.5 bg-accent animate-pulse" />
              RUNNING
            </span>
          )}
        </div>
      </header>

      <div className="flex-1 flex overflow-hidden">
        {/* Input Panel */}
        <div className="w-96 border-r border-border p-4 flex flex-col gap-4 bg-background">
          <div>
            <label className="block text-xs font-medium mb-1.5 uppercase tracking-wider">TARGET URL</label>
            <input
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="w-full px-3 py-2 border border-border bg-surface text-sm font-mono"
              disabled={isRunning}
            />
          </div>

          <div className="flex-1 flex flex-col">
            <label className="block text-xs font-medium mb-1.5 uppercase tracking-wider">REQUEST</label>
            <textarea
              value={request}
              onChange={(e) => setRequest(e.target.value)}
              placeholder="Find all SQL injection vulnerabilities and attempt to chain them for RCE..."
              className="flex-1 px-3 py-2 border border-border bg-surface resize-none text-sm"
              disabled={isRunning}
            />
          </div>

          <div className="flex gap-2">
            {!isRunning ? (
              <button
                onClick={startAgent}
                disabled={!target || !request}
                className="flex-1 btn btn-primary disabled:opacity-50"
              >
                <Play className="w-4 h-4 mr-2" />
                Execute
              </button>
            ) : (
              <button
                onClick={stopAgent}
                className="flex-1 btn bg-red-500 text-white hover:bg-red-600"
              >
                <Square className="w-4 h-4 mr-2" />
                Stop
              </button>
            )}
          </div>

          {/* Summary */}
          <div className="grid grid-cols-3 gap-2 pt-4 border-t border-border">
            <div className="text-center p-2 bg-surface border border-border">
              <div className="text-xl font-mono">{reasoning.length}</div>
              <div className="text-xs text-secondary uppercase">Steps</div>
            </div>
            <div className="text-center p-2 bg-surface border border-border">
              <div className="text-xl font-mono">{toolCalls.filter(t => t.type === 'tool_complete').length}</div>
              <div className="text-xs text-secondary uppercase">Tools</div>
            </div>
            <div className="text-center p-2 bg-surface border border-border">
              <div className="text-xl font-mono text-critical">{findings.length}</div>
              <div className="text-xs text-secondary uppercase">Findings</div>
            </div>
          </div>
        </div>

        {/* Events Panel */}
        <div className="flex-1 overflow-y-auto p-4 bg-surface">
          {events.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-secondary">
              <Bot className="w-10 h-10 mb-4 opacity-50" />
              <p className="text-sm uppercase tracking-wider">Enter target and request to start</p>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Decision Engine Section */}
              <section className="card border border-border">
                <button
                  onClick={() => toggleSection('decisionEngine')}
                  className="flex items-center justify-between w-full p-3"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-accent font-mono">[ENG]</span>
                    <span className="text-sm font-medium uppercase">Decision Engine</span>
                    {decisionEngine && (
                      <span className="text-xs text-secondary">
                        {decisionEngine.total_tests} tests
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => { e.stopPropagation(); loadDecisionEngine(); }}
                      className="p-1 hover:bg-hover"
                      title="Refresh"
                    >
                      <RefreshCw className={clsx('w-3 h-3 text-secondary', loadingEngine && 'animate-spin')} />
                    </button>
                    {expandedSections.decisionEngine ? (
                      <ChevronDown className="w-4 h-4 text-secondary" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-secondary" />
                    )}
                  </div>
                </button>
                {expandedSections.decisionEngine && decisionEngine && (
                  <div className="px-3 pb-3">
                    <div className="grid grid-cols-2 gap-2">
                      {Object.entries(decisionEngine.categories).map(([category, tests]) => (
                        tests.length > 0 && (
                          <div key={category} className="p-2 bg-background border border-border">
                            <h4 className="text-xs font-medium text-secondary uppercase mb-2">
                              {category.replace('_', ' ')}
                            </h4>
                            <div className="space-y-1">
                              {tests.map((test, i) => (
                                <div key={i} className="flex items-center gap-2 text-xs">
                                  <span className="w-1 h-1 bg-accent" />
                                  <span className="font-mono">{test.name}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )
                      ))}
                    </div>
                    <div className="mt-2 pt-2 border-t border-border">
                      <h4 className="text-xs font-medium text-secondary uppercase mb-2">Available Tests</h4>
                      <div className="flex flex-wrap gap-1">
                        {decisionEngine.available_tests.map((test, i) => (
                          <span
                            key={i}
                            className="px-1.5 py-0.5 text-xs font-mono bg-surface border border-border"
                            title={test.description}
                          >
                            {test.name}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </section>

              {/* Reasoning Section */}
              <section className="card border border-border">
                <button
                  onClick={() => toggleSection('reasoning')}
                  className="flex items-center justify-between w-full p-3"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-accent font-mono">[RSN]</span>
                    <span className="text-sm font-medium uppercase">Reasoning</span>
                    <span className="text-xs text-secondary">{reasoning.length}</span>
                  </div>
                  {expandedSections.reasoning ? (
                    <ChevronDown className="w-4 h-4 text-secondary" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-secondary" />
                  )}
                </button>
                {expandedSections.reasoning && (
                  <div className="px-3 pb-3 space-y-2">
                    {reasoning.map((event, i) => (
                      <div key={i} className="p-2 bg-background border border-border">
                        <div className="flex items-center gap-2 mb-1">
                          <span className={clsx(
                            'text-xs font-mono uppercase px-1.5 py-0.5 border',
                            event.data?.step === 'thought' && 'border-blue-500/50 text-blue-400',
                            event.data?.step === 'plan' && 'border-purple-500/50 text-purple-400',
                            event.data?.step === 'observation' && 'border-green-500/50 text-green-400',
                            event.data?.step === 'decision' && 'border-orange-500/50 text-orange-400'
                          )}>
                            {event.data?.step}
                          </span>
                        </div>
                        <p className="text-xs">{event.data?.content}</p>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {/* Tools Section */}
              <section className="card border border-border">
                <button
                  onClick={() => toggleSection('tools')}
                  className="flex items-center justify-between w-full p-3"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-accent font-mono">[TLS]</span>
                    <span className="text-sm font-medium uppercase">Tools</span>
                    <span className="text-xs text-secondary">
                      {toolCalls.filter(t => t.type === 'tool_complete').length}
                    </span>
                  </div>
                  {expandedSections.tools ? (
                    <ChevronDown className="w-4 h-4 text-secondary" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-secondary" />
                  )}
                </button>
                {expandedSections.tools && (
                  <div className="px-3 pb-3 space-y-2">
                    {toolCalls.map((event, i) => {
                      const isStart = event.type === 'tool_start';
                      const isComplete = event.type === 'tool_complete';

                      return (
                        <div
                          key={i}
                          className={clsx(
                            'flex items-center gap-3 p-2 border',
                            isStart && 'bg-yellow-500/5 border-yellow-500/30',
                            isComplete && event.data?.success && 'bg-green-500/5 border-green-500/30',
                            isComplete && !event.data?.success && 'bg-red-500/5 border-red-500/30'
                          )}
                        >
                          {isStart && <Loader className="w-3 h-3 animate-spin text-yellow-400" />}
                          {isComplete && event.data?.success && <CheckCircle className="w-3 h-3 text-green-400" />}
                          {isComplete && !event.data?.success && <XCircle className="w-3 h-3 text-red-400" />}

                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-xs">{event.data?.tool}</span>
                              {event.data?.duration_ms && (
                                <span className="text-xs text-secondary">
                                  {(event.data.duration_ms / 1000).toFixed(2)}s
                                </span>
                              )}
                            </div>
                            {event.data?.description && (
                              <p className="text-xs text-secondary truncate">{event.data.description}</p>
                            )}
                            {event.data?.summary && (
                              <p className="text-xs text-secondary">{event.data.summary}</p>
                            )}
                            {event.data?.error && (
                              <p className="text-xs text-red-400">{event.data.error}</p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </section>

              {/* Findings Section */}
              {findings.length > 0 && (
                <section className="card border border-border">
                  <button
                    onClick={() => toggleSection('findings')}
                    className="flex items-center justify-between w-full p-3"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-critical font-mono">[FND]</span>
                      <span className="text-sm font-medium uppercase">Findings</span>
                      <span className="text-xs text-secondary">{findings.length}</span>
                    </div>
                    {expandedSections.findings ? (
                      <ChevronDown className="w-4 h-4 text-secondary" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-secondary" />
                    )}
                  </button>
                  {expandedSections.findings && (
                    <div className="px-3 pb-3 space-y-2">
                      {findings.map((event, i) => (
                        <div
                          key={i}
                          className={clsx(
                            'p-2 border',
                            `severity-${event.data?.severity || 'medium'}`
                          )}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-sm font-medium">{event.data?.title || event.data?.type}</span>
                            <span className={clsx(
                              'text-xs font-mono px-1.5 py-0.5 border uppercase',
                              `severity-${event.data?.severity || 'medium'}`
                            )}>
                              {event.data?.severity}
                            </span>
                          </div>
                          {event.data?.url && (
                            <p className="text-xs text-secondary font-mono truncate">{event.data.url}</p>
                          )}
                          {event.data?.evidence && (
                            <p className="text-xs mt-1">{event.data.evidence}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              )}

              <div ref={eventsEndRef} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function Bot(props) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" {...props}>
      <path d="M12 8V4H8"/>
      <rect width="16" height="12" x="4" y="8" rx="2"/>
      <path d="M2 14h2"/>
      <path d="M20 14h2"/>
      <path d="M15 13v2"/>
      <path d="M9 13v2"/>
    </svg>
  );
}
