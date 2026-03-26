import { useState } from 'react'

function LogsPanel({ results, status }) {
  const [activeSection, setActiveSection] = useState('logs')
  const [expandedItems, setExpandedItems] = useState({})

  const toggleExpand = (key) => {
    setExpandedItems(prev => ({ ...prev, [key]: !prev[key] }))
  }

  const sections = [
    { id: 'logs', label: 'Detailed Logs' },
    { id: 'modules', label: 'Modules' },
    { id: 'enrichments', label: 'Enrichments' },
    { id: 'llm', label: 'AI Analysis' },
    { id: 'endpoints', label: 'Endpoints' },
    { id: 'errors', label: 'Errors' }
  ]

  const getStatusColor = (status) => {
    switch (status) {
      case 'vulnerability': return 'text-red-400'
      case 'warning': return 'text-yellow-400'
      case 'error': return 'text-red-500'
      case 'interesting': return 'text-orange-400'
      default: return 'text-gray-400'
    }
  }

  const getModuleStatusBadge = (status) => {
    if (status === 'completed') return 'bg-green-500/20 text-green-400 border-green-500/30'
    if (status === 'error') return 'bg-red-500/20 text-red-400 border-red-500/30'
    return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
  }

  const renderDetailedLogs = () => {
    const logs = results?.detailed_logs || []
    if (logs.length === 0) {
      return <div className="text-gray-600 text-center py-8">No detailed logs available</div>
    }

    return (
      <div className="space-y-1">
        {logs.map((log, idx) => (
          <div
            key={idx}
            className={`flex gap-3 py-1.5 px-2 rounded text-xs font-mono hover:bg-neutral-800/50 ${
              log.status === 'vulnerability' ? 'bg-red-500/5' :
              log.status === 'warning' ? 'bg-yellow-500/5' :
              log.status === 'error' ? 'bg-red-500/10' : ''
            }`}
          >
            <span className="text-gray-600 flex-shrink-0 w-20">
              {new Date(log.timestamp).toLocaleTimeString('en-US', { hour12: false })}
            </span>
            <span className="text-blue-400 flex-shrink-0 w-24 truncate">[{log.module}]</span>
            <span className={getStatusColor(log.status)}>{log.action}</span>
            {log.data && (
              <button
                onClick={() => toggleExpand(`log-${idx}`)}
                className="text-gray-500 hover:text-gray-300 ml-auto"
              >
                {expandedItems[`log-${idx}`] ? '[-]' : '[+]'}
              </button>
            )}
          </div>
        ))}
        {logs.map((log, idx) => (
          log.data && expandedItems[`log-${idx}`] && (
            <div key={`data-${idx}`} className="ml-48 mb-2 p-2 bg-neutral-950 rounded text-xs">
              <pre className="text-gray-400 whitespace-pre-wrap overflow-x-auto">
                {JSON.stringify(log.data, null, 2)}
              </pre>
            </div>
          )
        ))}
      </div>
    )
  }

  const renderModules = () => {
    const modules = results?.module_results || {}
    const moduleOrder = ['recon', 'auth', 'api', 'websocket', 'fuzzer']

    return (
      <div className="space-y-4">
        {moduleOrder.map(moduleName => {
          const data = modules[moduleName]
          if (!data) return null

          return (
            <div key={moduleName} className="border border-neutral-800 rounded-lg overflow-hidden">
              <div
                className="px-4 py-3 bg-neutral-900 flex items-center justify-between cursor-pointer hover:bg-neutral-800"
                onClick={() => toggleExpand(`module-${moduleName}`)}
              >
                <div className="flex items-center gap-3">
                  <span className="text-white font-medium capitalize">{moduleName}</span>
                  <span className={`text-[10px] uppercase px-2 py-0.5 rounded border ${getModuleStatusBadge(data.status)}`}>
                    {data.status}
                  </span>
                </div>
                <span className="text-gray-500 text-sm">
                  {expandedItems[`module-${moduleName}`] ? '[-]' : '[+]'}
                </span>
              </div>

              {expandedItems[`module-${moduleName}`] && (
                <div className="p-4 space-y-3">
                  {/* Module-specific stats */}
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    {moduleName === 'recon' && (
                      <>
                        <div>
                          <span className="text-gray-500">Subdomains:</span>
                          <span className="text-white ml-2">{data.subdomains_found || 0}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Ports:</span>
                          <span className="text-white ml-2">{data.ports_found || 0}</span>
                        </div>
                      </>
                    )}
                    {moduleName === 'auth' && (
                      <>
                        <div>
                          <span className="text-gray-500">Tests Run:</span>
                          <span className="text-white ml-2">{data.tests_run?.length || 0}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Findings:</span>
                          <span className={`ml-2 ${data.findings_count > 0 ? 'text-red-400' : 'text-white'}`}>
                            {data.findings_count || 0}
                          </span>
                        </div>
                      </>
                    )}
                    {moduleName === 'api' && (
                      <>
                        <div>
                          <span className="text-gray-500">Endpoints:</span>
                          <span className="text-white ml-2">{data.endpoints_discovered || 0}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Tested:</span>
                          <span className="text-white ml-2">{data.endpoints_tested || 0}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Findings:</span>
                          <span className={`ml-2 ${data.findings_count > 0 ? 'text-red-400' : 'text-white'}`}>
                            {data.findings_count || 0}
                          </span>
                        </div>
                      </>
                    )}
                    {moduleName === 'websocket' && (
                      <>
                        <div>
                          <span className="text-gray-500">Paths Checked:</span>
                          <span className="text-white ml-2">{data.paths_checked?.length || 0}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Found:</span>
                          <span className="text-white ml-2">{data.endpoints_found?.length || 0}</span>
                        </div>
                      </>
                    )}
                    {moduleName === 'fuzzer' && (
                      <>
                        <div>
                          <span className="text-gray-500">Endpoints Fuzzed:</span>
                          <span className="text-white ml-2">{data.endpoints_fuzzed || 0}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Interesting:</span>
                          <span className={`ml-2 ${data.interesting_responses > 0 ? 'text-orange-400' : 'text-white'}`}>
                            {data.interesting_responses || 0}
                          </span>
                        </div>
                      </>
                    )}
                  </div>

                  {/* Module data */}
                  {data.data && (
                    <div className="mt-3">
                      <div className="text-xs text-gray-500 mb-1">Raw Data</div>
                      <pre className="text-xs text-gray-400 bg-neutral-950 rounded p-2 overflow-x-auto max-h-48">
                        {JSON.stringify(data.data, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* API endpoints list */}
                  {data.endpoints_list && data.endpoints_list.length > 0 && (
                    <div className="mt-3">
                      <div className="text-xs text-gray-500 mb-1">API Endpoints</div>
                      <div className="bg-neutral-950 rounded p-2 max-h-32 overflow-y-auto">
                        {data.endpoints_list.map((ep, i) => (
                          <div key={i} className="text-xs text-blue-400 font-mono truncate">{ep}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* WebSocket endpoints */}
                  {data.endpoints_found && data.endpoints_found.length > 0 && (
                    <div className="mt-3">
                      <div className="text-xs text-gray-500 mb-1">WebSocket Endpoints</div>
                      <div className="bg-neutral-950 rounded p-2">
                        {data.endpoints_found.map((ep, i) => (
                          <div key={i} className="text-xs text-green-400 font-mono">{ep}</div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tests run */}
                  {data.tests_run && data.tests_run.length > 0 && (
                    <div className="mt-3">
                      <div className="text-xs text-gray-500 mb-1">Tests Executed</div>
                      <div className="flex flex-wrap gap-2">
                        {data.tests_run.map((test, i) => (
                          <span key={i} className="text-xs px-2 py-1 bg-neutral-800 rounded text-gray-300">
                            {test.replace(/_/g, ' ')}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}

        {Object.keys(modules).length === 0 && (
          <div className="text-gray-600 text-center py-8">No module results available yet</div>
        )}
      </div>
    )
  }

  const renderEnrichments = () => {
    const enrichments = results?.enrichments || []

    if (enrichments.length === 0) {
      return <div className="text-gray-600 text-center py-8">No enrichment data available</div>
    }

    return (
      <div className="space-y-4">
        {enrichments.map((enrichment, idx) => (
          <div key={idx} className="border border-neutral-800 rounded-lg overflow-hidden">
            <div
              className="px-4 py-3 bg-neutral-900 flex items-center justify-between cursor-pointer hover:bg-neutral-800"
              onClick={() => toggleExpand(`enrichment-${idx}`)}
            >
              <div className="flex items-center gap-3">
                <span className="text-white font-medium capitalize">{enrichment.source}</span>
                <span className="text-xs text-gray-500">
                  {new Date(enrichment.timestamp).toLocaleString()}
                </span>
              </div>
              <span className="text-gray-500 text-sm">
                {expandedItems[`enrichment-${idx}`] ? '[-]' : '[+]'}
              </span>
            </div>

            {expandedItems[`enrichment-${idx}`] && (
              <div className="p-4">
                {/* Source-specific rendering */}
                {enrichment.source === 'shodan' && enrichment.data && (
                  <div className="space-y-2 text-sm">
                    <div><span className="text-gray-500">IP:</span> <span className="text-white">{enrichment.data.ip}</span></div>
                    <div><span className="text-gray-500">Organization:</span> <span className="text-white">{enrichment.data.org || 'N/A'}</span></div>
                    <div><span className="text-gray-500">ISP:</span> <span className="text-white">{enrichment.data.isp || 'N/A'}</span></div>
                    {enrichment.data.ports && enrichment.data.ports.length > 0 && (
                      <div>
                        <span className="text-gray-500">Ports:</span>
                        <span className="text-green-400 ml-2">{enrichment.data.ports.join(', ')}</span>
                      </div>
                    )}
                    {enrichment.data.vulns && enrichment.data.vulns.length > 0 && (
                      <div>
                        <span className="text-gray-500">CVEs:</span>
                        <div className="mt-1 flex flex-wrap gap-1">
                          {enrichment.data.vulns.map((cve, i) => (
                            <span key={i} className="text-xs px-2 py-0.5 bg-red-500/20 text-red-400 rounded">{cve}</span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {enrichment.source === 'virustotal' && enrichment.data && (
                  <div className="grid grid-cols-4 gap-4 text-center">
                    <div className="p-3 bg-neutral-950 rounded">
                      <div className="text-2xl text-red-400">{enrichment.data.malicious || 0}</div>
                      <div className="text-xs text-gray-500">Malicious</div>
                    </div>
                    <div className="p-3 bg-neutral-950 rounded">
                      <div className="text-2xl text-yellow-400">{enrichment.data.suspicious || 0}</div>
                      <div className="text-xs text-gray-500">Suspicious</div>
                    </div>
                    <div className="p-3 bg-neutral-950 rounded">
                      <div className="text-2xl text-green-400">{enrichment.data.harmless || 0}</div>
                      <div className="text-xs text-gray-500">Harmless</div>
                    </div>
                    <div className="p-3 bg-neutral-950 rounded">
                      <div className="text-2xl text-gray-400">{enrichment.data.undetected || 0}</div>
                      <div className="text-xs text-gray-500">Undetected</div>
                    </div>
                  </div>
                )}

                {enrichment.source === 'urlscan' && enrichment.data && (
                  <div className="space-y-2">
                    <div className="text-sm">
                      <span className="text-gray-500">Domain:</span>
                      <span className="text-white ml-2">{enrichment.data.domain}</span>
                    </div>
                    <div className="text-sm">
                      <span className="text-gray-500">Scans Found:</span>
                      <span className="text-white ml-2">{enrichment.data.scan_count}</span>
                    </div>
                    {enrichment.data.recent_scans && enrichment.data.recent_scans.length > 0 && (
                      <div className="mt-2">
                        <div className="text-xs text-gray-500 mb-1">Recent Scans</div>
                        <div className="bg-neutral-950 rounded p-2 space-y-1">
                          {enrichment.data.recent_scans.map((scan, i) => (
                            <div key={i} className="text-xs font-mono">
                              <span className="text-blue-400">{scan.url}</span>
                              <span className="text-gray-500 ml-2">({scan.status})</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {enrichment.source === 'hackertarget' && enrichment.data && (
                  <div className="space-y-2">
                    <div className="text-sm">
                      <span className="text-gray-500">Domain:</span>
                      <span className="text-white ml-2">{enrichment.data.domain}</span>
                    </div>
                    {enrichment.data.hosts && enrichment.data.hosts.length > 0 && (
                      <div className="mt-2">
                        <div className="text-xs text-gray-500 mb-1">Hosts/Subdomains ({enrichment.data.hosts.length})</div>
                        <div className="bg-neutral-950 rounded p-2 max-h-48 overflow-y-auto space-y-1">
                          {enrichment.data.hosts.map((host, i) => (
                            <div key={i} className="text-xs font-mono flex justify-between">
                              <span className="text-green-400">{host.host}</span>
                              <span className="text-gray-500">{host.ip}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {enrichment.source === 'abuseipdb' && enrichment.data && (
                  <div className="space-y-2 text-sm">
                    <div><span className="text-gray-500">IP:</span> <span className="text-white">{enrichment.data.ip}</span></div>
                    <div>
                      <span className="text-gray-500">Abuse Score:</span>
                      <span className={`ml-2 ${enrichment.data.abuse_score > 50 ? 'text-red-400' : enrichment.data.abuse_score > 20 ? 'text-yellow-400' : 'text-green-400'}`}>
                        {enrichment.data.abuse_score}%
                      </span>
                    </div>
                    <div><span className="text-gray-500">Country:</span> <span className="text-white">{enrichment.data.country || 'N/A'}</span></div>
                    <div><span className="text-gray-500">ISP:</span> <span className="text-white">{enrichment.data.isp || 'N/A'}</span></div>
                    <div><span className="text-gray-500">Total Reports:</span> <span className="text-white">{enrichment.data.total_reports}</span></div>
                  </div>
                )}

                {/* Fallback for other sources */}
                {!['shodan', 'virustotal', 'urlscan', 'hackertarget', 'abuseipdb'].includes(enrichment.source) && (
                  <pre className="text-xs text-gray-400 bg-neutral-950 rounded p-2 overflow-x-auto">
                    {JSON.stringify(enrichment.data, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    )
  }

  const renderLLMAnalysis = () => {
    const analyses = results?.llm_analyses || []

    if (analyses.length === 0) {
      return (
        <div className="text-gray-600 text-center py-8">
          <p>No AI analysis available</p>
          <p className="text-xs mt-2">Set GROQ_API_KEY or run Ollama for AI analysis</p>
        </div>
      )
    }

    // Separate executive summary from finding analyses
    const summary = analyses.find(a => a.type === 'executive_summary')
    const findingAnalyses = analyses.filter(a => !a.type)

    return (
      <div className="space-y-4">
        {/* Executive Summary */}
        {summary && (
          <div className="border border-blue-500/30 rounded-lg overflow-hidden">
            <div className="px-4 py-3 bg-blue-500/10">
              <span className="text-blue-400 font-medium">Executive Summary</span>
            </div>
            <div className="p-4">
              <p className="text-gray-300 text-sm leading-relaxed whitespace-pre-wrap">
                {summary.summary}
              </p>
            </div>
          </div>
        )}

        {/* Finding Analyses */}
        {findingAnalyses.length > 0 && (
          <div className="space-y-3">
            <div className="text-xs text-gray-500 uppercase tracking-wider">Finding Analyses</div>
            {findingAnalyses.map((analysis, idx) => (
              <div key={idx} className="border border-neutral-800 rounded-lg overflow-hidden">
                <div
                  className="px-4 py-3 bg-neutral-900 flex items-center justify-between cursor-pointer hover:bg-neutral-800"
                  onClick={() => toggleExpand(`llm-${idx}`)}
                >
                  <span className="text-white">{analysis.vuln_type}</span>
                  <span className="text-gray-500 text-sm">
                    {expandedItems[`llm-${idx}`] ? '[-]' : '[+]'}
                  </span>
                </div>
                {expandedItems[`llm-${idx}`] && (
                  <div className="p-4">
                    <p className="text-gray-300 text-sm leading-relaxed whitespace-pre-wrap">
                      {analysis.analysis}
                    </p>
                    <div className="mt-2 text-xs text-gray-600">
                      Finding ID: {analysis.finding_id}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  const renderEndpoints = () => {
    const endpoints = results?.endpoints_list || []
    const technologies = results?.technologies || []

    return (
      <div className="space-y-4">
        {/* Technologies */}
        {technologies.length > 0 && (
          <div>
            <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">Technologies Detected</div>
            <div className="flex flex-wrap gap-2">
              {technologies.map((tech, idx) => (
                <span key={idx} className="text-xs px-3 py-1.5 bg-neutral-800 rounded-full text-gray-300">
                  {tech}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Endpoints */}
        <div>
          <div className="text-xs text-gray-500 uppercase tracking-wider mb-2">
            Discovered Endpoints ({endpoints.length})
          </div>
          {endpoints.length > 0 ? (
            <div className="bg-neutral-950 rounded-lg p-3 max-h-96 overflow-y-auto space-y-1">
              {endpoints.map((endpoint, idx) => (
                <div key={idx} className="text-xs font-mono text-blue-400 py-0.5 hover:bg-neutral-800 px-2 rounded truncate">
                  {endpoint}
                </div>
              ))}
            </div>
          ) : (
            <div className="text-gray-600 text-center py-4">No endpoints discovered yet</div>
          )}
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4 text-center">
          <div className="p-3 bg-neutral-900 rounded-lg">
            <div className="text-2xl text-white">{results?.endpoints_discovered || 0}</div>
            <div className="text-xs text-gray-500">Total Endpoints</div>
          </div>
          <div className="p-3 bg-neutral-900 rounded-lg">
            <div className="text-2xl text-white">{results?.total_requests || 0}</div>
            <div className="text-xs text-gray-500">Requests Made</div>
          </div>
          <div className="p-3 bg-neutral-900 rounded-lg">
            <div className="text-2xl text-white">{technologies.length}</div>
            <div className="text-xs text-gray-500">Technologies</div>
          </div>
        </div>
      </div>
    )
  }

  const renderErrors = () => {
    const errors = results?.errors || []

    if (errors.length === 0) {
      return <div className="text-gray-600 text-center py-8">No errors recorded</div>
    }

    return (
      <div className="space-y-2">
        {errors.map((error, idx) => (
          <div key={idx} className="p-3 bg-red-500/10 border border-red-500/30 rounded text-sm">
            <span className="text-red-400">{error}</span>
          </div>
        ))}
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* Section tabs */}
      <div className="flex border-b border-neutral-800 px-2 overflow-x-auto">
        {sections.map(section => (
          <button
            key={section.id}
            onClick={() => setActiveSection(section.id)}
            className={`px-4 py-2 text-xs whitespace-nowrap transition ${
              activeSection === section.id
                ? 'text-white border-b-2 border-white'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {section.label}
            {section.id === 'enrichments' && results?.enrichments?.length > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 bg-blue-500/20 text-blue-400 rounded text-[10px]">
                {results.enrichments.length}
              </span>
            )}
            {section.id === 'llm' && results?.llm_analyses?.length > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded text-[10px]">
                {results.llm_analyses.length}
              </span>
            )}
            {section.id === 'errors' && results?.errors?.length > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 bg-red-500/20 text-red-400 rounded text-[10px]">
                {results.errors.length}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeSection === 'logs' && renderDetailedLogs()}
        {activeSection === 'modules' && renderModules()}
        {activeSection === 'enrichments' && renderEnrichments()}
        {activeSection === 'llm' && renderLLMAnalysis()}
        {activeSection === 'endpoints' && renderEndpoints()}
        {activeSection === 'errors' && renderErrors()}
      </div>
    </div>
  )
}

export default LogsPanel
