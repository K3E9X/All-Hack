import { useState } from 'react'

function Results({ results }) {
  const [activeTab, setActiveTab] = useState('summary')
  const [selectedVuln, setSelectedVuln] = useState(null)

  if (!results) return null

  const timeline = results.timeline || []
  const dynamicEndpoints = results.dynamic_endpoints || []
  const osintFindings = results.osint_findings || []
  const apiSchemas = results.api_schemas || {}
  const attackChains = results.attack_chains || []
  const artifacts = results.artifacts || []
  const stabilityMetrics = results.stability_metrics || []

  const getSeverityBadgeClass = (severity) => {
    const classes = {
      critical: 'badge-critical',
      high: 'badge-high',
      medium: 'badge-medium',
      low: 'badge-low',
      info: 'badge-info'
    }
    return `badge ${classes[severity] || 'badge-info'}`
  }

  const renderSummary = () => (
    <div className="space-y-6">
      {/* Statistics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="text-sm text-gray-400 mb-1">Total Vulnerabilities</div>
          <div className="text-3xl font-bold text-accent-danger">
            {results.vulnerabilities.length}
          </div>
        </div>
        <div className="card">
          <div className="text-sm text-gray-400 mb-1">Misconfigurations</div>
          <div className="text-3xl font-bold text-accent-warning">
            {results.misconfigurations.length}
          </div>
        </div>
        <div className="card">
          <div className="text-sm text-gray-400 mb-1">Endpoints Found</div>
          <div className="text-3xl font-bold text-accent-secondary">
            {results.discovered_endpoints.length}
          </div>
          <div className="text-xs text-gray-500 mt-1">
            Browser routes: {dynamicEndpoints.length}
          </div>
        </div>
        <div className="card">
          <div className="text-sm text-gray-400 mb-1">Technologies</div>
          <div className="text-3xl font-bold text-accent-primary">
            {results.detected_technologies.length}
          </div>
        </div>
      </div>

      {/* Severity Breakdown */}
      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Vulnerabilities by Severity</h3>
        <div className="space-y-3">
          {Object.entries(results.vulnerabilities_by_severity || {}).map(([severity, count]) => (
            count > 0 && (
              <div key={severity} className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={getSeverityBadgeClass(severity)}>{severity.toUpperCase()}</span>
                </div>
                <span className="text-2xl font-bold text-gray-300">{count}</span>
              </div>
            )
          ))}
        </div>
      </div>

      {/* Detected Technologies */}
      {results.detected_technologies.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Detected Technologies</h3>
          <div className="flex flex-wrap gap-2">
            {results.detected_technologies.map((tech, index) => (
              <div key={index} className="px-3 py-2 bg-dark-hover border border-dark-border rounded-lg">
                <div className="font-medium text-gray-200">{tech.name}</div>
                {tech.version && (
                  <div className="text-xs text-gray-400">v{tech.version}</div>
                )}
                <div className="text-xs text-gray-500 mt-1">{tech.category}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {results.browser_crawl_summary && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-2">Browser Crawler Summary</h3>
          <p className="text-sm text-gray-400">{results.browser_crawl_summary}</p>
        </div>
      )}
    </div>
  )

  const renderVulnerabilities = () => (
    <div className="space-y-4">
      {results.vulnerabilities.length === 0 ? (
        <div className="card text-center py-12">
          <div className="text-accent-primary text-4xl mb-4">✓</div>
          <p className="text-gray-300">No vulnerabilities found!</p>
        </div>
      ) : (
        results.vulnerabilities.map((vuln, index) => (
          <div key={index} className="card hover:bg-dark-hover transition-colors cursor-pointer"
               onClick={() => setSelectedVuln(vuln)}>
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <span className={getSeverityBadgeClass(vuln.severity)}>
                    {vuln.severity.toUpperCase()}
                  </span>
                  <h4 className="text-lg font-semibold text-gray-100">{vuln.title}</h4>
                </div>
                <p className="text-gray-400 text-sm mb-3">{vuln.description}</p>
                <div className="flex flex-wrap gap-2 text-xs">
                  <span className="px-2 py-1 bg-dark-hover border border-dark-border rounded">
                    {vuln.category}
                  </span>
                  {vuln.affected_parameter && (
                    <span className="px-2 py-1 bg-dark-hover border border-dark-border rounded">
                      Parameter: {vuln.affected_parameter}
                    </span>
                  )}
                  {vuln.cwe_id && (
                    <span className="px-2 py-1 bg-dark-hover border border-dark-border rounded">
                      {vuln.cwe_id}
                    </span>
                  )}
                </div>
              </div>
              <svg className="w-5 h-5 text-gray-500 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </div>
          </div>
        ))
      )}

      {/* Vulnerability Detail Modal */}
      {selectedVuln && (
        <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50"
             onClick={() => setSelectedVuln(null)}>
          <div className="card max-w-3xl w-full max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-2xl font-bold text-gray-100">{selectedVuln.title}</h3>
              <button onClick={() => setSelectedVuln(null)} className="text-gray-400 hover:text-gray-200">
                <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <span className={getSeverityBadgeClass(selectedVuln.severity)}>
                  {selectedVuln.severity.toUpperCase()}
                </span>
              </div>

              <div>
                <h4 className="font-semibold text-gray-200 mb-2">Description</h4>
                <p className="text-gray-400">{selectedVuln.description}</p>
              </div>

              <div>
                <h4 className="font-semibold text-gray-200 mb-2">Affected URL</h4>
                <code className="block p-3 bg-dark-hover rounded text-sm text-accent-secondary break-all">
                  {selectedVuln.affected_url}
                </code>
              </div>

              {selectedVuln.proof_of_concept && (
                <div>
                  <h4 className="font-semibold text-gray-200 mb-2">Proof of Concept</h4>
                  <p className="text-gray-400 text-sm">{selectedVuln.proof_of_concept}</p>
                </div>
              )}

              {selectedVuln.payload && (
                <div>
                  <h4 className="font-semibold text-gray-200 mb-2">Payload</h4>
                  <code className="block p-3 bg-dark-hover rounded text-sm text-accent-primary break-all">
                    {selectedVuln.payload}
                  </code>
                </div>
              )}

              <div>
                <h4 className="font-semibold text-gray-200 mb-2">Remediation</h4>
                <p className="text-gray-400 text-sm">{selectedVuln.remediation}</p>
              </div>

              {selectedVuln.references && selectedVuln.references.length > 0 && (
                <div>
                  <h4 className="font-semibold text-gray-200 mb-2">References</h4>
                  <ul className="space-y-1">
                    {selectedVuln.references.map((ref, i) => (
                      <li key={i}>
                        <a href={ref} target="_blank" rel="noopener noreferrer"
                           className="text-accent-secondary hover:underline text-sm break-all">
                          {ref}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )

  const renderMisconfigurations = () => (
    <div className="space-y-4">
      {results.misconfigurations.length === 0 ? (
        <div className="card text-center py-12">
          <p className="text-gray-300">No misconfigurations found!</p>
        </div>
      ) : (
        results.misconfigurations.map((config, index) => (
          <div key={index} className="card">
            <div className="flex items-start gap-3">
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <span className={getSeverityBadgeClass(config.severity)}>
                    {config.severity.toUpperCase()}
                  </span>
                  <h4 className="text-lg font-semibold text-gray-100">{config.title}</h4>
                </div>
                <p className="text-gray-400 text-sm mb-3">{config.description}</p>
                {config.current_value && (
                  <div className="mb-2">
                    <span className="text-xs text-gray-500">Current:</span>
                    <code className="block p-2 bg-dark-hover rounded text-sm text-red-400 mt-1">
                      {config.current_value}
                    </code>
                  </div>
                )}
                {config.recommended_value && (
                  <div className="mb-2">
                    <span className="text-xs text-gray-500">Recommended:</span>
                    <code className="block p-2 bg-dark-hover rounded text-sm text-accent-primary mt-1">
                      {config.recommended_value}
                    </code>
                  </div>
                )}
                <div className="mt-3">
                  <span className="text-xs text-gray-500">Fix:</span>
                  <p className="text-gray-400 text-sm mt-1">{config.remediation}</p>
                </div>
              </div>
            </div>
          </div>
        ))
      )}
    </div>
  )

  const renderTimeline = () => (
    <div className="card">
      <h3 className="text-lg font-semibold mb-4">Execution Timeline</h3>
      {timeline.length === 0 ? (
        <p className="text-gray-400 text-sm">No timeline events recorded.</p>
      ) : (
        <div className="space-y-4">
          {timeline.map((event) => (
            <div key={event.id} className="border border-dark-border rounded-lg p-4 bg-dark-hover">
              <div className="flex justify-between text-sm text-gray-400 mb-2">
                <span>{new Date(event.timestamp).toLocaleString()}</span>
                <span className="uppercase tracking-wide text-xs text-accent-secondary">{event.phase}</span>
              </div>
              <div className="text-gray-200 font-medium">{event.message}</div>
              {event.metadata && Object.keys(event.metadata).length > 0 && (
                <pre className="mt-2 text-xs bg-dark-card border border-dark-border rounded p-3 overflow-x-auto text-gray-300">
                  {JSON.stringify(event.metadata, null, 2)}
                </pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )

  const renderRecon = () => (
    <div className="space-y-6">
      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Dynamic Endpoints</h3>
        {dynamicEndpoints.length ? (
          <div className="space-y-3">
            {dynamicEndpoints.map((endpoint, index) => (
              <div key={index} className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 p-3 bg-dark-hover border border-dark-border rounded-lg">
                <span className="text-gray-200 text-sm break-all">{endpoint.url}</span>
                <span className="text-xs text-gray-500 uppercase">{endpoint.method}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-400">No additional routes detected via the browser crawler.</p>
        )}
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">OSINT Findings</h3>
        {osintFindings.length ? (
          <ul className="space-y-3">
            {osintFindings.map((finding, index) => (
              <li key={index} className="border border-dark-border rounded-lg p-3 bg-dark-hover">
                <div className="text-accent-secondary text-sm font-semibold mb-1 uppercase">{finding.type}</div>
                <pre className="text-xs text-gray-300 whitespace-pre-wrap">
                  {JSON.stringify(finding, null, 2)}
                </pre>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-gray-400">No OSINT enrichment data captured.</p>
        )}
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">API Schemas</h3>
        {apiSchemas && Object.keys(apiSchemas).length > 0 ? (
          <div className="space-y-4">
            {Object.entries(apiSchemas).map(([path, schema]) => (
              <div key={path} className="border border-dark-border rounded-lg p-3 bg-dark-hover">
                <div className="text-sm text-accent-primary font-semibold mb-2">{path}</div>
                <pre className="text-xs text-gray-300 overflow-x-auto max-h-64">
                  {JSON.stringify(schema, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-400">No API schemas retrieved.</p>
        )}
      </div>

      {stabilityMetrics.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold mb-4">Host Stability Snapshots</h3>
          <div className="space-y-3 text-sm text-gray-300">
            {stabilityMetrics.map((snapshot, index) => (
              <div key={index} className="border border-dark-border rounded-lg p-3 bg-dark-hover">
                <div className="flex justify-between text-xs text-gray-500 mb-1">
                  <span>{snapshot.label}</span>
                  <span>{new Date(snapshot.timestamp).toLocaleString()}</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  <div>
                    <div className="text-gray-400">Load Average</div>
                    <pre>{JSON.stringify(snapshot.load_average, null, 2)}</pre>
                  </div>
                  <div>
                    <div className="text-gray-400">Memory (MB)</div>
                    <pre>{JSON.stringify(snapshot.memory, null, 2)}</pre>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )

  const renderAttackChains = () => (
    <div className="space-y-6">
      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Attack Chain Playbooks</h3>
        {attackChains.length ? (
          <div className="space-y-4">
            {attackChains.map((chain, index) => (
              <div key={index} className="border border-dark-border rounded-lg p-4 bg-dark-hover">
                <div className="flex items-center justify-between mb-3">
                  <h4 className="text-xl font-semibold text-gray-100">{chain.name}</h4>
                  <span className={getSeverityBadgeClass(chain.severity)}>{chain.severity.toUpperCase()}</span>
                </div>
                <p className="text-sm text-gray-400 mb-3">{chain.description}</p>
                {chain.steps?.length > 0 && (
                  <ol className="list-decimal list-inside text-sm text-gray-300 space-y-1">
                    {chain.steps.map((step, idx) => (
                      <li key={idx}>{step}</li>
                    ))}
                  </ol>
                )}
                {chain.impacted_assets?.length > 0 && (
                  <div className="mt-3 text-xs text-gray-500">
                    Impacted Assets: {chain.impacted_assets.join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-400">No attack chains were generated.</p>
        )}
      </div>

      <div className="card">
        <h3 className="text-lg font-semibold mb-4">Exploitation Artifacts</h3>
        {artifacts.length ? (
          <div className="space-y-4">
            {artifacts.map((artifact, index) => (
              <div key={index} className="border border-dark-border rounded-lg p-4 bg-dark-hover">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-lg font-semibold text-gray-100">{artifact.name}</h4>
                  <span className="text-xs uppercase text-accent-secondary">{artifact.type}</span>
                </div>
                <p className="text-sm text-gray-400 mb-3">{artifact.description}</p>
                <pre className="text-xs text-gray-300 bg-dark-card border border-dark-border rounded p-3 overflow-x-auto">
                  {artifact.content}
                </pre>
                {artifact.related_items?.length > 0 && (
                  <div className="mt-2 text-xs text-gray-500">
                    Related: {artifact.related_items.join(', ')}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-400">No exploitation artifacts generated.</p>
        )}
      </div>
    </div>
  )

  return (
    <div className="mt-8">
      <div className="card mb-6">
        <h2 className="text-2xl font-bold mb-4">Scan Results</h2>
        <div className="flex gap-4 border-b border-dark-border">
          <button
            onClick={() => setActiveTab('summary')}
            className={`pb-3 px-4 font-medium transition-colors ${
              activeTab === 'summary'
                ? 'text-accent-primary border-b-2 border-accent-primary'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Summary
          </button>
          <button
            onClick={() => setActiveTab('vulnerabilities')}
            className={`pb-3 px-4 font-medium transition-colors ${
              activeTab === 'vulnerabilities'
                ? 'text-accent-primary border-b-2 border-accent-primary'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Vulnerabilities ({results.vulnerabilities.length})
          </button>
          <button
            onClick={() => setActiveTab('misconfigurations')}
            className={`pb-3 px-4 font-medium transition-colors ${
              activeTab === 'misconfigurations'
                ? 'text-accent-primary border-b-2 border-accent-primary'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Misconfigurations ({results.misconfigurations.length})
          </button>
          <button
            onClick={() => setActiveTab('timeline')}
            className={`pb-3 px-4 font-medium transition-colors ${
              activeTab === 'timeline'
                ? 'text-accent-primary border-b-2 border-accent-primary'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Timeline
          </button>
          <button
            onClick={() => setActiveTab('recon')}
            className={`pb-3 px-4 font-medium transition-colors ${
              activeTab === 'recon'
                ? 'text-accent-primary border-b-2 border-accent-primary'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Recon Intelligence
          </button>
          <button
            onClick={() => setActiveTab('chains')}
            className={`pb-3 px-4 font-medium transition-colors ${
              activeTab === 'chains'
                ? 'text-accent-primary border-b-2 border-accent-primary'
                : 'text-gray-400 hover:text-gray-300'
            }`}
          >
            Attack Chains
          </button>
        </div>
      </div>

      {activeTab === 'summary' && renderSummary()}
      {activeTab === 'vulnerabilities' && renderVulnerabilities()}
      {activeTab === 'misconfigurations' && renderMisconfigurations()}
      {activeTab === 'timeline' && renderTimeline()}
      {activeTab === 'recon' && renderRecon()}
      {activeTab === 'chains' && renderAttackChains()}
    </div>
  )
}

export default Results
