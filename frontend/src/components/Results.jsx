import { useState } from 'react'

function Results({ results }) {
  const [activeTab, setActiveTab] = useState('summary')
  const [selectedVuln, setSelectedVuln] = useState(null)

  if (!results) return null

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
        </div>
      </div>

      {activeTab === 'summary' && renderSummary()}
      {activeTab === 'vulnerabilities' && renderVulnerabilities()}
      {activeTab === 'misconfigurations' && renderMisconfigurations()}
    </div>
  )
}

export default Results
