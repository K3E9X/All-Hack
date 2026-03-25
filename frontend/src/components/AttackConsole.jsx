import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001/api/v1'

function AttackConsole() {
  const [target, setTarget] = useState('')
  const [maxPages, setMaxPages] = useState(50)
  const [running, setRunning] = useState(false)
  const [scanId, setScanId] = useState(null)
  const [status, setStatus] = useState(null)
  const [results, setResults] = useState(null)
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const consoleRef = useRef(null)
  const pollRef = useRef(null)

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [events])

  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
      }
    }
  }, [])

  const addEvent = (phase, message, type = 'info') => {
    const event = {
      id: Date.now(),
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      phase,
      message,
      type
    }
    setEvents(prev => [...prev.slice(-200), event])
  }

  const startAttack = async () => {
    if (!target) {
      setError('Enter a target URL')
      return
    }

    setError(null)
    setRunning(true)
    setResults(null)
    setEvents([])
    addEvent('init', `Starting attack on ${target}`)

    try {
      // Start async scan
      const response = await axios.post(`${API_URL}/attack/async`, null, {
        params: { target_url: target, max_pages: maxPages }
      })

      const id = response.data.scan_id
      setScanId(id)
      addEvent('init', `Scan ID: ${id}`)

      // Poll for status
      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await axios.get(`${API_URL}/attack/${id}/status`)
          const data = statusRes.data

          setStatus(data)

          // Add new events
          if (data.events && Array.isArray(data.events)) {
            data.events.forEach(e => {
              setEvents(prev => {
                if (!prev.find(x => x.id === e.id)) {
                  return [...prev.slice(-200), {
                    id: e.id,
                    time: new Date(e.timestamp).toLocaleTimeString('en-US', { hour12: false }),
                    phase: e.phase,
                    message: e.message,
                    type: e.message.includes('FOUND') ? 'vuln' : 'info'
                  }]
                }
                return prev
              })
            })
          }

          // Check completion
          if (data.phase === 'complete' || data.phase === 'failed') {
            clearInterval(pollRef.current)
            pollRef.current = null

            // Get full results
            const resultsRes = await axios.get(`${API_URL}/attack/${id}`)
            setResults(resultsRes.data)
            setRunning(false)
            addEvent('complete', `Scan finished. ${resultsRes.data.findings_count} vulnerabilities found.`,
              resultsRes.data.findings_count > 0 ? 'vuln' : 'info')
          }
        } catch (err) {
          console.error('Poll error:', err)
        }
      }, 1500)

    } catch (err) {
      console.error('Attack error:', err)
      setError(err.response?.data?.detail || err.message)
      setRunning(false)
      addEvent('error', err.message, 'error')
    }
  }

  const stopAttack = async () => {
    if (!scanId) return

    try {
      await axios.post(`${API_URL}/attack/${scanId}/stop`)
      addEvent('stop', 'Stop requested')

      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }

      // Get partial results
      setTimeout(async () => {
        try {
          const resultsRes = await axios.get(`${API_URL}/attack/${scanId}`)
          setResults(resultsRes.data)
        } catch (e) {}
        setRunning(false)
      }, 2000)
    } catch (err) {
      setError(err.message)
    }
  }

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-400',
      high: 'text-orange-400',
      medium: 'text-yellow-400',
      low: 'text-blue-400',
      info: 'text-gray-400'
    }
    return colors[severity] || 'text-gray-400'
  }

  const getEventColor = (type) => {
    if (type === 'vuln') return 'text-red-400'
    if (type === 'error') return 'text-red-500'
    return 'text-gray-300'
  }

  return (
    <div className="min-h-screen bg-neutral-950 text-gray-100 p-6">
      {/* Header */}
      <header className="mb-8">
        <h1 className="text-3xl font-light tracking-wide text-white">all-hack</h1>
        <p className="text-sm text-gray-500 mt-1">automated security assessment</p>
      </header>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Panel - Controls */}
        <div className="lg:col-span-1 space-y-6">
          {/* Target Input */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
            <label className="block text-xs uppercase tracking-wider text-gray-500 mb-3">
              Target
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com"
              disabled={running}
              className="w-full bg-neutral-950 border border-neutral-700 rounded px-4 py-3 text-sm font-mono focus:outline-none focus:border-gray-500 disabled:opacity-50"
            />

            <label className="block text-xs uppercase tracking-wider text-gray-500 mt-4 mb-2">
              Max Pages
            </label>
            <input
              type="number"
              value={maxPages}
              onChange={(e) => setMaxPages(parseInt(e.target.value) || 50)}
              min={10}
              max={200}
              disabled={running}
              className="w-full bg-neutral-950 border border-neutral-700 rounded px-4 py-2 text-sm font-mono focus:outline-none focus:border-gray-500 disabled:opacity-50"
            />

            {error && (
              <p className="text-red-400 text-xs mt-3">{error}</p>
            )}

            <div className="flex gap-3 mt-5">
              <button
                onClick={startAttack}
                disabled={running || !target}
                className="flex-1 bg-white text-black font-medium py-3 rounded text-sm hover:bg-gray-200 transition disabled:opacity-30 disabled:cursor-not-allowed"
              >
                {running ? 'Running...' : 'Start Attack'}
              </button>
              {running && (
                <button
                  onClick={stopAttack}
                  className="px-5 py-3 border border-red-500 text-red-400 rounded text-sm hover:bg-red-500/10 transition"
                >
                  Stop
                </button>
              )}
            </div>
          </div>

          {/* Status */}
          {status && (
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-4">Status</h3>

              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Phase</span>
                  <span className="font-mono">{status.phase}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Progress</span>
                  <span className="font-mono">{status.progress}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Findings</span>
                  <span className={`font-mono ${status.findings_count > 0 ? 'text-red-400' : ''}`}>
                    {status.findings_count}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Requests</span>
                  <span className="font-mono">{status.requests}</span>
                </div>
              </div>

              {/* Progress bar */}
              <div className="mt-4 h-1 bg-neutral-800 rounded overflow-hidden">
                <div
                  className="h-full bg-gray-400 transition-all duration-300"
                  style={{ width: `${status.progress}%` }}
                />
              </div>
            </div>
          )}

          {/* Results Summary */}
          {results && (
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-5">
              <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-4">Results</h3>

              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Endpoints</span>
                  <span className="font-mono">{results.endpoints_discovered}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Technologies</span>
                  <span className="font-mono text-right text-xs">
                    {results.technologies?.join(', ') || 'None'}
                  </span>
                </div>
              </div>

              {results.severity_summary && (
                <div className="mt-4 pt-4 border-t border-neutral-800">
                  <div className="grid grid-cols-5 gap-2 text-center text-xs">
                    <div>
                      <div className="text-red-400 font-mono text-lg">{results.severity_summary.critical}</div>
                      <div className="text-gray-600">crit</div>
                    </div>
                    <div>
                      <div className="text-orange-400 font-mono text-lg">{results.severity_summary.high}</div>
                      <div className="text-gray-600">high</div>
                    </div>
                    <div>
                      <div className="text-yellow-400 font-mono text-lg">{results.severity_summary.medium}</div>
                      <div className="text-gray-600">med</div>
                    </div>
                    <div>
                      <div className="text-blue-400 font-mono text-lg">{results.severity_summary.low}</div>
                      <div className="text-gray-600">low</div>
                    </div>
                    <div>
                      <div className="text-gray-400 font-mono text-lg">{results.severity_summary.info}</div>
                      <div className="text-gray-600">info</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Panel - Console & Findings */}
        <div className="lg:col-span-2 space-y-6">
          {/* Console Output */}
          <div className="bg-neutral-900 border border-neutral-800 rounded-lg">
            <div className="px-4 py-3 border-b border-neutral-800 flex items-center justify-between">
              <span className="text-xs uppercase tracking-wider text-gray-500">Console</span>
              {running && (
                <span className="flex items-center gap-2 text-xs text-gray-500">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  live
                </span>
              )}
            </div>
            <div
              ref={consoleRef}
              className="h-80 overflow-y-auto p-4 font-mono text-xs space-y-1"
            >
              {events.length === 0 ? (
                <div className="text-gray-600 text-center py-8">
                  Waiting for scan...
                </div>
              ) : (
                events.map(event => (
                  <div key={event.id} className="flex gap-3">
                    <span className="text-gray-600 flex-shrink-0">{event.time}</span>
                    <span className="text-gray-500 flex-shrink-0 w-24 truncate">[{event.phase}]</span>
                    <span className={getEventColor(event.type)}>{event.message}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Findings */}
          {results && results.findings && results.findings.length > 0 && (
            <div className="bg-neutral-900 border border-neutral-800 rounded-lg">
              <div className="px-4 py-3 border-b border-neutral-800">
                <span className="text-xs uppercase tracking-wider text-gray-500">
                  Findings ({results.findings.length})
                </span>
              </div>
              <div className="divide-y divide-neutral-800 max-h-96 overflow-y-auto">
                {results.findings.map((finding, idx) => (
                  <div key={finding.id || idx} className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3">
                          <span className={`text-xs uppercase font-medium ${getSeverityColor(finding.severity)}`}>
                            {finding.severity}
                          </span>
                          <span className="text-sm font-medium text-white">{finding.vuln_type}</span>
                        </div>
                        <p className="text-xs text-gray-500 mt-1 truncate font-mono">{finding.url}</p>
                        {finding.parameter && (
                          <p className="text-xs text-gray-600 mt-1">param: {finding.parameter}</p>
                        )}
                      </div>
                    </div>

                    <div className="mt-3">
                      <p className="text-xs text-gray-400">{finding.evidence}</p>
                    </div>

                    {finding.poc && (
                      <details className="mt-3">
                        <summary className="text-xs text-gray-500 cursor-pointer hover:text-gray-400">
                          View PoC
                        </summary>
                        <pre className="mt-2 text-xs bg-neutral-950 p-3 rounded overflow-x-auto text-gray-400">
                          {finding.poc}
                        </pre>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AttackConsole
