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
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [copiedIndex, setCopiedIndex] = useState(null)
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

  const copyToClipboard = async (text, index) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedIndex(index)
      setTimeout(() => setCopiedIndex(null), 2000)
    } catch (err) {
      console.error('Copy failed:', err)
    }
  }

  const generateCurlCommand = (finding) => {
    const url = finding.url || ''
    const param = finding.parameter || ''
    const payload = finding.payload || ''

    if (param && payload) {
      const encodedPayload = encodeURIComponent(payload)
      return `curl -s "${url}?${param}=${encodedPayload}"`
    }
    return `curl -s "${url}"`
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
    setSelectedFinding(null)
    addEvent('init', `Starting attack on ${target}`)

    try {
      const response = await axios.post(`${API_URL}/attack/async`, null, {
        params: { target_url: target, max_pages: maxPages }
      })

      const id = response.data.scan_id
      setScanId(id)
      addEvent('init', `Scan ID: ${id}`)

      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await axios.get(`${API_URL}/attack/${id}/status`)
          const data = statusRes.data

          setStatus(data)

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

          if (data.phase === 'complete' || data.phase === 'failed') {
            clearInterval(pollRef.current)
            pollRef.current = null

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
      critical: 'text-red-400 bg-red-500/10 border-red-500/30',
      high: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
      medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
      low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
      info: 'text-gray-400 bg-gray-500/10 border-gray-500/30'
    }
    return colors[severity] || colors.info
  }

  const getSeverityBadge = (severity) => {
    const colors = {
      critical: 'bg-red-500',
      high: 'bg-orange-500',
      medium: 'bg-yellow-500',
      low: 'bg-blue-500',
      info: 'bg-gray-500'
    }
    return colors[severity] || colors.info
  }

  const getEventColor = (type) => {
    if (type === 'vuln') return 'text-red-400'
    if (type === 'error') return 'text-red-500'
    return 'text-gray-300'
  }

  return (
    <div className="min-h-screen bg-neutral-950 text-gray-100">
      {/* Header */}
      <header className="border-b border-neutral-800 px-6 py-4">
        <h1 className="text-xl font-light tracking-wide text-white">all-hack</h1>
      </header>

      <div className="flex h-[calc(100vh-57px)]">
        {/* Left Panel - Controls */}
        <div className="w-80 border-r border-neutral-800 p-4 space-y-4 overflow-y-auto">
          {/* Target Input */}
          <div>
            <label className="block text-xs uppercase tracking-wider text-gray-500 mb-2">
              Target
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://target.com"
              disabled={running}
              className="w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-neutral-500 disabled:opacity-50"
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wider text-gray-500 mb-2">
              Depth
            </label>
            <input
              type="number"
              value={maxPages}
              onChange={(e) => setMaxPages(parseInt(e.target.value) || 50)}
              min={10}
              max={200}
              disabled={running}
              className="w-full bg-neutral-900 border border-neutral-700 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-neutral-500 disabled:opacity-50"
            />
          </div>

          {error && (
            <p className="text-red-400 text-xs">{error}</p>
          )}

          <div className="flex gap-2">
            <button
              onClick={startAttack}
              disabled={running || !target}
              className="flex-1 bg-white text-black font-medium py-2.5 rounded text-sm hover:bg-gray-200 transition disabled:opacity-30 disabled:cursor-not-allowed"
            >
              {running ? 'Running...' : 'Start'}
            </button>
            {running && (
              <button
                onClick={stopAttack}
                className="px-4 py-2.5 border border-red-500/50 text-red-400 rounded text-sm hover:bg-red-500/10 transition"
              >
                Stop
              </button>
            )}
          </div>

          {/* Status */}
          {status && (
            <div className="pt-4 border-t border-neutral-800">
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span className="text-gray-500">Phase</span>
                  <span className="font-mono text-xs">{status.phase}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Progress</span>
                  <span className="font-mono">{status.progress}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">Vulns</span>
                  <span className={`font-mono ${status.findings_count > 0 ? 'text-red-400' : ''}`}>
                    {status.findings_count}
                  </span>
                </div>
              </div>
              <div className="mt-3 h-1 bg-neutral-800 rounded overflow-hidden">
                <div
                  className="h-full bg-white/50 transition-all duration-300"
                  style={{ width: `${status.progress}%` }}
                />
              </div>
            </div>
          )}

          {/* Severity Summary */}
          {results?.severity_summary && (
            <div className="pt-4 border-t border-neutral-800">
              <div className="grid grid-cols-5 gap-1 text-center text-xs">
                {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
                  <div key={sev}>
                    <div className={`font-mono text-lg ${
                      sev === 'critical' ? 'text-red-400' :
                      sev === 'high' ? 'text-orange-400' :
                      sev === 'medium' ? 'text-yellow-400' :
                      sev === 'low' ? 'text-blue-400' : 'text-gray-400'
                    }`}>
                      {results.severity_summary[sev] || 0}
                    </div>
                    <div className="text-gray-600 text-[10px]">{sev.slice(0, 4)}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Center Panel - Console */}
        <div className="flex-1 flex flex-col border-r border-neutral-800">
          <div className="px-4 py-2 border-b border-neutral-800 flex items-center justify-between">
            <span className="text-xs uppercase tracking-wider text-gray-500">Console</span>
            {running && (
              <span className="flex items-center gap-2 text-xs text-gray-500">
                <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
                live
              </span>
            )}
          </div>
          <div
            ref={consoleRef}
            className="flex-1 overflow-y-auto p-3 font-mono text-xs space-y-0.5"
          >
            {events.length === 0 ? (
              <div className="text-gray-600 text-center py-8">
                Waiting for scan...
              </div>
            ) : (
              events.map(event => (
                <div key={event.id} className={`flex gap-2 py-0.5 ${event.type === 'vuln' ? 'bg-red-500/5' : ''}`}>
                  <span className="text-gray-600 flex-shrink-0 w-16">{event.time}</span>
                  <span className="text-gray-500 flex-shrink-0 w-20 truncate">[{event.phase}]</span>
                  <span className={getEventColor(event.type)}>{event.message}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Panel - Findings Detail */}
        <div className="w-[480px] flex flex-col">
          <div className="px-4 py-2 border-b border-neutral-800">
            <span className="text-xs uppercase tracking-wider text-gray-500">
              Findings {results?.findings?.length ? `(${results.findings.length})` : ''}
            </span>
          </div>

          {results?.findings?.length > 0 ? (
            <div className="flex-1 overflow-y-auto">
              {results.findings.map((finding, idx) => (
                <div
                  key={finding.id || idx}
                  className={`border-b border-neutral-800 ${selectedFinding === idx ? 'bg-neutral-900' : ''}`}
                >
                  {/* Finding Header - Clickable */}
                  <div
                    onClick={() => setSelectedFinding(selectedFinding === idx ? null : idx)}
                    className="p-3 cursor-pointer hover:bg-neutral-900/50 transition"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`w-2 h-2 rounded-full ${getSeverityBadge(finding.severity)}`}></span>
                      <span className="text-sm font-medium text-white">{finding.vuln_type}</span>
                      <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${getSeverityColor(finding.severity)}`}>
                        {finding.severity}
                      </span>
                    </div>
                    <p className="text-xs text-gray-500 font-mono truncate">{finding.url}</p>
                    {finding.parameter && (
                      <p className="text-xs text-gray-600 mt-0.5">
                        param: <span className="text-gray-400">{finding.parameter}</span>
                      </p>
                    )}
                  </div>

                  {/* Finding Detail - Expanded */}
                  {selectedFinding === idx && (
                    <div className="px-3 pb-3 space-y-3">
                      {/* Evidence */}
                      <div>
                        <div className="text-[10px] uppercase text-gray-500 mb-1">Evidence</div>
                        <div className="text-xs text-gray-300 bg-neutral-950 rounded p-2">
                          {finding.evidence}
                        </div>
                      </div>

                      {/* Payload */}
                      {finding.payload && (
                        <div>
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Payload</div>
                          <div className="relative">
                            <pre className="text-xs text-red-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono">
                              {finding.payload}
                            </pre>
                            <button
                              onClick={() => copyToClipboard(finding.payload, `payload-${idx}`)}
                              className="absolute top-1 right-1 text-[10px] px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 rounded text-gray-400 transition"
                            >
                              {copiedIndex === `payload-${idx}` ? 'copied' : 'copy'}
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Curl Command */}
                      <div>
                        <div className="text-[10px] uppercase text-gray-500 mb-1">Reproduce</div>
                        <div className="relative">
                          <pre className="text-xs text-green-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap break-all">
                            {generateCurlCommand(finding)}
                          </pre>
                          <button
                            onClick={() => copyToClipboard(generateCurlCommand(finding), `curl-${idx}`)}
                            className="absolute top-1 right-1 text-[10px] px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 rounded text-gray-400 transition"
                          >
                            {copiedIndex === `curl-${idx}` ? 'copied' : 'copy'}
                          </button>
                        </div>
                      </div>

                      {/* Full PoC */}
                      {finding.poc && (
                        <div>
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Full PoC</div>
                          <div className="relative">
                            <pre className="text-xs text-gray-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap max-h-48">
                              {finding.poc}
                            </pre>
                            <button
                              onClick={() => copyToClipboard(finding.poc, `poc-${idx}`)}
                              className="absolute top-1 right-1 text-[10px] px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 rounded text-gray-400 transition"
                            >
                              {copiedIndex === `poc-${idx}` ? 'copied' : 'copy'}
                            </button>
                          </div>
                        </div>
                      )}

                      {/* Extracted Data */}
                      {finding.extracted_data && Object.keys(finding.extracted_data).length > 0 && (
                        <div>
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Extracted Data</div>
                          <pre className="text-xs text-yellow-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap max-h-32">
                            {JSON.stringify(finding.extracted_data, null, 2)}
                          </pre>
                        </div>
                      )}

                      {/* Exploitation Timeline */}
                      {finding.timeline && finding.timeline.length > 0 && (
                        <div>
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Exploitation Timeline</div>
                          <div className="bg-neutral-950 rounded p-2 space-y-2 max-h-64 overflow-y-auto">
                            {finding.timeline.map((step, stepIdx) => (
                              <div
                                key={stepIdx}
                                className={`text-xs border-l-2 pl-2 ${
                                  step.success ? 'border-green-500' : 'border-neutral-700'
                                }`}
                              >
                                <div className="flex items-center gap-2">
                                  <span className="text-gray-500 font-mono">#{step.step}</span>
                                  <span className={step.success ? 'text-green-400' : 'text-gray-400'}>
                                    {step.action}
                                  </span>
                                </div>
                                {step.response_status && (
                                  <div className="text-gray-600 mt-0.5">
                                    Status: <span className={
                                      step.response_status >= 200 && step.response_status < 300
                                        ? 'text-green-400'
                                        : step.response_status >= 400
                                          ? 'text-red-400'
                                          : 'text-yellow-400'
                                    }>{step.response_status}</span>
                                  </div>
                                )}
                                {step.note && (
                                  <div className="text-green-400 mt-0.5">{step.note}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* HTTP Captures */}
                      {finding.http_captures && finding.http_captures.length > 0 && (
                        <div>
                          <div className="text-[10px] uppercase text-gray-500 mb-1">HTTP Captures</div>
                          <div className="space-y-2">
                            {finding.http_captures.slice(-3).map((capture, capIdx) => (
                              <div key={capIdx} className="bg-neutral-950 rounded overflow-hidden">
                                <div
                                  className="px-2 py-1 bg-neutral-900 text-[10px] flex justify-between cursor-pointer"
                                  onClick={() => {
                                    const el = document.getElementById(`capture-${idx}-${capIdx}`)
                                    if (el) el.classList.toggle('hidden')
                                  }}
                                >
                                  <span className="text-blue-400 font-mono">
                                    {capture.request?.method} {capture.request?.url?.slice(0, 50)}...
                                  </span>
                                  <span className={
                                    capture.response?.status >= 200 && capture.response?.status < 300
                                      ? 'text-green-400'
                                      : capture.response?.status >= 400
                                        ? 'text-red-400'
                                        : 'text-yellow-400'
                                  }>
                                    {capture.response?.status} ({capture.response?.time?.toFixed(2)}s)
                                  </span>
                                </div>
                                <div id={`capture-${idx}-${capIdx}`} className="hidden p-2 text-xs font-mono space-y-2">
                                  <div>
                                    <div className="text-gray-500 text-[10px] mb-1">REQUEST</div>
                                    <div className="text-blue-400">
                                      {capture.request?.method} {capture.request?.url}
                                    </div>
                                    {capture.request?.headers && (
                                      <div className="text-gray-500 mt-1">
                                        {Object.entries(capture.request.headers).map(([k, v]) => (
                                          <div key={k}>{k}: {v}</div>
                                        ))}
                                      </div>
                                    )}
                                    {capture.request?.body && (
                                      <pre className="text-gray-400 mt-1 whitespace-pre-wrap">
                                        {capture.request.body}
                                      </pre>
                                    )}
                                  </div>
                                  <div>
                                    <div className="text-gray-500 text-[10px] mb-1">RESPONSE</div>
                                    <pre className="text-gray-400 whitespace-pre-wrap max-h-32 overflow-y-auto">
                                      {capture.response?.body?.slice(0, 500)}
                                      {capture.response?.body?.length > 500 && '...'}
                                    </pre>
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Screenshot */}
                      {finding.screenshot_path && (
                        <div>
                          <div className="text-[10px] uppercase text-gray-500 mb-1">Screenshot</div>
                          <div className="bg-neutral-950 rounded p-2">
                            <img
                              src={`${API_URL.replace('/api/v1', '')}/screenshots/${finding.screenshot_path.split('/').pop()}`}
                              alt="Vulnerability screenshot"
                              className="w-full rounded border border-neutral-700"
                              onError={(e) => {
                                e.target.style.display = 'none'
                                e.target.nextSibling.style.display = 'block'
                              }}
                            />
                            <p className="text-gray-500 text-xs hidden">Screenshot unavailable</p>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-gray-600 text-sm">
              {running ? 'Scanning...' : 'No findings yet'}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default AttackConsole
