import { useState, useEffect, useRef, useCallback } from 'react'
import axios from 'axios'
import LogsPanel from './LogsPanel'
import ResizablePanels from './ResizablePanels'
import { useScan } from '../contexts/ScanContext'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001/api/v1'

function AttackConsole() {
  const { globalTarget, setGlobalTarget, updateResults, updateStatus, events, addEvent, clearEvents } = useScan()

  const [target, setTarget] = useState(globalTarget || '')
  const [maxPages, setMaxPages] = useState(50)
  const [running, setRunning] = useState(false)
  const [scanId, setScanId] = useState(null)
  const [status, setStatus] = useState(null)
  const [results, setResults] = useState(null)
  const [localEvents, setLocalEvents] = useState([])
  const [error, setError] = useState(null)
  const [selectedFinding, setSelectedFinding] = useState(null)
  const [copiedIndex, setCopiedIndex] = useState(null)
  const [rightPanelTab, setRightPanelTab] = useState('findings')

  // Panel widths
  const [leftWidth, setLeftWidth] = useState(280)
  const [rightWidth, setRightWidth] = useState(480)

  const consoleRef = useRef(null)
  const pollRef = useRef(null)
  const containerRef = useRef(null)

  // Sync with global target
  useEffect(() => {
    if (globalTarget && globalTarget !== target) {
      setTarget(globalTarget)
    }
  }, [globalTarget])

  // Scroll console to bottom
  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
    }
  }, [localEvents])

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current)
      }
    }
  }, [])

  const localAddEvent = (phase, message, type = 'info') => {
    const event = {
      id: Date.now(),
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      phase,
      message,
      type
    }
    setLocalEvents(prev => [...prev.slice(-200), event])
    addEvent(phase, message, type)
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

    // Update global target
    setGlobalTarget(target)

    setError(null)
    setRunning(true)
    setResults(null)
    setLocalEvents([])
    setSelectedFinding(null)
    updateStatus('attack', { running: true, progress: 0, phase: 'init' })
    localAddEvent('init', `Starting attack on ${target}`)

    try {
      const response = await axios.post(`${API_URL}/attack/async`, null, {
        params: { target_url: target, max_pages: maxPages }
      })

      const id = response.data.scan_id
      setScanId(id)
      localAddEvent('init', `Scan ID: ${id}`)

      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await axios.get(`${API_URL}/attack/${id}/status`)
          const data = statusRes.data

          setStatus(data)
          updateStatus('attack', { running: true, progress: data.progress, phase: data.phase })

          if (data.events && Array.isArray(data.events)) {
            data.events.forEach(e => {
              setLocalEvents(prev => {
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
            updateResults('attack', resultsRes.data)
            setRunning(false)
            updateStatus('attack', { running: false, progress: 100, phase: 'complete' })
            localAddEvent('complete', `Scan finished. ${resultsRes.data.findings_count} vulnerabilities found.`,
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
      updateStatus('attack', { running: false, progress: 0, phase: 'error' })
      localAddEvent('error', err.message, 'error')
    }
  }

  const stopAttack = async () => {
    if (!scanId) return

    try {
      await axios.post(`${API_URL}/attack/${scanId}/stop`)
      localAddEvent('stop', 'Stop requested')

      if (pollRef.current) {
        clearInterval(pollRef.current)
        pollRef.current = null
      }

      setTimeout(async () => {
        try {
          const resultsRes = await axios.get(`${API_URL}/attack/${scanId}`)
          setResults(resultsRes.data)
          updateResults('attack', resultsRes.data)
        } catch (e) {}
        setRunning(false)
        updateStatus('attack', { running: false, progress: status?.progress || 0, phase: 'stopped' })
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

  // Resizable panel handlers
  const handleLeftResize = useCallback((e) => {
    e.preventDefault()
    const startX = e.clientX
    const startWidth = leftWidth

    const onMouseMove = (moveEvent) => {
      const delta = moveEvent.clientX - startX
      const newWidth = Math.max(200, Math.min(400, startWidth + delta))
      setLeftWidth(newWidth)
    }

    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }, [leftWidth])

  const handleRightResize = useCallback((e) => {
    e.preventDefault()
    const startX = e.clientX
    const startWidth = rightWidth

    const onMouseMove = (moveEvent) => {
      const delta = startX - moveEvent.clientX
      const newWidth = Math.max(300, Math.min(800, startWidth + delta))
      setRightWidth(newWidth)
    }

    const onMouseUp = () => {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }, [rightWidth])

  // Left Panel Content
  const LeftPanel = (
    <div className="h-full border-r border-border p-4 space-y-4 overflow-y-auto bg-background">
      {/* Target Input */}
      <div>
        <label className="block text-xs uppercase tracking-wider text-secondary mb-2">
          Target
        </label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://target.com"
          disabled={running}
          className="w-full bg-surface border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-neutral-500 disabled:opacity-50"
        />
      </div>

      <div>
        <label className="block text-xs uppercase tracking-wider text-secondary mb-2">
          Depth
        </label>
        <input
          type="number"
          value={maxPages}
          onChange={(e) => setMaxPages(parseInt(e.target.value) || 50)}
          min={10}
          max={200}
          disabled={running}
          className="w-full bg-surface border border-border rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-neutral-500 disabled:opacity-50"
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
        <div className="pt-4 border-t border-border">
          <div className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-secondary">Phase</span>
              <span className="font-mono text-xs">{status.phase}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-secondary">Progress</span>
              <span className="font-mono">{status.progress}%</span>
            </div>
            <div className="flex justify-between">
              <span className="text-secondary">Vulns</span>
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
        <div className="pt-4 border-t border-border">
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
  )

  // Center Panel Content (Console)
  const CenterPanel = (
    <div className="h-full flex flex-col border-r border-border">
      <div className="px-4 py-2 border-b border-border flex items-center justify-between flex-shrink-0">
        <span className="text-xs uppercase tracking-wider text-secondary">Console</span>
        {running && (
          <span className="flex items-center gap-2 text-xs text-secondary">
            <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
            live
          </span>
        )}
      </div>
      <div
        ref={consoleRef}
        className="flex-1 overflow-y-auto p-3 font-mono text-xs space-y-0.5"
      >
        {localEvents.length === 0 ? (
          <div className="text-gray-600 text-center py-8">
            Waiting for scan...
          </div>
        ) : (
          localEvents.map(event => (
            <div key={event.id} className={`flex gap-2 py-0.5 ${event.type === 'vuln' ? 'bg-red-500/5' : ''}`}>
              <span className="text-gray-600 flex-shrink-0 w-16">{event.time}</span>
              <span className="text-secondary flex-shrink-0 w-20 truncate">[{event.phase}]</span>
              <span className={getEventColor(event.type)}>{event.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )

  // Right Panel Content (Findings/Logs)
  const RightPanel = (
    <div className="h-full flex flex-col">
      {/* Tab Header */}
      <div className="px-2 py-1 border-b border-border flex items-center gap-1 flex-shrink-0">
        <button
          onClick={() => setRightPanelTab('findings')}
          className={`px-4 py-1.5 text-xs uppercase tracking-wider rounded transition ${
            rightPanelTab === 'findings'
              ? 'bg-neutral-800 text-white'
              : 'text-secondary hover:text-gray-300'
          }`}
        >
          Findings
          {results?.findings?.length > 0 && (
            <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] ${
              rightPanelTab === 'findings' ? 'bg-red-500/30 text-red-400' : 'bg-neutral-700 text-gray-400'
            }`}>
              {results.findings.length}
            </span>
          )}
        </button>
        <button
          onClick={() => setRightPanelTab('logs')}
          className={`px-4 py-1.5 text-xs uppercase tracking-wider rounded transition ${
            rightPanelTab === 'logs'
              ? 'bg-neutral-800 text-white'
              : 'text-secondary hover:text-gray-300'
          }`}
        >
          Logs
          {results?.enrichments?.length > 0 && (
            <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] ${
              rightPanelTab === 'logs' ? 'bg-blue-500/30 text-blue-400' : 'bg-neutral-700 text-gray-400'
            }`}>
              {results.enrichments.length}
            </span>
          )}
        </button>
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-hidden">
        {rightPanelTab === 'logs' ? (
          <LogsPanel results={results} status={status} />
        ) : results?.findings?.length > 0 ? (
          <div className="h-full overflow-y-auto">
            {results.findings.map((finding, idx) => (
              <div
                key={finding.id || idx}
                className={`border-b border-border ${selectedFinding === idx ? 'bg-surface' : ''}`}
              >
                {/* Finding Header - Clickable */}
                <div
                  onClick={() => setSelectedFinding(selectedFinding === idx ? null : idx)}
                  className="p-3 cursor-pointer hover:bg-surface/50 transition"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`w-2 h-2 rounded-full ${getSeverityBadge(finding.severity)}`}></span>
                    <span className="text-sm font-medium text-white">{finding.vuln_type}</span>
                    <span className={`text-[10px] uppercase px-1.5 py-0.5 rounded border ${getSeverityColor(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className="ml-auto text-secondary text-xs">
                      {selectedFinding === idx ? '[-]' : '[+]'}
                    </span>
                  </div>
                  <p className="text-xs text-secondary font-mono truncate">{finding.url}</p>
                  {finding.parameter && (
                    <p className="text-xs text-gray-600 mt-0.5">
                      param: <span className="text-gray-400">{finding.parameter}</span>
                    </p>
                  )}
                </div>

                {/* Finding Detail - Expanded (directly below) */}
                {selectedFinding === idx && (
                  <div className="px-3 pb-3 space-y-3 border-l-2 border-accent/50 ml-3">
                    {/* Evidence */}
                    <div>
                      <div className="text-[10px] uppercase text-secondary mb-1">Evidence</div>
                      <div className="text-xs text-gray-300 bg-neutral-950 rounded p-2">
                        {finding.evidence}
                      </div>
                    </div>

                    {/* Payload */}
                    {finding.payload && (
                      <div>
                        <div className="text-[10px] uppercase text-secondary mb-1">Payload</div>
                        <div className="relative">
                          <pre className="text-xs text-red-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono">
                            {finding.payload}
                          </pre>
                          <button
                            onClick={(e) => { e.stopPropagation(); copyToClipboard(finding.payload, `payload-${idx}`); }}
                            className="absolute top-1 right-1 text-[10px] px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 rounded text-gray-400 transition"
                          >
                            {copiedIndex === `payload-${idx}` ? 'copied' : 'copy'}
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Curl Command */}
                    <div>
                      <div className="text-[10px] uppercase text-secondary mb-1">Reproduce</div>
                      <div className="relative">
                        <pre className="text-xs text-green-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap break-all">
                          {generateCurlCommand(finding)}
                        </pre>
                        <button
                          onClick={(e) => { e.stopPropagation(); copyToClipboard(generateCurlCommand(finding), `curl-${idx}`); }}
                          className="absolute top-1 right-1 text-[10px] px-2 py-0.5 bg-neutral-800 hover:bg-neutral-700 rounded text-gray-400 transition"
                        >
                          {copiedIndex === `curl-${idx}` ? 'copied' : 'copy'}
                        </button>
                      </div>
                    </div>

                    {/* Full PoC */}
                    {finding.poc && (
                      <div>
                        <div className="text-[10px] uppercase text-secondary mb-1">Full PoC</div>
                        <div className="relative">
                          <pre className="text-xs text-gray-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap max-h-48">
                            {finding.poc}
                          </pre>
                          <button
                            onClick={(e) => { e.stopPropagation(); copyToClipboard(finding.poc, `poc-${idx}`); }}
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
                        <div className="text-[10px] uppercase text-secondary mb-1">Extracted Data</div>
                        <pre className="text-xs text-yellow-400 bg-neutral-950 rounded p-2 overflow-x-auto font-mono whitespace-pre-wrap max-h-32">
                          {JSON.stringify(finding.extracted_data, null, 2)}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : rightPanelTab === 'findings' ? (
          <div className="h-full flex items-center justify-center text-gray-600 text-sm">
            {running ? 'Scanning...' : 'No findings yet'}
          </div>
        ) : null}
      </div>
    </div>
  )

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-6 h-14 border-b border-border bg-background flex-shrink-0">
        <h1 className="text-lg font-semibold">Attack Console</h1>
        {running && (
          <span className="flex items-center gap-2 text-sm text-secondary">
            <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
            Scanning
          </span>
        )}
      </header>

      {/* Resizable 3-column layout */}
      <div ref={containerRef} className="flex flex-1 overflow-hidden">
        {/* Left Panel */}
        <div style={{ width: leftWidth, minWidth: 200, maxWidth: 400 }} className="flex-shrink-0">
          {LeftPanel}
        </div>

        {/* Left Divider */}
        <div
          className="w-1 bg-border hover:bg-accent cursor-col-resize flex-shrink-0 transition-colors"
          onMouseDown={handleLeftResize}
        />

        {/* Center Panel (flexible) */}
        <div className="flex-1 min-w-[200px]">
          {CenterPanel}
        </div>

        {/* Right Divider */}
        <div
          className="w-1 bg-border hover:bg-accent cursor-col-resize flex-shrink-0 transition-colors"
          onMouseDown={handleRightResize}
        />

        {/* Right Panel */}
        <div style={{ width: rightWidth, minWidth: 300, maxWidth: 800 }} className="flex-shrink-0">
          {RightPanel}
        </div>
      </div>
    </div>
  )
}

export default AttackConsole
