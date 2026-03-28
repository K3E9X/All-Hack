import { useState, useEffect, useRef } from 'react'
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001/api/v1'

function Scanner({ onScanStart, onScanComplete }) {
  const [url, setUrl] = useState('')
  const [mode, setMode] = useState('black_box')
  const [scanDepth, setScanDepth] = useState('balanced')
  const [authToken, setAuthToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [status, setStatus] = useState(null)
  const [progress, setProgress] = useState(0)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [browserCrawling, setBrowserCrawling] = useState(true)
  const [apiSchemaHarvesting, setApiSchemaHarvesting] = useState(true)
  const [osintEnrichment, setOsintEnrichment] = useState(true)
  const [stabilityTracking, setStabilityTracking] = useState(true)
  const [authSequenceText, setAuthSequenceText] = useState('')
  const [mfaSecret, setMfaSecret] = useState('')
  const [eventLog, setEventLog] = useState([])
  const [currentScanId, setCurrentScanId] = useState(null)
  const eventLogRef = useRef(null)
  const pollIntervalRef = useRef(null)

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    if (eventLogRef.current && eventLog.length > 0) {
      eventLogRef.current.scrollTop = eventLogRef.current.scrollHeight
    }
  }, [eventLog])

  const stopScan = async () => {
    if (!currentScanId) {
      alert('No active scan to stop')
      return
    }

    try {
      console.log('Stopping scan:', currentScanId)
      await axios.post(`${API_URL}/scans/${currentScanId}/stop`)

      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current)
        pollIntervalRef.current = null
      }

      setStatus('Scan stopped by user. Fetching partial results...')

      // Wait a bit then fetch partial results
      setTimeout(async () => {
        try {
          const resultsResponse = await axios.get(`${API_URL}/scans/${currentScanId}`)
          onScanComplete(resultsResponse.data)
          setLoading(false)
          setStatus('Scan stopped. Partial results available.')
        } catch (error) {
          console.error('Error fetching partial results:', error)
          setLoading(false)
          setStatus(' Scan stopped but could not fetch results')
        }
      }, 2000)
    } catch (error) {
      console.error('Error stopping scan:', error)
      alert('Failed to stop scan: ' + (error.response?.data?.detail || error.message))
    }
  }

  const startScan = async () => {
    console.log('Start Scan button clicked!')
    console.log('URL:', url)
    console.log('Mode:', mode)
    console.log('Scan Depth:', scanDepth)

    if (!url) {
      alert('Please enter a target URL before starting the scan')
      return
    }

    console.log('URL validation passed, starting scan...')
    setLoading(true)
    setStatus('Starting scan...')
    setProgress(0)
    setEventLog([])

    try {
      let parsedSequence = null
      if (authSequenceText.trim()) {
        try {
          parsedSequence = JSON.parse(authSequenceText)
        } catch (error) {
          console.error('Invalid auth sequence JSON:', error)
          setLoading(false)
          setStatus('Error: Invalid authentication sequence JSON')
          alert('Authentication sequence must be valid JSON')
          return
        }
      }

      console.log('Sending POST request to:', `${API_URL}/scans`)
      console.log('Request payload preview:', {
        target_url: url,
        mode: mode,
        scan_depth: scanDepth,
      })

      // Start the scan
      const response = await axios.post(`${API_URL}/scans`, {
        target_url: url,
        mode: mode,
        scan_depth: scanDepth,
        auth_token: authToken || null,
        auth_sequence: parsedSequence,
        mfa_totp_secret: mfaSecret || null,
        enable_active_tests: true,
        enable_fuzzing: true,
        // Note: enable_nuclei and enable_sqlmap removed (not implemented yet)
        rate_limit: 10,
        max_depth: 3,
        browser_crawling: browserCrawling,
        collect_api_schemas: apiSchemaHarvesting,
        enrich_osint: osintEnrichment,
        track_stability: stabilityTracking
      })

      console.log('Scan started successfully! Response:', response.data)
      const scanId = response.data.scan_id
      console.log('📋 Scan ID:', scanId)

      setCurrentScanId(scanId)
      onScanStart(scanId)
      setStatus('Scan started. Monitoring progress...')

      // Poll for status
      pollIntervalRef.current = setInterval(async () => {
        try {
          const statusResponse = await axios.get(`${API_URL}/scans/${scanId}/status`)
          const data = statusResponse.data

          setProgress(data.progress)
          setStatus(`${data.current_phase} - ${data.vulnerabilities_found} vulnerabilities found`)
          if (Array.isArray(data.recent_events)) {
            setEventLog((prev) => {
              const merged = [...prev]
              data.recent_events.forEach((event) => {
                if (!merged.find((item) => item.id === event.id)) {
                  merged.push(event)
                }
              })
              return merged.slice(-50)
            })
          }

          // Check if scan is complete or stopped
          if (data.status === 'completed' || data.status === 'stopped') {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null

            // Get full/partial results
            const resultsResponse = await axios.get(`${API_URL}/scans/${scanId}`)
            onScanComplete(resultsResponse.data)

            setLoading(false)
            setCurrentScanId(null)
            setStatus(data.status === 'stopped' ? 'Scan stopped!' : 'Scan completed!')
          } else if (data.status === 'failed') {
            clearInterval(pollIntervalRef.current)
            pollIntervalRef.current = null
            setLoading(false)
            setCurrentScanId(null)
            setStatus('Scan failed!')
          }
        } catch (error) {
          console.error('Error polling status:', error)
        }
      }, 2000) // Poll every 2 seconds

    } catch (error) {
      console.error('Scan error:', error)
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        config: error.config
      })

      setLoading(false)
      const errorMessage = error.response?.data?.detail || error.message || 'Unknown error'
      setStatus('Error: ' + errorMessage)

      // Show user-friendly error
      if (error.code === 'ERR_NETWORK' || error.message.includes('Network Error')) {
        alert('Cannot connect to backend server. Please ensure:\n\n1. Backend is running (uvicorn app.main:app --reload)\n2. Backend is accessible at ' + API_URL)
      } else {
        alert('Scan failed: ' + errorMessage)
      }
    }
  }

  return (
    <div className="border border-border bg-surface p-4 mb-6">
      <h2 className="text-sm font-medium uppercase tracking-wider mb-4">[SCN] Security Scan</h2>

      {/* Target URL */}
      <div className="mb-4">
        <label className="block text-xs font-medium uppercase tracking-wider mb-1">TARGET URL</label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          className="w-full px-3 py-2 border border-border bg-background text-sm font-mono"
          disabled={loading}
        />
      </div>

      {/* Scan Mode */}
      <div className="mb-4">
        <label className="block text-xs font-medium uppercase tracking-wider mb-1">MODE</label>
        <div className="flex gap-4">
          <label className="flex items-center gap-2 cursor-pointer text-xs">
            <input
              type="radio"
              value="black_box"
              checked={mode === 'black_box'}
              onChange={(e) => setMode(e.target.value)}
              disabled={loading}
              className="w-3 h-3"
            />
            <span>BLACK BOX</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer text-xs">
            <input
              type="radio"
              value="grey_box"
              checked={mode === 'grey_box'}
              onChange={(e) => setMode(e.target.value)}
              disabled={loading}
              className="w-3 h-3"
            />
            <span>GREY BOX</span>
          </label>
        </div>
      </div>

      {/* Scan Depth */}
      <div className="mb-4">
        <label className="block text-xs font-medium uppercase tracking-wider mb-1">DEPTH</label>
        <div className="flex gap-4">
          <label className="flex items-center gap-2 cursor-pointer text-xs">
            <input
              type="radio"
              value="quick"
              checked={scanDepth === 'quick'}
              onChange={(e) => setScanDepth(e.target.value)}
              disabled={loading}
              className="w-3 h-3"
            />
            <span>QUICK</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer text-xs">
            <input
              type="radio"
              value="balanced"
              checked={scanDepth === 'balanced'}
              onChange={(e) => setScanDepth(e.target.value)}
              disabled={loading}
              className="w-3 h-3"
            />
            <span>BALANCED</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer text-xs">
            <input
              type="radio"
              value="deep"
              checked={scanDepth === 'deep'}
              onChange={(e) => setScanDepth(e.target.value)}
              disabled={loading}
              className="w-3 h-3"
            />
            <span>DEEP</span>
          </label>
        </div>
      </div>

      {/* Advanced Options */}
      <div className="mb-4">
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-accent text-xs uppercase tracking-wider hover:underline"
        >
          [{showAdvanced ? '-' : '+'}] Advanced
        </button>
      </div>

      {showAdvanced && (
        <div className="mb-4 p-3 bg-background border border-border">
          {mode === 'grey_box' && (
            <div className="mb-3">
              <label className="block text-xs font-medium uppercase mb-1">AUTH TOKEN</label>
              <input
                type="text"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                placeholder="Bearer token..."
                className="w-full px-2 py-1.5 border border-border bg-surface text-xs font-mono"
                disabled={loading}
              />
            </div>
          )}

          {mode === 'grey_box' && (
            <div className="grid md:grid-cols-2 gap-2 mb-3">
              <div>
                <label className="block text-xs font-medium uppercase mb-1">AUTH SEQUENCE (JSON)</label>
                <textarea
                  value={authSequenceText}
                  onChange={(e) => setAuthSequenceText(e.target.value)}
                  placeholder='[{"method":"POST","path":"/login"...}]'
                  className="w-full px-2 py-1.5 border border-border bg-surface text-xs font-mono h-24"
                  disabled={loading}
                />
              </div>
              <div>
                <label className="block text-xs font-medium uppercase mb-1">MFA TOTP SECRET</label>
                <input
                  type="text"
                  value={mfaSecret}
                  onChange={(e) => setMfaSecret(e.target.value)}
                  placeholder="JBSWY3DPEHPK3PXP"
                  className="w-full px-2 py-1.5 border border-border bg-surface text-xs font-mono"
                  disabled={loading}
                />
              </div>
            </div>
          )}

          <div className="grid md:grid-cols-2 gap-2 mb-3">
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={browserCrawling}
                onChange={(e) => setBrowserCrawling(e.target.checked)}
                disabled={loading}
                className="w-3 h-3"
              />
              Browser crawling
            </label>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={apiSchemaHarvesting}
                onChange={(e) => setApiSchemaHarvesting(e.target.checked)}
                disabled={loading}
                className="w-3 h-3"
              />
              API schema harvest
            </label>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={osintEnrichment}
                onChange={(e) => setOsintEnrichment(e.target.checked)}
                disabled={loading}
                className="w-3 h-3"
              />
              OSINT enrichment
            </label>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={stabilityTracking}
                onChange={(e) => setStabilityTracking(e.target.checked)}
                disabled={loading}
                className="w-3 h-3"
              />
              Stability metrics
            </label>
          </div>

          <div className="text-xs text-secondary">
            <p className="font-medium uppercase mb-1">Tests: SQLi, XSS, RCE, SSRF, IDOR, PrivEsc, CORS</p>
          </div>
        </div>
      )}

      {/* Progress Bar and Live Test Output */}
      {loading && (
        <div className="mb-4">
          <div className="flex justify-between text-xs mb-1">
            <span className="text-accent uppercase">{status}</span>
            <span className="font-mono">{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-background h-1.5 border border-border">
            <div
              className="bg-accent h-full transition-all duration-500"
              style={{ width: `${progress}%` }}
            ></div>
          </div>

          {/* Live Test Output */}
          <div className="mt-3">
            <div className="flex items-center gap-2 mb-1">
              <div className="w-1.5 h-1.5 bg-accent animate-pulse"></div>
              <h3 className="text-xs font-medium uppercase">Live Output</h3>
            </div>
            <div ref={eventLogRef} className="max-h-64 overflow-y-auto text-xs bg-background border border-border p-2 font-mono">
              {eventLog.length === 0 ? (
                <div className="text-secondary text-center py-2">
                  Waiting...
                </div>
              ) : (
                eventLog.map((event, index) => (
                  <div
                    key={event.id}
                    className="flex items-start gap-2 py-0.5 border-l border-border pl-2 hover:border-accent transition-colors"
                  >
                    <span className="text-secondary flex-shrink-0 w-16">
                      {new Date(event.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="text-accent flex-shrink-0 w-24 truncate" title={event.phase}>
                      [{event.phase}]
                    </span>
                    <span className="flex-1">{event.message}</span>
                  </div>
                ))
              )}
              {eventLog.length > 0 && (
                <div className="text-secondary text-center pt-1 border-t border-border mt-1">
                  {eventLog.length} events
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Start Button */}
      <div>
        <div className="flex gap-2">
          <button
            onClick={startScan}
            disabled={loading || !url}
            className="btn btn-primary flex-1 disabled:opacity-50 disabled:cursor-not-allowed text-xs uppercase"
            title={!url ? 'Enter target URL first' : 'Start scan'}
          >
            {loading ? (
              <span className="flex items-center justify-center gap-1">
                <span className="w-3 h-3 border border-background border-t-transparent animate-spin"></span>
                SCANNING...
              </span>
            ) : (
              'START SCAN'
            )}
          </button>

          {loading && (
            <button
              onClick={stopScan}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-xs uppercase transition-colors border border-red-500"
              title="Stop scan"
            >
              STOP
            </button>
          )}
        </div>
        {!url && !loading && (
          <p className="text-xs text-yellow-500 mt-1 uppercase">
            Enter target URL to enable scan
          </p>
        )}
      </div>
    </div>
  )
}

export default Scanner
