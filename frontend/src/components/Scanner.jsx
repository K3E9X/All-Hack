import { useState } from 'react'
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1'

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

  const startScan = async () => {
    if (!url) {
      alert('Please enter a target URL')
      return
    }

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
          setLoading(false)
          setStatus('Error: Invalid authentication sequence JSON')
          return
        }
      }

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

      const scanId = response.data.scan_id
      onScanStart(scanId)
      setStatus('Scan started. Monitoring progress...')

      // Poll for status
      const pollInterval = setInterval(async () => {
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

          // Check if scan is complete
          if (data.status === 'completed') {
            clearInterval(pollInterval)

            // Get full results
            const resultsResponse = await axios.get(`${API_URL}/scans/${scanId}`)
            onScanComplete(resultsResponse.data)

            setLoading(false)
            setStatus('Scan completed!')
          } else if (data.status === 'failed') {
            clearInterval(pollInterval)
            setLoading(false)
            setStatus('Scan failed!')
          }
        } catch (error) {
          console.error('Error polling status:', error)
        }
      }, 2000) // Poll every 2 seconds

    } catch (error) {
      setLoading(false)
      setStatus('Error: ' + (error.response?.data?.detail || error.message))
      console.error('Scan error:', error)
    }
  }

  return (
    <div className="card mb-8">
      <h2 className="text-2xl font-bold mb-6 text-gray-100">Start Security Scan</h2>

      {/* Target URL */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-300 mb-2">Target URL</label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          className="input-field"
          disabled={loading}
        />
        <p className="text-xs text-gray-500 mt-2">Enter the full URL of the target application</p>
      </div>

      {/* Scan Mode */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-300 mb-2">Scan Mode</label>
        <div className="flex gap-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              value="black_box"
              checked={mode === 'black_box'}
              onChange={(e) => setMode(e.target.value)}
              disabled={loading}
              className="w-4 h-4"
            />
            <span className="text-gray-300">Black Box (No Authentication)</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              value="grey_box"
              checked={mode === 'grey_box'}
              onChange={(e) => setMode(e.target.value)}
              disabled={loading}
              className="w-4 h-4"
            />
            <span className="text-gray-300">Grey Box (With Authentication)</span>
          </label>
        </div>
      </div>

      {/* Scan Depth */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-gray-300 mb-2">Scan Depth / Speed</label>
        <div className="flex gap-4">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              value="quick"
              checked={scanDepth === 'quick'}
              onChange={(e) => setScanDepth(e.target.value)}
              disabled={loading}
              className="w-4 h-4"
            />
            <span className="text-gray-300">Quick (10 endpoints, ~5-15 min) ⚡</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              value="balanced"
              checked={scanDepth === 'balanced'}
              onChange={(e) => setScanDepth(e.target.value)}
              disabled={loading}
              className="w-4 h-4"
            />
            <span className="text-gray-300">Balanced (50 endpoints, ~30-60 min) ⚖️</span>
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              value="deep"
              checked={scanDepth === 'deep'}
              onChange={(e) => setScanDepth(e.target.value)}
              disabled={loading}
              className="w-4 h-4"
            />
            <span className="text-gray-300">Deep (All endpoints, 2-10 hours) 🔥</span>
          </label>
        </div>
        <p className="text-xs text-gray-500 mt-2">Balanced is recommended for most scans. Quick for testing, Deep for comprehensive pentests.</p>
      </div>

      {/* Advanced Options */}
      <div className="mb-6">
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="text-accent-primary text-sm hover:underline"
        >
          {showAdvanced ? '▼' : '▶'} Advanced Options
        </button>
      </div>

      {showAdvanced && (
        <div className="mb-6 p-4 bg-dark-hover rounded-lg border border-dark-border">
          {mode === 'grey_box' && (
            <div className="mb-4">
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Authentication Token (Bearer)
              </label>
              <input
                type="text"
                value={authToken}
                onChange={(e) => setAuthToken(e.target.value)}
                placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                className="input-field"
                disabled={loading}
              />
              <p className="text-xs text-gray-500 mt-2">Optional: JWT token or API key for authenticated scans</p>
            </div>
          )}

          {mode === 'grey_box' && (
            <div className="grid md:grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Authentication Sequence (JSON)</label>
                <textarea
                  value={authSequenceText}
                  onChange={(e) => setAuthSequenceText(e.target.value)}
                  placeholder='[{"method":"POST","path":"/login","json":{"username":"admin","password":"pass"},"store_tokens":true}]'
                  className="input-field h-32"
                  disabled={loading}
                />
                <p className="text-xs text-gray-500 mt-2">Define multi-step login flows with optional TOTP injection.</p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">MFA TOTP Secret</label>
                <input
                  type="text"
                  value={mfaSecret}
                  onChange={(e) => setMfaSecret(e.target.value)}
                  placeholder="JBSWY3DPEHPK3PXP"
                  className="input-field"
                  disabled={loading}
                />
                <p className="text-xs text-gray-500 mt-2">Used when steps require an OTP code.</p>
              </div>
            </div>
          )}

          <div className="grid md:grid-cols-2 gap-4 mb-4">
            <label className="flex items-center gap-3 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={browserCrawling}
                onChange={(e) => setBrowserCrawling(e.target.checked)}
                disabled={loading}
              />
              Enable browser-based crawling for SPA routes
            </label>
            <label className="flex items-center gap-3 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={apiSchemaHarvesting}
                onChange={(e) => setApiSchemaHarvesting(e.target.checked)}
                disabled={loading}
              />
              Harvest OpenAPI / GraphQL schemas
            </label>
            <label className="flex items-center gap-3 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={osintEnrichment}
                onChange={(e) => setOsintEnrichment(e.target.checked)}
                disabled={loading}
              />
              Collect local OSINT insights (DNS, certificates, secrets)
            </label>
            <label className="flex items-center gap-3 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={stabilityTracking}
                onChange={(e) => setStabilityTracking(e.target.checked)}
                disabled={loading}
              />
              Capture host stability metrics during scan
            </label>
          </div>

          <div className="text-sm text-gray-400">
            <p className="font-medium text-gray-300 mb-2">Enabled Tests:</p>
            <ul className="list-disc list-inside space-y-1">
              <li>SQL Injection Detection</li>
              <li>Cross-Site Scripting (XSS)</li>
              <li>Command Injection</li>
              <li>SSRF (Server-Side Request Forgery)</li>
              <li>IDOR (Insecure Direct Object Reference)</li>
              <li>Privilege Escalation</li>
              <li>Security Misconfigurations</li>
              <li>CORS Misconfiguration</li>
              <li>Endpoint Discovery & Fuzzing</li>
            </ul>
          </div>
        </div>
      )}

      {/* Progress Bar */}
      {loading && (
        <div className="mb-6">
          <div className="flex justify-between text-sm text-gray-400 mb-2">
            <span>{status}</span>
            <span>{Math.round(progress)}%</span>
          </div>
          <div className="w-full bg-dark-hover rounded-full h-2 overflow-hidden">
            <div
              className="bg-accent-primary h-full transition-all duration-500"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          {eventLog.length > 0 && (
            <div className="mt-4 max-h-48 overflow-y-auto text-sm bg-dark-card border border-dark-border rounded-lg p-3 space-y-2">
              {eventLog.map((event) => (
                <div key={event.id} className="flex flex-col">
                  <span className="text-xs text-gray-500">
                    {new Date(event.timestamp).toLocaleTimeString()} • {event.phase}
                  </span>
                  <span className="text-gray-200">{event.message}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Start Button */}
      <button
        onClick={startScan}
        disabled={loading || !url}
        className="btn-primary w-full disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {loading ? (
          <span className="flex items-center justify-center gap-2">
            <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            Scanning...
          </span>
        ) : (
          'Start Scan'
        )}
      </button>
    </div>
  )
}

export default Scanner
