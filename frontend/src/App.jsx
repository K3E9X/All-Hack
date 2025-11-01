import { useState } from 'react'
import Scanner from './components/Scanner'
import Results from './components/Results'
import './index.css'

function App() {
  const [scanId, setScanId] = useState(null)
  const [scanResults, setScanResults] = useState(null)

  return (
    <div className="min-h-screen bg-dark-bg">
      {/* Header */}
      <header className="border-b border-dark-border">
        <div className="container mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold bg-gradient-to-r from-accent-primary to-accent-secondary bg-clip-text text-transparent">
                Advanced Pentest Tool
              </h1>
              <p className="text-gray-400 text-sm mt-1">Automated Web Application Security Scanner</p>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="px-3 py-1 bg-dark-card border border-dark-border rounded-full text-gray-400">
                v1.0.0
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-6 py-8">
        {/* Warning Banner */}
        <div className="mb-8 p-4 bg-red-900 bg-opacity-20 border border-red-700 rounded-lg">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-red-400 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <p className="text-red-200 font-semibold">Legal Warning</p>
              <p className="text-red-300 text-sm mt-1">
                Only use this tool on applications you own or have explicit written permission to test.
                Unauthorized penetration testing is illegal.
              </p>
            </div>
          </div>
        </div>

        {/* Scanner Component */}
        <Scanner onScanStart={setScanId} onScanComplete={setScanResults} />

        {/* Results Component */}
        {scanResults && <Results results={scanResults} />}
      </main>

      {/* Footer */}
      <footer className="border-t border-dark-border mt-12">
        <div className="container mx-auto px-6 py-6 text-center text-gray-500 text-sm">
          <p>Built for authorized security testing purposes only</p>
        </div>
      </footer>
    </div>
  )
}

export default App
