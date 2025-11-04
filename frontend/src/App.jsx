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
        <div className="container mx-auto px-6 py-8">
          <div className="flex flex-col items-center justify-center gap-4">
            <p className="text-gray-500 text-sm">
              Built for authorized security testing purposes only
            </p>

            {/* GitHub Signature */}
            <div className="flex items-center gap-2 text-gray-400 hover:text-accent-primary transition-colors">
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
              </svg>
              <a
                href="https://github.com/K3E9X"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm font-medium"
              >
                Created by <span className="text-accent-primary font-semibold">K3E9X</span>
              </a>
            </div>

            <div className="flex items-center gap-2 text-xs text-gray-600">
              <span>MIT License</span>
              <span>•</span>
              <span>2024</span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default App
