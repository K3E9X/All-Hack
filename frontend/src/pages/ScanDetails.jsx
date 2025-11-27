import { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';
import axios from 'axios';
import ChatInterface from '../components/ChatInterface';
import AgentStatus from '../components/AgentStatus';
import VulnerabilityChart from '../components/VulnerabilityChart';
import { ArrowLeftIcon, ShieldExclamationIcon } from '@heroicons/react/24/outline';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export default function ScanDetails() {
  const { scanId } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');

  useEffect(() => {
    const fetchScan = async () => {
      try {
        const response = await axios.get(`${API_BASE}/scans/${scanId}`);
        setScan(response.data);
        setLoading(false);
      } catch (error) {
        console.error('Failed to fetch scan:', error);
        setLoading(false);
      }
    };

    fetchScan();
    const interval = setInterval(fetchScan, 5000);

    return () => clearInterval(interval);
  }, [scanId]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-purple-500 mx-auto mb-4" />
          <p className="text-gray-400">Loading scan details...</p>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
        <div className="text-center">
          <ShieldExclamationIcon className="w-16 h-16 text-gray-400 mx-auto mb-4" />
          <p className="text-xl mb-2">Scan not found</p>
          <Link to="/" className="text-blue-400 hover:text-blue-300">
            ← Back to Dashboard
          </Link>
        </div>
      </div>
    );
  }

  const vulnerabilities = scan.vulnerabilities || [];

  const tabs = [
    { id: 'overview', name: 'Overview' },
    { id: 'vulnerabilities', name: `Vulnerabilities (${vulnerabilities.length})` },
    { id: 'agents', name: '🤖 AI Agents' },
    { id: 'chat', name: '💬 AI Chat' },
  ];

  const getSeverityColor = (severity) => {
    const colors = {
      critical: 'text-red-500',
      high: 'text-orange-500',
      medium: 'text-yellow-500',
      low: 'text-blue-500',
      informational: 'text-gray-500',
    };
    return colors[severity?.toLowerCase()] || 'text-gray-500';
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      {/* Header */}
      <div className="mb-8">
        <Link to="/" className="text-blue-400 hover:text-blue-300 flex items-center mb-4">
          <ArrowLeftIcon className="w-4 h-4 mr-2" />
          Back to Dashboard
        </Link>

        <h1 className="text-4xl font-bold mb-2">Scan Details</h1>
        <p className="text-gray-400">{scan.target_url}</p>

        <div className="mt-4 flex gap-4">
          <div className="px-4 py-2 bg-gray-800 rounded-lg">
            <span className="text-sm text-gray-400">Status: </span>
            <span
              className={`font-semibold ${
                scan.status === 'completed' ? 'text-green-500' : scan.status === 'running' ? 'text-yellow-500' : 'text-gray-500'
              }`}
            >
              {scan.status}
            </span>
          </div>
          <div className="px-4 py-2 bg-gray-800 rounded-lg">
            <span className="text-sm text-gray-400">Scan ID: </span>
            <span className="font-mono text-sm">{scanId.slice(0, 16)}...</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6 border-b border-gray-700">
        <div className="flex gap-4">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 font-semibold transition-colors ${
                activeTab === tab.id
                  ? 'text-purple-400 border-b-2 border-purple-400'
                  : 'text-gray-400 hover:text-gray-300'
              }`}
            >
              {tab.name}
            </button>
          ))}
        </div>
      </div>

      {/* Tab Content */}
      <div>
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <VulnerabilityChart vulnerabilities={vulnerabilities} />

            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
              <h3 className="text-xl font-semibold mb-4">Scan Statistics</h3>
              <div className="grid md:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-gray-400">Total Vulnerabilities</p>
                  <p className="text-3xl font-bold">{vulnerabilities.length}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Endpoints Discovered</p>
                  <p className="text-3xl font-bold">{scan.discovered_endpoints?.length || 0}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Technologies Detected</p>
                  <p className="text-3xl font-bold">{scan.detected_technologies?.length || 0}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-400">Scan Duration</p>
                  <p className="text-3xl font-bold">{scan.scan_duration?.toFixed(1) || 0}s</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
            <h3 className="text-xl font-semibold mb-4">Vulnerabilities</h3>
            <div className="space-y-4">
              {vulnerabilities.length === 0 ? (
                <p className="text-gray-400 text-center py-8">No vulnerabilities found!</p>
              ) : (
                vulnerabilities.map((vuln, idx) => (
                  <div key={idx} className="p-4 bg-gray-750 rounded-lg border border-gray-700">
                    <div className="flex items-start justify-between mb-2">
                      <h4 className="font-semibold text-lg">{vuln.title}</h4>
                      <span className={`px-3 py-1 rounded text-sm font-semibold ${getSeverityColor(vuln.severity)}`}>
                        {vuln.severity?.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-gray-400 text-sm mb-2">{vuln.description}</p>
                    <div className="flex gap-4 text-sm">
                      <span className="text-gray-500">
                        <strong>URL:</strong> {vuln.affected_url}
                      </span>
                      {vuln.affected_parameter && (
                        <span className="text-gray-500">
                          <strong>Parameter:</strong> {vuln.affected_parameter}
                        </span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {activeTab === 'agents' && (
          <div>
            <AgentStatus scanId={scanId} />
          </div>
        )}

        {activeTab === 'chat' && (
          <div className="h-[600px]">
            <ChatInterface scanId={scanId} />
          </div>
        )}
      </div>
    </div>
  );
}
