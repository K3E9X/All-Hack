import { useState, useEffect } from 'react';
import axios from 'axios';
import { ChartBarIcon, ShieldCheckIcon, BeakerIcon } from '@heroicons/react/24/outline';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export default function Dashboard() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [newScan, setNewScan] = useState({ target_url: '', mode: 'black_box' });

  const startScan = async (useAgents = false) => {
    setLoading(true);
    try {
      const endpoint = useAgents ? `${API_BASE}/agents/scan` : `${API_BASE}/scans`;
      const response = await axios.post(endpoint, newScan);

      alert(`Scan started! ID: ${response.data.scan_id}`);
      setNewScan({ target_url: '', mode: 'black_box' });
      fetchScans();
    } catch (error) {
      console.error('Scan failed:', error);
      alert('Scan failed: ' + (error.response?.data?.detail || error.message));
    }
    setLoading(false);
  };

  const fetchScans = async () => {
    try {
      const response = await axios.get(`${API_BASE}/scans`);
      setScans(response.data);
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-gray-900 text-white p-8">
      <header className="mb-12">
        <h1 className="text-5xl font-bold mb-2">🎯 All-Hack</h1>
        <p className="text-gray-400 text-lg">AI-Powered Penetration Testing Tool</p>
      </header>

      {/* New Scan Form */}
      <div className="bg-gray-800 rounded-lg p-6 mb-8 border border-gray-700">
        <h2 className="text-2xl font-semibold mb-4">🚀 Start New Scan</h2>

        <div className="space-y-4">
          <input
            type="text"
            placeholder="Target URL (e.g., http://testphp.vulnweb.com)"
            value={newScan.target_url}
            onChange={(e) => setNewScan({ ...newScan, target_url: e.target.value })}
            className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-blue-500"
          />

          <select
            value={newScan.mode}
            onChange={(e) => setNewScan({ ...newScan, mode: e.target.value })}
            className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg focus:outline-none focus:border-blue-500"
          >
            <option value="black_box">Black Box (No credentials)</option>
            <option value="grey_box">Grey Box (With credentials)</option>
          </select>

          <div className="flex gap-4">
            <button
              onClick={() => startScan(false)}
              disabled={loading || !newScan.target_url}
              className="flex-1 bg-blue-600 hover:bg-blue-700 px-6 py-3 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <ShieldCheckIcon className="inline w-5 h-5 mr-2" />
              {loading ? 'Starting...' : 'Standard Scan'}
            </button>

            <button
              onClick={() => startScan(true)}
              disabled={loading || !newScan.target_url}
              className="flex-1 bg-purple-600 hover:bg-purple-700 px-6 py-3 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <BeakerIcon className="inline w-5 h-5 mr-2" />
              {loading ? 'Starting...' : '🤖 AI Agent Scan (Phase 2)'}
            </button>
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <h2 className="text-2xl font-semibold mb-4 flex items-center">
          <ChartBarIcon className="w-6 h-6 mr-2" />
          Recent Scans
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4">Scan ID</th>
                <th className="text-left py-3 px-4">Target</th>
                <th className="text-left py-3 px-4">Status</th>
                <th className="text-left py-3 px-4">Vulnerabilities</th>
                <th className="text-left py-3 px-4">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 ? (
                <tr>
                  <td colSpan="5" className="text-center py-8 text-gray-400">
                    No scans yet. Start your first scan above!
                  </td>
                </tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.scan_id} className="border-b border-gray-700 hover:bg-gray-750">
                    <td className="py-3 px-4 font-mono text-sm">{scan.scan_id.slice(0, 8)}...</td>
                    <td className="py-3 px-4">{scan.target_url}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-1 rounded text-xs font-semibold ${
                          scan.status === 'completed'
                            ? 'bg-green-600'
                            : scan.status === 'running'
                            ? 'bg-yellow-600'
                            : scan.status === 'failed'
                            ? 'bg-red-600'
                            : 'bg-gray-600'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3 px-4">{scan.vulnerabilities_count || 0}</td>
                    <td className="py-3 px-4">
                      <a
                        href={`/scan/${scan.scan_id}`}
                        className="text-blue-400 hover:text-blue-300 text-sm"
                      >
                        View Details →
                      </a>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
