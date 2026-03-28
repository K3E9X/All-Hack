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
    <div className="min-h-screen bg-background text-primary p-4">
      <header className="mb-6">
        <h1 className="text-xl font-medium tracking-wider uppercase">ALL-HACK</h1>
        <p className="text-secondary text-xs uppercase">AI-Powered Penetration Testing</p>
      </header>

      {/* New Scan Form */}
      <div className="border border-border bg-surface p-4 mb-4">
        <h2 className="text-sm font-medium uppercase mb-3">[NEW] Start Scan</h2>

        <div className="space-y-3">
          <input
            type="text"
            placeholder="Target URL (e.g., http://testphp.vulnweb.com)"
            value={newScan.target_url}
            onChange={(e) => setNewScan({ ...newScan, target_url: e.target.value })}
            className="w-full px-3 py-2 border border-border bg-background text-sm font-mono"
          />

          <select
            value={newScan.mode}
            onChange={(e) => setNewScan({ ...newScan, mode: e.target.value })}
            className="w-full px-3 py-2 border border-border bg-background text-sm uppercase"
          >
            <option value="black_box">BLACK BOX</option>
            <option value="grey_box">GREY BOX</option>
          </select>

          <div className="flex gap-2">
            <button
              onClick={() => startScan(false)}
              disabled={loading || !newScan.target_url}
              className="flex-1 btn btn-secondary text-xs uppercase disabled:opacity-50"
            >
              <ShieldCheckIcon className="inline w-4 h-4 mr-1" />
              {loading ? 'STARTING...' : 'STANDARD'}
            </button>

            <button
              onClick={() => startScan(true)}
              disabled={loading || !newScan.target_url}
              className="flex-1 btn btn-primary text-xs uppercase disabled:opacity-50"
            >
              <BeakerIcon className="inline w-4 h-4 mr-1" />
              {loading ? 'STARTING...' : 'AI AGENT'}
            </button>
          </div>
        </div>
      </div>

      {/* Recent Scans */}
      <div className="border border-border bg-surface p-4">
        <h2 className="text-sm font-medium uppercase mb-3 flex items-center">
          <ChartBarIcon className="w-4 h-4 mr-1" />
          Recent Scans
        </h2>

        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left py-2 px-2 uppercase">ID</th>
                <th className="text-left py-2 px-2 uppercase">Target</th>
                <th className="text-left py-2 px-2 uppercase">Status</th>
                <th className="text-left py-2 px-2 uppercase">Vulns</th>
                <th className="text-left py-2 px-2 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 ? (
                <tr>
                  <td colSpan="5" className="text-center py-4 text-secondary uppercase">
                    No scans. Start above.
                  </td>
                </tr>
              ) : (
                scans.map((scan) => (
                  <tr key={scan.scan_id} className="border-b border-border hover:bg-hover">
                    <td className="py-2 px-2 font-mono">{scan.scan_id.slice(0, 8)}</td>
                    <td className="py-2 px-2 font-mono truncate max-w-32">{scan.target_url}</td>
                    <td className="py-2 px-2">
                      <span
                        className={`px-1.5 py-0.5 border text-xs font-mono uppercase ${
                          scan.status === 'completed'
                            ? 'border-green-500 text-green-400'
                            : scan.status === 'running'
                            ? 'border-yellow-500 text-yellow-400'
                            : scan.status === 'failed'
                            ? 'border-red-500 text-red-400'
                            : 'border-border text-secondary'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-2 px-2 font-mono">{scan.vulnerabilities_count || 0}</td>
                    <td className="py-2 px-2">
                      <a
                        href={`/scan/${scan.scan_id}`}
                        className="text-accent hover:underline"
                      >
                        VIEW
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
