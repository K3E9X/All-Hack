import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, ExternalLink, Trash2, Search, Filter } from 'lucide-react';
import clsx from 'clsx';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

export default function HistoryView() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const navigate = useNavigate();

  useEffect(() => {
    fetchScans();
  }, []);

  const fetchScans = async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/scans`);
      if (response.ok) {
        const data = await response.json();
        setScans(data.scans || []);
      }
    } catch (error) {
      console.error('Failed to fetch scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredScans = scans.filter(scan => {
    const matchesSearch = scan.target?.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesFilter = filter === 'all' ||
      (filter === 'completed' && scan.status === 'completed') ||
      (filter === 'running' && scan.status === 'running') ||
      (filter === 'failed' && scan.status === 'failed');
    return matchesSearch && matchesFilter;
  });

  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A';
    return new Date(dateStr).toLocaleString();
  };

  const getSeverityCounts = (scan) => {
    return {
      critical: scan.critical_count || 0,
      high: scan.high_count || 0,
      medium: scan.medium_count || 0,
      low: scan.low_count || 0
    };
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-6 h-14 border-b border-border bg-background">
        <h1 className="text-lg font-semibold">Scan History</h1>
      </header>

      {/* Filters */}
      <div className="flex items-center gap-4 px-6 py-4 border-b border-border bg-background">
        <div className="flex-1 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-secondary" />
          <input
            type="text"
            placeholder="Search by target..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 rounded-lg border border-border bg-surface"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-secondary" />
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-3 py-2 rounded-lg border border-border bg-surface"
          >
            <option value="all">All</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      {/* Scans List */}
      <div className="flex-1 overflow-y-auto p-6 bg-surface">
        {loading ? (
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin w-8 h-8 border-2 border-accent border-t-transparent rounded-full" />
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-secondary">
            <Clock className="w-12 h-12 mb-4 opacity-50" />
            <p>No scans found</p>
          </div>
        ) : (
          <div className="space-y-3">
            {filteredScans.map((scan) => {
              const counts = getSeverityCounts(scan);

              return (
                <div
                  key={scan.id}
                  className="card p-4 hover:border-accent/50 transition-colors cursor-pointer"
                  onClick={() => navigate(`/scan/${scan.id}`)}
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <span className={clsx(
                        'w-2 h-2 rounded-full',
                        scan.status === 'completed' && 'bg-green-400',
                        scan.status === 'running' && 'bg-yellow-400 animate-pulse',
                        scan.status === 'failed' && 'bg-red-400'
                      )} />
                      <span className="font-mono text-sm truncate max-w-md">
                        {scan.target}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-sm text-secondary">
                      <span>{formatDate(scan.started_at)}</span>
                      <ExternalLink className="w-4 h-4" />
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="flex items-center gap-2">
                      {counts.critical > 0 && (
                        <span className="severity-critical px-2 py-0.5 rounded text-xs font-medium border">
                          {counts.critical} Critical
                        </span>
                      )}
                      {counts.high > 0 && (
                        <span className="severity-high px-2 py-0.5 rounded text-xs font-medium border">
                          {counts.high} High
                        </span>
                      )}
                      {counts.medium > 0 && (
                        <span className="severity-medium px-2 py-0.5 rounded text-xs font-medium border">
                          {counts.medium} Medium
                        </span>
                      )}
                      {counts.low > 0 && (
                        <span className="severity-low px-2 py-0.5 rounded text-xs font-medium border">
                          {counts.low} Low
                        </span>
                      )}
                      {counts.critical === 0 && counts.high === 0 && counts.medium === 0 && counts.low === 0 && (
                        <span className="text-xs text-secondary">No findings</span>
                      )}
                    </div>

                    <span className="text-xs text-secondary ml-auto">
                      {scan.depth || 'balanced'} scan
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
