import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Clock, ExternalLink, Trash2, Search, Filter, RefreshCw, Activity } from 'lucide-react';
import clsx from 'clsx';
import { useActiveScans } from '../contexts/ActiveScansContext';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

export default function HistoryView() {
  const { activeScans, fetchActiveScans } = useActiveScans();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const navigate = useNavigate();

  const fetchScans = useCallback(async () => {
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
  }, []);

  useEffect(() => {
    fetchScans();
    // Refresh every 10 seconds if there are active scans
    const interval = setInterval(() => {
      if (activeScans.length > 0) {
        fetchScans();
      }
    }, 10000);
    return () => clearInterval(interval);
  }, [fetchScans, activeScans.length]);

  const refresh = () => {
    setLoading(true);
    fetchScans();
    fetchActiveScans();
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
      <header className="flex items-center justify-between px-4 h-10 border-b border-border bg-surface">
        <div className="flex items-center gap-3">
          <h1 className="text-xs font-medium tracking-wider uppercase">HISTORY</h1>
          {activeScans.length > 0 && (
            <span className="flex items-center gap-1 px-1.5 py-0.5 border border-accent text-accent text-xs">
              <span className="w-1.5 h-1.5 bg-accent animate-pulse" />
              {activeScans.length} running
            </span>
          )}
        </div>
        <button
          onClick={refresh}
          disabled={loading}
          className="btn btn-secondary text-xs p-1.5"
        >
          <RefreshCw className={clsx('w-3 h-3', loading && 'animate-spin')} />
        </button>
      </header>

      {/* Filters */}
      <div className="flex items-center gap-3 px-4 py-2 border-b border-border bg-surface">
        <div className="flex-1 relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-secondary" />
          <input
            type="text"
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-7 pr-3 py-1.5 border border-border bg-background text-sm font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="px-2 py-1.5 border border-border bg-background text-xs uppercase"
          >
            <option value="all">All</option>
            <option value="completed">Completed</option>
            <option value="running">Running</option>
            <option value="failed">Failed</option>
          </select>
        </div>
      </div>

      {/* Scans List */}
      <div className="flex-1 overflow-y-auto p-4 bg-background">
        {loading ? (
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin w-6 h-6 border-2 border-accent border-t-transparent" />
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-secondary">
            <Clock className="w-8 h-8 mb-3 opacity-50" />
            <p className="text-xs uppercase tracking-wider">No scans found</p>
          </div>
        ) : (
          <div className="space-y-2">
            {filteredScans.map((scan) => {
              const counts = getSeverityCounts(scan);

              return (
                <div
                  key={scan.id}
                  className="p-3 border border-border bg-surface hover:border-accent/50 transition-colors cursor-pointer"
                  onClick={() => navigate(`/scan/${scan.id}`)}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={clsx(
                        'w-1.5 h-1.5',
                        scan.status === 'completed' && 'bg-green-400',
                        scan.status === 'running' && 'bg-yellow-400 animate-pulse',
                        scan.status === 'failed' && 'bg-red-400'
                      )} />
                      <span className="font-mono text-xs truncate max-w-md">
                        {scan.target}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-xs text-secondary">
                      <span>{formatDate(scan.started_at)}</span>
                      <ExternalLink className="w-3 h-3" />
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    <div className="flex items-center gap-1">
                      {counts.critical > 0 && (
                        <span className="severity-critical px-1.5 py-0.5 text-xs font-mono border">
                          {counts.critical}C
                        </span>
                      )}
                      {counts.high > 0 && (
                        <span className="severity-high px-1.5 py-0.5 text-xs font-mono border">
                          {counts.high}H
                        </span>
                      )}
                      {counts.medium > 0 && (
                        <span className="severity-medium px-1.5 py-0.5 text-xs font-mono border">
                          {counts.medium}M
                        </span>
                      )}
                      {counts.low > 0 && (
                        <span className="severity-low px-1.5 py-0.5 text-xs font-mono border">
                          {counts.low}L
                        </span>
                      )}
                      {counts.critical === 0 && counts.high === 0 && counts.medium === 0 && counts.low === 0 && (
                        <span className="text-xs text-secondary">-</span>
                      )}
                    </div>

                    <span className="text-xs text-secondary ml-auto uppercase">
                      {scan.depth || 'balanced'}
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
