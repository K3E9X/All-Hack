import { useActiveScans } from '../contexts/ActiveScansContext';
import { Activity, XCircle, Loader, CheckCircle, AlertTriangle } from 'lucide-react';
import clsx from 'clsx';

const MODULE_COLORS = {
  scan: 'text-blue-400',
  recon: 'text-purple-400',
  tools: 'text-yellow-400',
  agent: 'text-green-400',
};

const MODULE_LABELS = {
  scan: 'Scan',
  recon: 'Recon',
  tools: 'Tools',
  agent: 'Agent',
};

export default function GlobalStatusBar() {
  const { activeScans, moduleStates, stopScan } = useActiveScans();

  // Get running modules from moduleStates
  const runningModules = Object.entries(moduleStates)
    .filter(([_, state]) => state.running)
    .map(([module, state]) => ({
      module,
      ...state
    }));

  // Combine with activeScans from backend
  const allRunning = [...runningModules];
  activeScans.forEach(scan => {
    if (!allRunning.find(r => r.scanId === scan.scan_id)) {
      allRunning.push({
        module: scan.module || 'scan',
        target: scan.target,
        progress: scan.progress,
        phase: scan.phase,
        scanId: scan.scan_id
      });
    }
  });

  if (allRunning.length === 0) {
    return null;
  }

  return (
    <div className="fixed bottom-0 left-0 right-0 bg-background border-t border-border z-50">
      <div className="flex items-center gap-4 px-4 py-2 overflow-x-auto">
        <div className="flex items-center gap-2 text-sm font-medium text-secondary shrink-0">
          <Activity className="w-4 h-4 animate-pulse text-accent" />
          <span>{allRunning.length} Active</span>
        </div>

        <div className="h-4 w-px bg-border" />

        <div className="flex items-center gap-3 flex-1 overflow-x-auto">
          {allRunning.map((scan, idx) => (
            <div
              key={scan.scanId || idx}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface border border-border shrink-0"
            >
              <Loader className={clsx('w-3.5 h-3.5 animate-spin', MODULE_COLORS[scan.module])} />

              <span className={clsx('text-xs font-medium', MODULE_COLORS[scan.module])}>
                {MODULE_LABELS[scan.module] || scan.module}
              </span>

              <span className="text-xs text-secondary max-w-32 truncate">
                {scan.target || 'Running...'}
              </span>

              {scan.progress > 0 && (
                <div className="flex items-center gap-1">
                  <div className="w-16 h-1.5 bg-border rounded-full overflow-hidden">
                    <div
                      className="h-full bg-accent rounded-full transition-all"
                      style={{ width: `${scan.progress}%` }}
                    />
                  </div>
                  <span className="text-xs text-secondary">{Math.round(scan.progress)}%</span>
                </div>
              )}

              <span className="text-xs text-secondary capitalize">
                {scan.phase}
              </span>

              {scan.scanId && (
                <button
                  onClick={() => stopScan(scan.module, scan.scanId)}
                  className="p-0.5 rounded hover:bg-red-500/20 text-secondary hover:text-red-400 transition-colors"
                  title="Stop scan"
                >
                  <XCircle className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
