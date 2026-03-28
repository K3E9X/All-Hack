import { useActiveScans } from '../contexts/ActiveScansContext';
import { X, Square } from 'lucide-react';
import clsx from 'clsx';

const MODULE_LABELS = {
  scan: 'SCAN',
  recon: 'RECON',
  tools: 'TOOLS',
  agent: 'AGENT',
};

export default function GlobalStatusBar() {
  const { activeScans, moduleStates, stopScan } = useActiveScans();

  const runningModules = Object.entries(moduleStates)
    .filter(([_, state]) => state.running)
    .map(([module, state]) => ({
      module,
      ...state
    }));

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
    <div className="fixed bottom-0 left-0 right-0 bg-surface border-t border-border z-50">
      <div className="flex items-center gap-3 px-3 py-1.5 overflow-x-auto text-xs">
        <div className="flex items-center gap-2 text-accent shrink-0">
          <Square className="w-2 h-2 fill-current animate-pulse" />
          <span className="uppercase tracking-wider">{allRunning.length} running</span>
        </div>

        <span className="text-border">|</span>

        <div className="flex items-center gap-2 flex-1 overflow-x-auto">
          {allRunning.map((scan, idx) => (
            <div
              key={scan.scanId || idx}
              className="flex items-center gap-2 px-2 py-1 border border-border shrink-0"
            >
              <span className="text-accent">
                [{MODULE_LABELS[scan.module] || scan.module.toUpperCase()}]
              </span>

              <span className="text-secondary max-w-40 truncate">
                {scan.target || '...'}
              </span>

              {scan.progress > 0 && (
                <span className="text-secondary">
                  {Math.round(scan.progress)}%
                </span>
              )}

              {scan.phase && (
                <span className="text-secondary uppercase">
                  {scan.phase}
                </span>
              )}

              {scan.scanId && (
                <button
                  onClick={() => stopScan(scan.module, scan.scanId)}
                  className="text-secondary hover:text-critical transition-colors"
                  title="Stop"
                >
                  <X className="w-3 h-3" strokeWidth={2} />
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
