import { createContext, useContext, useState, useCallback } from 'react';

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  // Global target shared across all tabs
  const [globalTarget, setGlobalTarget] = useState('');

  // Results storage by tab/module
  const [scanResults, setScanResults] = useState({
    attack: null,      // Main attack console results
    recon: null,       // Recon page results
    tools: null,       // Tools page results
    agent: null,       // Agent page results
  });

  // Scan status by tab
  const [scanStatus, setScanStatus] = useState({
    attack: { running: false, progress: 0, phase: 'idle' },
    recon: { running: false, progress: 0, phase: 'idle' },
    tools: { running: false, progress: 0, phase: 'idle' },
    agent: { running: false, progress: 0, phase: 'idle' },
  });

  // Console events (shared)
  const [events, setEvents] = useState([]);

  // Update results for a specific tab
  const updateResults = useCallback((tab, results) => {
    setScanResults(prev => ({ ...prev, [tab]: results }));
  }, []);

  // Update status for a specific tab
  const updateStatus = useCallback((tab, status) => {
    setScanStatus(prev => ({
      ...prev,
      [tab]: { ...prev[tab], ...status }
    }));
  }, []);

  // Add event to console
  const addEvent = useCallback((phase, message, type = 'info') => {
    const event = {
      id: Date.now() + Math.random(),
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      phase,
      message,
      type
    };
    setEvents(prev => [...prev.slice(-500), event]);
  }, []);

  // Clear events
  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  // Launch scan on all tabs (parallel)
  const launchGlobalScan = useCallback(async (target) => {
    setGlobalTarget(target);
    // This will be implemented by each tab listening to globalTarget changes
    // and launching their own scans
  }, []);

  const value = {
    globalTarget,
    setGlobalTarget,
    scanResults,
    updateResults,
    scanStatus,
    updateStatus,
    events,
    addEvent,
    clearEvents,
    launchGlobalScan,
  };

  return (
    <ScanContext.Provider value={value}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScan must be used within a ScanProvider');
  }
  return context;
}

export default ScanContext;
