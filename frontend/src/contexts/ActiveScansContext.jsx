import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

const ActiveScansContext = createContext(null);

export function ActiveScansProvider({ children }) {
  // All active scans across all modules
  const [activeScans, setActiveScans] = useState([]);

  // Scan results cache (persists when navigating between tabs)
  const [scanCache, setScanCache] = useState({
    // scan_id -> { results, lastUpdated }
  });

  // Module-specific states (persists between tab navigation)
  const [moduleStates, setModuleStates] = useState({
    scan: { target: '', results: null, running: false, progress: 0, phase: 'idle', scanId: null },
    recon: { target: '', results: null, running: false, progress: 0, phase: 'idle' },
    tools: { results: {}, running: false },
    agent: { target: '', results: null, running: false, progress: 0, phase: 'idle', scanId: null },
  });

  // Console events (global)
  const [events, setEvents] = useState([]);

  // Polling interval ref
  const pollRef = useRef(null);

  // Fetch active scans from backend
  const fetchActiveScans = useCallback(async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/scans/active`);
      if (response.ok) {
        const data = await response.json();
        setActiveScans(data.active_scans || []);

        // Update module states based on active scans
        data.active_scans?.forEach(scan => {
          const module = scan.module || 'scan';
          setModuleStates(prev => ({
            ...prev,
            [module]: {
              ...prev[module],
              running: true,
              progress: scan.progress || 0,
              phase: scan.phase || 'scanning',
              scanId: scan.scan_id
            }
          }));
        });
      }
    } catch (error) {
      console.error('Failed to fetch active scans:', error);
    }
  }, []);

  // Poll for active scans
  useEffect(() => {
    fetchActiveScans();
    pollRef.current = setInterval(fetchActiveScans, 3000);
    return () => clearInterval(pollRef.current);
  }, [fetchActiveScans]);

  // Update module state
  const updateModuleState = useCallback((module, updates) => {
    setModuleStates(prev => ({
      ...prev,
      [module]: { ...prev[module], ...updates }
    }));
  }, []);

  // Cache scan results
  const cacheResults = useCallback((scanId, results) => {
    setScanCache(prev => ({
      ...prev,
      [scanId]: { results, lastUpdated: Date.now() }
    }));
  }, []);

  // Get cached results
  const getCachedResults = useCallback((scanId) => {
    return scanCache[scanId]?.results || null;
  }, [scanCache]);

  // Add event to console (global)
  const addEvent = useCallback((module, phase, message, type = 'info', data = null) => {
    const event = {
      id: Date.now() + Math.random(),
      time: new Date().toLocaleTimeString('en-US', { hour12: false }),
      module,
      phase,
      message,
      type,
      data
    };
    setEvents(prev => [...prev.slice(-500), event]);
  }, []);

  // Clear events
  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  // Start a scan and track it
  const startScan = useCallback(async (module, target, scanFn) => {
    updateModuleState(module, { target, running: true, progress: 0, phase: 'starting' });
    addEvent(module, 'start', `Starting ${module} scan for ${target}`, 'info');

    try {
      const result = await scanFn();
      updateModuleState(module, {
        results: result,
        running: false,
        progress: 100,
        phase: 'completed',
        scanId: result?.scan_id || null
      });
      if (result?.scan_id) {
        cacheResults(result.scan_id, result);
      }
      addEvent(module, 'complete', `${module} scan completed`, 'success');
      return result;
    } catch (error) {
      updateModuleState(module, { running: false, phase: 'error' });
      addEvent(module, 'error', `${module} scan failed: ${error.message}`, 'error');
      throw error;
    }
  }, [updateModuleState, addEvent, cacheResults]);

  // Stop a scan
  const stopScan = useCallback(async (module, scanId) => {
    try {
      await fetch(`${API_URL}/api/v1/scans/${scanId}/stop`, { method: 'POST' });
      updateModuleState(module, { running: false, phase: 'stopped' });
      addEvent(module, 'stop', `${module} scan stopped`, 'warning');
    } catch (error) {
      console.error('Failed to stop scan:', error);
    }
  }, [updateModuleState, addEvent]);

  const value = {
    activeScans,
    moduleStates,
    updateModuleState,
    scanCache,
    cacheResults,
    getCachedResults,
    events,
    addEvent,
    clearEvents,
    startScan,
    stopScan,
    fetchActiveScans,
  };

  return (
    <ActiveScansContext.Provider value={value}>
      {children}
    </ActiveScansContext.Provider>
  );
}

export function useActiveScans() {
  const context = useContext(ActiveScansContext);
  if (!context) {
    throw new Error('useActiveScans must be used within ActiveScansProvider');
  }
  return context;
}

export default ActiveScansContext;
