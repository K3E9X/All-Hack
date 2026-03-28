import { useState, useEffect } from 'react';
import axios from 'axios';
import { CpuChipIcon, CheckCircleIcon, ClockIcon, XCircleIcon } from '@heroicons/react/24/outline';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

export default function AgentStatus({ scanId }) {
  const [workflow, setWorkflow] = useState(null);
  const [agents, setAgents] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchWorkflowStatus = async () => {
      try {
        const response = await axios.get(`${API_BASE}/agents/scan/${scanId}/workflow`);
        setWorkflow(response.data.workflow);
        setAgents(response.data.agents);
        setLoading(false);
      } catch (error) {
        console.error('Failed to fetch workflow status:', error);
        setLoading(false);
      }
    };

    fetchWorkflowStatus();
    const interval = setInterval(fetchWorkflowStatus, 3000);

    return () => clearInterval(interval);
  }, [scanId]);

  if (loading) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <div className="flex items-center justify-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500" />
          <span className="ml-3 text-gray-400">Loading workflow status...</span>
        </div>
      </div>
    );
  }

  if (!workflow) {
    return (
      <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
        <p className="text-gray-400">No multi-agent workflow found for this scan.</p>
        <p className="text-sm text-gray-500 mt-2">
          This scan was run in standard mode. Use AI Agent Scan to enable multi-agent workflow.
        </p>
      </div>
    );
  }

  const getPhaseIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="w-5 h-5 text-green-500" />;
      case 'in_progress':
        return <ClockIcon className="w-5 h-5 text-yellow-500 animate-pulse" />;
      case 'failed':
        return <XCircleIcon className="w-5 h-5 text-red-500" />;
      default:
        return <div className="w-5 h-5 rounded-full border-2 border-gray-600" />;
    }
  };

  const phases = [
    { id: 'recon', name: 'Reconnaissance', code: 'RCN' },
    { id: 'exploitation', name: 'Exploitation', code: 'EXP' },
    { id: 'validation', name: 'Validation', code: 'VAL' },
    { id: 'analysis', name: 'Analysis', code: 'ANL' },
    { id: 'reporting', name: 'Reporting', code: 'RPT' },
  ];

  return (
    <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
      <div className="flex items-center mb-6">
        <CpuChipIcon className="w-6 h-6 mr-2 text-purple-400" />
        <h3 className="text-2xl font-semibold">Multi-Agent Workflow</h3>
      </div>

      {/* Current Phase */}
      <div className="mb-6 p-4 bg-gray-700 rounded-lg">
        <p className="text-sm text-gray-400 mb-1">Current Phase</p>
        <p className="text-xl font-semibold">
          [{phases.find((p) => p.id === workflow.current_phase)?.code}]{' '}
          {workflow.current_phase.charAt(0).toUpperCase() + workflow.current_phase.slice(1)}
        </p>
      </div>

      {/* Workflow Timeline */}
      <div className="space-y-3">
        {phases.map((phase, idx) => {
          const phaseData = workflow.phases[phase.id];
          const isActive = workflow.current_phase === phase.id;

          return (
            <div
              key={phase.id}
              className={`flex items-center p-4 rounded-lg ${
                isActive ? 'bg-purple-900 bg-opacity-30 border border-purple-700' : 'bg-gray-750'
              }`}
            >
              <div className="flex items-center flex-1">
                <span className="text-xs font-mono mr-3 px-2 py-1 border border-current">[{phase.code}]</span>
                <div className="flex-1">
                  <p className="font-semibold">{phase.name}</p>
                  <p className="text-sm text-gray-400">Agent: {phaseData.agent}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {getPhaseIcon(phaseData.status)}
                <span className="text-sm capitalize">{phaseData.status.replace('_', ' ')}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Agent States */}
      <div className="mt-6 pt-6 border-t border-gray-700">
        <h4 className="font-semibold mb-3">Agent States</h4>
        <div className="grid grid-cols-2 gap-3">
          {Object.entries(agents).map(([agentId, state]) => (
            <div key={agentId} className="p-3 bg-gray-750 rounded">
              <p className="text-sm font-semibold capitalize">{agentId}</p>
              <p className="text-xs text-gray-400">Queue: {state.queue_size} messages</p>
            </div>
          ))}
        </div>
      </div>

      {/* Statistics */}
      <div className="mt-6 grid grid-cols-2 gap-4">
        <div className="p-4 bg-gray-750 rounded-lg">
          <p className="text-sm text-gray-400">Findings</p>
          <p className="text-2xl font-semibold">{workflow.findings_count}</p>
        </div>
        <div className="p-4 bg-gray-750 rounded-lg">
          <p className="text-sm text-gray-400">Errors</p>
          <p className="text-2xl font-semibold">{workflow.errors_count}</p>
        </div>
      </div>
    </div>
  );
}
