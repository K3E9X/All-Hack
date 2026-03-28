import { useState, useEffect } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import { Save, Key, Palette, Sliders, CheckCircle, AlertCircle, Bot, Plus, Trash2, RefreshCw } from 'lucide-react';
import clsx from 'clsx';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

const PROVIDER_TYPES = [
  { value: 'openai', label: 'OpenAI', hint: 'GPT-4o, GPT-4' },
  { value: 'groq', label: 'Groq', hint: 'Llama 3.1 (Fast)' },
  { value: 'grok', label: 'Grok (xAI)', hint: 'Grok Beta' },
  { value: 'ollama', label: 'Ollama', hint: 'Local LLM' },
  { value: 'qwen', label: 'Qwen (DashScope)', hint: 'Qwen Plus' },
  { value: 'anthropic', label: 'Anthropic', hint: 'Claude' },
  { value: 'together', label: 'Together.ai', hint: 'Open models' },
  { value: 'openrouter', label: 'OpenRouter', hint: 'Multi-provider' },
];

const CONSENSUS_MODES = [
  { value: 'single', label: 'Single', desc: 'Use primary only' },
  { value: 'fallback', label: 'Fallback', desc: 'Try next on failure' },
  { value: 'voting', label: 'Voting', desc: 'Majority decision' },
  { value: 'weighted', label: 'Weighted', desc: 'By confidence/speed' },
  { value: 'all', label: 'All', desc: 'Combine all responses' },
];

export default function SettingsView() {
  const { theme, setTheme } = useTheme();
  const [settings, setSettings] = useState({
    groq_api_key: '',
    dashscope_api_key: '',
    openrouter_api_key: '',
    default_depth: 'balanced',
    auto_exploit: true,
    validate_findings: true,
    agent_enabled: true
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);

  // Multi-agent state
  const [providers, setProviders] = useState([]);
  const [newProvider, setNewProvider] = useState({ name: '', type: 'groq', api_key: '', model: '', role: 'general' });
  const [consensusMode, setConsensusMode] = useState('fallback');
  const [primaryProvider, setPrimaryProvider] = useState('');
  const [checkingProviders, setCheckingProviders] = useState(false);

  useEffect(() => {
    fetchSettings();
    fetchMultiAgentStatus();
  }, []);

  const fetchSettings = async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/settings`);
      if (response.ok) {
        const data = await response.json();
        setSettings(prev => ({ ...prev, ...data }));
      }
    } catch (err) {
      // Settings endpoint might not exist yet
    }
  };

  const fetchMultiAgentStatus = async () => {
    try {
      const response = await fetch(`${API_URL}/api/v1/multi-agent/status`);
      if (response.ok) {
        const data = await response.json();
        setProviders(data.providers || []);
        setConsensusMode(data.consensus_mode || 'fallback');
        setPrimaryProvider(data.primary_provider || '');
      }
    } catch (err) {
      // Multi-agent endpoint might not exist yet
    }
  };

  const addProvider = async () => {
    if (!newProvider.name || !newProvider.type) return;

    try {
      const response = await fetch(`${API_URL}/api/v1/multi-agent/providers`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(newProvider)
      });

      if (response.ok) {
        setNewProvider({ name: '', type: 'groq', api_key: '', model: '', role: 'general' });
        fetchMultiAgentStatus();
      }
    } catch (err) {
      setError('Failed to add provider');
    }
  };

  const removeProvider = async (name) => {
    try {
      await fetch(`${API_URL}/api/v1/multi-agent/providers/${name}`, { method: 'DELETE' });
      fetchMultiAgentStatus();
    } catch (err) {
      setError('Failed to remove provider');
    }
  };

  const checkProviders = async () => {
    setCheckingProviders(true);
    try {
      const response = await fetch(`${API_URL}/api/v1/multi-agent/providers/check`, { method: 'POST' });
      if (response.ok) {
        fetchMultiAgentStatus();
      }
    } catch (err) {
      // ignore
    } finally {
      setCheckingProviders(false);
    }
  };

  const updateConsensusMode = async (mode) => {
    try {
      await fetch(`${API_URL}/api/v1/multi-agent/set-consensus-mode/${mode}`, { method: 'POST' });
      setConsensusMode(mode);
    } catch (err) {
      setError('Failed to update consensus mode');
    }
  };

  const updatePrimaryProvider = async (name) => {
    try {
      await fetch(`${API_URL}/api/v1/multi-agent/set-primary/${name}`, { method: 'POST' });
      setPrimaryProvider(name);
    } catch (err) {
      setError('Failed to set primary provider');
    }
  };

  const saveSettings = async () => {
    setSaving(true);
    setError(null);
    setSaved(false);

    try {
      const response = await fetch(`${API_URL}/api/v1/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings)
      });

      if (response.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 3000);
      } else {
        throw new Error('Failed to save');
      }
    } catch (err) {
      setError('Failed to save settings. Backend might not support this yet.');
    } finally {
      setSaving(false);
    }
  };

  const updateSetting = (key, value) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  };

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <header className="flex items-center justify-between px-6 h-14 border-b border-border bg-background">
        <h1 className="text-lg font-semibold">Settings</h1>
        <button
          onClick={saveSettings}
          disabled={saving}
          className="btn btn-primary"
        >
          {saving ? (
            <span className="animate-spin w-4 h-4 border-2 border-white border-t-transparent rounded-full mr-2" />
          ) : saved ? (
            <CheckCircle className="w-4 h-4 mr-2" />
          ) : (
            <Save className="w-4 h-4 mr-2" />
          )}
          {saved ? 'Saved' : 'Save'}
        </button>
      </header>

      {/* Settings Content */}
      <div className="flex-1 overflow-y-auto p-6 bg-surface">
        <div className="max-w-2xl mx-auto space-y-8">
          {error && (
            <div className="flex items-center gap-2 p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400">
              <AlertCircle className="w-5 h-5" />
              {error}
            </div>
          )}

          {/* Appearance */}
          <section className="card p-6">
            <div className="flex items-center gap-3 mb-4">
              <Palette className="w-5 h-5 text-accent" />
              <h2 className="font-semibold">Appearance</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Theme</label>
                <div className="flex gap-3">
                  {['light', 'dark', 'system'].map((t) => (
                    <button
                      key={t}
                      onClick={() => setTheme(t)}
                      className={clsx(
                        'px-4 py-2 rounded-lg border capitalize transition-colors',
                        theme === t
                          ? 'border-accent bg-accent/10 text-accent'
                          : 'border-border hover:border-accent/50'
                      )}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </section>

          {/* API Keys */}
          <section className="card p-6">
            <div className="flex items-center gap-3 mb-4">
              <Key className="w-5 h-5 text-accent" />
              <h2 className="font-semibold">API Keys</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1.5">
                  Groq API Key
                  <span className="text-secondary font-normal ml-2">(Recommended)</span>
                </label>
                <input
                  type="password"
                  value={settings.groq_api_key}
                  onChange={(e) => updateSetting('groq_api_key', e.target.value)}
                  placeholder="gsk_..."
                  className="w-full px-3 py-2 rounded-lg border border-border bg-surface font-mono text-sm"
                />
                <p className="text-xs text-secondary mt-1">
                  Free at console.groq.com - 30 requests/minute
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1.5">
                  DashScope API Key
                  <span className="text-secondary font-normal ml-2">(Qwen)</span>
                </label>
                <input
                  type="password"
                  value={settings.dashscope_api_key}
                  onChange={(e) => updateSetting('dashscope_api_key', e.target.value)}
                  placeholder="sk-..."
                  className="w-full px-3 py-2 rounded-lg border border-border bg-surface font-mono text-sm"
                />
                <p className="text-xs text-secondary mt-1">
                  Free at dashscope.aliyun.com - 1M tokens/month
                </p>
              </div>

              <div>
                <label className="block text-sm font-medium mb-1.5">
                  OpenRouter API Key
                </label>
                <input
                  type="password"
                  value={settings.openrouter_api_key}
                  onChange={(e) => updateSetting('openrouter_api_key', e.target.value)}
                  placeholder="sk-or-..."
                  className="w-full px-3 py-2 rounded-lg border border-border bg-surface font-mono text-sm"
                />
              </div>
            </div>
          </section>

          {/* Multi-Agent Configuration */}
          <section className="card p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <Bot className="w-5 h-5 text-accent" />
                <h2 className="font-semibold">Multi-Agent LLM</h2>
              </div>
              <button
                onClick={checkProviders}
                disabled={checkingProviders}
                className="flex items-center gap-1 text-sm text-secondary hover:text-primary"
              >
                <RefreshCw className={clsx('w-4 h-4', checkingProviders && 'animate-spin')} />
                Check All
              </button>
            </div>

            <p className="text-sm text-secondary mb-4">
              Configure multiple LLM providers for consensus-based security decisions.
            </p>

            {/* Consensus Mode */}
            <div className="mb-6">
              <label className="block text-sm font-medium mb-2">Consensus Mode</label>
              <div className="grid grid-cols-5 gap-2">
                {CONSENSUS_MODES.map((mode) => (
                  <button
                    key={mode.value}
                    onClick={() => updateConsensusMode(mode.value)}
                    className={clsx(
                      'p-2 rounded-lg border text-center transition-colors',
                      consensusMode === mode.value
                        ? 'border-accent bg-accent/10 text-accent'
                        : 'border-border hover:border-accent/50'
                    )}
                  >
                    <div className="text-sm font-medium">{mode.label}</div>
                    <div className="text-xs text-secondary">{mode.desc}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Active Providers */}
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">
                Active Providers ({providers.length})
              </label>
              {providers.length === 0 ? (
                <p className="text-sm text-secondary p-4 rounded-lg bg-background border border-border">
                  No providers configured. Add one below.
                </p>
              ) : (
                <div className="space-y-2">
                  {providers.map((provider) => (
                    <div
                      key={provider.name}
                      className="flex items-center justify-between p-3 rounded-lg bg-background border border-border"
                    >
                      <div className="flex items-center gap-3">
                        <div className={clsx(
                          'w-2 h-2 rounded-full',
                          provider.available ? 'bg-green-400' : 'bg-red-400'
                        )} />
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{provider.name}</span>
                            {primaryProvider === provider.name && (
                              <span className="text-xs px-1.5 py-0.5 rounded bg-accent/20 text-accent">Primary</span>
                            )}
                          </div>
                          <div className="text-xs text-secondary">
                            {provider.type} / {provider.model} / {provider.role}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {primaryProvider !== provider.name && (
                          <button
                            onClick={() => updatePrimaryProvider(provider.name)}
                            className="text-xs text-secondary hover:text-accent"
                          >
                            Set Primary
                          </button>
                        )}
                        <button
                          onClick={() => removeProvider(provider.name)}
                          className="p-1 text-secondary hover:text-red-400"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Add New Provider */}
            <div className="p-4 rounded-lg bg-background border border-border">
              <div className="flex items-center gap-2 mb-3">
                <Plus className="w-4 h-4 text-secondary" />
                <span className="text-sm font-medium">Add Provider</span>
              </div>

              <div className="grid grid-cols-2 gap-3 mb-3">
                <input
                  type="text"
                  placeholder="Name (e.g., primary-gpt)"
                  value={newProvider.name}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, name: e.target.value }))}
                  className="px-3 py-2 rounded-lg border border-border bg-surface text-sm"
                />
                <select
                  value={newProvider.type}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, type: e.target.value }))}
                  className="px-3 py-2 rounded-lg border border-border bg-surface text-sm"
                >
                  {PROVIDER_TYPES.map((pt) => (
                    <option key={pt.value} value={pt.value}>{pt.label} - {pt.hint}</option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3 mb-3">
                <input
                  type="password"
                  placeholder="API Key"
                  value={newProvider.api_key}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, api_key: e.target.value }))}
                  className="px-3 py-2 rounded-lg border border-border bg-surface text-sm font-mono"
                />
                <input
                  type="text"
                  placeholder="Model (optional, uses default)"
                  value={newProvider.model}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, model: e.target.value }))}
                  className="px-3 py-2 rounded-lg border border-border bg-surface text-sm"
                />
              </div>

              <div className="flex items-center gap-3">
                <select
                  value={newProvider.role}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, role: e.target.value }))}
                  className="px-3 py-2 rounded-lg border border-border bg-surface text-sm"
                >
                  <option value="general">General</option>
                  <option value="analyst">Analyst</option>
                  <option value="payload_gen">Payload Generator</option>
                  <option value="validator">Validator</option>
                </select>
                <button
                  onClick={addProvider}
                  disabled={!newProvider.name}
                  className="btn btn-primary text-sm disabled:opacity-50"
                >
                  <Plus className="w-4 h-4 mr-1" />
                  Add
                </button>
              </div>
            </div>
          </section>

          {/* Scan Preferences */}
          <section className="card p-6">
            <div className="flex items-center gap-3 mb-4">
              <Sliders className="w-5 h-5 text-accent" />
              <h2 className="font-semibold">Scan Preferences</h2>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-2">Default Scan Depth</label>
                <select
                  value={settings.default_depth}
                  onChange={(e) => updateSetting('default_depth', e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-border bg-surface"
                >
                  <option value="quick">Quick - Fast surface scan</option>
                  <option value="balanced">Balanced - Recommended</option>
                  <option value="deep">Deep - Thorough analysis</option>
                </select>
              </div>

              <div className="flex items-center justify-between py-2">
                <div>
                  <p className="font-medium">Auto Exploit</p>
                  <p className="text-sm text-secondary">Automatically attempt exploitation</p>
                </div>
                <button
                  onClick={() => updateSetting('auto_exploit', !settings.auto_exploit)}
                  className={clsx(
                    'w-12 h-6 rounded-full transition-colors',
                    settings.auto_exploit ? 'bg-accent' : 'bg-border'
                  )}
                >
                  <span className={clsx(
                    'block w-5 h-5 rounded-full bg-white shadow transition-transform',
                    settings.auto_exploit ? 'translate-x-6' : 'translate-x-0.5'
                  )} />
                </button>
              </div>

              <div className="flex items-center justify-between py-2">
                <div>
                  <p className="font-medium">Validate Findings</p>
                  <p className="text-sm text-secondary">Reduce false positives with strict validation</p>
                </div>
                <button
                  onClick={() => updateSetting('validate_findings', !settings.validate_findings)}
                  className={clsx(
                    'w-12 h-6 rounded-full transition-colors',
                    settings.validate_findings ? 'bg-accent' : 'bg-border'
                  )}
                >
                  <span className={clsx(
                    'block w-5 h-5 rounded-full bg-white shadow transition-transform',
                    settings.validate_findings ? 'translate-x-6' : 'translate-x-0.5'
                  )} />
                </button>
              </div>

              <div className="flex items-center justify-between py-2">
                <div>
                  <p className="font-medium">Agent Enabled</p>
                  <p className="text-sm text-secondary">Enable AI agent for intelligent scanning</p>
                </div>
                <button
                  onClick={() => updateSetting('agent_enabled', !settings.agent_enabled)}
                  className={clsx(
                    'w-12 h-6 rounded-full transition-colors',
                    settings.agent_enabled ? 'bg-accent' : 'bg-border'
                  )}
                >
                  <span className={clsx(
                    'block w-5 h-5 rounded-full bg-white shadow transition-transform',
                    settings.agent_enabled ? 'translate-x-6' : 'translate-x-0.5'
                  )} />
                </button>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
