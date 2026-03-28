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
  { value: 'codex_iliad', label: 'Codex Iliad', hint: 'Devstral, Qwen 397B' },
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
    codex_iliad_api_key: '',
    default_depth: 'balanced',
    auto_exploit: true,
    validate_findings: true,
    agent_enabled: true
  });
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState(null);

  // Track originally configured keys (to know whether to preserve them)
  const [originalKeys, setOriginalKeys] = useState({ groq: false, dashscope: false, openrouter: false, codex_iliad: false });

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
        // Track which keys are already configured
        setOriginalKeys({
          groq: data.groq_api_key === '***',
          dashscope: data.dashscope_api_key === '***',
          openrouter: data.openrouter_api_key === '***',
          codex_iliad: data.codex_iliad_api_key === '***'
        });
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
      // Prepare settings - keep "***" for configured keys that weren't changed
      const settingsToSave = { ...settings };

      // If the input is empty but was originally "***", send "***" to keep existing key
      if (!settingsToSave.groq_api_key && originalKeys.groq) {
        settingsToSave.groq_api_key = '***';
      }
      if (!settingsToSave.dashscope_api_key && originalKeys.dashscope) {
        settingsToSave.dashscope_api_key = '***';
      }
      if (!settingsToSave.openrouter_api_key && originalKeys.openrouter) {
        settingsToSave.openrouter_api_key = '***';
      }
      if (!settingsToSave.codex_iliad_api_key && originalKeys.codex_iliad) {
        settingsToSave.codex_iliad_api_key = '***';
      }

      const response = await fetch(`${API_URL}/api/v1/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settingsToSave)
      });

      if (response.ok) {
        setSaved(true);
        setTimeout(() => setSaved(false), 3000);
        // Refresh to get updated masked keys
        fetchSettings();
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
      <header className="flex items-center justify-between px-4 h-10 border-b border-border bg-surface">
        <h1 className="text-xs font-medium tracking-wider uppercase">SETTINGS</h1>
        <button
          onClick={saveSettings}
          disabled={saving}
          className="btn btn-primary text-xs py-1 px-2"
        >
          {saving ? (
            <span className="animate-spin w-3 h-3 border border-background border-t-transparent mr-1" />
          ) : saved ? (
            <CheckCircle className="w-3 h-3 mr-1" />
          ) : (
            <Save className="w-3 h-3 mr-1" />
          )}
          {saved ? 'SAVED' : 'SAVE'}
        </button>
      </header>

      {/* Settings Content */}
      <div className="flex-1 overflow-y-auto p-4 bg-background">
        <div className="max-w-2xl mx-auto space-y-6">
          {error && (
            <div className="flex items-center gap-2 p-2 bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
              <AlertCircle className="w-3 h-3" />
              {error}
            </div>
          )}

          {/* Appearance */}
          <section className="p-4 border border-border bg-surface">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-xs text-accent font-mono">[THM]</span>
              <h2 className="text-sm font-medium uppercase">Appearance</h2>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium mb-2 uppercase">Theme</label>
                <div className="flex gap-2">
                  {['light', 'dark', 'system'].map((t) => (
                    <button
                      key={t}
                      onClick={() => setTheme(t)}
                      className={clsx(
                        'px-3 py-1.5 border text-xs uppercase transition-colors',
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
          <section className="p-4 border border-border bg-surface">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-xs text-accent font-mono">[KEY]</span>
              <h2 className="text-sm font-medium uppercase">API Keys</h2>
            </div>

            <p className="text-xs text-secondary mb-3">
              Keys saved securely. Green = configured.
            </p>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium mb-1 flex items-center gap-2 uppercase">
                  Groq
                  {settings.groq_api_key === '***' && (
                    <span className="text-green-400 flex items-center gap-0.5">
                      <CheckCircle className="w-2.5 h-2.5" />
                    </span>
                  )}
                </label>
                <input
                  type="password"
                  value={settings.groq_api_key === '***' ? '' : settings.groq_api_key}
                  onChange={(e) => updateSetting('groq_api_key', e.target.value)}
                  placeholder={settings.groq_api_key === '***' ? '(configured)' : 'gsk_...'}
                  className={clsx(
                    'w-full px-2 py-1.5 border bg-background font-mono text-xs',
                    settings.groq_api_key === '***' ? 'border-green-500/30' : 'border-border'
                  )}
                />
              </div>

              <div>
                <label className="block text-xs font-medium mb-1 flex items-center gap-2 uppercase">
                  DashScope (Qwen)
                  {settings.dashscope_api_key === '***' && (
                    <span className="text-green-400 flex items-center gap-0.5">
                      <CheckCircle className="w-2.5 h-2.5" />
                    </span>
                  )}
                </label>
                <input
                  type="password"
                  value={settings.dashscope_api_key === '***' ? '' : settings.dashscope_api_key}
                  onChange={(e) => updateSetting('dashscope_api_key', e.target.value)}
                  placeholder={settings.dashscope_api_key === '***' ? '(configured)' : 'sk-...'}
                  className={clsx(
                    'w-full px-2 py-1.5 border bg-background font-mono text-xs',
                    settings.dashscope_api_key === '***' ? 'border-green-500/30' : 'border-border'
                  )}
                />
              </div>

              <div>
                <label className="block text-xs font-medium mb-1 flex items-center gap-2 uppercase">
                  OpenRouter
                  {settings.openrouter_api_key === '***' && (
                    <span className="text-green-400 flex items-center gap-0.5">
                      <CheckCircle className="w-2.5 h-2.5" />
                    </span>
                  )}
                </label>
                <input
                  type="password"
                  value={settings.openrouter_api_key === '***' ? '' : settings.openrouter_api_key}
                  onChange={(e) => updateSetting('openrouter_api_key', e.target.value)}
                  placeholder={settings.openrouter_api_key === '***' ? '(configured)' : 'sk-or-...'}
                  className={clsx(
                    'w-full px-2 py-1.5 border bg-background font-mono text-xs',
                    settings.openrouter_api_key === '***' ? 'border-green-500/30' : 'border-border'
                  )}
                />
              </div>

              <div>
                <label className="block text-xs font-medium mb-1 flex items-center gap-2 uppercase">
                  Codex Iliad
                  {settings.codex_iliad_api_key === '***' && (
                    <span className="text-green-400 flex items-center gap-0.5">
                      <CheckCircle className="w-2.5 h-2.5" />
                    </span>
                  )}
                </label>
                <input
                  type="password"
                  value={settings.codex_iliad_api_key === '***' ? '' : settings.codex_iliad_api_key}
                  onChange={(e) => updateSetting('codex_iliad_api_key', e.target.value)}
                  placeholder={settings.codex_iliad_api_key === '***' ? '(configured)' : 'sk-...'}
                  className={clsx(
                    'w-full px-2 py-1.5 border bg-background font-mono text-xs',
                    settings.codex_iliad_api_key === '***' ? 'border-green-500/30' : 'border-border'
                  )}
                />
              </div>
            </div>
          </section>

          {/* Multi-Agent Configuration */}
          <section className="p-4 border border-border bg-surface">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="text-xs text-accent font-mono">[AGT]</span>
                <h2 className="text-sm font-medium uppercase">Multi-Agent LLM</h2>
              </div>
              <button
                onClick={checkProviders}
                disabled={checkingProviders}
                className="flex items-center gap-1 text-xs text-secondary hover:text-primary"
              >
                <RefreshCw className={clsx('w-3 h-3', checkingProviders && 'animate-spin')} />
              </button>
            </div>

            <p className="text-xs text-secondary mb-3">
              Configure LLM providers for consensus-based decisions.
            </p>

            {/* Consensus Mode */}
            <div className="mb-4">
              <label className="block text-xs font-medium mb-2 uppercase">Consensus Mode</label>
              <div className="grid grid-cols-5 gap-1">
                {CONSENSUS_MODES.map((mode) => (
                  <button
                    key={mode.value}
                    onClick={() => updateConsensusMode(mode.value)}
                    className={clsx(
                      'p-1.5 border text-center transition-colors',
                      consensusMode === mode.value
                        ? 'border-accent bg-accent/10 text-accent'
                        : 'border-border hover:border-accent/50'
                    )}
                  >
                    <div className="text-xs font-medium uppercase">{mode.label}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Active Providers */}
            <div className="mb-3">
              <label className="block text-xs font-medium mb-2 uppercase">
                Providers ({providers.length})
              </label>
              {providers.length === 0 ? (
                <p className="text-xs text-secondary p-2 bg-background border border-border">
                  No providers. Add below.
                </p>
              ) : (
                <div className="space-y-1">
                  {providers.map((provider) => (
                    <div
                      key={provider.name}
                      className="flex items-center justify-between p-2 bg-background border border-border"
                    >
                      <div className="flex items-center gap-2">
                        <div className={clsx(
                          'w-1.5 h-1.5',
                          provider.available ? 'bg-green-400' : 'bg-red-400'
                        )} />
                        <div>
                          <div className="flex items-center gap-1">
                            <span className="text-xs font-medium">{provider.name}</span>
                            {primaryProvider === provider.name && (
                              <span className="text-xs px-1 border border-accent text-accent">1</span>
                            )}
                          </div>
                          <div className="text-xs text-secondary font-mono">
                            {provider.type}/{provider.model}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        {primaryProvider !== provider.name && (
                          <button
                            onClick={() => updatePrimaryProvider(provider.name)}
                            className="text-xs text-secondary hover:text-accent px-1"
                          >
                            [1]
                          </button>
                        )}
                        <button
                          onClick={() => removeProvider(provider.name)}
                          className="p-0.5 text-secondary hover:text-red-400"
                        >
                          <Trash2 className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Add New Provider */}
            <div className="p-2 bg-background border border-border">
              <div className="flex items-center gap-1 mb-2">
                <Plus className="w-3 h-3 text-secondary" />
                <span className="text-xs font-medium uppercase">Add Provider</span>
              </div>

              <div className="grid grid-cols-2 gap-2 mb-2">
                <input
                  type="text"
                  placeholder="Name"
                  value={newProvider.name}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, name: e.target.value }))}
                  className="px-2 py-1.5 border border-border bg-surface text-xs"
                />
                <select
                  value={newProvider.type}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, type: e.target.value }))}
                  className="px-2 py-1.5 border border-border bg-surface text-xs"
                >
                  {PROVIDER_TYPES.map((pt) => (
                    <option key={pt.value} value={pt.value}>{pt.label}</option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-2 mb-2">
                <input
                  type="password"
                  placeholder="API Key"
                  value={newProvider.api_key}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, api_key: e.target.value }))}
                  className="px-2 py-1.5 border border-border bg-surface text-xs font-mono"
                />
                <input
                  type="text"
                  placeholder="Model (optional)"
                  value={newProvider.model}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, model: e.target.value }))}
                  className="px-2 py-1.5 border border-border bg-surface text-xs"
                />
              </div>

              <div className="flex items-center gap-2">
                <select
                  value={newProvider.role}
                  onChange={(e) => setNewProvider(prev => ({ ...prev, role: e.target.value }))}
                  className="px-2 py-1.5 border border-border bg-surface text-xs"
                >
                  <option value="general">General</option>
                  <option value="analyst">Analyst</option>
                  <option value="payload_gen">Payload Gen</option>
                  <option value="validator">Validator</option>
                </select>
                <button
                  onClick={addProvider}
                  disabled={!newProvider.name}
                  className="btn btn-primary text-xs py-1 px-2 disabled:opacity-50"
                >
                  <Plus className="w-3 h-3 mr-0.5" />
                  ADD
                </button>
              </div>
            </div>
          </section>

          {/* Scan Preferences */}
          <section className="p-4 border border-border bg-surface">
            <div className="flex items-center gap-2 mb-3">
              <span className="text-xs text-accent font-mono">[SCN]</span>
              <h2 className="text-sm font-medium uppercase">Scan Preferences</h2>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium mb-1 uppercase">Default Depth</label>
                <select
                  value={settings.default_depth}
                  onChange={(e) => updateSetting('default_depth', e.target.value)}
                  className="w-full px-2 py-1.5 border border-border bg-background text-xs uppercase"
                >
                  <option value="quick">Quick</option>
                  <option value="balanced">Balanced</option>
                  <option value="deep">Deep</option>
                </select>
              </div>

              <div className="flex items-center justify-between py-1">
                <div>
                  <p className="text-xs font-medium uppercase">Auto Exploit</p>
                  <p className="text-xs text-secondary">Auto attempt exploitation</p>
                </div>
                <button
                  onClick={() => updateSetting('auto_exploit', !settings.auto_exploit)}
                  className={clsx(
                    'w-8 h-4 transition-colors border',
                    settings.auto_exploit ? 'bg-accent border-accent' : 'bg-background border-border'
                  )}
                >
                  <span className={clsx(
                    'block w-3 h-3 bg-primary transition-transform',
                    settings.auto_exploit ? 'translate-x-4' : 'translate-x-0.5'
                  )} />
                </button>
              </div>

              <div className="flex items-center justify-between py-1">
                <div>
                  <p className="text-xs font-medium uppercase">Validate Findings</p>
                  <p className="text-xs text-secondary">Strict validation</p>
                </div>
                <button
                  onClick={() => updateSetting('validate_findings', !settings.validate_findings)}
                  className={clsx(
                    'w-8 h-4 transition-colors border',
                    settings.validate_findings ? 'bg-accent border-accent' : 'bg-background border-border'
                  )}
                >
                  <span className={clsx(
                    'block w-3 h-3 bg-primary transition-transform',
                    settings.validate_findings ? 'translate-x-4' : 'translate-x-0.5'
                  )} />
                </button>
              </div>

              <div className="flex items-center justify-between py-1">
                <div>
                  <p className="text-xs font-medium uppercase">Agent Enabled</p>
                  <p className="text-xs text-secondary">AI-powered scanning</p>
                </div>
                <button
                  onClick={() => updateSetting('agent_enabled', !settings.agent_enabled)}
                  className={clsx(
                    'w-8 h-4 transition-colors border',
                    settings.agent_enabled ? 'bg-accent border-accent' : 'bg-background border-border'
                  )}
                >
                  <span className={clsx(
                    'block w-3 h-3 bg-primary transition-transform',
                    settings.agent_enabled ? 'translate-x-4' : 'translate-x-0.5'
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
