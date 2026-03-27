import { useState, useEffect } from 'react';
import { useTheme } from '../contexts/ThemeContext';
import { Save, Key, Palette, Sliders, CheckCircle, AlertCircle } from 'lucide-react';
import clsx from 'clsx';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

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

  useEffect(() => {
    fetchSettings();
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
