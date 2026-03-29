import { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useTheme } from '../contexts/ThemeContext';
import { useActiveScans } from '../contexts/ActiveScansContext';
import clsx from 'clsx';
import {
  Crosshair,
  Bot,
  History,
  MessageSquare,
  Settings,
  Sun,
  Moon,
  ChevronLeft,
  ChevronRight,
  Terminal,
  Radar,
  Wrench
} from 'lucide-react';

const navItems = [
  { path: '/', icon: Crosshair, label: 'Scan', exact: true },
  { path: '/recon', icon: Radar, label: 'Recon' },
  { path: '/tools', icon: Wrench, label: 'Tools' },
  { path: '/agent', icon: Bot, label: 'OpenClaw' },
  { path: '/history', icon: History, label: 'History' },
  { path: '/chat', icon: MessageSquare, label: 'Chat' },
];

export default function Layout() {
  const { theme, toggleTheme } = useTheme();
  const { moduleStates, activeScans } = useActiveScans();
  const [collapsed, setCollapsed] = useState(false);

  const hasRunningScans = Object.values(moduleStates).some(s => s.running) || activeScans.length > 0;

  return (
    <div className={clsx('flex h-screen bg-background text-primary', hasRunningScans && 'pb-10')}>
      {/* Sidebar */}
      <aside
        className={clsx(
          'flex flex-col border-r border-border bg-surface transition-all duration-150',
          collapsed ? 'w-14' : 'w-48'
        )}
      >
        {/* Logo */}
        <div className="flex items-center h-14 px-4 border-b border-border">
          <div className="w-8 h-8 rounded-lg bg-accent/10 flex items-center justify-center">
            <Terminal className="w-4 h-4 text-accent" />
          </div>
          {!collapsed && (
            <span className="ml-3 font-semibold text-sm text-primary">
              All-Hack
            </span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-3 px-2 space-y-1">
          {navItems.map(({ path, icon: Icon, label, exact }) => {
            const moduleMap = { '/': 'scan', '/recon': 'recon', '/tools': 'tools', '/agent': 'agent' };
            const moduleName = moduleMap[path];
            const isModuleRunning = moduleName && moduleStates[moduleName]?.running;

            return (
              <NavLink
                key={path}
                to={path}
                end={exact}
                className={({ isActive }) =>
                  clsx(
                    'flex items-center px-3 py-2 rounded-lg transition-colors text-sm',
                    isActive
                      ? 'bg-accent/10 text-accent'
                      : 'text-secondary hover:text-primary hover:bg-hover'
                  )
                }
              >
                <div className="relative">
                  <Icon className="w-5 h-5 shrink-0" strokeWidth={1.5} />
                  {isModuleRunning && (
                    <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-accent rounded-full" />
                  )}
                </div>
                {!collapsed && <span className="ml-3 font-medium">{label}</span>}
              </NavLink>
            );
          })}
        </nav>

        {/* Bottom */}
        <div className="px-2 py-3 border-t border-border space-y-1">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              clsx(
                'flex items-center px-3 py-2 rounded-lg transition-colors text-sm',
                isActive
                  ? 'bg-accent/10 text-accent'
                  : 'text-secondary hover:text-primary hover:bg-hover'
              )
            }
          >
            <Settings className="w-5 h-5 shrink-0" strokeWidth={1.5} />
            {!collapsed && <span className="ml-3 font-medium">Settings</span>}
          </NavLink>

          <button
            onClick={toggleTheme}
            className="flex items-center w-full px-3 py-2 rounded-lg transition-colors hover:bg-hover text-secondary hover:text-primary text-sm"
          >
            {theme === 'dark' ? (
              <Sun className="w-5 h-5 shrink-0" strokeWidth={1.5} />
            ) : (
              <Moon className="w-5 h-5 shrink-0" strokeWidth={1.5} />
            )}
            {!collapsed && (
              <span className="ml-3 font-medium">
                {theme === 'dark' ? 'Light' : 'Dark'}
              </span>
            )}
          </button>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="flex items-center w-full px-3 py-2 rounded-lg transition-colors hover:bg-hover text-secondary hover:text-primary text-sm"
          >
            {collapsed ? (
              <ChevronRight className="w-5 h-5 shrink-0" strokeWidth={1.5} />
            ) : (
              <>
                <ChevronLeft className="w-5 h-5 shrink-0" strokeWidth={1.5} />
                <span className="ml-3 font-medium">Collapse</span>
              </>
            )}
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col overflow-hidden bg-background">
        <Outlet />
      </main>
    </div>
  );
}
