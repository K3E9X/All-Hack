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
  { path: '/', icon: Crosshair, label: 'SCAN', exact: true },
  { path: '/recon', icon: Radar, label: 'RECON' },
  { path: '/tools', icon: Wrench, label: 'TOOLS' },
  { path: '/agent', icon: Bot, label: 'OPENCLAW' },
  { path: '/history', icon: History, label: 'HISTORY' },
  { path: '/chat', icon: MessageSquare, label: 'CHAT' },
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
        <div className="flex items-center h-12 px-3 border-b border-border">
          <Terminal className="w-5 h-5 text-accent shrink-0" />
          {!collapsed && (
            <span className="ml-2 font-medium text-sm tracking-wider text-accent">
              ALL-HACK
            </span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-2 px-1">
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
                    'flex items-center px-2 py-2 transition-colors text-xs',
                    'hover:bg-hover border-l-2',
                    isActive
                      ? 'border-accent text-accent bg-hover'
                      : 'border-transparent text-secondary hover:text-primary hover:border-border'
                  )
                }
              >
                <div className="relative">
                  <Icon className="w-4 h-4 shrink-0" strokeWidth={1.5} />
                  {isModuleRunning && (
                    <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 bg-accent" />
                  )}
                </div>
                {!collapsed && <span className="ml-2 tracking-wide">{label}</span>}
              </NavLink>
            );
          })}
        </nav>

        {/* Bottom */}
        <div className="px-1 py-2 border-t border-border">
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              clsx(
                'flex items-center px-2 py-2 transition-colors text-xs',
                'hover:bg-hover border-l-2',
                isActive
                  ? 'border-accent text-accent bg-hover'
                  : 'border-transparent text-secondary hover:text-primary'
              )
            }
          >
            <Settings className="w-4 h-4 shrink-0" strokeWidth={1.5} />
            {!collapsed && <span className="ml-2 tracking-wide">SETTINGS</span>}
          </NavLink>

          <button
            onClick={toggleTheme}
            className="flex items-center w-full px-2 py-2 transition-colors hover:bg-hover text-secondary hover:text-primary text-xs border-l-2 border-transparent"
          >
            {theme === 'dark' ? (
              <Sun className="w-4 h-4 shrink-0" strokeWidth={1.5} />
            ) : (
              <Moon className="w-4 h-4 shrink-0" strokeWidth={1.5} />
            )}
            {!collapsed && (
              <span className="ml-2 tracking-wide">
                {theme === 'dark' ? 'LIGHT' : 'DARK'}
              </span>
            )}
          </button>

          <button
            onClick={() => setCollapsed(!collapsed)}
            className="flex items-center w-full px-2 py-2 transition-colors hover:bg-hover text-secondary hover:text-primary text-xs border-l-2 border-transparent"
          >
            {collapsed ? (
              <ChevronRight className="w-4 h-4 shrink-0" strokeWidth={1.5} />
            ) : (
              <>
                <ChevronLeft className="w-4 h-4 shrink-0" strokeWidth={1.5} />
                <span className="ml-2 tracking-wide">COLLAPSE</span>
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
