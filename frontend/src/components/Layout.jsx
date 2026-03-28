import { useState } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useTheme } from '../contexts/ThemeContext';
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
  Shield,
  Radar,
  Wrench
} from 'lucide-react';

const navItems = [
  { path: '/', icon: Crosshair, label: 'Scan', exact: true },
  { path: '/recon', icon: Radar, label: 'Recon' },
  { path: '/tools', icon: Wrench, label: 'Tools' },
  { path: '/agent', icon: Bot, label: 'Agent' },
  { path: '/history', icon: History, label: 'History' },
  { path: '/chat', icon: MessageSquare, label: 'Chat' },
];

export default function Layout() {
  const { theme, toggleTheme } = useTheme();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <div className="flex h-screen bg-surface text-primary">
      {/* Sidebar */}
      <aside
        className={clsx(
          'flex flex-col border-r border-border bg-background transition-all duration-200',
          collapsed ? 'w-16' : 'w-56'
        )}
      >
        {/* Logo */}
        <div className="flex items-center h-14 px-4 border-b border-border">
          <Shield className="w-6 h-6 text-accent shrink-0" />
          {!collapsed && (
            <span className="ml-3 font-semibold text-lg tracking-tight">
              ALL-HACK
            </span>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-4 px-2 space-y-1">
          {navItems.map(({ path, icon: Icon, label, exact }) => (
            <NavLink
              key={path}
              to={path}
              end={exact}
              className={({ isActive }) =>
                clsx(
                  'flex items-center px-3 py-2.5 rounded-lg transition-colors',
                  'hover:bg-hover',
                  isActive
                    ? 'bg-accent/10 text-accent'
                    : 'text-secondary hover:text-primary'
                )
              }
            >
              <Icon className="w-5 h-5 shrink-0" />
              {!collapsed && <span className="ml-3 text-sm font-medium">{label}</span>}
            </NavLink>
          ))}
        </nav>

        {/* Bottom actions */}
        <div className="p-2 border-t border-border space-y-1">
          {/* Settings */}
          <NavLink
            to="/settings"
            className={({ isActive }) =>
              clsx(
                'flex items-center px-3 py-2.5 rounded-lg transition-colors',
                'hover:bg-hover',
                isActive
                  ? 'bg-accent/10 text-accent'
                  : 'text-secondary hover:text-primary'
              )
            }
          >
            <Settings className="w-5 h-5 shrink-0" />
            {!collapsed && <span className="ml-3 text-sm font-medium">Settings</span>}
          </NavLink>

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            className="flex items-center w-full px-3 py-2.5 rounded-lg transition-colors hover:bg-hover text-secondary hover:text-primary"
          >
            {theme === 'dark' ? (
              <Sun className="w-5 h-5 shrink-0" />
            ) : (
              <Moon className="w-5 h-5 shrink-0" />
            )}
            {!collapsed && (
              <span className="ml-3 text-sm font-medium">
                {theme === 'dark' ? 'Light' : 'Dark'}
              </span>
            )}
          </button>

          {/* Collapse toggle */}
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="flex items-center w-full px-3 py-2.5 rounded-lg transition-colors hover:bg-hover text-secondary hover:text-primary"
          >
            {collapsed ? (
              <ChevronRight className="w-5 h-5 shrink-0" />
            ) : (
              <>
                <ChevronLeft className="w-5 h-5 shrink-0" />
                <span className="ml-3 text-sm font-medium">Collapse</span>
              </>
            )}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <Outlet />
      </main>
    </div>
  );
}
