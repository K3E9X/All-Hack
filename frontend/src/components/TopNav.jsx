import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { api } from '../lib/api.js';

// Canonical nav order (HANDOFF section 1). Text-only, no icons.
const LINKS = [
  { label: 'Home', to: '/' },
  { label: 'Engagements', to: '/engagements' },
  { label: 'Live', to: '/live' },         // resolves to the most-recent engagement
  { label: 'Scans', to: '/scans' },
  { label: 'Findings', to: '/findings' },
  { label: 'Surface', to: '/surface' },
  { label: 'Methodology', to: '/methodology' },
  { label: 'Sandbox', to: '/sandbox' },
  { label: 'Proxy', to: '/proxy' },
  { label: 'Reports', to: '/reports' },
  { label: 'Settings', to: '/settings' },
];

export default function TopNav() {
  // "Live" points at the most-recent engagement's live view.
  const [liveTo, setLiveTo] = useState('/engagements');
  useEffect(() => {
    let alive = true;
    api.engagements.list()
      .then((res) => {
        const items = res?.items || [];
        if (alive && items.length) setLiveTo(`/engagements/${items[0].id}/live`);
      })
      .catch(() => {});
    return () => { alive = false; };
  }, []);

  return (
    <nav className="topnav">
      <span className="topnav__wm">allhack</span>
      <div className="topnav__links">
        {LINKS.map((l) => {
          const to = l.label === 'Live' ? liveTo : l.to;
          return (
            <NavLink
              key={l.label}
              to={to}
              end={l.to === '/'}
              className={({ isActive }) =>
                'topnav__link' + (isActive ? ' topnav__link--active' : '')}
            >
              {l.label}
            </NavLink>
          );
        })}
      </div>
    </nav>
  );
}
