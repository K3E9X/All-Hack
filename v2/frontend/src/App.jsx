import { NavLink, Outlet } from 'react-router-dom';

export default function App() {
  return (
    <div className="layout">
      <header className="topbar">
        <div className="brand">allhack</div>
        <nav className="nav">
          <NavLink to="/" end>Home</NavLink>
          <NavLink to="/proxy">Proxy</NavLink>
          <NavLink to="/scans">Scans</NavLink>
          <NavLink to="/reports">Reports</NavLink>
        </nav>
      </header>
      <main className="content">
        <Outlet />
      </main>
      <footer className="footer">v2.0.0</footer>
    </div>
  );
}
