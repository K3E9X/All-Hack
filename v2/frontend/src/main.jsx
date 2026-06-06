import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import App from './App.jsx';
import Home from './pages/Home.jsx';
import Engagements from './pages/Engagements.jsx';
import Proxy from './pages/Proxy.jsx';
import Scans from './pages/Scans.jsx';
import Reports from './pages/Reports.jsx';
import './styles.css';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<App />}>
          <Route index element={<Home />} />
          <Route path="engagements" element={<Engagements />} />
          <Route path="proxy" element={<Proxy />} />
          <Route path="scans" element={<Scans />} />
          <Route path="reports" element={<Reports />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </React.StrictMode>
);
