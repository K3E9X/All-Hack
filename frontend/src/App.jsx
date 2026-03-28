import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider } from './contexts/ThemeContext';
import { ScanProvider } from './contexts/ScanContext';
import Layout from './components/Layout';
import AttackConsole from './components/AttackConsole';
import AgentView from './pages/AgentView';
import HistoryView from './pages/HistoryView';
import ChatView from './pages/ChatView';
import SettingsView from './pages/SettingsView';
import ScanDetails from './pages/ScanDetails';
import ReconView from './pages/ReconView';
import ToolsView from './pages/ToolsView';
import './index.css';

function App() {
  return (
    <ThemeProvider>
      <ScanProvider>
        <Router>
          <Routes>
            <Route element={<Layout />}>
              <Route path="/" element={<AttackConsole />} />
              <Route path="/agent" element={<AgentView />} />
              <Route path="/history" element={<HistoryView />} />
              <Route path="/chat" element={<ChatView />} />
              <Route path="/settings" element={<SettingsView />} />
              <Route path="/scan/:scanId" element={<ScanDetails />} />
              <Route path="/recon" element={<ReconView />} />
              <Route path="/tools" element={<ToolsView />} />
            </Route>
          </Routes>
        </Router>
      </ScanProvider>
    </ThemeProvider>
  );
}

export default App;
