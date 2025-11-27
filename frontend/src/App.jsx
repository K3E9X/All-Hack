import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import ScanDetails from './pages/ScanDetails';
import './index.css';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/:scanId" element={<ScanDetails />} />
      </Routes>
    </Router>
  );
}

export default App;
