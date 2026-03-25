import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import AttackConsole from './components/AttackConsole';
import ScanDetails from './pages/ScanDetails';
import './index.css';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AttackConsole />} />
        <Route path="/scan/:scanId" element={<ScanDetails />} />
      </Routes>
    </Router>
  );
}

export default App;
