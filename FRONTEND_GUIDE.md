# 🎨 Phase 3: Frontend Guide

**Modern React UI for All-Hack**

---

## 🚀 Overview

Phase 3 provides a **modern, responsive web interface** for All-Hack with real-time updates, AI chat, and beautiful visualizations.

### Features:
- ✅ Dashboard with scan management
- ✅ Real-time WebSocket chat
- ✅ Agent workflow visualization
- ✅ Interactive vulnerability charts
- ✅ Responsive design (Tailwind CSS)
- ✅ Dark mode UI

---

## 📦 Installation

### 1. Install Dependencies
```bash
cd frontend
npm install
```

### 2. Configure Environment
```bash
# Edit .env file
VITE_API_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000
```

### 3. Start Development Server
```bash
npm run dev
```

**Frontend**: http://localhost:5173

---

## 🧩 Components

### 1. Dashboard.jsx
**Purpose**: Main interface for starting and managing scans

**Features:**
- Start new scans (Standard or AI Agent mode)
- View recent scans
- Real-time status updates
- Quick access to scan details

**Usage:**
```jsx
import Dashboard from './components/Dashboard';

<Dashboard />
```

---

### 2. ChatInterface.jsx
**Purpose**: Real-time AI chat about scan results

**Features:**
- WebSocket connection for streaming responses
- Quick question suggestions
- Message history
- Connection status indicator

**Props:**
```jsx
<ChatInterface scanId="scan_123" />
```

**WebSocket Protocol:**
```javascript
// Send message
ws.send(JSON.stringify({ message: "What are the critical vulnerabilities?" }));

// Receive responses
{
  type: "assistant_chunk",  // Streaming chunk
  content: "The critical..."
}

{
  type: "assistant_complete"  // Message complete
}
```

---

### 3. AgentStatus.jsx
**Purpose**: Visualize multi-agent workflow progress

**Features:**
- Real-time workflow phase tracking
- Agent state monitoring
- Progress indicators
- Error tracking

**Props:**
```jsx
<AgentStatus scanId="scan_123" />
```

**Displays:**
- Current phase (Recon, Exploitation, Analysis, etc.)
- Phase completion status
- Agent queue sizes
- Findings and errors count

---

### 4. VulnerabilityChart.jsx
**Purpose**: Interactive charts for vulnerability data

**Features:**
- Severity distribution (Pie Chart)
- Category distribution (Bar Chart)
- Color-coded by severity
- Responsive layout

**Props:**
```jsx
<VulnerabilityChart vulnerabilities={scanResult.vulnerabilities} />
```

---

### 5. ScanDetails.jsx
**Purpose**: Complete scan details page with tabs

**Features:**
- Overview tab (stats + charts)
- Vulnerabilities tab (detailed list)
- AI Agents tab (workflow status)
- AI Chat tab (real-time chat)

**Route:**
```
/scan/:scanId
```

---

## 🎨 Styling

### Tailwind CSS
All components use Tailwind CSS for styling.

**Color Scheme:**
- Background: `bg-gray-900`
- Cards: `bg-gray-800`
- Borders: `border-gray-700`
- Primary: `bg-purple-600`
- Secondary: `bg-blue-600`

**Dark Mode:**
All components are designed for dark mode by default.

---

## 📱 Pages & Routes

### Routes Configuration (App.jsx)

```jsx
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import ScanDetails from './pages/ScanDetails';

<Router>
  <Routes>
    <Route path="/" element={<Dashboard />} />
    <Route path="/scan/:scanId" element={<ScanDetails />} />
  </Routes>
</Router>
```

---

## 🔌 API Integration

### HTTP Requests (axios)

```javascript
import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v1';

// Start scan
const response = await axios.post(`${API_BASE}/scans`, {
  target_url: 'http://example.com',
  mode: 'black_box'
});

// Get scan results
const scan = await axios.get(`${API_BASE}/scans/${scanId}`);
```

---

### WebSocket (Real-time Chat)

```javascript
const WS_BASE = import.meta.env.VITE_WS_URL || 'ws://localhost:8000';

const ws = new WebSocket(`${WS_BASE}/ws/chat/${scanId}`);

ws.onopen = () => {
  console.log('✅ Connected');
};

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);

  if (data.type === 'assistant_chunk') {
    // Append streaming content
    console.log(data.content);
  }
};

// Send message
ws.send(JSON.stringify({ message: 'What are the vulnerabilities?' }));
```

---

## 🎯 User Flows

### Flow 1: Start New Scan

```
1. User visits Dashboard (/)
2. User enters target URL
3. User selects scan mode (Standard or AI Agent)
4. User clicks "Start Scan"
5. API request to /api/v1/scans or /api/v1/agents/scan
6. Scan ID returned
7. Dashboard polls for updates every 5s
8. User clicks "View Details" → /scan/{scanId}
```

---

### Flow 2: View Scan Results

```
1. User navigates to /scan/{scanId}
2. Tabs: Overview | Vulnerabilities | AI Agents | AI Chat
3. Overview Tab:
   - Vulnerability charts
   - Scan statistics
4. Vulnerabilities Tab:
   - Detailed vulnerability list
   - Severity badges
5. AI Agents Tab:
   - Workflow visualization
   - Agent states
6. AI Chat Tab:
   - Real-time chat with AI
   - Ask questions about scan
```

---

### Flow 3: Chat with AI

```
1. User clicks "AI Chat" tab
2. WebSocket connection established
3. User sees quick question suggestions
4. User types question or clicks suggestion
5. Message sent to backend
6. AI response streams in real-time
7. Message displayed in chat
8. User can ask follow-up questions
```

---

## 🛠️ Development

### Project Structure

```
frontend/
├── src/
│   ├── components/
│   │   ├── Dashboard.jsx           # Main dashboard
│   │   ├── ChatInterface.jsx       # Real-time chat
│   │   ├── AgentStatus.jsx         # Agent workflow
│   │   └── VulnerabilityChart.jsx  # Charts
│   ├── pages/
│   │   └── ScanDetails.jsx         # Scan details page
│   ├── App.jsx                     # Router setup
│   ├── main.jsx                    # Entry point
│   └── index.css                   # Tailwind CSS
├── .env                            # Environment vars
├── package.json                    # Dependencies
├── tailwind.config.js              # Tailwind config
└── vite.config.js                  # Vite config
```

---

### Build for Production

```bash
# Build
npm run build

# Preview production build
npm run preview

# Deploy dist/ folder to your server
```

---

## 🎨 Customization

### Change Colors

Edit `tailwind.config.js`:

```javascript
module.exports = {
  theme: {
    extend: {
      colors: {
        primary: '#8b5cf6',    // Purple
        secondary: '#3b82f6',  // Blue
      }
    }
  }
}
```

---

### Add New Page

1. Create component in `src/pages/`
2. Add route in `App.jsx`:

```jsx
<Route path="/new-page" element={<NewPage />} />
```

---

## 📊 Features by Tab

### Overview Tab
- **Severity Distribution** (Pie Chart)
- **Category Distribution** (Bar Chart)
- **Scan Statistics** (4 cards)
  - Total Vulnerabilities
  - Endpoints Discovered
  - Technologies Detected
  - Scan Duration

---

### Vulnerabilities Tab
- **Vulnerability List** (cards)
  - Title
  - Severity badge (color-coded)
  - Description
  - Affected URL
  - Affected Parameter

---

### AI Agents Tab
- **Current Phase** indicator
- **Workflow Timeline** (5 phases)
  - Recon 🔍
  - Exploitation 💥
  - Validation ✅
  - Analysis 🧠
  - Reporting 📄
- **Agent States** (grid)
- **Statistics** (findings, errors)

---

### AI Chat Tab
- **Real-time Chat Interface**
- **Quick Questions** (buttons)
- **Streaming Responses**
- **Connection Status** indicator
- **Message History**

---

## 🚀 Quick Start

### Full Stack Setup

```bash
# Terminal 1: Backend
cd backend
python -m uvicorn app.main:app --reload

# Terminal 2: Frontend
cd frontend
npm run dev

# Open browser
# http://localhost:5173
```

---

### Test Workflow

1. **Start Scan**: Enter `http://testphp.vulnweb.com`
2. **Wait**: Scan completes (~30 seconds)
3. **View Details**: Click "View Details"
4. **Explore Tabs**:
   - Overview → See charts
   - Vulnerabilities → See findings
   - AI Agents → See workflow (if AI scan)
   - AI Chat → Ask questions

---

## 📝 Environment Variables

### Development (.env)

```bash
VITE_API_URL=http://localhost:8000/api/v1
VITE_WS_URL=ws://localhost:8000
```

### Production (.env.production)

```bash
VITE_API_URL=https://your-domain.com/api/v1
VITE_WS_URL=wss://your-domain.com
```

---

## 🐛 Troubleshooting

### Issue: WebSocket connection fails

**Solution:**
1. Check backend is running on port 8000
2. Check `.env` has correct `VITE_WS_URL`
3. Check browser console for errors

---

### Issue: Charts not rendering

**Solution:**
1. Install recharts: `npm install recharts`
2. Check `vulnerabilities` data is array
3. Check browser console for errors

---

### Issue: API requests fail

**Solution:**
1. Check backend is running
2. Check `.env` has correct `VITE_API_URL`
3. Check CORS is enabled in backend
4. Open browser DevTools → Network tab

---

## 🎯 Next Steps

### Planned Features:
- [ ] User authentication
- [ ] Scan scheduling
- [ ] PDF report export
- [ ] Dark/Light mode toggle
- [ ] Notification system
- [ ] Advanced filters
- [ ] Vulnerability search

---

## 📚 Dependencies

### Main Dependencies:
- `react` - UI framework
- `react-dom` - React DOM rendering
- `react-router-dom` - Routing
- `axios` - HTTP client
- `recharts` - Charts
- `@heroicons/react` - Icons

### Dev Dependencies:
- `vite` - Build tool
- `tailwindcss` - CSS framework
- `eslint` - Linting
- `prettier` - Code formatting

---

**🎉 Frontend Complete! Beautiful UI ready!**

Stack: React + Vite + Tailwind CSS + Recharts
