# All-Hack

```
   █████╗ ██╗     ██╗          ██╗  ██╗ █████╗  ██████╗██╗  ██╗
  ██╔══██╗██║     ██║          ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
  ███████║██║     ██║          ███████║███████║██║     █████╔╝
  ██╔══██║██║     ██║          ██╔══██║██╔══██║██║     ██╔═██╗
  ██║  ██║███████╗███████╗     ██║  ██║██║  ██║╚██████╗██║  ██╗
  ╚═╝  ╚═╝╚══════╝╚══════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

Automated penetration testing framework with AI-powered agent.

## Features

**AI Agent Loop**
- LLM-powered task planning and execution
- Natural language requests ("Find all SQLi and chain to RCE")
- Adaptive strategy based on findings
- Memory system for learning successful patterns

**Vulnerability Scanning**
- SQL Injection (time-based, boolean, error-based)
- XSS (reflected, stored, DOM)
- LFI/RCE/SSRF/SSTI
- XXE, NoSQL, JWT, GraphQL, Deserialization

**API Security**
- BOLA/BFLA detection
- Mass Assignment
- Rate Limiting bypass
- OpenAPI schema parsing

**WebSocket Testing**
- Authentication bypass
- Message injection
- Race conditions

**Reconnaissance**
- Intelligent crawling
- Technology fingerprinting
- Subdomain enumeration
- Port scanning

**Advanced**
- Mutation-based fuzzing
- Chained exploitation
- WAF bypass payloads
- Exploitation timeline with HTTP captures
- Automatic screenshots (Playwright)
- Post-exploitation and data extraction

## Requirements

- Python 3.9+
- Node.js 18+

## Installation

```bash
git clone https://github.com/K3E9X/All-Hack.git
cd All-Hack
chmod +x install.sh && ./install.sh
```

Manual setup:

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium

# Frontend
cd ../frontend
npm install
npm run build
```

## Usage

### Start

```bash
# Terminal 1 - Backend
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001

# Terminal 2 - Frontend (dev mode)
cd frontend
npm run dev
```

Production: Open http://localhost:8001
Development: Open http://localhost:5173

### Web Interface

**Scan Tab**
1. Enter target URL
2. Set crawl depth
3. Click Start
4. View findings with payload, timeline, HTTP captures, curl command

**Agent Tab**
1. Enter target URL
2. Describe what you want in natural language
3. Watch the agent plan and execute tasks
4. Real-time streaming of reasoning and findings

**Settings Tab**
- Configure API keys (Groq, Qwen/DashScope, OpenRouter)
- Set default scan depth
- Toggle auto-exploit and validation

### API

```bash
# Classic scan
curl -X POST "http://localhost:8001/api/v1/attack/async?target_url=https://target.com&max_pages=50"

# Agent execution
curl -X POST "http://localhost:8001/api/v1/agent/execute" \
  -H "Content-Type: application/json" \
  -d '{"target": "https://target.com", "request": "Find SQL injection vulnerabilities"}'

# Agent WebSocket (real-time)
wscat -c "ws://localhost:8001/api/v1/agent/ws/https://target.com"
```

## LLM Configuration

Set API keys for AI features (optional, has fallbacks):

```bash
# backend/.env
GROQ_API_KEY=gsk_...           # Free at console.groq.com
DASHSCOPE_API_KEY=sk-...       # Free at dashscope.aliyun.com (Qwen)
OPENROUTER_API_KEY=sk-or-...   # openrouter.ai
```

## Docker

```bash
docker-compose up -d
```

Access at http://localhost:8001

## Architecture

```
All-Hack/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI server
│   │   ├── unified_scanner.py   # Core scanner
│   │   ├── database/            # SQLite + SQLAlchemy
│   │   ├── openclaw/            # Agent Loop system
│   │   │   ├── core/            # Agent loop, task planner
│   │   │   ├── tools/           # Offensive tools registry
│   │   │   └── memory/          # Learning system
│   │   ├── payloads/            # SQLi, XSS, SSTI, XXE, etc.
│   │   ├── modules/             # Auth, API, WebSocket, Fuzzer
│   │   └── services/            # LLM, validation, screenshots
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/          # Layout, AttackConsole
│   │   ├── pages/               # Agent, History, Chat, Settings
│   │   └── contexts/            # Theme provider
│   └── dist/                    # Production build
├── install.sh
├── docker-compose.yml
└── README.md
```

## Configuration

```bash
# backend/.env
API_PORT=8001
CORS_ORIGINS=http://localhost:8001,http://localhost:5173
SCAN_TIMEOUT=43200

# LLM (optional)
GROQ_API_KEY=
DASHSCOPE_API_KEY=
OPENROUTER_API_KEY=
```

## Legal

**For authorized security testing only.**

- Use on systems you own or have written permission
- Unauthorized testing is illegal
- You are responsible for your actions

## License

MIT

---

**[@K3E9X](https://github.com/K3E9X)**
