# All-Hack

Automated penetration testing framework.

## Features

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
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

Open http://localhost:8001

### Web Interface

1. Enter target URL
2. Set crawl depth
3. Click Start
4. View findings with:
   - Payload used
   - Exploitation timeline
   - HTTP request/response
   - Curl command to reproduce
   - Screenshot (critical/high)

### API

```bash
# Start async scan
curl -X POST "http://localhost:8001/api/v1/attack/async?target_url=https://target.com&max_pages=50"

# Check status
curl "http://localhost:8001/api/v1/attack/{scan_id}/status"

# Get results
curl "http://localhost:8001/api/v1/attack/{scan_id}"

# Stop scan
curl -X POST "http://localhost:8001/api/v1/attack/{scan_id}/stop"
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
│   │   ├── payloads/            # SQLi, XSS, SSTI, XXE, etc.
│   │   ├── modules/             # Auth, API, WebSocket, Fuzzer
│   │   └── services/            # Screenshot service
│   └── requirements.txt
├── frontend/
│   ├── src/components/
│   │   └── AttackConsole.jsx    # Main UI
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
