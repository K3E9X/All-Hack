# All-Hack

Automated penetration testing tool.

## Features

- **Vulnerability Scanning**: SQLi, XSS, LFI, RCE, SSRF, SSTI, XXE, NoSQL, JWT, GraphQL
- **API Security**: BOLA, BFLA, Mass Assignment, Rate Limiting
- **WebSocket Testing**: Auth bypass, injection, race conditions
- **Recon**: Crawling, tech detection, subdomain enum, port scan
- **Fuzzing**: Mutation-based, format strings, buffer overflow
- **Exploitation Timeline**: Step-by-step tracking with HTTP captures
- **Screenshots**: Automatic capture for critical findings

## Requirements

- Python 3.9+
- Node.js 18+

## Installation

```bash
git clone https://github.com/K3E9X/All-Hack.git
cd All-Hack
chmod +x install.sh && ./install.sh
```

Or manually:

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

```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001
```

Open http://localhost:8001

1. Enter target URL
2. Click Start
3. View findings with payloads, timeline, and curl commands

## API

```bash
# Start scan
curl -X POST "http://localhost:8001/api/v1/attack/async?target_url=https://target.com"

# Get status
curl "http://localhost:8001/api/v1/attack/{scan_id}/status"

# Get results
curl "http://localhost:8001/api/v1/attack/{scan_id}"
```

## Docker

```bash
docker-compose up -d
```

## Legal

For authorized testing only. You are responsible for your actions.

## License

MIT
