# Advanced Pentest Tool

Automated penetration testing tool for web applications with intelligent analysis and adaptive testing.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![React](https://img.shields.io/badge/react-18+-61dafb)

## Legal Warning

**IMPORTANT:** For authorized security testing and educational purposes only. Unauthorized penetration testing is illegal.

## Features

- **OWASP Top 10** - SQL Injection, XSS, Command Injection, SSRF
- **Access Control** - IDOR, Privilege Escalation
- **Infrastructure** - Port Scanning (30+ ports), SSL/TLS Analysis, Subdomain Enumeration
- **Reconnaissance** - Technology Detection, Directory Fuzzing (250+ endpoints)
- **Intelligent Analysis** - Adaptive testing based on findings
- **Robust** - Auto-retry with exponential backoff, auto-save every 5 minutes
- **IP Support** - Accepts URLs, domains, and IP addresses

## Platform Support

- **Linux** - Fully supported
- **macOS ARM** (Apple Silicon) - Fully supported
- **macOS Intel** - Fully supported
- **Windows** - Supported with WSL2 recommended

**macOS Prerequisites:**
```bash
# Install Xcode Command Line Tools (required for lxml, cryptography)
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.9+ and Node.js
brew install python@3.9 node
```

## Installation

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend
```bash
cd frontend
npm install
```

## Quick Start

**Launch everything with one command:**
```bash
./start.sh
```

Access the app at `http://localhost:5173`

Press `Ctrl+C` to stop all services.

## Usage

### Manual Start

**Backend:**
```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
cd frontend
npm run dev
```

### Run Scan
1. Open `http://localhost:5173`
2. Enter target (URL, domain, or IP address)
3. Click "Start Scan"
4. Wait for results (5-10 hours for comprehensive scans)

## Configuration

Scans support long-running operations:
- **Scan timeout**: 12 hours
- **Auto-save**: Every 5 minutes
- **Max retries**: 5 with exponential backoff
- **Resume**: Automatic recovery after crashes

## Architecture

```
backend/
├── app/
│   ├── intelligence/      # ScanBrain - Intelligent analysis
│   ├── scanners/          # OWASP, access control, recon
│   ├── utils/             # RobustScanner, TargetValidator
│   └── persistence/       # Auto-save & resume
frontend/
└── src/components/        # React UI
```

## Security

- Use only on private networks
- Never expose to the Internet
- Keep scan results confidential

## License

MIT License - For educational and authorized security testing only.
