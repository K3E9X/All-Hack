# Advanced Pentest Tool

Automated penetration testing tool for web applications with intelligent analysis and adaptive testing.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9--3.12-green)
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

# Install Python 3.11 or 3.12 and Node.js
# ⚠️ Python 3.14+ not yet supported (pydantic-core compatibility)
brew install python@3.11 node
```

## Installation

### Backend
```bash
cd backend

# macOS: Use python3.11 or python3.12 explicitly
python3.11 -m venv venv  # or python3.12

# Linux/WSL: python3 is fine
# python3 -m venv venv

source venv/bin/activate  # Windows: venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### Frontend
```bash
cd frontend
npm install
```

## Optional Features

### Browser-Based Crawling (Playwright)

**Status:** Optional - not installed by default

For dynamic Single Page Applications (React/Vue/Angular), you can enable browser-based crawling:

```bash
cd backend
source venv/bin/activate
pip install playwright==1.40.0
playwright install chromium
```

**What it does:** Discovers client-side routes that don't appear in static HTML

**When to use:** Testing SPAs with dynamic routing

**If not installed:** Tool works normally but skips browser-based discovery (logs a warning)

### Future Integrations (Not Yet Implemented)

The following features are planned but not yet available:

- **SQLMap Integration** - Advanced SQL injection testing
- **Nuclei Templates** - Community vulnerability templates

See `PROJECT_GAPS.md` for complete list of known limitations.

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

### Scan Settings

Scans support long-running operations:
- **Scan timeout**: 12 hours
- **Auto-save**: Every 5 minutes
- **Max retries**: 5 with exponential backoff
- **Resume**: Automatic recovery after crashes

### Environment Variables

All configuration is portable and environment-based. Create `backend/.env` to customize:

```bash
# API Settings
ALLOWED_ORIGINS=http://localhost:5173,https://your-domain.com
VERIFY_SSL=false  # Disable SSL verification for pentesting

# Scan Configuration
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=43200  # 12 hours
REQUEST_TIMEOUT=60

# Paths (auto-detected, override if needed)
# TOOLS_DIR=/custom/path/to/tools
# WORDLISTS_DIR=/custom/path/to/wordlists
```

**Note:** All paths use relative resolution by default - no hard-coded absolute paths

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
