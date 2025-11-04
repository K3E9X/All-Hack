<div align="center">

```
   █████╗ ██╗     ██╗          ██╗  ██╗ █████╗  ██████╗██╗  ██╗
  ██╔══██╗██║     ██║          ██║  ██║██╔══██╗██╔════╝██║ ██╔╝
  ███████║██║     ██║          ███████║███████║██║     █████╔╝
  ██╔══██║██║     ██║          ██╔══██║██╔══██║██║     ██╔═██╗
  ██║  ██║███████╗███████╗     ██║  ██║██║  ██║╚██████╗██║  ██╗
  ╚═╝  ╚═╝╚══════╝╚══════╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

### 🛡️ Advanced Penetration Testing Framework

**Professional-grade automated security testing** with AI-enhanced analysis

[![Version](https://img.shields.io/badge/version-1.0.0-blue)](https://github.com/K3E9X/All-Hack)
[![Python](https://img.shields.io/badge/python-3.9--3.12-green)](https://www.python.org/)
[![React](https://img.shields.io/badge/react-18+-61dafb)](https://reactjs.org/)
[![License](https://img.shields.io/badge/license-MIT-orange)](./LICENSE)
[![GitHub](https://img.shields.io/badge/by-K3E9X-black?logo=github)](https://github.com/K3E9X)

---

### 🎯 All-in-One Security Testing Solution

**OWASP Top 10** • **API Security** • **AI-Powered** • **Grey Box Testing** • **100+ Vulnerabilities**

<!--
🎬 Demo GIF Coming Soon!
Add your demo GIF at ./assets/demo.gif
See assets/GIF_CREATION_GUIDE.md for instructions

![Demo](./assets/demo.gif)
-->

</div>

## 📋 Table of Contents

- [⚠️ Legal Warning](#️-legal-warning)
- [✨ Key Features](#-key-features)
- [🚀 Quick Start](#-quick-start)
- [📖 Usage](#-usage)
- [🏗️ Architecture](#️-architecture)
- [📊 Statistics & Coverage](#-statistics--coverage)
- [🔒 Security & Best Practices](#-security--best-practices)
- [📧 Contact](#-contact)

---

## ⚠️ Legal Warning

**IMPORTANT:** This tool is designed for **authorized security testing and educational purposes only**.

- ✅ Use on systems you own
- ✅ Use with explicit written permission
- ❌ Unauthorized penetration testing is **illegal**
- ❌ Never use on production systems without approval

**You are responsible for your actions. Use ethically and legally.**

---

## ✨ Key Features

### 🔥 OWASP Top 10 Coverage
- **SQL Injection** - Time-based, boolean-based, error-based detection
- **Cross-Site Scripting (XSS)** - Reflected, stored, DOM-based
- **Command Injection** - OS command execution vulnerabilities
- **Server-Side Request Forgery (SSRF)** - Internal network probing
- **Security Misconfigurations** - Headers, CORS, SSL/TLS

### 🔐 API Security Testing (NEW!)
- **JWT Security** - Algorithm confusion, weak secrets, claims manipulation (87 built-in secrets)
- **GraphQL Security** - Schema introspection, batching attacks, nested queries
- **NoSQL Injection** - MongoDB, CouchDB, Redis, Cassandra (blind injection + data extraction)
- **File Upload Vulnerabilities** - 10 attack vectors including polyglot files, XXE, ZIP slip
- **OAuth 2.0 Security** - CSRF, redirect_uri bypass, token leakage (13+ bypass techniques)
- **SAML Security** - XXE, signature wrapping, assertion replay

### 🎯 Access Control Testing
- **IDOR Detection** - Horizontal & vertical, authenticated endpoint testing
- **Privilege Escalation** - Vertical escalation, function-level access control
- **Authorization Bypass** - Role manipulation, missing access checks

### 🧠 AI-Powered Agent System (NEW!)
- **Memory System** - Persistent learning from successful exploits
- **Intelligent Payload Generation** - Context-aware payloads using Claude AI
- **Exploitation Chain Builder** - Multi-step attack path discovery
- **Professional Report Generator** - Executive, technical, remediation, and risk assessment reports

### 🔒 Black Box vs 🔓 Grey Box Testing (NEW!)
- **Black Box Mode** - External testing without authentication (~50-100 endpoints)
- **Grey Box Mode** - Authenticated testing with credentials (~150-300 endpoints)
- **3-6x More Coverage** in grey box mode
- **Critical IDOR & Privilege Escalation** testing in grey box
- See [MODE_DIFFERENTIATION.md](./MODE_DIFFERENTIATION.md) for detailed comparison

### 🕵️ Advanced Reconnaissance
- **Technology Detection** - Wappalyzer-style fingerprinting
- **Endpoint Discovery** - 250+ common endpoints + authenticated discovery (grey box)
- **Directory Fuzzing** - Intelligent fuzzing with adaptive wordlists
- **Subdomain Enumeration** - Comprehensive subdomain discovery
- **Port Scanning** - 30+ critical ports with service detection
- **SSL/TLS Analysis** - Certificate validation, cipher strength

### 🧪 Intelligent & Adaptive
- **Scan Depth Modes** - Quick (⚡), Balanced (⚖️), Deep (🔥)
- **Adaptive Testing** - Adjusts strategy based on findings
- **Smart Endpoint Selection** - Prioritizes high-value targets
- **Real-time Progress** - Live updates and timeline events

### 💪 Robust & Reliable
- **Auto-retry** - Exponential backoff for network failures
- **Auto-save** - Every 5 minutes with crash recovery
- **Long-running Scans** - 12-hour timeout for comprehensive testing
- **Stability Monitoring** - Tracks target stability during scans
- **IP Address Support** - URLs, domains, and IP addresses

---

## 📊 Statistics & Coverage

### Vulnerability Detection
- **100+ vulnerability types** tested across all scanners
- **20+ CWE classifications** covered
- **OWASP Top 10 2021** complete coverage
- **API Security OWASP Top 10** covered

### Testing Depth
| Scan Mode | Endpoints | Payloads/Endpoint | Duration | Coverage |
|-----------|-----------|-------------------|----------|----------|
| Quick ⚡   | Priority  | ~3                | 30-60 min | 60% |
| Balanced ⚖️ | Standard | ~10               | 2-4 hours | 85% |
| Deep 🔥    | All       | Full              | 8-12 hours | 95%+ |

### Black Box vs Grey Box
| Aspect | Black Box 🔒 | Grey Box 🔓 | Improvement |
|--------|-------------|------------|-------------|
| Endpoints | 50-100 | 150-300 | **3-6x** |
| IDOR Tests | Limited | Comprehensive | **10-30x** |
| Critical Vulns | 0-2 | 5-15 | **5-10x** |

---

## 🚀 Quick Start

### Prerequisites

- **Python 3.9-3.12** (⚠️ 3.14+ not yet supported)
- **Node.js 16+**
- **Git**

### Installation

```bash
# Clone the repository
git clone https://github.com/K3E9X/devasc-study-team.git
cd devasc-study-team

# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt

# Frontend setup
cd ../frontend
npm install

# Create frontend .env file
cp .env.example .env
```

### Launch (One Command)

```bash
./start.sh
```

Access the application at **http://localhost:5173**

Press `Ctrl+C` to stop all services.

---

## 📖 Usage

### Basic Scan

1. Open **http://localhost:5173**
2. Enter target URL (e.g., `https://example.com`)
3. Select **scan mode**:
   - 🔒 **Black Box** - External testing (no credentials)
   - 🔓 **Grey Box** - Authenticated testing (provide token)
4. Choose **scan depth**:
   - ⚡ **Quick** - Fast scan (~30-60 min)
   - ⚖️ **Balanced** - Standard depth (~2-4 hours)
   - 🔥 **Deep** - Maximum coverage (~8-12 hours)
5. Click **Start Scan**

### Grey Box Testing (Recommended)

For comprehensive testing with authentication:

1. Select **Grey Box** mode
2. Provide **auth token** (JWT/Bearer token)
3. Optionally provide **authentication sequence** for complex login flows
4. Tool will discover **70+ authenticated endpoints** automatically
5. **3-6x more coverage** than black box

### Advanced Configuration

```bash
cd backend
cp .env.example .env
# Edit .env to customize settings
```

**Key Settings:**
```bash
# API Configuration
API_PORT=8001
ALLOWED_ORIGINS=http://localhost:5173

# Scan Configuration
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=43200  # 12 hours
REQUEST_TIMEOUT=60

# AI Agent (Optional - requires Anthropic API key)
ANTHROPIC_API_KEY=your_api_key_here
ENABLE_AI_AGENT=true
```

---

## 🏗️ Architecture

```
devasc-study-team/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI application
│   │   ├── scanner_orchestrator.py    # Main scan coordinator
│   │   ├── ai_enhanced_orchestrator.py # AI-powered scanning (NEW)
│   │   ├── config.py                  # Configuration
│   │   ├── models/                    # Data models
│   │   ├── scanners/
│   │   │   ├── owasp/                 # OWASP Top 10 scanners
│   │   │   ├── api_security/          # API security scanners (NEW)
│   │   │   │   ├── jwt_scanner.py
│   │   │   │   ├── graphql_scanner.py
│   │   │   │   ├── nosql_injection.py
│   │   │   │   ├── file_upload_scanner.py
│   │   │   │   ├── oauth_scanner.py
│   │   │   │   └── saml_scanner.py
│   │   │   ├── access_control/        # IDOR, privilege escalation
│   │   │   ├── reconnaissance/        # Tech detection, endpoint discovery
│   │   │   ├── advanced/              # Port scan, subdomain enum
│   │   │   └── misconfig/             # Security headers, CORS
│   │   ├── ai_agent/                  # AI Agent System (NEW)
│   │   │   ├── memory_system.py       # Persistent learning
│   │   │   ├── payload_generator.py   # AI payload generation
│   │   │   ├── exploitation_chains.py # Chain discovery
│   │   │   ├── report_generator.py    # Professional reports
│   │   │   └── enhanced_autonomous_agent.py
│   │   ├── intelligence/              # Scan brain & analysis
│   │   ├── utils/                     # HTTP client, validators
│   │   └── persistence/               # Auto-save & resume
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── App.jsx                    # Main application
│   │   ├── components/
│   │   │   ├── Scanner.jsx            # Scan configuration
│   │   │   └── Results.jsx            # Results display
│   │   └── main.jsx
│   └── package.json
├── MODE_DIFFERENTIATION.md            # Black Box vs Grey Box guide
├── MARATHON_SESSION_SUMMARY.md        # Development session log
└── README.md                          # This file
```

---

## 🎯 Scan Phases

### Phase 1: Reconnaissance (20-30 min)
- 🔍 Technology detection (Wappalyzer-style)
- 🕷️ Endpoint discovery (crawling + fuzzing)
- 🔓 **Grey Box**: Authenticated endpoint discovery (+70 endpoints)
- 📘 API schema collection (Swagger, OpenAPI)
- 🌐 Browser-based crawling (if enabled)
- 🔬 Intelligence gathering

### Phase 2: OWASP Top 10 Scanning (2-8 hours)
- 🗃️ SQL Injection (time-based, boolean, error-based)
- 🎨 XSS (reflected, stored, DOM)
- 💻 Command Injection
- 🌐 SSRF
- 🔐 **API Security** (JWT, GraphQL, NoSQL, File Upload, OAuth, SAML)

### Phase 3: Access Control Testing (30-60 min)
- 🔑 IDOR detection
  - 🔒 **Black Box**: 10 public endpoints
  - 🔓 **Grey Box**: ALL endpoints + write operations
- ⬆️ Privilege escalation (grey box exclusive)

### Phase 4: Security Misconfigurations (15-30 min)
- 🛡️ Security headers
- 🌍 CORS policies
- 🔒 SSL/TLS analysis
- 🔍 Port scanning
- 📁 Directory fuzzing

### Phase 5: Advanced (if enabled)
- 🌐 Subdomain enumeration
- 🧠 **AI Agent** analysis (if enabled)
- 🔗 Exploitation chain discovery
- 📊 Professional report generation

---

## 📱 Platform Support

| Platform | Support | Notes |
|----------|---------|-------|
| **Linux** | ✅ Full | Recommended |
| **macOS Intel** | ✅ Full | Requires Xcode CLI tools |
| **macOS ARM (M1/M2/M3)** | ✅ Full | Native Apple Silicon support |
| **Windows** | ⚠️ WSL2 | WSL2 recommended |

### macOS Prerequisites

```bash
# Install Xcode Command Line Tools (required)
xcode-select --install

# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.11 or 3.12 and Node.js
brew install python@3.11 node
```

---

## 🔧 Optional Features

### AI Agent System

**Requires Anthropic API key** (Claude)

```bash
# In backend/.env
ANTHROPIC_API_KEY=your_api_key_here
ENABLE_AI_AGENT=true
```

**Features:**
- 🧠 Learns from successful exploits
- 🎯 Generates intelligent payloads
- 🔗 Discovers exploitation chains
- 📄 Creates professional reports (4 types)

### Browser-Based Crawling (Playwright)

For dynamic SPAs (React/Vue/Angular):

```bash
cd backend
source venv/bin/activate
pip install playwright==1.40.0
playwright install chromium
```

### External Tools (Not Yet Implemented)

- **SQLMap** - Advanced SQL injection
- **Nuclei** - Community templates

See `PROJECT_GAPS.md` for limitations.

---

## 📚 Documentation

- **[MODE_DIFFERENTIATION.md](./MODE_DIFFERENTIATION.md)** - Black Box vs Grey Box detailed guide
- **[MARATHON_SESSION_SUMMARY.md](./MARATHON_SESSION_SUMMARY.md)** - Development session log
- **[PROJECT_GAPS.md](./PROJECT_GAPS.md)** - Known limitations

---

## 🔒 Security & Best Practices

### Important Reminders

- ✅ **Private Networks Only** - Never expose to the Internet
- ✅ **Authorized Testing** - Always get written permission
- ✅ **Confidential Results** - Keep scan results secure
- ✅ **Responsible Disclosure** - Report findings responsibly
- ⚠️ **Loud Testing** - This tool is **NOT stealthy** (many requests)

### Scan Impact

- **Request Volume**: 1,000-10,000+ requests per scan
- **Server Load**: Moderate to high
- **Network Traffic**: Significant bandwidth usage
- **Detection**: Easily detectable by WAF/IDS

**Recommendation**: Run during maintenance windows or on staging environments.

---

## 🎓 Educational Use

This tool is perfect for:
- 🎓 **Security Training** - Learn penetration testing techniques
- 🏫 **Academic Research** - Study web application security
- 🔬 **Security Labs** - Practice in controlled environments
- 📖 **OWASP Learning** - Understand vulnerability types
- 🛠️ **Tool Development** - Build your own security tools

---

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- 🆕 New scanners (XXE, Deserialization, etc.)
- 🧪 Test coverage
- 📖 Documentation
- 🎨 UI/UX enhancements
- 🌍 Internationalization

---

## 📝 License

**MIT License** - See [LICENSE](./LICENSE) for details

**For educational and authorized security testing only.**

---

## 🙏 Acknowledgments

- **OWASP** - Vulnerability classification and guidelines
- **Anthropic** - Claude AI for intelligent payload generation
- **Community** - Security researchers and ethical hackers

---

## 📧 Contact

- **GitHub**: [@K3E9X](https://github.com/K3E9X)
- **Issues**: [GitHub Issues](https://github.com/K3E9X/devasc-study-team/issues)

---

## ⭐ Show Your Support

If this tool helps you, please:
- ⭐ Star the repository
- 🍴 Fork and contribute
- 🐛 Report issues
- 📢 Share with others

---

<div align="center">

**Built with ❤️ for the security community**

**Created by [K3E9X](https://github.com/K3E9X)**

![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)

*2024 - For authorized testing only*

</div>
