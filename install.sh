#!/bin/bash

# All-Hack Installation Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }
header() { echo ""; echo -e "${BOLD}$1${NC}"; echo "----------------------------------------"; }

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

header "All-Hack Installation"

# Detect OS
OS="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
elif [ "$(uname)" == "Darwin" ]; then
    OS="macos"
fi
log "OS: $OS"

# ---- Python ----
header "Python"
if command -v python3 &> /dev/null; then
    log "Python: $(python3 --version 2>&1)"
else
    error "Python 3 not found. Install Python 3.9+"
fi

# ---- Node.js 18+ ----
header "Node.js"
NEED_NODE=false

if command -v node &> /dev/null; then
    NODE_MAJOR=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_MAJOR" -lt 18 ]; then
        warn "Node.js $(node -v) found but v18+ is required"
        NEED_NODE=true
    else
        log "Node.js: $(node -v)"
    fi
else
    warn "Node.js not found"
    NEED_NODE=true
fi

if [ "$NEED_NODE" = true ]; then
    log "Installing Node.js 20..."
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        if [ "$EUID" -eq 0 ]; then
            curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
            apt-get install -y nodejs
        else
            curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
            sudo apt-get install -y nodejs
        fi
    elif [ "$OS" == "macos" ]; then
        brew install node@20
    elif [ "$OS" == "fedora" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ]; then
        if [ "$EUID" -eq 0 ]; then
            curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
            dnf install -y nodejs
        else
            curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
            sudo dnf install -y nodejs
        fi
    else
        error "Install Node.js 18+ manually: https://nodejs.org/"
    fi
    log "Node.js: $(node -v)"
fi

# ---- Backend Python Environment ----
header "Backend Setup"

cd "$ROOT_DIR/backend"

if [ ! -d "venv" ]; then
    log "Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
log "Upgrading pip..."
pip install --upgrade pip -q

log "Installing Python dependencies..."
pip install -r requirements.txt -q

# Playwright
log "Installing Playwright chromium..."
if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
    if [ "$EUID" -eq 0 ]; then
        apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 2>/dev/null || true
    else
        sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 2>/dev/null || true
    fi
fi
python3 -m playwright install chromium 2>/dev/null || warn "Playwright chromium install failed."
python3 -m playwright install-deps chromium 2>/dev/null || true

# Create data directory
mkdir -p "$ROOT_DIR/backend/data"

cd "$ROOT_DIR"

# ---- Frontend ----
header "Frontend Setup"
cd "$ROOT_DIR/frontend"

# Clean install if node_modules exists but might have issues
if [ -d "node_modules" ] && [ ! -f "node_modules/.package-lock.json" ]; then
    log "Cleaning old node_modules..."
    rm -rf node_modules package-lock.json
fi

log "Installing Node dependencies..."
npm install

log "Building frontend..."
npm run build

cd "$ROOT_DIR"

# ---- Config ----
header "Configuration"
if [ ! -f "$ROOT_DIR/backend/.env" ]; then
    cat > "$ROOT_DIR/backend/.env" << EOF
# All-Hack Configuration
API_HOST=0.0.0.0
API_PORT=8001
CORS_ORIGINS=http://localhost:8001,http://localhost:5173

# LLM API Keys (optional - enables AI features)
# Get free key at: https://console.groq.com
GROQ_API_KEY=

# Get free key at: https://dashscope.aliyun.com (Qwen)
DASHSCOPE_API_KEY=

# OpenRouter (optional)
OPENROUTER_API_KEY=
EOF
    log "Created backend/.env"
else
    log ".env already exists"
fi

# ---- Start script ----
cat > "$ROOT_DIR/start.sh" << 'STARTEOF'
#!/bin/bash

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

# Parse arguments
MODE="${1:-prod}"  # prod or dev

cleanup() {
    log "Shutting down..."
    kill $BACKEND_PID 2>/dev/null
    kill $FRONTEND_PID 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

# Start backend
log "Starting backend..."
cd "$ROOT_DIR/backend"
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8001 &
BACKEND_PID=$!
cd "$ROOT_DIR"

sleep 2

if ! kill -0 $BACKEND_PID 2>/dev/null; then
    echo -e "${RED}[x]${NC} Backend failed to start"
    exit 1
fi

log "Backend running on http://localhost:8001"

if [ "$MODE" == "dev" ]; then
    # Development mode: run frontend dev server
    log "Starting frontend dev server..."
    cd "$ROOT_DIR/frontend"
    npm run dev &
    FRONTEND_PID=$!
    cd "$ROOT_DIR"

    sleep 3
    log "Frontend running on http://localhost:5173"
    echo ""
    log "Development mode - Open http://localhost:5173"
else
    # Production mode: serve frontend from backend
    echo ""
    log "Production mode - Open http://localhost:8001"
fi

echo ""
log "Press Ctrl+C to stop"

# Wait for processes
wait
STARTEOF
chmod +x "$ROOT_DIR/start.sh"

# ---- Stop script ----
cat > "$ROOT_DIR/stop.sh" << 'STOPEOF'
#!/bin/bash

echo "[+] Stopping All-Hack..."

# Kill uvicorn
pkill -f "uvicorn app.main:app" 2>/dev/null

# Kill vite dev server
pkill -f "vite" 2>/dev/null

echo "[+] Stopped"
STOPEOF
chmod +x "$ROOT_DIR/stop.sh"

# ---- Done ----
header "Installation Complete"
echo ""
log "Start (production):"
echo "    ./start.sh"
echo ""
log "Start (development with hot reload):"
echo "    ./start.sh dev"
echo ""
log "Stop:"
echo "    ./stop.sh"
echo ""
log "URLs:"
echo "    Production:  http://localhost:8001"
echo "    Development: http://localhost:5173"
echo ""
