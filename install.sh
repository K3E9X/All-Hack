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

# ---- Node.js 20+ ----
header "Node.js"
NEED_NODE=false

if command -v node &> /dev/null; then
    NODE_MAJOR=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_MAJOR" -lt 20 ]; then
        warn "Node.js $(node -v) found but v20+ is required"
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
        error "Install Node.js 20+ manually: https://nodejs.org/"
    fi
    log "Node.js: $(node -v)"
fi

# ---- Ollama ----
header "Ollama (Local LLM)"
if command -v ollama &> /dev/null; then
    log "Ollama already installed"
else
    log "Installing Ollama..."
    if [ "$OS" == "macos" ]; then
        brew install ollama
    else
        curl -fsSL https://ollama.com/install.sh | sh
    fi
fi

# Start Ollama
if ! pgrep -x "ollama" > /dev/null 2>&1; then
    log "Starting Ollama..."
    if [ "$OS" == "macos" ]; then
        brew services start ollama 2>/dev/null || ollama serve &
    else
        if [ "$EUID" -eq 0 ]; then
            systemctl enable ollama 2>/dev/null || true
            systemctl start ollama 2>/dev/null || ollama serve &
        else
            sudo systemctl enable ollama 2>/dev/null || true
            sudo systemctl start ollama 2>/dev/null || ollama serve &
        fi
    fi
    sleep 2
fi

log "Pulling llama3.2..."
ollama pull llama3.2 2>/dev/null || warn "Could not pull model. Run 'ollama pull llama3.2' later."

# ---- Python venv ----
header "Python Environment"

if [ ! -d "$ROOT_DIR/venv" ]; then
    log "Creating virtual environment..."
    python3 -m venv "$ROOT_DIR/venv"
fi

source "$ROOT_DIR/venv/bin/activate"
log "Upgrading pip..."
pip install --upgrade pip -q

log "Installing dependencies..."
pip install -r "$ROOT_DIR/backend/requirements.txt" -q

# Playwright
log "Installing Playwright chromium..."
if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
    # Install system dependencies for Playwright
    if [ "$EUID" -eq 0 ]; then
        apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 2>/dev/null || true
    else
        sudo apt-get install -y libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2 2>/dev/null || true
    fi
fi
python3 -m playwright install chromium 2>/dev/null || warn "Playwright chromium install failed."
python3 -m playwright install-deps chromium 2>/dev/null || true

# ---- Frontend ----
header "Frontend"
cd "$ROOT_DIR/frontend"

# Clean install to avoid native binding issues
if [ -d "node_modules" ]; then
    log "Cleaning old node_modules..."
    rm -rf node_modules package-lock.json
fi

log "Installing dependencies..."
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
ALLOWED_ORIGINS=http://localhost:8001,http://localhost:5173
EOF
    log "Created backend/.env"
else
    log ".env already exists"
fi

# ---- Start script ----
cat > "$ROOT_DIR/start.sh" << 'STARTEOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate

if ! pgrep -x "ollama" > /dev/null 2>&1; then
    echo "[+] Starting Ollama..."
    ollama serve &
    sleep 2
fi

cd backend
echo "[+] All-Hack running on http://localhost:8001"
uvicorn app.main:app --host 0.0.0.0 --port 8001
STARTEOF
chmod +x "$ROOT_DIR/start.sh"

# ---- Done ----
header "Installation Complete"
echo ""
log "Start with:"
echo "    ./start.sh"
echo ""
log "Or manually:"
echo "    source venv/bin/activate"
echo "    cd backend"
echo "    uvicorn app.main:app --host 0.0.0.0 --port 8001"
echo ""
log "Open: http://localhost:8001"
echo ""
