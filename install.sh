#!/bin/bash

# All-Hack Installation Script
# Compatible: macOS, Debian, Ubuntu, Fedora, CentOS, RHEL

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }
header() { echo ""; echo -e "${BOLD}$1${NC}"; echo "----------------------------------------"; }

# Get script directory (cross-platform)
get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [ -h "$source" ]; do
        local dir="$(cd -P "$(dirname "$source")" && pwd)"
        source="$(readlink "$source" 2>/dev/null || greadlink "$source")"
        [[ $source != /* ]] && source="$dir/$source"
    done
    echo "$(cd -P "$(dirname "$source")" && pwd)"
}

ROOT_DIR="$(get_script_dir)"
cd "$ROOT_DIR"

header "All-Hack Installation"

# ---- Detect OS ----
detect_os() {
    OS="unknown"
    OS_FAMILY="unknown"
    PKG_MANAGER=""

    if [ "$(uname)" == "Darwin" ]; then
        OS="macos"
        OS_FAMILY="macos"
        PKG_MANAGER="brew"
    elif [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        case $ID in
            ubuntu|debian|linuxmint|pop|elementary|zorin|kali)
                OS_FAMILY="debian"
                PKG_MANAGER="apt"
                ;;
            fedora|rhel|centos|rocky|almalinux)
                OS_FAMILY="redhat"
                PKG_MANAGER="dnf"
                ;;
            arch|manjaro|endeavouros)
                OS_FAMILY="arch"
                PKG_MANAGER="pacman"
                ;;
            opensuse*|sles)
                OS_FAMILY="suse"
                PKG_MANAGER="zypper"
                ;;
            alpine)
                OS_FAMILY="alpine"
                PKG_MANAGER="apk"
                ;;
        esac
    fi

    log "OS: $OS ($OS_FAMILY)"
}

detect_os

# ---- Check/Install Homebrew on macOS ----
if [ "$OS" == "macos" ]; then
    if ! command -v brew &> /dev/null; then
        warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

        # Add brew to path for Apple Silicon
        if [ -f "/opt/homebrew/bin/brew" ]; then
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
    fi
    log "Homebrew: $(brew --version | head -1)"
fi

# ---- Helper: Install package ----
install_package() {
    local pkg="$1"
    local brew_pkg="${2:-$1}"

    case $PKG_MANAGER in
        apt)
            if [ "$EUID" -eq 0 ]; then
                apt-get update -qq && apt-get install -y "$pkg"
            else
                sudo apt-get update -qq && sudo apt-get install -y "$pkg"
            fi
            ;;
        dnf)
            if [ "$EUID" -eq 0 ]; then
                dnf install -y "$pkg"
            else
                sudo dnf install -y "$pkg"
            fi
            ;;
        pacman)
            if [ "$EUID" -eq 0 ]; then
                pacman -S --noconfirm "$pkg"
            else
                sudo pacman -S --noconfirm "$pkg"
            fi
            ;;
        brew)
            brew install "$brew_pkg"
            ;;
        apk)
            if [ "$EUID" -eq 0 ]; then
                apk add "$pkg"
            else
                sudo apk add "$pkg"
            fi
            ;;
    esac
}

# ---- Python ----
header "Python"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    log "Python: $PYTHON_VERSION"

    # Check minimum version
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
        warn "Python 3.9+ recommended (found $PYTHON_VERSION)"
    fi
else
    error "Python 3 not found. Install Python 3.9+"
fi

# Check pip
if ! python3 -m pip --version &> /dev/null; then
    warn "pip not found, installing..."
    case $OS_FAMILY in
        debian) install_package "python3-pip" ;;
        redhat) install_package "python3-pip" ;;
        macos) python3 -m ensurepip --upgrade ;;
        *) error "Please install pip manually" ;;
    esac
fi

# Check venv
if ! python3 -c "import venv" &> /dev/null; then
    warn "venv module not found, installing..."
    case $OS_FAMILY in
        debian) install_package "python3-venv" ;;
        *) ;;  # Usually included
    esac
fi

# ---- Node.js 18+ ----
header "Node.js"
NEED_NODE=false

if command -v node &> /dev/null; then
    NODE_VERSION=$(node -v | sed 's/v//')
    NODE_MAJOR=$(echo $NODE_VERSION | cut -d. -f1)
    if [ "$NODE_MAJOR" -lt 18 ]; then
        warn "Node.js v$NODE_VERSION found but v18+ required"
        NEED_NODE=true
    else
        log "Node.js: v$NODE_VERSION"
    fi
else
    warn "Node.js not found"
    NEED_NODE=true
fi

if [ "$NEED_NODE" = true ]; then
    log "Installing Node.js 20..."
    case $OS_FAMILY in
        debian)
            if [ "$EUID" -eq 0 ]; then
                curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
                apt-get install -y nodejs
            else
                curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
                sudo apt-get install -y nodejs
            fi
            ;;
        redhat)
            if [ "$EUID" -eq 0 ]; then
                curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
                dnf install -y nodejs
            else
                curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
                sudo dnf install -y nodejs
            fi
            ;;
        macos)
            brew install node@20
            # Add to path
            export PATH="/opt/homebrew/opt/node@20/bin:$PATH"
            ;;
        arch)
            install_package "nodejs" "node"
            install_package "npm"
            ;;
        *)
            error "Install Node.js 18+ manually: https://nodejs.org/"
            ;;
    esac
    log "Node.js: $(node -v)"
fi

# ---- Backend Python Environment ----
header "Backend Setup"

cd "$ROOT_DIR/backend"

if [ ! -d "venv" ]; then
    log "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate venv (cross-platform)
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
fi

log "Upgrading pip..."
pip install --upgrade pip -q

log "Installing Python dependencies..."
pip install -r requirements.txt -q

# ---- Playwright dependencies ----
log "Installing Playwright chromium..."
PLAYWRIGHT_DEPS=""

case $OS_FAMILY in
    debian)
        PLAYWRIGHT_DEPS="libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 libpango-1.0-0 libcairo2"
        if [ "$EUID" -eq 0 ]; then
            apt-get install -y $PLAYWRIGHT_DEPS 2>/dev/null || true
        else
            sudo apt-get install -y $PLAYWRIGHT_DEPS 2>/dev/null || true
        fi
        ;;
    redhat)
        PLAYWRIGHT_DEPS="nss nspr atk at-spi2-atk cups-libs libdrm libxkbcommon libXcomposite libXdamage libXfixes libXrandr mesa-libgbm alsa-lib pango cairo"
        if [ "$EUID" -eq 0 ]; then
            dnf install -y $PLAYWRIGHT_DEPS 2>/dev/null || true
        else
            sudo dnf install -y $PLAYWRIGHT_DEPS 2>/dev/null || true
        fi
        ;;
    macos)
        # macOS doesn't need additional deps for Playwright
        ;;
esac

python3 -m playwright install chromium 2>/dev/null || warn "Playwright chromium install failed (optional)"
python3 -m playwright install-deps chromium 2>/dev/null || true

# Create data directory
mkdir -p "$ROOT_DIR/backend/data"

cd "$ROOT_DIR"

# ---- Frontend ----
header "Frontend Setup"
cd "$ROOT_DIR/frontend"

# Clean install if node_modules might have issues
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

# Grok (xAI)
GROK_API_KEY=

# OpenRouter (optional)
OPENROUTER_API_KEY=

# Anthropic Claude (optional)
ANTHROPIC_API_KEY=

# OpenAI (optional)
OPENAI_API_KEY=
EOF
    log "Created backend/.env"
else
    log ".env already exists"
fi

# ---- Create start.sh ----
cat > "$ROOT_DIR/start.sh" << 'STARTEOF'
#!/bin/bash

# All-Hack Start Script
# Usage: ./start.sh [dev|prod]

# Get script directory (cross-platform)
get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [ -h "$source" ]; do
        local dir="$(cd -P "$(dirname "$source")" && pwd)"
        source="$(readlink "$source" 2>/dev/null || greadlink "$source" 2>/dev/null || echo "$source")"
        [[ $source != /* ]] && source="$dir/$source"
    done
    echo "$(cd -P "$(dirname "$source")" && pwd)"
}

ROOT_DIR="$(get_script_dir)"
cd "$ROOT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[x]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

# Parse arguments
MODE="${1:-prod}"

# PID file for tracking
PID_FILE="$ROOT_DIR/.allhack.pid"
LOG_DIR="$ROOT_DIR/logs"
mkdir -p "$LOG_DIR"

# Check if already running
if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null)
    if kill -0 "$OLD_PID" 2>/dev/null; then
        warn "All-Hack already running (PID: $OLD_PID)"
        warn "Run ./stop.sh first or use: kill $OLD_PID"
        exit 1
    else
        rm -f "$PID_FILE"
    fi
fi

cleanup() {
    log "Shutting down..."
    [ -n "$BACKEND_PID" ] && kill $BACKEND_PID 2>/dev/null
    [ -n "$FRONTEND_PID" ] && kill $FRONTEND_PID 2>/dev/null
    rm -f "$PID_FILE"
    exit 0
}
trap cleanup SIGINT SIGTERM

# Check prerequisites
if [ ! -d "backend/venv" ]; then
    error "Backend not installed. Run ./install.sh first"
fi

if [ ! -d "frontend/node_modules" ]; then
    error "Frontend not installed. Run ./install.sh first"
fi

# Start backend
log "Starting backend..."
cd "$ROOT_DIR/backend"

# Activate venv (cross-platform)
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
fi

uvicorn app.main:app --host 0.0.0.0 --port 8001 > "$LOG_DIR/backend.log" 2>&1 &
BACKEND_PID=$!
echo "$BACKEND_PID" > "$PID_FILE"

cd "$ROOT_DIR"

# Wait for backend
sleep 2
if ! kill -0 $BACKEND_PID 2>/dev/null; then
    error "Backend failed to start. Check $LOG_DIR/backend.log"
fi

log "Backend running on http://localhost:8001"

if [ "$MODE" == "dev" ]; then
    # Development mode: run frontend dev server
    log "Starting frontend dev server..."
    cd "$ROOT_DIR/frontend"
    npm run dev > "$LOG_DIR/frontend.log" 2>&1 &
    FRONTEND_PID=$!
    echo "$FRONTEND_PID" >> "$PID_FILE"
    cd "$ROOT_DIR"

    sleep 3
    if ! kill -0 $FRONTEND_PID 2>/dev/null; then
        warn "Frontend dev server failed. Check $LOG_DIR/frontend.log"
    else
        log "Frontend running on http://localhost:5173"
    fi

    echo ""
    info "Development mode"
    info "  Frontend: http://localhost:5173"
    info "  Backend:  http://localhost:8001"
    info "  API Docs: http://localhost:8001/docs"
else
    # Production mode: serve frontend from backend
    echo ""
    info "Production mode"
    info "  URL:      http://localhost:8001"
    info "  API Docs: http://localhost:8001/docs"
fi

echo ""
info "Logs: $LOG_DIR/"
log "Press Ctrl+C to stop"

# Wait for processes
wait
STARTEOF
chmod +x "$ROOT_DIR/start.sh"

# ---- Create stop.sh ----
cat > "$ROOT_DIR/stop.sh" << 'STOPEOF'
#!/bin/bash

# All-Hack Stop Script

# Get script directory (cross-platform)
get_script_dir() {
    local source="${BASH_SOURCE[0]}"
    while [ -h "$source" ]; do
        local dir="$(cd -P "$(dirname "$source")" && pwd)"
        source="$(readlink "$source" 2>/dev/null || greadlink "$source" 2>/dev/null || echo "$source")"
        [[ $source != /* ]] && source="$dir/$source"
    done
    echo "$(cd -P "$(dirname "$source")" && pwd)"
}

ROOT_DIR="$(get_script_dir)"
PID_FILE="$ROOT_DIR/.allhack.pid"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

log "Stopping All-Hack..."

# Kill by PID file
if [ -f "$PID_FILE" ]; then
    while read pid; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            log "Killed process $pid"
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
fi

# Also kill by process name (fallback)
pkill -f "uvicorn app.main:app" 2>/dev/null && log "Killed uvicorn"
pkill -f "vite.*frontend" 2>/dev/null && log "Killed vite"

log "Stopped"
STOPEOF
chmod +x "$ROOT_DIR/stop.sh"

# ---- Create status.sh ----
cat > "$ROOT_DIR/status.sh" << 'STATUSEOF'
#!/bin/bash

# All-Hack Status Script

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "All-Hack Status"
echo "---------------"

# Check backend
if pgrep -f "uvicorn app.main:app" > /dev/null; then
    echo -e "Backend:  ${GREEN}Running${NC}"

    # Try to get actual status
    if command -v curl &> /dev/null; then
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8001/health 2>/dev/null || echo "000")
        if [ "$HTTP_CODE" == "200" ]; then
            echo -e "  Health: ${GREEN}OK${NC}"
        else
            echo -e "  Health: Checking..."
        fi
    fi
else
    echo -e "Backend:  ${RED}Stopped${NC}"
fi

# Check frontend dev
if pgrep -f "vite" > /dev/null; then
    echo -e "Frontend: ${GREEN}Running (dev)${NC}"
else
    echo -e "Frontend: Served by backend (prod)"
fi

# URLs
echo ""
echo "URLs:"
echo "  http://localhost:8001"
echo "  http://localhost:8001/docs"
STATUSEOF
chmod +x "$ROOT_DIR/status.sh"

# ---- Done ----
header "Installation Complete"
echo ""
log "Commands:"
echo "    ./start.sh       Start in production mode"
echo "    ./start.sh dev   Start in development mode"
echo "    ./stop.sh        Stop all services"
echo "    ./status.sh      Check status"
echo ""
log "URLs:"
echo "    Production:  http://localhost:8001"
echo "    Development: http://localhost:5173"
echo "    API Docs:    http://localhost:8001/docs"
echo ""
