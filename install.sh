#!/bin/bash

# All-Hack Installation Script
# Automated security assessment tool

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[x]${NC} $1"
    exit 1
}

header() {
    echo ""
    echo -e "${BOLD}$1${NC}"
    echo "----------------------------------------"
}

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    warn "Running as root. Recommend running as normal user."
fi

header "All-Hack Installation"

# Detect OS
OS="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
elif [ "$(uname)" == "Darwin" ]; then
    OS="macos"
fi

log "Detected OS: $OS"

# Check Python
header "Checking Python"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
    log "Python found: $PYTHON_VERSION"
else
    error "Python 3 not found. Please install Python 3.10+"
fi

# Check Node.js
header "Checking Node.js"
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    log "Node.js found: $NODE_VERSION"
else
    warn "Node.js not found. Installing..."
    if [ "$OS" == "ubuntu" ] || [ "$OS" == "debian" ]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [ "$OS" == "macos" ]; then
        brew install node
    else
        error "Please install Node.js manually: https://nodejs.org/"
    fi
fi

# Install Ollama
header "Installing Ollama (Local LLM)"
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

# Start Ollama service
log "Starting Ollama service..."
if [ "$OS" == "macos" ]; then
    brew services start ollama 2>/dev/null || true
else
    sudo systemctl enable ollama 2>/dev/null || true
    sudo systemctl start ollama 2>/dev/null || true
fi

# Pull default model
log "Pulling llama3.2 model (this may take a while)..."
ollama pull llama3.2 2>/dev/null || warn "Could not pull model. Run 'ollama pull llama3.2' manually."

# Create Python virtual environment
header "Setting up Python environment"
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    log "Creating virtual environment..."
    python3 -m venv venv
fi

log "Activating virtual environment..."
source venv/bin/activate

log "Installing Python dependencies..."
pip install --upgrade pip
pip install -r backend/requirements.txt

# Install frontend dependencies
header "Setting up Frontend"
cd frontend

if [ ! -d "node_modules" ]; then
    log "Installing Node.js dependencies..."
    npm install
fi

log "Building frontend..."
npm run build

cd ..

# Create .env file if not exists
header "Configuration"
if [ ! -f "backend/.env" ]; then
    log "Creating .env file..."
    cat > backend/.env << EOF
# All-Hack Configuration

# API Settings
API_HOST=0.0.0.0
API_PORT=8001

# Ollama Settings
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama3.2

# Scan Settings
DEFAULT_TIMEOUT=30
MAX_CONCURRENT_REQUESTS=20
EOF
    log "Created backend/.env"
else
    log ".env file already exists"
fi

# Create start script
log "Creating start script..."
cat > start.sh << 'EOF'
#!/bin/bash

# Start All-Hack

cd "$(dirname "$0")"
source venv/bin/activate

# Check Ollama
if ! pgrep -x "ollama" > /dev/null; then
    echo "[+] Starting Ollama..."
    ollama serve &
    sleep 2
fi

# Start backend
cd backend
echo "[+] Starting All-Hack on http://localhost:8001"
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
EOF
chmod +x start.sh

header "Installation Complete"
echo ""
log "To start All-Hack:"
echo "    ./start.sh"
echo ""
log "Then open: http://localhost:8001"
echo ""
log "API docs: http://localhost:8001/docs"
echo ""
