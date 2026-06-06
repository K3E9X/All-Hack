#!/usr/bin/env bash
# install.sh - one-shot installer for Ubuntu, Debian, macOS (Apple Silicon or
# Intel), and Windows via WSL2 (inside WSL the OS is detected as Linux).
#
# What it does:
#   1. Verify Docker and Docker Compose are installed.
#   2. Create .env from .env.example if missing.
#   3. Create ./data directory (SQLite + session storage).
#   4. Build Docker images (backend + frontend).
#
# After this script finishes, run ./start.sh to launch the stack.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { printf '[install] %s\n' "$*"; }
fail() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

detect_os() {
    local uname_s
    uname_s="$(uname -s)"
    case "$uname_s" in
        Linux*)  echo "linux"  ;;
        Darwin*) echo "macos"  ;;
        *)       echo "unknown";;
    esac
}

OS="$(detect_os)"
ARCH="$(uname -m)"
log "Detected OS: ${OS} (${ARCH})"

if [ "$OS" = "unknown" ]; then
    fail "Unsupported OS. Supported: Ubuntu, Debian, macOS, Windows via WSL2."
fi

# Friendly note when running inside WSL.
if [ "$OS" = "linux" ] && grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
    log "Running under WSL2. Make sure Docker is reachable (Docker Desktop WSL"
    log "integration, or docker-ce inside this distro)."
fi

# Docker check.
if ! command -v docker >/dev/null 2>&1; then
    if [ "$OS" = "macos" ]; then
        fail "Docker not found. Install Docker Desktop or OrbStack, then re-run."
    else
        fail "Docker not found. Install with: curl -fsSL https://get.docker.com | sh"
    fi
fi

if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon is not running. Start Docker (or Docker Desktop) and re-run."
fi

# Docker Compose check (v2 plugin preferred).
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    fail "Docker Compose not found. Install Docker Compose v2 (comes with Docker Desktop)."
fi

log "Using compose command: ${COMPOSE_CMD}"

# .env bootstrap.
if [ ! -f .env ]; then
    if [ -f .env.example ]; then
        cp .env.example .env
        log "Created .env from .env.example - open it and set OPENROUTER_API_KEY."
    else
        fail ".env.example not found."
    fi
else
    log ".env already exists, leaving it alone."
fi

# Data dir.
mkdir -p ./data
log "Data directory ready: ./data"

# Build images.
log "Building images (this can take a few minutes the first time)..."
$COMPOSE_CMD build

log "Install complete. Next step:"
log "  1. Edit .env and set OPENROUTER_API_KEY (get one at https://openrouter.ai/keys)."
log "  2. Run: ./start.sh"
