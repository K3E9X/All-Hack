#!/bin/bash

# All-Hack Start Script
# Usage: ./start.sh [dev|prod]
# Compatible: macOS, Debian, Ubuntu, Fedora

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
    OLD_PID=$(cat "$PID_FILE" 2>/dev/null | head -1)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        warn "All-Hack already running (PID: $OLD_PID)"
        warn "Run ./stop.sh first"
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

# Activate venv (cross-platform: Linux/macOS vs Windows Git Bash)
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
