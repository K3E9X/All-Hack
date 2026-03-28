#!/bin/bash

# All-Hack Stop Script
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
PID_FILE="$ROOT_DIR/.allhack.pid"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

log "Stopping All-Hack..."

STOPPED=0

# Kill by PID file
if [ -f "$PID_FILE" ]; then
    while read pid; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            log "Killed process $pid"
            STOPPED=1
        fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
fi

# Also kill by process name (fallback)
if pgrep -f "uvicorn app.main:app" > /dev/null 2>&1; then
    pkill -f "uvicorn app.main:app" 2>/dev/null
    log "Killed uvicorn"
    STOPPED=1
fi

if pgrep -f "vite" > /dev/null 2>&1; then
    pkill -f "vite.*frontend" 2>/dev/null || pkill -f "vite" 2>/dev/null
    log "Killed vite"
    STOPPED=1
fi

if [ $STOPPED -eq 0 ]; then
    warn "No running processes found"
else
    log "Stopped"
fi
